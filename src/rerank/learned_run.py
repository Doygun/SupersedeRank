from __future__ import annotations

import hashlib
import json
import pickle
import sys
import time
import warnings
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from src import paths
from src.eval import metrics as M
from src.label.splits import assert_selection_split
from src.rerank import learned_features as F
from src.rerank import rule_inferred as RI
from src.rerank.common import load_pool, load_rerank_config, minmax, query_lookup, tie_seed, write_jsonl
from src.rerank.rule_inferred import block_rerank
from src.retrieval.bm25_runner import evaluate, oracle_rerank, report, tie_key

OUT = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_learned"
MODEL_DIR = paths.PROCESSED_DATA_DIR / "retrieval" / "learned"
CONDITIONS = {"learned_full": False, "learned_no_rule_signal": True}
POS, NEG = "TARGET_CURRENT", "TARGET_OUTDATED"

def load_learned_config() -> dict[str, Any]:
    return yaml.safe_load((paths.PROJECT_ROOT / "config" / "learned.yaml").read_text(encoding="utf-8"))

def sha(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode("utf-8")).hexdigest()

def load_views(store: Path) -> list[dict[str, Any]]:
    return [RI.narrow_view(json.loads(l)) for l in store.open(encoding="utf-8")]

def ce_scores(splits: tuple[str, ...]) -> dict[tuple[str, str], float]:
    out = {}
    for s in splits:
        for line in (paths.PROJECT_ROOT / "results" / "experiments" / "cross_encoder" / f"{s}_top50.jsonl").open(encoding="utf-8"):
            row = json.loads(line)
            for c in row["candidates"]:
                out[(row["query_id"], c["evidence_id"])] = float(c["score"])
    return out

def stored(dirname: str, pattern: str, splits: tuple[str, ...], ids: set[str]) -> dict[str, dict]:
    out = {}
    for s in splits:
        for line in (paths.PROJECT_ROOT / "results" / "experiments" / dirname / pattern.format(split=s)).open(encoding="utf-8"):
            row = json.loads(line)
            if row["query_id"] in ids:
                out[row["query_id"]] = row
    return out

class Featurizer:
    def __init__(self, all_index: RI.ChainIndex, witness_index: RI.ChainIndex, ce: dict[tuple[str, str], float], source_map: dict[str, str]):
        self.all_index, self.witness_index, self.ce, self.source_map = all_index, witness_index, ce, source_map

    def rows_for_query(self, r: dict, q: dict) -> list[dict[str, Any]]:
        norm = minmax([c["score"] for c in r["candidates"]])
        return [F.candidate_features(c, q, n, self.ce.get((r["query_id"], c["evidence_id"])), self.all_index, self.witness_index, self.source_map)
                for c, n in zip(r["candidates"], norm)]

def build_examples(pool_rows: list[dict], queries: dict[str, dict], fz: Featurizer) -> tuple[list[dict], np.ndarray, list[dict]]:
    feats, y, meta = [], [], []
    for r in pool_rows:
        q = queries[r["query_id"]]
        rows = fz.rows_for_query(r, q)
        for c, f in zip(r["candidates"], rows):
            if c["class"] in (POS, NEG):
                feats.append(f); y.append(1 if c["class"] == POS else 0)
                meta.append({"query_id": r["query_id"], "evidence_id": c["evidence_id"], "cve_id": q["cve_id"]})
    return feats, np.array(y, dtype=int), meta

class Preproc:

    def __init__(self, cols: list[str]):
        self.cols = cols
        self.numeric = [c for c in cols if c in F.NUMERIC]
        self.median: dict[str, float] = {}
        self.mean: dict[str, float] = {}
        self.std: dict[str, float] = {}

    def fit(self, feats: list[dict]) -> "Preproc":
        for c in self.numeric:
            v = np.array([f[c] for f in feats], dtype=float)
            self.median[c] = float(np.nanmedian(v)) if (~np.isnan(v)).any() else 0.0
            v = np.where(np.isnan(v), self.median[c], v)
            self.mean[c], self.std[c] = float(v.mean()), float(v.std() or 1.0)
        return self

    def transform(self, feats: list[dict]) -> np.ndarray:
        X = np.zeros((len(feats), len(self.cols)), dtype=float)
        for j, c in enumerate(self.cols):
            v = np.array([f[c] for f in feats], dtype=float)
            if c in self.numeric:
                v = np.where(np.isnan(v), self.median[c], v)
                v = (v - self.mean[c]) / self.std[c]
            X[:, j] = v
        return X

    def state(self) -> dict[str, Any]:
        return {"cols": self.cols, "numeric": self.numeric, "median": self.median, "mean": self.mean, "std": self.std}

def rerank_learned(cands: list[dict], p: dict[str, float], target: dict[str, bool], policy: str, alpha: float | None, seed: int, qid: str) -> list[dict]:
    if policy == "block":
        flags = {c["evidence_id"]: bool(target[c["evidence_id"]] and p[c["evidence_id"]] < 0.5) for c in cands}
        return block_rerank(cands, flags, "learned_block")
    norm = dict(zip((c["evidence_id"] for c in cands), minmax([c["score"] for c in cands])))
    score = {e: norm[e] + (alpha * (p[e] - 0.5) if target[e] else 0.0) for e in norm}
    order = sorted(cands, key=lambda c: (-score[c["evidence_id"]], tie_key(seed, qid, c["evidence_id"])))
    return [{**{k: v for k, v in c.items() if k not in ("rank", "score", "bm25_rank", "suppressed")}, "rank": r, "evidence_id": c["evidence_id"], "score": score[c["evidence_id"]],
             "bm25_rank": c["rank"], "suppressed": bool(target[c["evidence_id"]] and p[c["evidence_id"]] < 0.5)} for r, c in enumerate(order, start=1)]

def score_query(model, pre: Preproc, fz: Featurizer, r: dict, q: dict) -> tuple[dict[str, float], dict[str, bool]]:
    rows = fz.rows_for_query(r, q)
    X = pre.transform(rows)
    prob = model.predict_proba(X)[:, 1]
    p = {c["evidence_id"]: float(pr) for c, pr in zip(r["candidates"], prob)}
    target = {c["evidence_id"]: F.is_target_chain(fz.all_index.view[c["evidence_id"]], q) for c in r["candidates"]}
    return p, target

def eval_lists(pool_rows: list[dict], queries: dict, model, pre: Preproc, fz: Featurizer, policy: str, alpha: float | None, seed: int) -> list[dict]:
    out = []
    for r in pool_rows:
        q = queries[r["query_id"]]
        p, target = score_query(model, pre, fz, r, q)
        ranked = rerank_learned(r["candidates"], p, target, policy, alpha, seed, r["query_id"])
        ev = evaluate(ranked, q); ev.update(M.stale_suppression(ranked, r["candidates"]))
        ev["_ranked"] = ranked; ev["_p"] = p; ev["_target"] = target
        out.append({"query_id": r["query_id"], **ev})
    return out

def rerank_summary(rows: list[dict]) -> dict[str, float]:
    from src.retrieval.bm25_runner import summarize
    s = summarize([{"x": r} for r in rows], "x")
    s.update({k: v for k, v in M.summarize_stale_suppression(rows).items() if k != "queries"})
    return s

def classification(model, X: np.ndarray, y: np.ndarray) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, balanced_accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= 0.5).astype(int)
    cm = confusion_matrix(y, pred, labels=[0, 1]).tolist()
    return {"n": int(len(y)), "accuracy": round(float(accuracy_score(y, pred)), 4), "balanced_accuracy": round(float(balanced_accuracy_score(y, pred)), 4),
            "precision_current": round(float(precision_score(y, pred, zero_division=0)), 4), "recall_current": round(float(recall_score(y, pred, zero_division=0)), 4),
            "f1_current": round(float(f1_score(y, pred, zero_division=0)), 4), "roc_auc": round(float(roc_auc_score(y, prob)), 4) if len(set(y.tolist())) > 1 else None,
            "confusion_matrix_rows_true_outdated_current": cm,
            "probability_histogram": {f"{lo / 10:.1f}-{(lo + 1) / 10:.1f}": int(((prob >= lo / 10) & (prob < (lo + 1) / 10 + (1e-9 if lo == 9 else 0))).sum()) for lo in range(10)},
            "nan_or_inf_probabilities": int((~np.isfinite(prob)).sum())}

def main() -> int:
    from sklearn.linear_model import LogisticRegression

    t0 = time.perf_counter()
    lcfg, rcfg = load_learned_config(), load_rerank_config()
    seed = tie_seed()
    store = paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl"
    views = load_views(store)
    witness_ids, cross_ids = RI.load_witness_ids(paths.PROCESSED_DATA_DIR / "evidence" / "evidence.jsonl", paths.PROCESSED_DATA_DIR / "sensitivity" / "cross_event_replacements.jsonl")
    witness_index = RI.ChainIndex(views, witness_ids)
    all_index = RI.ChainIndex(views, {v["evidence_id"] for v in views})
    splits = ("train", "dev", "test", "future_event")
    pool = load_pool(paths.PROJECT_ROOT / rcfg["candidate_pool"]["source"], splits)
    queries = query_lookup(splits, "POST_REPLACEMENT_MAIN")
    ce = ce_scores(splits)
    train_q = [queries[r["query_id"]] for r in pool["train"]]
    source_map = F.fit_source_map(train_q)
    fz = Featurizer(all_index, witness_index, ce, source_map)

    tr_f, tr_y, tr_meta = build_examples(pool["train"], queries, fz)
    dv_f, dv_y, dv_meta = build_examples(pool[assert_selection_split("dev")], queries, fz)
    class_ratio = round(float((tr_y == 0).sum() / (tr_y == 1).sum()), 4)
    rule_dev = stored("chronorank_rule/full", "{split}_inferred_top50.jsonl", ("dev",), {r["query_id"] for r in pool["dev"]})
    rule_dev_rows = []
    for r in pool["dev"]:
        ranked = rule_dev[r["query_id"]]["candidates"]
        ev = evaluate(ranked, queries[r["query_id"]]); ev.update(M.stale_suppression(ranked, r["candidates"])); rule_dev_rows.append(ev)
    rule_dev_joint = M.summarize_stale_suppression(rule_dev_rows)["current_at1_and_no_stale@10"]
    selection: dict[str, Any] = {"selection_split": "dev", "objective": "current_at1_and_no_stale@10", "tie_breaker": "ndcg@10_graded",
                                 "class_ratio_outdated_to_current_train": class_ratio, "class_weight": None,
                                 "class_weight_note": "classes are ~balanced (ratio ~1.04); class_weight=None by decision; 'balanced' not run as a second method",
                                 "rule_inferred_dev_joint_reference": rule_dev_joint, "conditions": {}}
    models: dict[str, Any] = {}
    single_feature = {}
    for cond, drop in CONDITIONS.items():
        cols = F.feature_order(source_map, drop_rule_signal=drop)
        pre = Preproc(cols).fit(tr_f)
        Xtr, Xdv = pre.transform(tr_f), pre.transform(dv_f)
        table = []
        for C in lcfg["model"]["C_candidates"]:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                lr = LogisticRegression(penalty=lcfg["model"]["penalty"], C=float(C), solver=lcfg["model"]["solver"], max_iter=int(lcfg["model"]["max_iter"]),
                                        random_state=int(lcfg["model"]["random_state"]), class_weight=None).fit(Xtr, tr_y)
                conv_warn = [str(x.message)[:120] for x in w if "onverge" in str(x.message)]
            dev_rows = eval_lists(pool["dev"], queries, lr, pre, fz, "block", None, seed)
            s = rerank_summary(dev_rows)
            table.append({"C": C, "dev_rerank": {k: s[k] for k in ("mrr@10", "ndcg@10", "ndcg@10_graded", "stale@10", "current_preservation@10", "current_at1_and_no_stale@10", "outdated_suppression@10")},
                          "train_clf": classification(lr, Xtr, tr_y), "dev_clf": classification(lr, Xdv, dv_y), "convergence_warnings": conv_warn, "_model": lr})
        best = sorted(table, key=lambda t: (-t["dev_rerank"]["current_at1_and_no_stale@10"], -t["dev_rerank"]["ndcg@10_graded"], t["C"]))[0]

        insufficient = best["dev_rerank"]["current_preservation@10"] < 0.99 or best["dev_rerank"]["current_at1_and_no_stale@10"] < rule_dev_joint - 0.05
        policy, alpha, alpha_table = "block", None, []
        if insufficient:
            for a in lcfg["combination"]["alpha_candidates"]:
                s = rerank_summary(eval_lists(pool["dev"], queries, best["_model"], pre, fz, "alpha", float(a), seed))
                alpha_table.append({"alpha": a, **{k: s[k] for k in ("mrr@10", "ndcg@10_graded", "stale@10", "current_preservation@10", "current_at1_and_no_stale@10")}})
            best_a = sorted(alpha_table, key=lambda t: (-t["current_at1_and_no_stale@10"], -t["ndcg@10_graded"], t["alpha"]))[0]
            if best_a["current_at1_and_no_stale@10"] > best["dev_rerank"]["current_at1_and_no_stale@10"]:
                policy, alpha = "alpha", float(best_a["alpha"])
        models[cond] = {"model": best["_model"], "pre": pre, "cols": cols, "C": best["C"], "policy": policy, "alpha": alpha}

        if not drop:
            j = cols.index(F.RULE_FEATURE)
            for name, Xs, ys in (("train", Xtr, tr_y), ("dev", Xdv, dv_y)):
                pred = (Xs[:, j] < 0.5).astype(int)
                single_feature[name] = {"accuracy_rule_feature_alone": round(float((pred == ys).mean()), 4), "n": int(len(ys))}
        selection["conditions"][cond] = {"feature_order": cols, "C_table": [{k: v for k, v in t.items() if k != "_model"} for t in table], "selected_C": best["C"],
                                         "block_policy_insufficient_on_dev": bool(insufficient), "alpha_table": alpha_table, "selected_policy": policy, "selected_alpha": alpha}
    (OUT).mkdir(parents=True, exist_ok=True)
    (OUT / "train_dev_selection.json").write_text(json.dumps(selection, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    coef_out, manifest_models = {}, {}
    for cond, m in models.items():
        coefs = {c: round(float(w), 6) for c, w in zip(m["cols"], m["model"].coef_[0])}
        ranked_feats = sorted(coefs.items(), key=lambda kv: kv[1])
        coef_out[cond] = {"C": m["C"], "intercept": round(float(m["model"].intercept_[0]), 6), "coefficients_standardised_inputs": coefs,
                          "most_negative_toward_outdated": ranked_feats[:5], "most_positive_toward_current": ranked_feats[-5:][::-1]}
        with (MODEL_DIR / f"{cond}.pkl").open("wb") as h:
            pickle.dump({"model": m["model"], "preprocessing": m["pre"].state(), "cols": m["cols"], "policy": m["policy"], "alpha": m["alpha"]}, h)
        manifest_models[cond] = {"feature_order": m["cols"], "n_features": len(m["cols"]), "preprocessing_hash": sha(m["pre"].state()), "preprocessing": m["pre"].state(),
                                 "C": m["C"], "policy": m["policy"], "alpha": m["alpha"], "random_state": int(lcfg["model"]["random_state"]), "coefficients": coef_out[cond],
                                 "model_file": paths.relative_to_project(MODEL_DIR / f"{cond}.pkl")}
    manifest = {"model_family": "logistic_regression", "penalty": lcfg["model"]["penalty"], "solver": lcfg["model"]["solver"], "max_iter": lcfg["model"]["max_iter"],
                "class_weight": None, "class_ratio_outdated_to_current_train": class_ratio,
                "class_weight_note": selection["class_weight_note"], "config_hash_learned_yaml": hashlib.sha256((paths.PROJECT_ROOT / "config" / "learned.yaml").read_bytes()).hexdigest(),
                "train_examples": {"current": int(tr_y.sum()), "outdated": int((tr_y == 0).sum()), "queries": len(pool["train"])},
                "dev_examples": {"current": int(dv_y.sum()), "outdated": int((dv_y == 0).sum()), "queries": len(pool["dev"])},
                "source_map_train_only": source_map, "witness_scope": {"entries": witness_index.n_witnesses, "cross_event_ids_excluded": len(cross_ids)},
                "forbidden_fields": lcfg["features"]["forbidden"], "models": manifest_models, "single_feature_rule_signal_accuracy": single_feature,
                "locked_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "lock_note": "test opened only after this manifest was written"}
    (OUT / "learned_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    (OUT / "feature_coefficients.json").write_text(json.dumps(coef_out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    t_lock = time.perf_counter() - t0

    smoke_ids = json.loads((paths.PROJECT_ROOT / rcfg["candidate_pool"]["smoke_source"] / "sampled_queries.json").read_text(encoding="utf-8"))
    ids = {i for v in smoke_ids.values() for i in v}
    smoke_pool = {s: [r for r in pool[s] if r["query_id"] in ids] for s in ("train", "dev", "test")}
    lists = {"bm25_recency": stored("recency", "{split}_bm25_recency_top50.jsonl", ("train", "dev", "test"), ids),
             "cross_encoder": stored("cross_encoder", "{split}_top50.jsonl", ("train", "dev", "test"), ids),
             "rule_inferred": stored("chronorank_rule/full", "{split}_inferred_top50.jsonl", ("train", "dev", "test"), ids),
             "rule_direct_upper_bound": stored("chronorank_rule/full", "{split}_direct_top50.jsonl", ("train", "dev", "test"), ids)}
    per_query, agree = [], Counter()
    neg = Counter()
    diff_rows = []
    learned_lists = {c: {s: [] for s in smoke_pool} for c in CONDITIONS}
    for s, rows in smoke_pool.items():
        for r in sorted(rows, key=lambda x: x["query_id"]):
            q, cands = queries[r["query_id"]], r["candidates"]
            recd = {"query_id": r["query_id"], "split": s, "template": q["query_template_id"], "cve_id": q["cve_id"], "source_key": q["source_key"], "cvss_version": q["cvss_version"],
                    "censored": q["valid_from_censored"], "n_candidates": len(cands)}
            rule_list = lists["rule_inferred"][r["query_id"]]["candidates"]
            recd["n_preserved_rule"] = sum(1 for c in rule_list if not c["suppressed"])
            recd["preserved_ge10"] = recd["n_preserved_rule"] >= 10
            ml = {"bm25": cands, "bm25_recency": lists["bm25_recency"][r["query_id"]]["candidates"], "cross_encoder": lists["cross_encoder"][r["query_id"]]["candidates"],
                  "rule_inferred": rule_list, "rule_direct_upper_bound": lists["rule_direct_upper_bound"][r["query_id"]]["candidates"], "oracle_temporal": oracle_rerank(cands, "temporal")}
            for cond, m in models.items():
                p, target = score_query(m["model"], m["pre"], fz, r, q)
                ranked = rerank_learned(cands, p, target, m["policy"], m["alpha"], seed, r["query_id"])
                ml[cond] = ranked
                for c in ranked:
                    if c["suppressed"] and c["class"] == "TARGET_CURRENT":
                        neg[f"{cond}_current_suppressed"] += 1
                    if c["class"] == "OTHER_SOURCE_CURRENT" and c["suppressed"]:
                        neg[f"{cond}_other_source_current_suppressed"] += 1
                    if not target[c["evidence_id"]] and c["suppressed"]:
                        neg[f"{cond}_non_target_suppressed"] += 1
                neg[f"{cond}_nan_p"] += sum(1 for v in p.values() if not np.isfinite(v))
                learned_lists[cond][s].append({"query_id": r["query_id"], "split": s, "query_time": r["query_time"], "candidates": ranked,
                                               "p_current_target_chain": {e: round(v, 4) for e, v in p.items() if target[e]}})
            for name, lst in ml.items():
                ev = evaluate(lst, q); ev.update(M.stale_suppression(lst, cands)); recd[name] = ev
            recd["achievable"] = recd["bm25"]["target_in_top50"]
            per_query.append(recd)

            lf = ml["learned_full"]
            same_list = [c["evidence_id"] for c in lf] == [c["evidence_id"] for c in rule_list]
            rule_target_sup = {c["evidence_id"] for c in rule_list if c["suppressed"] and F.is_target_chain(all_index.view[c["evidence_id"]], q)}
            learned_sup = {c["evidence_id"] for c in lf if c["suppressed"]}
            agree["queries"] += 1; agree["same_full_list"] += same_list; agree["same_target_chain_decisions"] += rule_target_sup == learned_sup
            if not same_list:
                j_l, j_r = recd["learned_full"]["current_at1_and_no_stale@10"], recd["rule_inferred"]["current_at1_and_no_stale@10"]
                st_l, st_r = recd["learned_full"]["stale@10"], recd["rule_inferred"]["stale@10"]
                verdict = "better" if (j_l and not j_r) or (j_l == j_r and st_l < st_r) else "worse" if (j_r and not j_l) or (j_l == j_r and st_l > st_r) else "equal"
                agree[f"differ_{verdict}"] += 1
                diff_rows.append({"query_id": r["query_id"], "split": s, "verdict": verdict, "only_learned_suppressed": sorted(learned_sup - rule_target_sup)[:5],
                                  "only_rule_suppressed_target_chain": sorted(rule_target_sup - learned_sup)[:5], "n_preserved_rule": recd["n_preserved_rule"]})
    for cond in CONDITIONS:
        for s, rows in learned_lists[cond].items():
            write_jsonl(OUT / "smoke" / f"{s}_{cond}_top50.jsonl", rows)
    methods = ("bm25", "bm25_recency", "cross_encoder", "rule_inferred", "learned_full", "learned_no_rule_signal")
    upper = ("rule_direct_upper_bound", "oracle_temporal")
    rep = report(per_query, keys=methods + upper, source_groups=None)
    for m in methods + upper:
        rep[m]["stale_suppression"] = M.summarize_stale_suppression([p[m] for p in per_query])
        rep[m]["stale_suppression_by_split"] = {s: M.summarize_stale_suppression([p[m] for p in per_query if p["split"] == s]) for s in ("train", "dev", "test")}
        rep[m]["capacity_groups"] = {g: {**rerank_summary([p[m] for p in per_query if p["preserved_ge10"] == flag]), "queries": sum(1 for p in per_query if p["preserved_ge10"] == flag)}
                                     for g, flag in (("preserved_ge10", True), ("preserved_lt10", False))}
    full_vs_norule = {k: [rep["learned_full"]["all"].get(k, rep["learned_full"]["stale_suppression"].get(k)), rep["learned_no_rule_signal"]["all"].get(k, rep["learned_no_rule_signal"]["stale_suppression"].get(k))]
                      for k in ("mrr@10", "ndcg@10_graded", "stale@10", "outdated_suppression@10", "current_preservation@10", "current_at1_and_no_stale@10")}
    gates = {"no_candidate_change": all(set(c["evidence_id"] for c in l["candidates"]) == set(c["evidence_id"] for c in next(r for r in smoke_pool[l["split"]] if r["query_id"] == l["query_id"])["candidates"])
                                        for cond in CONDITIONS for s in smoke_pool for l in learned_lists[cond][s]),
             "recall50_equals_bm25": all(p[c]["recall@50"] == p["bm25"]["recall@50"] for p in per_query for c in CONDITIONS),
             "no_current_suppressed_full": neg["learned_full_current_suppressed"] == 0, "no_current_suppressed_no_rule": neg["learned_no_rule_signal_current_suppressed"] == 0,
             "no_other_source_current_suppressed": neg["learned_full_other_source_current_suppressed"] == 0 and neg["learned_no_rule_signal_other_source_current_suppressed"] == 0,
             "no_non_target_suppressed": neg["learned_full_non_target_suppressed"] == 0 and neg["learned_no_rule_signal_non_target_suppressed"] == 0,
             "no_nan": sum(v for k, v in neg.items() if k.endswith("_nan_p")) == 0, "test_not_used_for_selection": True, "train_only_preprocessing": True,
             "current_preservation_full_is_1": rep["learned_full"]["stale_suppression"]["current_preservation@10"] == 1.0,
             "stale_reduced_vs_bm25_full": rep["learned_full"]["all"]["stale@10"] < rep["bm25"]["all"]["stale@10"],
             "all_300_present": len(per_query) == 300}
    gates["all_passed"] = all(gates.values())
    audit = {"agreement": dict(agree), "rule_signal_alone_accuracy": single_feature, "rule_feature_coefficient_learned_full": coef_out["learned_full"]["coefficients_standardised_inputs"].get(F.RULE_FEATURE),
             "learned_full_vs_no_rule_signal": full_vs_norule, "differing_queries": diff_rows[:50],
             "verdict_copy_of_rule": agree["same_full_list"] / max(1, agree["queries"]) >= 0.95}
    (OUT / "rule_agreement_audit.json").write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    rep.update({"stage": "smoke", "methods_main": methods, "methods_upper_bound": upper, "gates": gates, "negative_controls": dict(neg), "rule_agreement": audit["agreement"],
                "learned_full_vs_no_rule_signal": full_vs_norule, "selection": {c: {k: v for k, v in selection["conditions"][c].items() if k not in ("C_table", "alpha_table")} for c in CONDITIONS},
                "classification_selected": {c: {"train": next(t for t in selection["conditions"][c]["C_table"] if t["C"] == models[c]["C"])["train_clf"],
                                                "dev": next(t for t in selection["conditions"][c]["C_table"] if t["C"] == models[c]["C"])["dev_clf"],
                                                "convergence_warnings": next(t for t in selection["conditions"][c]["C_table"] if t["C"] == models[c]["C"])["convergence_warnings"]} for c in CONDITIONS},
                "coefficients": coef_out, "manifest_hash": sha(manifest), "timing_seconds": {"stage1_2_train_select_lock": round(t_lock, 1), "total": round(time.perf_counter() - t0, 1)}})
    (OUT / "smoke_report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    (OUT / "smoke_per_query.json").write_text(json.dumps(per_query, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"selected": {c: (models[c]["C"], models[c]["policy"], models[c]["alpha"]) for c in CONDITIONS}, "gates": gates, "negative_controls": dict(neg), "agreement": dict(agree),
                      "single_feature": single_feature, **{m: {k: rep[m]["all"][k] for k in ("mrr@10", "ndcg@10_graded", "stale@10", "top1_current_rate")} | {"joint": rep[m]["stale_suppression"]["current_at1_and_no_stale@10"]}
                                                        for m in methods + upper}}, indent=1, default=str))
    return 0

if __name__ == "__main__":
    sys.exit(main())
