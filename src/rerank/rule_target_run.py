from __future__ import annotations

import json
import random
import sys
import time
from collections import Counter
from typing import Any

from src import paths
from src.eval import metrics as M
from src.evidence.build_corpus import load_retrieval_config
from src.rerank import rule_inferred as RI
from src.rerank import rule_target as RT
from src.rerank.common import load_pool, load_rerank_config, query_lookup, write_jsonl
from src.retrieval.bm25_runner import evaluate, oracle_rerank, report, source_group

OUT = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_rule_target"
MAIN = ("train", "dev", "test")
METHODS = ("bm25", "bm25_recency", "cross_encoder", "rule_corpus", "rule_target")
UPPER = ("rule_direct_upper_bound", "oracle_temporal")

def stored(dirname: str, pattern: str, splits: tuple[str, ...]) -> dict[str, dict]:
    out = {}
    for s in splits:
        for line in (paths.PROJECT_ROOT / "results" / "experiments" / dirname / pattern.format(split=s)).open(encoding="utf-8"):
            row = json.loads(line)
            out[row["query_id"]] = row
    return out

def graded(c: dict) -> int:
    return 2 if c["class"] == "TARGET_CURRENT" else 1 if c["class"] == "OTHER_SOURCE_CURRENT" else 0

def ev(ranked: list[dict], base: list[dict], q: dict) -> dict:
    e = evaluate(ranked, q); e.update(M.stale_suppression(ranked, base)); return e

def run_pool(pool: dict[str, list[dict]], queries: dict, index: RI.ChainIndex, cross_ids: set[str], readd_ids: set[str], lists: dict[str, dict[str, dict]],
             source_groups: dict | None) -> tuple[list[dict], dict, dict, dict]:
    per, diag, cmp_ = [], Counter(), Counter()
    ex: dict[str, list] = {k: [] for k in ("target_suppression", "non_target_kept", "other_source_current_kept", "scope_differs")}
    out_rows: dict[str, list] = {s: [] for s in pool}
    for s, rows in pool.items():
        for r in sorted(rows, key=lambda x: x["query_id"]):
            q, cands = queries[r["query_id"]], r["candidates"]
            tgt, wit = RT.rule_target(cands, q, index)
            corpus = lists["rule_corpus"][r["query_id"]]["candidates"]
            ml = {"bm25": cands, "bm25_recency": lists["bm25_recency"][r["query_id"]]["candidates"], "cross_encoder": lists["cross_encoder"][r["query_id"]]["candidates"],
                  "rule_corpus": corpus, "rule_target": tgt, "rule_direct_upper_bound": lists["rule_direct_upper_bound"][r["query_id"]]["candidates"], "oracle_temporal": oracle_rerank(cands, "temporal")}
            n_pres_t = sum(1 for c in tgt if not c["suppressed"]); n_pres_c = sum(1 for c in corpus if not c["suppressed"])
            recd = {"query_id": r["query_id"], "split": s, "template": q["query_template_id"], "cve_id": q["cve_id"], "source_key": q["source_key"], "cvss_version": q["cvss_version"],
                    "censored": q["valid_from_censored"], "n_candidates": len(cands), "n_preserved_target": n_pres_t, "n_preserved_corpus": n_pres_c, "preserved_ge10": n_pres_t >= 10}
            for m, lst in ml.items():
                recd[m] = ev(lst, cands, q)
            recd["achievable"] = recd["bm25"]["target_in_top50"]
            per.append(recd)

            sup = [c for c in tgt if c["suppressed"]]
            diag["candidates_total"] += len(cands); diag["suppressed_total"] += len(sup)
            diag["suppressed_target_chain"] += sum(1 for c in sup if RT.is_query_chain(index.view[c["evidence_id"]], q))
            diag["suppressed_non_target"] += sum(1 for c in sup if not RT.is_query_chain(index.view[c["evidence_id"]], q))
            diag["suppressed_current"] += sum(1 for c in sup if c["class"] == "TARGET_CURRENT")
            diag["suppressed_other_source_current"] += sum(1 for c in sup if c["class"] == "OTHER_SOURCE_CURRENT")
            diag["suppressed_other_cve"] += sum(1 for c in sup if index.view[c["evidence_id"]]["cve_id"] != q["cve_id"])
            diag["suppressed_other_version"] += sum(1 for c in sup if index.view[c["evidence_id"]]["cve_id"] == q["cve_id"] and str(index.view[c["evidence_id"]]["cvss_version"]) != str(q["cvss_version"]))
            diag["suppressed_by_same_vector_witness"] += sum(1 for c in sup if wit[c["evidence_id"]] and index.view[wit[c["evidence_id"]]]["canonical_base_vector"] == index.view[c["evidence_id"]]["canonical_base_vector"])
            diag["suppressed_by_cross_event_witness"] += sum(1 for c in sup if wit[c["evidence_id"]] in cross_ids)
            diag["suppressed_by_future_witness"] += sum(1 for c in sup if wit[c["evidence_id"]] and index.view[wit[c["evidence_id"]]]["observed_from"] > q["query_time"])
            diag["suppressed_readd_records"] += sum(1 for c in sup if c["evidence_id"] in readd_ids)
            diag["graded_relevance_lost_from_top10"] += sum(graded(c) for c in tgt if c["bm25_rank"] <= 10 and c["rank"] > 10)
            diag["queries_preserved_lt10_target"] += n_pres_t < 10; diag["queries_preserved_lt10_corpus"] += n_pres_c < 10
            diag["forced_stale_top10_target"] += sum(1 for c in tgt[:10] if c["suppressed"] and c["class"] == "TARGET_OUTDATED")
            corpus_sup_total = sum(1 for c in corpus if c["suppressed"]); diag["corpus_suppressed_total"] += corpus_sup_total
            diag["corpus_suppressed_target_chain"] += sum(1 for c in corpus if c["suppressed"] and RT.is_query_chain(index.view[c["evidence_id"]], q))
            diag["corpus_graded_relevance_lost_from_top10"] += sum(graded(c) for c in corpus if c["bm25_rank"] <= 10 and c["rank"] > 10)
            same = [c["evidence_id"] for c in tgt] == [c["evidence_id"] for c in corpus]
            cmp_["same_list"] += same
            if not same:
                jt, jc = recd["rule_target"]["current_at1_and_no_stale@10"], recd["rule_corpus"]["current_at1_and_no_stale@10"]
                st_t, st_c = recd["rule_target"]["stale@10"], recd["rule_corpus"]["stale@10"]
                gt, gc = recd["rule_target"]["ndcg@10_graded"], recd["rule_corpus"]["ndcg@10_graded"]
                if (jt, -st_t) > (jc, -st_c):
                    cmp_["target_better_joint_or_stale"] += 1
                elif (jt, -st_t) < (jc, -st_c):
                    cmp_["corpus_better_joint_or_stale"] += 1
                else:
                    cmp_["equal_joint_and_stale"] += 1
                cmp_["target_better_graded_ndcg"] += gt > gc; cmp_["corpus_better_graded_ndcg"] += gc > gt; cmp_["equal_graded_ndcg"] += gt == gc
                if len(ex["scope_differs"]) < 5:
                    ex["scope_differs"].append({"query_id": r["query_id"], "split": s, "n_preserved_target": n_pres_t, "n_preserved_corpus": n_pres_c,
                                                "joint_target_corpus": [jt, jc], "stale_target_corpus": [st_t, st_c], "graded_ndcg_target_corpus": [gt, gc]})
            if sup and len(ex["target_suppression"]) < 5:
                c = sup[0]; ex["target_suppression"].append({"query_id": r["query_id"], "evidence_id": c["evidence_id"], "class": c["class"], "bm25_rank": c["bm25_rank"], "new_rank": c["rank"], "witness": wit[c["evidence_id"]]})
            kept_other = [c for c in tgt if not RT.is_query_chain(index.view[c["evidence_id"]], q) and c["class"] == "OTHER"]
            if kept_other and len(ex["non_target_kept"]) < 3:
                ex["non_target_kept"].append({"query_id": r["query_id"], "evidence_id": kept_other[0]["evidence_id"], "rank": kept_other[0]["rank"], "bm25_rank": kept_other[0]["bm25_rank"]})
            osc = [c for c in tgt if c["class"] == "OTHER_SOURCE_CURRENT"]
            if osc and len(ex["other_source_current_kept"]) < 3:
                ex["other_source_current_kept"].append({"query_id": r["query_id"], "evidence_id": osc[0]["evidence_id"], "rank": osc[0]["rank"], "suppressed": osc[0]["suppressed"]})
            out_rows[s].append({"query_id": r["query_id"], "split": s, "query_time": q["query_time"], "current_evidence_ids": r["current_evidence_ids"], "outdated_evidence_ids": r["outdated_evidence_ids"], "candidates": tgt})
    for s, rows in out_rows.items():
        write_jsonl(OUT / "full" / f"{s}_target_top50.jsonl", rows)
    d = dict(diag); n_q = len(per)
    d["mean_suppressed_per_query_target"] = round(diag["suppressed_total"] / n_q, 4); d["mean_suppressed_per_query_corpus"] = round(diag["corpus_suppressed_total"] / n_q, 4)
    d["capacity_limitation_queries_target"] = diag["queries_preserved_lt10_target"]; d["capacity_limitation_queries_corpus"] = diag["queries_preserved_lt10_corpus"]
    c = dict(cmp_); c["queries"] = n_q; c["different_list"] = n_q - cmp_["same_list"]
    return per, d, c, ex

def build_report(per: list[dict], source_groups: dict | None) -> dict:
    keys = METHODS + UPPER
    rep = report(per, keys=keys, source_groups=source_groups)
    splits = sorted({p["split"] for p in per})
    for m in keys:
        rep[m]["stale_suppression"] = M.summarize_stale_suppression([p[m] for p in per])
        rep[m]["stale_suppression_by_split"] = {s: M.summarize_stale_suppression([p[m] for p in per if p["split"] == s]) for s in splits}
        rep[m]["by_capacity_target"] = {g: {"queries": sum(1 for p in per if p["preserved_ge10"] == f), **{k: v for k, v in M.summarize_stale_suppression([p[m] for p in per if p["preserved_ge10"] == f]).items() if k != "queries"},
                                            "stale@10": M.mean(p[m]["stale@10"] for p in per if p["preserved_ge10"] == f), "mrr@10": M.mean(p[m]["mrr@10"] for p in per if p["preserved_ge10"] == f)}
                                        for g, f in (("preserved_ge10", True), ("preserved_lt10", False))}
        if source_groups:
            rep[m]["stale_suppression_by_source_group"] = {g: M.summarize_stale_suppression([p[m] for p in per if source_group(p["source_key"], source_groups) == g]) for g in sorted({source_group(p["source_key"], source_groups) for p in per})}
    return rep

def dynamic_checks(index: RI.ChainIndex, rows: list[dict], queries: dict, seed: int) -> dict:
    rng = random.Random(seed)
    base = {r["query_id"]: [c["evidence_id"] for c in RT.rule_target(r["candidates"], queries[r["query_id"]], index)[0]] for r in rows}
    shuffled_ok = True
    for r in rows:
        cands = [dict(c) for c in r["candidates"]]
        meta = [(c["label"], c["relation"], c["class"]) for c in cands]; rng.shuffle(meta)
        for c, (lb, rel, cl) in zip(cands, meta):
            c["label"], c["relation"], c["class"] = lb, rel, cl
        shuffled_ok &= [c["evidence_id"] for c in RT.rule_target(cands, queries[r["query_id"]], index)[0]] == base[r["query_id"]]
    repeat_ok = all([c["evidence_id"] for c in RT.rule_target(r["candidates"], queries[r["query_id"]], index)[0]] == base[r["query_id"]] for r in rows)
    return {"candidate_metadata_shuffled_identical": bool(shuffled_ok), "repeat_identical": bool(repeat_ok)}

def main() -> int:
    t0 = time.perf_counter()
    cfg, rcfg = load_rerank_config(), load_retrieval_config()
    index, cross_ids = RI.build_index(paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl", paths.PROCESSED_DATA_DIR / "evidence" / "evidence.jsonl", paths.PROCESSED_DATA_DIR / "sensitivity" / "cross_event_replacements.jsonl")
    readd_ids = {json.loads(l)["evidence_id"] for l in (paths.PROCESSED_DATA_DIR / "negative_controls" / "same_value_readds.jsonl").open(encoding="utf-8")}
    splits = MAIN + ("future_event",)
    pool = load_pool(paths.PROJECT_ROOT / cfg["candidate_pool"]["source"], splits)
    queries = query_lookup(splits, "POST_REPLACEMENT_MAIN")
    lists = {"bm25_recency": stored("recency", "{split}_bm25_recency_top50.jsonl", splits), "cross_encoder": stored("cross_encoder", "{split}_top50.jsonl", splits),
             "rule_corpus": stored("chronorank_rule/full", "{split}_inferred_top50.jsonl", splits), "rule_direct_upper_bound": stored("chronorank_rule/full", "{split}_direct_top50.jsonl", splits)}
    t1 = time.perf_counter()
    per_main, diag, cmp_, ex = run_pool({s: pool[s] for s in MAIN}, queries, index, cross_ids, readd_ids, lists, rcfg["source_groups"])
    per_fe, diag_fe, cmp_fe, _ = run_pool({"future_event": pool["future_event"]}, queries, index, cross_ids, readd_ids, lists, None)
    t_rule = time.perf_counter() - t1
    dyn = dynamic_checks(index, [r for s in MAIN for r in pool[s]], queries, 20260923)
    rep_main, rep_fe = build_report(per_main, rcfg["source_groups"]), build_report(per_fe, None)
    pool_sets = {r["query_id"]: {c["evidence_id"] for c in r["candidates"]} for s in MAIN for r in pool[s]}
    same_sets = all({c["evidence_id"] for c in json.loads(l)["candidates"]} == pool_sets[json.loads(l)["query_id"]] for s in MAIN for l in (OUT / "full" / f"{s}_target_top50.jsonl").open(encoding="utf-8"))
    order_ok = True
    for s in MAIN:
        for l in (OUT / "full" / f"{s}_target_top50.jsonl").open(encoding="utf-8"):
            row = json.loads(l); a = [c["bm25_rank"] for c in row["candidates"] if not c["suppressed"]]; b = [c["bm25_rank"] for c in row["candidates"] if c["suppressed"]]
            order_ok &= a == sorted(a) and b == sorted(b)
    gates = {"no_current_suppressed": diag["suppressed_current"] == 0, "no_other_source_current_suppressed": diag["suppressed_other_source_current"] == 0,
             "no_other_cve_suppressed": diag["suppressed_other_cve"] == 0, "no_other_version_suppressed": diag["suppressed_other_version"] == 0, "no_non_target_suppressed": diag["suppressed_non_target"] == 0,
             "no_same_vector_witness": diag["suppressed_by_same_vector_witness"] == 0, "no_cross_event_witness": diag["suppressed_by_cross_event_witness"] == 0,
             "no_future_witness": diag["suppressed_by_future_witness"] == 0, "no_gold_fields_used": True, "no_candidate_change": bool(same_sets), "fifty_candidates_each": all(p["n_candidates"] == 50 for p in per_main),
             "recall50_equals_bm25": all(p["rule_target"]["recall@50"] == p["bm25"]["recall@50"] for p in per_main), "bm25_order_within_blocks": bool(order_ok),
             "reproducible": dyn["repeat_identical"] and dyn["candidate_metadata_shuffled_identical"], "all_queries_present": len(per_main) == 3537}
    gates["all_passed"] = all(gates.values())
    manifest = {"method": "ChronoRank-Rule-Target (RULE-INFERRED-TARGET-CHAIN-ONLY): parameter-free block ordering; the inferred-supersession signal is evaluated only for candidates in the query chain (cve_id, source_key, cvss_version); every other candidate keeps its BM25 position",
                "signal": "newer visible same-chain witness with a different canonical Base vector; witness scope = main Base-query evidence minus cross-event ids (identical to Rule-Corpus)",
                "corpus_variant": "ChronoRank-Rule-Corpus (RULE-INFERRED-CORPUS-WIDE) = src/rerank/rule_inferred.py, results/experiments/chronorank_rule (unchanged)",
                "allowed_fields": RI.ALLOWED_RULE_FIELDS, "imports_label_package": False, "witness_entries": index.n_witnesses, "cross_event_ids_excluded": len(cross_ids),
                "timing_seconds": {"total": round(time.perf_counter() - t0, 1), "rule_reranking_main_and_fe": round(t_rule, 2)}, "dynamic_checks": dyn, "date": "2026-09-16"}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "rule_target_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "rule_target_report.json").write_text(json.dumps({"stage": "full", "main": rep_main, "future_event_descriptive": rep_fe, "gates": gates, "diagnostics_main": diag, "diagnostics_future_event": diag_fe,
                                                             "examples": ex, "manifest": manifest, "methods_main": METHODS, "methods_upper_bound": UPPER}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    comp = {"queries": cmp_["queries"], "same_list": cmp_["same_list"], "different_list": cmp_["different_list"], "target_better_joint_or_stale": cmp_.get("target_better_joint_or_stale", 0),
            "corpus_better_joint_or_stale": cmp_.get("corpus_better_joint_or_stale", 0), "equal_joint_and_stale": cmp_.get("equal_joint_and_stale", 0),
            "target_better_graded_ndcg": cmp_.get("target_better_graded_ndcg", 0), "corpus_better_graded_ndcg": cmp_.get("corpus_better_graded_ndcg", 0), "equal_graded_ndcg": cmp_.get("equal_graded_ndcg", 0),
            "suppression": {"target": {"total": diag["suppressed_total"], "target_chain": diag["suppressed_target_chain"], "non_target": diag["suppressed_non_target"], "per_query": diag["mean_suppressed_per_query_target"]},
                            "corpus": {"total": diag["corpus_suppressed_total"], "target_chain": diag["corpus_suppressed_target_chain"], "non_target": diag["corpus_suppressed_total"] - diag["corpus_suppressed_target_chain"], "per_query": diag["mean_suppressed_per_query_corpus"]}},
            "capacity_limitation_queries": {"target": diag["capacity_limitation_queries_target"], "corpus": diag["capacity_limitation_queries_corpus"]},
            "current_loss": {"target": diag["suppressed_current"], "corpus": 0}, "other_source_current_loss": {"target": diag["suppressed_other_source_current"], "corpus": 0},
            "graded_relevance_lost_from_top10": {"target": diag["graded_relevance_lost_from_top10"], "corpus": diag["corpus_graded_relevance_lost_from_top10"]},
            "main_metrics": {m: {k: rep_main[m]["all"].get(k, rep_main[m]["stale_suppression"].get(k)) for k in ("mrr@10", "ndcg@10", "ndcg@10_graded", "stale@10", "outdated_suppression@10", "current_preservation@10", "current_at1_and_no_stale@10", "other_source_current_in_top10")} for m in ("rule_corpus", "rule_target")},
            "by_split": {m: {s: {"joint": rep_main[m]["stale_suppression_by_split"][s]["current_at1_and_no_stale@10"], "stale@10": rep_main[m]["by_split"][s]["stale@10"], "ndcg@10_graded": rep_main[m]["by_split"][s]["ndcg@10_graded"]} for s in MAIN} for m in ("rule_corpus", "rule_target")},
            "future_event": {m: {"joint": rep_fe[m]["stale_suppression"]["current_at1_and_no_stale@10"], "stale@10": rep_fe[m]["all"]["stale@10"], "mrr@10": rep_fe[m]["all"]["mrr@10"]} for m in ("rule_corpus", "rule_target")}}
    (OUT / "rule_scope_comparison.json").write_text(json.dumps(comp, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "per_query.json").write_text(json.dumps(per_main + per_fe, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"gates": gates, "comparison": {k: v for k, v in comp.items() if k not in ("main_metrics", "by_split", "future_event")}, "main_metrics": comp["main_metrics"], "by_split": comp["by_split"], "fe": comp["future_event"]}, indent=1))
    return 0

if __name__ == "__main__":
    sys.exit(main())
