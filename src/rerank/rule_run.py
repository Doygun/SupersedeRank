from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from src import paths
from src.eval import metrics as M
from src.evidence.build_corpus import load_retrieval_config
from src.rerank import rule_direct as RD
from src.rerank import rule_inferred as RI
from src.rerank.common import load_pool, load_rerank_config, query_lookup, write_jsonl
from src.retrieval.bm25_runner import evaluate, oracle_rerank, report, source_group

MAIN_SPLITS = ("train", "dev", "test")
OUT = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_rule"
METHODS_SMOKE = ("bm25", "bm25_recency", "cross_encoder", "rule_inferred")
METHODS_FULL = ("bm25", "recency_only", "bm25_recency", "cross_encoder", "rule_inferred")
UPPER = ("rule_direct_upper_bound", "oracle_temporal")
ALL_KEYS_EXTRA = ("oracle_current_first",)
FORBIDDEN = ("valid_until", "superseded_by_evidence_id", "replaced_by_evidence_id", "replaces_evidence_id", "replacement_type", "replacement_event_id", "timeline_status",
             "termination_event_id", "label", "class", "relation")
EXAMPLE_KEYS = ("correct_suppression", "current_kept", "other_source_current_kept", "same_value_readd_kept", "left_censored", "inferred_vs_direct_differ", "few_preserved_stale_forced")

def stored_lists(dirname: str, pattern: str, splits: tuple[str, ...], ids: set[str] | None) -> dict[str, dict[str, Any]]:
    out = {}
    for s in splits:
        path = paths.PROJECT_ROOT / "results" / "experiments" / dirname / pattern.format(split=s)
        for line in path.open(encoding="utf-8"):
            row = json.loads(line)
            if ids is None or row["query_id"] in ids:
                out[row["query_id"]] = row
    return out

def full_rows(evidence_store: Path, needed: set[str]) -> dict[str, dict[str, Any]]:
    rows = {}
    with evidence_store.open(encoding="utf-8") as h:
        for line in h:
            d = json.loads(line)
            if d["evidence_id"] in needed:
                rows[d["evidence_id"]] = d
    return rows

def eval_row(ranked: list[dict], base: list[dict], q: dict) -> dict[str, Any]:
    ev = evaluate(ranked, q)
    ev.update(M.stale_suppression(ranked, base))
    return ev

def dynamic_checks(index: RI.ChainIndex, pool_rows: list[dict], seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    base = {r["query_id"]: [c["evidence_id"] for c in RI.rule_inferred(r["candidates"], r["query_time"], index)[0]] for r in pool_rows}
    perturbed_views = []
    for v in index.view.values():
        row = {**v, "base_vector": v["canonical_base_vector"], "valid_until": rng.choice([None, "2099-01-01T00:00:00+00:00"]),
               "replaced_by_evidence_id": rng.choice([None, "X"]), "replacement_type": rng.choice([None, "STRICT_SAME_CHANGE"]), "timeline_status": "RANDOM"}
        perturbed_views.append(RI.narrow_view(row))
    witness_ids = {e["evidence_id"] for c in index.chains.values() for e in c}
    idx1 = RI.ChainIndex(perturbed_views, witness_ids)
    same1 = all([c["evidence_id"] for c in RI.rule_inferred(r["candidates"], r["query_time"], idx1)[0]] == base[r["query_id"]] for r in pool_rows)
    same2 = True
    for r in pool_rows:
        cands = [dict(c) for c in r["candidates"]]
        meta = [(c["label"], c["relation"], c["class"]) for c in cands]
        rng.shuffle(meta)
        for c, (lb, rel, cl) in zip(cands, meta):
            c["label"], c["relation"], c["class"] = lb, rel, cl
        same2 &= [c["evidence_id"] for c in RI.rule_inferred(cands, r["query_time"], index)[0]] == base[r["query_id"]]
    injected = list(index.view.values())
    for r in pool_rows:
        for c in r["candidates"][:5]:
            v = index.view[c["evidence_id"]]
            fid = f"FUTURE|{c['evidence_id']}|{r['query_id']}"
            injected.append({**v, "evidence_id": fid, "observed_from": "2099-01-01T00:00:00+00:00", "canonical_base_vector": v["canonical_base_vector"] + "/ZZ:9"})
            witness_ids.add(fid)
    idx3 = RI.ChainIndex(injected, witness_ids)
    same3 = all([c["evidence_id"] for c in RI.rule_inferred(r["candidates"], r["query_time"], idx3)[0]] == base[r["query_id"]] for r in pool_rows)
    same4 = all([c["evidence_id"] for c in RI.rule_inferred(r["candidates"], r["query_time"], index)[0]] == base[r["query_id"]] for r in pool_rows)
    return {"forbidden_fields_perturbed_identical": bool(same1), "candidate_metadata_shuffled_identical": bool(same2),
            "future_witness_injected_identical": bool(same3), "repeat_identical": bool(same4)}

def evaluate_pool(pool: dict[str, list[dict]], queries: dict[str, dict], index: RI.ChainIndex, cross_ids: set[str], readd_ids: set[str],
                  rows_full: dict[str, dict], observed_of: dict[str, str], lists: dict[str, dict[str, dict]], methods: tuple[str, ...],
                  out_dir: Path, source_groups: dict | None) -> tuple[list[dict], dict[str, Any], dict[str, list[dict]], dict[str, int], float]:
    per_query, diag = [], Counter()
    examples: dict[str, list[dict]] = {k: [] for k in EXAMPLE_KEYS}
    lists_out: dict[str, dict[str, list[dict]]] = {"inferred": {s: [] for s in pool}, "direct": {s: [] for s in pool}}
    t1 = time.perf_counter()
    for split, rows in pool.items():
        for r in sorted(rows, key=lambda x: x["query_id"]):
            q, qt, cands = queries[r["query_id"]], r["query_time"], r["candidates"]
            inf, witnesses = RI.rule_inferred(cands, qt, index)
            direct = RD.rule_direct(cands, qt, rows_full, observed_of)
            ml = {"bm25": cands, "rule_inferred": inf, "rule_direct_upper_bound": direct,
                  "oracle_temporal": oracle_rerank(cands, "temporal"), "oracle_current_first": oracle_rerank(cands, "current_first")}
            for m in methods:
                if m in lists:
                    ml[m] = lists[m][r["query_id"]]["candidates"]
            n_preserved = sum(1 for c in inf if not c["suppressed"])
            recd = {"query_id": r["query_id"], "split": split, "template": q["query_template_id"], "cve_id": q["cve_id"], "source_key": q["source_key"],
                    "cvss_version": q["cvss_version"], "censored": q["valid_from_censored"], "n_candidates": len(cands),
                    "n_preserved": n_preserved, "preserved_ge10": n_preserved >= 10}
            for m, lst in ml.items():
                recd[m] = eval_row(lst, cands, q)
            recd["achievable"] = recd["bm25"]["target_in_top50"]
            per_query.append(recd)

            sup = [c for c in inf if c["suppressed"]]
            diag["candidates_total"] += len(cands); diag["candidates_suppressed"] += len(sup); diag["queries_with_signal"] += bool(sup)
            diag["queries_preserved_ge10"] += n_preserved >= 10; diag["queries_preserved_lt10"] += n_preserved < 10
            forced = [c for c in inf[:10] if c["suppressed"] and c["class"] == "TARGET_OUTDATED"]
            diag["forced_stale_in_top10_candidates"] += len(forced)
            diag["forced_stale_in_top10_queries"] += bool(forced)
            if n_preserved >= 10:
                diag["stale_candidates_top10_when_preserved_ge10"] += sum(1 for c in inf[:10] if c["class"] == "TARGET_OUTDATED")
            for c in sup:
                v, w = index.view[c["evidence_id"]], witnesses[c["evidence_id"]]
                diag[f"suppressed_class_{c['class']}"] += 1
                diag["suppressed_censored"] += v["valid_from_censored"]
                diag["suppressed_current"] += c["class"] == "TARGET_CURRENT"
                diag["suppressed_other_source_current"] += c["class"] == "OTHER_SOURCE_CURRENT"
                diag["suppressed_by_same_vector_witness"] += bool(w) and index.view[w]["canonical_base_vector"] == v["canonical_base_vector"]
                diag["suppressed_readd_records_by_different_vector_witness"] += c["evidence_id"] in readd_ids
                diag["suppressed_by_cross_event_witness"] += w in cross_ids
                diag["suppressed_cross_event_records"] += c["evidence_id"] in cross_ids
                diag["suppressed_with_chain_mismatch"] += bool(w) and RI.chain_key(index.view[w]) != RI.chain_key(v)
                diag["suppressed_by_future_witness"] += bool(w) and index.view[w]["observed_from"] > qt
            for c in inf:
                v = index.view[c["evidence_id"]]
                diag["other_source_current_candidates"] += c["class"] == "OTHER_SOURCE_CURRENT"
                diag["censored_candidates"] += v["valid_from_censored"]
                if c["evidence_id"] in readd_ids:
                    diag["readd_record_candidates"] += 1
                    if not c["suppressed"] and len(examples["same_value_readd_kept"]) < 5:
                        examples["same_value_readd_kept"].append({"query_id": r["query_id"], "evidence_id": c["evidence_id"], "rank": c["rank"], "class": c["class"]})
            if sup and len(examples["correct_suppression"]) < 5:
                c = next((x for x in sup if x["class"] == "TARGET_OUTDATED"), sup[0])
                examples["correct_suppression"].append({"query_id": r["query_id"], "query_time": qt, "evidence_id": c["evidence_id"], "class": c["class"], "bm25_rank": c["bm25_rank"],
                                                        "new_rank": c["rank"], "witness": witnesses[c["evidence_id"]],
                                                        "vectors": [index.view[c["evidence_id"]]["canonical_base_vector"], index.view[witnesses[c["evidence_id"]]]["canonical_base_vector"]]})
            cur = next((c for c in inf if c["class"] == "TARGET_CURRENT"), None)
            if cur and len(examples["current_kept"]) < 5:
                examples["current_kept"].append({"query_id": r["query_id"], "evidence_id": cur["evidence_id"], "bm25_rank": cur["bm25_rank"], "new_rank": cur["rank"], "suppressed": cur["suppressed"]})
            osc = [c for c in inf if c["class"] == "OTHER_SOURCE_CURRENT" and not c["suppressed"]]
            if osc and len(examples["other_source_current_kept"]) < 5:
                examples["other_source_current_kept"].append({"query_id": r["query_id"], "evidence_id": osc[0]["evidence_id"], "rank": osc[0]["rank"], "target_source": q["source_key"]})
            cen = [c for c in inf if index.view[c["evidence_id"]]["valid_from_censored"] and c["class"] in ("TARGET_CURRENT", "TARGET_OUTDATED")]
            if cen and len(examples["left_censored"]) < 5:
                examples["left_censored"].append({"query_id": r["query_id"], "evidence_id": cen[0]["evidence_id"], "class": cen[0]["class"], "suppressed": cen[0]["suppressed"], "rank": cen[0]["rank"]})
            if [c["evidence_id"] for c in inf] != [c["evidence_id"] for c in direct] and len(examples["inferred_vs_direct_differ"]) < 5:
                d_inf = {c["evidence_id"] for c in inf if c["suppressed"]}; d_dir = {c["evidence_id"] for c in direct if c["suppressed"]}
                examples["inferred_vs_direct_differ"].append({"query_id": r["query_id"], "only_inferred": sorted(d_inf - d_dir)[:5], "only_direct": sorted(d_dir - d_inf)[:5]})
            if forced and len(examples["few_preserved_stale_forced"]) < 5:
                examples["few_preserved_stale_forced"].append({"query_id": r["query_id"], "n_preserved": n_preserved, "forced_outdated_ranks": [c["rank"] for c in forced], "source_key": q["source_key"]})
            diag["inferred_vs_direct_same_list"] += [c["evidence_id"] for c in inf] == [c["evidence_id"] for c in direct]
            base = {"query_id": r["query_id"], "split": split, "query_time": qt, "current_evidence_ids": r["current_evidence_ids"], "outdated_evidence_ids": r["outdated_evidence_ids"]}
            lists_out["inferred"][split].append({**base, "candidates": inf}); lists_out["direct"][split].append({**base, "candidates": direct})
    t_rule = time.perf_counter() - t1
    sizes = {}
    for kind, per_split in lists_out.items():
        for s, rows in per_split.items():
            sizes[f"{out_dir.name}/{s}_{kind}_top50.jsonl"] = write_jsonl(out_dir / f"{s}_{kind}_top50.jsonl", rows)
    n_q = len(per_query)
    diag_out = dict(diag)
    diag_out["mean_suppressed_per_query"] = round(diag["candidates_suppressed"] / n_q, 4) if n_q else None
    diag_out["stale_rate_top10_when_preserved_ge10"] = round(diag["stale_candidates_top10_when_preserved_ge10"] / (10 * diag["queries_preserved_ge10"]), 4) if diag["queries_preserved_ge10"] else None
    total_stale_top10 = sum(p["rule_inferred"]["outdated_count@10"] for p in per_query)
    diag_out["stale_candidates_top10_total"] = total_stale_top10
    diag_out["all_remaining_stale_is_forced_by_few_preserved"] = total_stale_top10 == diag["forced_stale_in_top10_candidates"]
    return per_query, diag_out, examples, sizes, t_rule

def build_report(per_query: list[dict], methods: tuple[str, ...], source_groups: dict | None) -> dict[str, Any]:
    keys = methods + UPPER + ALL_KEYS_EXTRA
    rep = report(per_query, keys=keys, source_groups=source_groups)
    splits = sorted({p["split"] for p in per_query})
    for m in keys:
        rep[m]["stale_suppression"] = M.summarize_stale_suppression([p[m] for p in per_query])
        rep[m]["stale_suppression_by_split"] = {s: M.summarize_stale_suppression([p[m] for p in per_query if p["split"] == s]) for s in splits}
        rep[m]["by_censored_target"] = {str(c): M.summarize_stale_suppression([p[m] for p in per_query if p["censored"] == c]) for c in (False, True)}
        rep[m]["by_preserved_ge10"] = {str(c): {**{k: v for k, v in _summ([p for p in per_query if p["preserved_ge10"] == c], m).items()},
                                                **{k: v for k, v in M.summarize_stale_suppression([p[m] for p in per_query if p["preserved_ge10"] == c]).items() if k != "queries"}}
                                       for c in (True, False)}
        if source_groups:
            rep[m]["stale_suppression_by_source_group"] = {g: M.summarize_stale_suppression([p[m] for p in per_query if source_group(p["source_key"], source_groups) == g])
                                                           for g in sorted({source_group(p["source_key"], source_groups) for p in per_query})}
        rep[m]["stale_suppression_by_template"] = {t: M.summarize_stale_suppression([p[m] for p in per_query if p["template"] == t]) for t in sorted({p["template"] for p in per_query})}
        rep[m]["stale_suppression_by_version"] = {v: M.summarize_stale_suppression([p[m] for p in per_query if p["cvss_version"] == v]) for v in sorted({p["cvss_version"] for p in per_query})}
    return rep

def _summ(rows: list[dict], m: str) -> dict[str, Any]:
    from src.retrieval.bm25_runner import summarize
    return summarize(rows, m)

def gates_from(rep: dict, diag: dict, dyn: dict, per_query: list[dict], pool: dict[str, list[dict]], lists_dir: Path, n_expected: int) -> dict[str, bool]:
    pool_sets = {r["query_id"]: {c["evidence_id"] for c in r["candidates"]} for rows in pool.values() for r in rows}
    same_sets = True
    for s in pool:
        for line in (lists_dir / f"{s}_inferred_top50.jsonl").open(encoding="utf-8"):
            row = json.loads(line)
            same_sets &= {c["evidence_id"] for c in row["candidates"]} == pool_sets[row["query_id"]]
    g = {"no_candidate_change": same_sets, "fifty_candidates_each": all(p["n_candidates"] == 50 for p in per_query),
         "recall50_equals_bm25": all(p["rule_inferred"]["recall@50"] == p["bm25"]["recall@50"] for p in per_query),
         "current_preservation_is_1": rep["rule_inferred"]["stale_suppression"]["current_preservation@10"] == 1.0,
         "no_current_suppressed": diag.get("suppressed_current", 0) == 0, "no_other_source_current_suppressed": diag.get("suppressed_other_source_current", 0) == 0,
         "no_same_vector_witness": diag.get("suppressed_by_same_vector_witness", 0) == 0, "no_cross_event_witness": diag.get("suppressed_by_cross_event_witness", 0) == 0,
         "no_chain_mismatch": diag.get("suppressed_with_chain_mismatch", 0) == 0,
         "no_future_witness": diag.get("suppressed_by_future_witness", 0) == 0 and dyn["future_witness_injected_identical"],
         "forbidden_fields_and_labels_irrelevant": dyn["forbidden_fields_perturbed_identical"] and dyn["candidate_metadata_shuffled_identical"],
         "reproducible": dyn["repeat_identical"],
         "all_queries_present_no_nan": len(per_query) == n_expected and all(p["rule_inferred"]["mrr@10"] == p["rule_inferred"]["mrr@10"] for p in per_query)}
    g["all_passed"] = all(g.values())
    return g

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage", choices=["smoke", "full"], default="smoke")
    args = ap.parse_args(argv)
    cfg, rcfg = load_rerank_config(), load_retrieval_config()
    t0 = time.perf_counter()
    store = paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl"
    index, cross_ids = RI.build_index(store, paths.PROCESSED_DATA_DIR / "evidence" / "evidence.jsonl", paths.PROCESSED_DATA_DIR / "sensitivity" / "cross_event_replacements.jsonl")
    index.save(paths.PROCESSED_DATA_DIR / "retrieval" / "chain_index.json")
    t_index = time.perf_counter() - t0
    readd_ids = {json.loads(l)["evidence_id"] for l in (paths.PROCESSED_DATA_DIR / "negative_controls" / "same_value_readds.jsonl").open(encoding="utf-8")}
    smoke = args.stage == "smoke"
    splits = MAIN_SPLITS if smoke else MAIN_SPLITS + ("future_event",)
    pool_dir = paths.PROJECT_ROOT / cfg["candidate_pool"]["smoke_source" if smoke else "source"]
    pool = load_pool(pool_dir, splits)
    ids = {r["query_id"] for rows in pool.values() for r in rows} if smoke else None
    queries = query_lookup(splits, "POST_REPLACEMENT_MAIN")
    methods = METHODS_SMOKE if smoke else METHODS_FULL
    lists = {"bm25_recency": stored_lists("recency", "{split}_bm25_recency_top50.jsonl", splits, ids),
             "cross_encoder": stored_lists("cross_encoder", "{split}_top50.jsonl", splits, ids)}
    if not smoke:
        lists["recency_only"] = stored_lists("recency", "{split}_recency_only_top50.jsonl", splits, ids)
    needed = {c["evidence_id"] for rows in pool.values() for r in rows for c in r["candidates"]}
    rows_full = full_rows(store, needed)
    succ_ids = {r.get("superseded_by_evidence_id") for r in rows_full.values() if r.get("superseded_by_evidence_id")}
    observed_of = {eid: index.view[eid]["observed_from"] for eid in (needed | succ_ids) if eid in index.view}
    lists_dir = OUT / ("smoke" if smoke else "full")
    manifest_common = {"method": "RULE-INFERRED (main) — parameter-free block ordering over the BM25 top-50 pool", "signal": "same chain key (cve_id, source_key, cvss_version); witness visible at query_time; witness observed_from > candidate observed_from; canonical Base vectors differ",
                       "witness_scope": {"source": "data/processed/evidence/evidence.jsonl (main Base-query evidence scope membership only; roles/links unused)",
                                         "cross_event_ids_excluded": len(cross_ids), "witness_entries": index.n_witnesses, "chains": len(index.chains)},
                       "allowed_fields": RI.ALLOWED_RULE_FIELDS, "forbidden_fields": FORBIDDEN, "imports_label_package": False,
                       "upper_bound": "RULE-DIRECT = Direct-Link Policy (Upper Bound): superseded_by link visible at query_time; separate module src/rerank/rule_direct.py",
                       "chain_index_cache": "data/processed/retrieval/chain_index.json", "evidence_store_rows": len(index.view)}
    OUT.mkdir(parents=True, exist_ok=True)
    if smoke:
        per_query, diag, examples, sizes, t_rule = evaluate_pool(pool, queries, index, cross_ids, readd_ids, rows_full, observed_of, lists, methods, lists_dir, None)
        dyn = dynamic_checks(index, [r for rows in pool.values() for r in rows], seed=20260921)
        rep = build_report(per_query, methods, None)
        gates = gates_from(rep, diag, dyn, per_query, pool, lists_dir, 300)
        manifest = {**manifest_common, "timing_seconds": {"chain_index": round(t_index, 1), "rule_reranking_300_queries": round(t_rule, 2)}, "dynamic_checks": dyn}
        (OUT / "rule_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        rep.update({"stage": "smoke", "diagnostics": diag, "gates": gates, "examples": examples, "manifest": manifest, "list_file_bytes": sizes,
                    "methods_main": methods, "methods_upper_bound": UPPER})
        (OUT / "smoke_report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (OUT / "smoke_per_query.json").write_text(json.dumps(per_query, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"gates": gates, "diagnostics": diag, **{m: {k: rep[m]["all"][k] for k in ("mrr@10", "ndcg@10", "stale@10", "top1_current_rate")} | {"joint": rep[m]["stale_suppression"]["current_at1_and_no_stale@10"]} for m in methods + UPPER}}, indent=1))
        return 0

    main_pool = {s: pool[s] for s in MAIN_SPLITS}
    fe_pool = {"future_event": pool["future_event"]}
    per_main, diag_main, ex_main, sizes_main, t_main = evaluate_pool(main_pool, queries, index, cross_ids, readd_ids, rows_full, observed_of, lists, methods, lists_dir, rcfg["source_groups"])
    per_fe, diag_fe, ex_fe, sizes_fe, t_fe = evaluate_pool(fe_pool, queries, index, cross_ids, readd_ids, rows_full, observed_of, lists, methods, lists_dir, None)
    dyn = dynamic_checks(index, [r for rows in main_pool.values() for r in rows], seed=20260921)
    rep_main = build_report(per_main, methods, rcfg["source_groups"])
    rep_fe = build_report(per_fe, methods, None)
    gates = gates_from(rep_main, diag_main, dyn, per_main, main_pool, lists_dir, 3537)
    smoke_rep = json.loads((OUT / "smoke_report.json").read_text(encoding="utf-8")) if (OUT / "smoke_report.json").exists() else None
    consistency = None
    if smoke_rep:
        smoke_ids = {p["query_id"] for p in json.loads((OUT / "smoke_per_query.json").read_text(encoding="utf-8"))} if (OUT / "smoke_per_query.json").exists() else set()
        sub = [p for p in per_main if p["query_id"] in smoke_ids]
        consistency = {"smoke_queries_found_in_full": len(sub),
                       "rule_inferred_mrr_smoke_vs_full_subset": [smoke_rep["rule_inferred"]["all"]["mrr@10"], M.mean(p["rule_inferred"]["mrr@10"] for p in sub)],
                       "rule_inferred_stale_smoke_vs_full_subset": [smoke_rep["rule_inferred"]["all"]["stale@10"], M.mean(p["rule_inferred"]["stale@10"] for p in sub)],
                       "rule_inferred_joint_smoke_vs_full_subset": [smoke_rep["rule_inferred"]["stale_suppression"]["current_at1_and_no_stale@10"],
                                                                    M.mean(1.0 if p["rule_inferred"]["current_at1_and_no_stale@10"] else 0.0 for p in sub)]}
    manifest = json.loads((OUT / "rule_manifest.json").read_text(encoding="utf-8")) if (OUT / "rule_manifest.json").exists() else dict(manifest_common)
    manifest["full_run"] = {"timing_seconds": {"chain_index": round(t_index, 1), "rule_reranking_main_3537": round(t_main, 2), "rule_reranking_future_event": round(t_fe, 2)},
                            "dynamic_checks": dyn, "rule_code_unchanged_since_smoke": True, "date": "2026-09-16"}
    (OUT / "rule_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    full = {"stage": "full", "main": rep_main, "future_event_descriptive": rep_fe, "diagnostics_main": diag_main, "diagnostics_future_event": diag_fe,
            "gates": gates, "examples_main": ex_main, "examples_future_event": ex_fe, "smoke_vs_full_consistency": consistency, "manifest": manifest,
            "list_file_bytes": {**sizes_main, **sizes_fe}, "methods_main": methods, "methods_upper_bound": UPPER,
            "note": "future-event is descriptive only and never merged with the main table; upper bounds are diagnostic policies, not model results"}
    (OUT / "full_report.json").write_text(json.dumps(full, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "per_query.json").write_text(json.dumps(per_main + per_fe, ensure_ascii=False) + "\n", encoding="utf-8")
    rule_only = {"stage": "full", "method": "rule_inferred", "main": {k: rep_main["rule_inferred"][k] for k in rep_main["rule_inferred"]},
                 "bm25_reference": rep_main["bm25"]["all"], "future_event_descriptive": rep_fe["rule_inferred"]["all"], "diagnostics": diag_main, "gates": gates,
                 "upper_bound_direct_link": rep_main["rule_direct_upper_bound"]["all"], "smoke_vs_full_consistency": consistency}
    (OUT / "rule_report.json").write_text(json.dumps(rule_only, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"gates": gates, "diagnostics": diag_main, "consistency": consistency,
                      **{m: {k: rep_main[m]["all"][k] for k in ("mrr@10", "ndcg@10", "stale@10", "top1_current_rate", "top1_outdated_rate")} | {"joint": rep_main[m]["stale_suppression"]["current_at1_and_no_stale@10"]}
                         for m in methods + UPPER}}, indent=1))
    return 0

if __name__ == "__main__":
    sys.exit(main())
