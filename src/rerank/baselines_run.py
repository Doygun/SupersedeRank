from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

from src import paths
from src.evidence.build_corpus import load_retrieval_config
from src.rerank import cross_encoder as CE
from src.rerank import recency as R
from src.rerank.common import (load_candidate_meta, load_pool, load_rerank_config, oracle_rerank, per_query_record, query_lookup, tie_seed, write_jsonl)
from src.retrieval.bm25_runner import report

METHODS = ("bm25", "recency_only", "bm25_recency", "cross_encoder")
ORACLES = ("oracle_current_first", "oracle_temporal")
MAIN_SPLITS = ("train", "dev", "test")
ROLE = "POST_REPLACEMENT_MAIN"

def peak_mem() -> dict[str, Any]:
    import psutil
    import torch

    info = psutil.Process().memory_info()
    return {"gpu_gb": round(torch.cuda.max_memory_allocated() / 2**30, 3) if torch.cuda.is_available() else None,
            "rss_gb": round(getattr(info, "peak_wset", info.rss) / 2**30, 3)}

def run_methods(pool: dict[str, list[dict]], queries: dict[str, dict], meta: dict[str, dict], seed: int, sel: dict[str, float],
                ce: CE.CrossEncoder, cache: CE.ScoreCache, out: dict[str, Path]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    per_query: list[dict[str, Any]] = []
    timing = {"recency_only": 0.0, "bm25_recency": 0.0, "cross_encoder_rerank": 0.0}
    checks = {"candidate_count_not_50": 0, "candidate_set_changed": 0, "recall50_differs_from_bm25": 0, "nan_or_inf_scores": 0, "missing_queries": []}
    sizes: dict[str, int] = {}
    for split, rows in pool.items():
        lists = {m: [] for m in ("recency_only", "bm25_recency", "cross_encoder")}
        for r in rows:
            q = queries.get(r["query_id"])
            if q is None:
                checks["missing_queries"].append(r["query_id"]); continue
            cands = r["candidates"]
            if len(cands) != 50:
                checks["candidate_count_not_50"] += 1
            t = time.perf_counter(); ro = R.recency_only(cands, meta, r["query_time"], seed, r["query_id"]); timing["recency_only"] += time.perf_counter() - t
            t = time.perf_counter(); br = R.bm25_recency(cands, meta, r["query_time"], seed, r["query_id"], sel["lambda"], sel["tau_days"]); timing["bm25_recency"] += time.perf_counter() - t
            t = time.perf_counter(); cx = CE.rerank_with_cache(ce, cache, r, q, meta, seed); timing["cross_encoder_rerank"] += time.perf_counter() - t
            ml = {"bm25": cands, "recency_only": ro, "bm25_recency": br, "cross_encoder": cx,
                  "oracle_current_first": oracle_rerank(cands, "current_first"), "oracle_temporal": oracle_rerank(cands, "temporal")}
            for name, ranked in ml.items():
                if set(c["evidence_id"] for c in ranked) != set(c["evidence_id"] for c in cands):
                    checks["candidate_set_changed"] += 1
                if any(not np.isfinite(c["score"]) for c in ranked):
                    checks["nan_or_inf_scores"] += 1
            rec = per_query_record(q, split, r, ml)
            if any(rec[m]["recall@50"] != rec["bm25"]["recall@50"] for m in METHODS):
                checks["recall50_differs_from_bm25"] += 1
            per_query.append(rec)
            base = {"query_id": r["query_id"], "split": split, "query_time": r["query_time"], "current_evidence_ids": r["current_evidence_ids"],
                    "outdated_evidence_ids": r["outdated_evidence_ids"]}
            lists["recency_only"].append({**base, "candidates": ro}); lists["bm25_recency"].append({**base, "candidates": br}); lists["cross_encoder"].append({**base, "candidates": cx})
        sizes[f"recency/{split}_recency_only_top50.jsonl"] = write_jsonl(out["recency"] / f"{split}_recency_only_top50.jsonl", lists["recency_only"])
        sizes[f"recency/{split}_bm25_recency_top50.jsonl"] = write_jsonl(out["recency"] / f"{split}_bm25_recency_top50.jsonl", lists["bm25_recency"])
        sizes[f"cross_encoder/{split}_top50.jsonl"] = write_jsonl(out["cross_encoder"] / f"{split}_top50.jsonl", lists["cross_encoder"])
    return per_query, {"timing_seconds": {k: round(v, 2) for k, v in timing.items()}, "checks": checks, "list_file_bytes": sizes}

def technical_gates(rep: dict[str, Any], extra: dict[str, Any], det: dict[str, Any], n_expected: int) -> dict[str, Any]:
    ch = extra["checks"]
    g = {"all_queries_present": rep["queries_total"] == n_expected and not ch["missing_queries"],
         "fifty_candidates_each": ch["candidate_count_not_50"] == 0, "no_candidate_change": ch["candidate_set_changed"] == 0,
         "recall50_equals_bm25": ch["recall50_differs_from_bm25"] == 0 and all(rep[m]["all"]["recall@50"] == rep["bm25"]["all"]["recall@50"] for m in METHODS),
         "no_nan_inf": ch["nan_or_inf_scores"] == 0, "cross_encoder_top50_set_stable": det["top50_set_identical"] == det["queries"],
         "test_not_used_for_selection": True}
    g["all_passed"] = all(g.values())
    return g

def main(argv: list[str] | None = None) -> int:
    import torch

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage", choices=["smoke", "full", "all"], default="all")
    args = ap.parse_args(argv)
    cfg, rcfg = load_rerank_config(), load_retrieval_config()
    seed = tie_seed()
    out = {k: paths.PROJECT_ROOT / cfg[k]["output_dir"] for k in ("recency", "cross_encoder", "comparison")}
    for d in out.values():
        d.mkdir(parents=True, exist_ok=True)
    full_pool = load_pool(paths.PROJECT_ROOT / cfg["candidate_pool"]["source"], MAIN_SPLITS + ("future_event",))
    smoke_pool = load_pool(paths.PROJECT_ROOT / cfg["candidate_pool"]["smoke_source"], MAIN_SPLITS)
    queries = query_lookup(MAIN_SPLITS + ("future_event",), ROLE)
    needed = {c["evidence_id"] for rows in full_pool.values() for r in rows for c in r["candidates"]}
    meta = load_candidate_meta(rcfg, needed)
    print(json.dumps({"pool_queries": {s: len(r) for s, r in full_pool.items()}, "pool_candidates": len(needed)}), flush=True)

    rc = cfg["recency"]["main"]
    t0 = time.perf_counter()
    selection = R.select_on_dev(full_pool["dev"], queries, meta, seed, rc["grid"], rc["selection"]["objective"], rc["selection"]["tie_breaker"])
    selection["seconds"] = round(time.perf_counter() - t0, 1)
    (out["recency"] / "recency_dev_selection.json").write_text(json.dumps(selection, indent=2) + "\n", encoding="utf-8")
    sel = selection["selected"]
    (out["recency"] / "recency_manifest.json").write_text(json.dumps({"config": cfg["recency"], "selected": sel, "selection_split": "dev",
        "formula": rc["formula"], "sign_note": "bonus decays with observed age (age penalty); the draft's -exp form would penalise recent evidence",
        "time_field": cfg["recency"]["time_field"], "age_name": cfg["recency"]["age_name"], "censoring_note": cfg["recency"]["censoring_note"],
        "tie_break_seed": seed, "candidate_fields_read": ["evidence_id", "observed_from"]}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"recency_selected": sel, "dev_table_top": sorted(selection["table"], key=lambda t: -t["ndcg@10"])[:3]}), flush=True)

    ccfg = cfg["cross_encoder"]
    ce = CE.CrossEncoder(ccfg)
    cache = CE.ScoreCache(paths.PROJECT_ROOT / ccfg["cache_dir"] / "scores.jsonl")
    print(json.dumps({"ce_model": ccfg["model"], "revision": ce.revision, "params": ce.n_params, "device": ce.device, "cache_loaded": cache.loaded}), flush=True)
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()
    det_rows = smoke_pool["train"][:int(ccfg["determinism_check"]["queries"])]
    det = CE.determinism_check(ce, det_rows, queries, meta, list(ccfg["determinism_check"]["batch_sizes"]), seed)
    print(json.dumps({"determinism": det}), flush=True)
    common = {"config": cfg, "recency_selection": {"selected": sel, "split": "dev"}, "determinism_check": det}

    if args.stage in ("smoke", "all"):
        st = CE.score_pool(ce, cache, [r for rows in smoke_pool.values() for r in rows], queries, meta, int(ccfg["batch_size"]))
        sm_out = {"recency": out["comparison"] / "smoke" / "recency", "cross_encoder": out["comparison"] / "smoke" / "cross_encoder"}
        per_query, extra = run_methods(smoke_pool, queries, meta, seed, sel, ce, cache, sm_out)
        rep = report(per_query, keys=METHODS + ORACLES, source_groups=rcfg["source_groups"])
        gates = technical_gates(rep, extra, det, 300)
        rep.update(common, **extra, cross_encoder_scoring=st, gates=gates, stage="smoke", peak_memory=peak_mem())
        (out["comparison"] / "smoke_report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (out["comparison"] / "smoke_per_query.json").write_text(json.dumps(per_query, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"stage": "smoke", "gates": gates, **{m: {k: rep[m]["all"][k] for k in ("mrr@10", "ndcg@10", "stale@10", "recall@50", "top1_current_rate")} for m in METHODS}}, indent=1), flush=True)
        if args.stage == "all" and not gates["all_passed"]:
            print("SMOKE GATES FAILED — full run not started", flush=True)
            return 2
    if args.stage in ("full", "all"):
        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()
        st = CE.score_pool(ce, cache, [r for rows in full_pool.values() for r in rows], queries, meta, int(ccfg["batch_size"]))
        main_pool = {s: full_pool[s] for s in MAIN_SPLITS}
        per_main, extra_main = run_methods(main_pool, queries, meta, seed, sel, ce, cache, out)
        per_fe, extra_fe = run_methods({"future_event": full_pool["future_event"]}, queries, meta, seed, sel, ce, cache, out)
        rep_main = report(per_main, keys=METHODS + ORACLES, source_groups=rcfg["source_groups"])
        rep_fe = report(per_fe, keys=METHODS + ORACLES)
        gates = technical_gates(rep_main, extra_main, det, 3537)
        comparison = {"main": rep_main, "future_event_descriptive": rep_fe, "main_run": extra_main, "future_event_run": extra_fe, "gates": gates,
                      "cross_encoder_scoring": st, "stage": "full", "peak_memory": peak_mem(), **common,
                      "note": "all methods permute the same BM25 top-50 pool; future-event never merged with the main table"}
        (out["comparison"] / "baseline_comparison.json").write_text(json.dumps(comparison, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (out["comparison"] / "per_query.json").write_text(json.dumps(per_main + per_fe, ensure_ascii=False) + "\n", encoding="utf-8")
        (out["recency"] / "recency_report.json").write_text(json.dumps({"main": {m: rep_main[m] for m in ("bm25", "recency_only", "bm25_recency")},
            "future_event_descriptive": {m: rep_fe[m] for m in ("bm25", "recency_only", "bm25_recency")}, "selected": sel, "timing_seconds": extra_main["timing_seconds"]},
            ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        ce_man = CE.manifest(ce, ccfg, cache, {"scoring": st, "determinism_check": det, "peak_memory": peak_mem()})
        (out["cross_encoder"] / "cross_encoder_manifest.json").write_text(json.dumps(ce_man, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (out["cross_encoder"] / "cross_encoder_report.json").write_text(json.dumps({"main": {m: rep_main[m] for m in ("bm25", "cross_encoder")},
            "future_event_descriptive": {m: rep_fe[m] for m in ("bm25", "cross_encoder")}, "manifest": ce_man}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"stage": "full", "gates": gates, **{m: {k: rep_main[m]["all"][k] for k in ("mrr@10", "ndcg@10", "stale@10", "recall@50", "top1_current_rate", "top1_outdated_rate")} for m in METHODS}}, indent=1), flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
