from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

from src import paths
from src.retrieval import dense_runner as D
from src.retrieval.bm25_runner import evaluate, load_main_queries, load_retrieval_config, oracle_rerank, report

METHOD_KEYS = ("bm25", "dense", "hybrid")
ORACLE_KEYS = ("dense_oracle_current_first", "dense_oracle_temporal", "hybrid_oracle_current_first", "hybrid_oracle_temporal")
SMOKE_GATES = {"dense_recall@50_min": 0.5, "hybrid_recall@50_min": 0.95}

def peak_rss_gb() -> float:
    import psutil

    info = psutil.Process().memory_info()
    return round(getattr(info, "peak_wset", info.rss) / 2**30, 3)

def write_lists(path: Path, rows: list[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path.stat().st_size

def run_stage(cfg: dict[str, Any], corpus: list[dict], encoder: D.Encoder, index: D.DenseIndex, queries: dict[str, list[dict]],
              bm25_dir: Path, dense_dir: Path, hybrid_dir: Path, repeat_check: bool) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    dcfg, hcfg = cfg["dense"], cfg["hybrid"]
    seed, top100, top50, rrf_k = int(cfg["bm25"]["tie_break"]["seed"]), int(dcfg["candidates_top_k"]), int(dcfg["eval_top_k"]), int(hcfg["rrf_k"])
    obs = {d["evidence_id"]: d["observed_from"] for d in corpus}
    timing = {"query_encode": 0.0, "dense_retrieval": 0.0, "rrf": 0.0, "bm25_lists_load": 0.0}
    checks = {"visibility_violations": 0, "duplicate_results": 0, "nan_or_inf_scores": 0, "missing_queries": [],
              "dense_repeat_identical": None, "query_nan_or_inf": 0}
    per_query: list[dict[str, Any]] = []
    sizes: dict[str, int] = {}
    for split, qs in queries.items():
        t0 = time.perf_counter()
        bm25_lists = D.load_lists(bm25_dir / f"{split}_top100.jsonl")
        timing["bm25_lists_load"] += time.perf_counter() - t0
        t0 = time.perf_counter()
        q_emb, q_stats = encoder.encode([q["query_text"] for q in qs], int(dcfg["batch_size"]), prefix=dcfg["query_prefix"])
        timing["query_encode"] += time.perf_counter() - t0
        checks["query_nan_or_inf"] += int((~np.isfinite(q_emb)).sum())
        checks.setdefault("query_token_stats", {})[split] = q_stats
        t0 = time.perf_counter()
        dense_ranked: list[tuple[list[dict], int]] = []
        for start in range(0, len(qs), 64):
            dense_ranked.extend(index.rank_batch(qs[start:start + 64], q_emb[start:start + 64], top100))
        timing["dense_retrieval"] += time.perf_counter() - t0
        if repeat_check:
            again = []
            for start in range(0, len(qs), 64):
                again.extend(index.rank_batch(qs[start:start + 64], q_emb[start:start + 64], top100))
            same = all([c["evidence_id"] for c in a[0]] == [c["evidence_id"] for c in b[0]] for a, b in zip(dense_ranked, again))
            checks["dense_repeat_identical"] = bool(same) if checks["dense_repeat_identical"] is None else bool(checks["dense_repeat_identical"] and same)
        d100_rows, d50_rows, h50_rows = [], [], []
        for q, (dr, n_visible) in zip(qs, dense_ranked):
            qid = q["query_id"]
            if qid not in bm25_lists:
                checks["missing_queries"].append(qid)
                continue
            b100 = bm25_lists[qid]["candidates"]
            t0 = time.perf_counter()
            hyb = D.rrf_fuse({"bm25": b100, "dense": dr}, rrf_k, seed, qid, top50)
            timing["rrf"] += time.perf_counter() - t0
            for ranked in (dr, hyb):
                ids = [c["evidence_id"] for c in ranked]
                checks["duplicate_results"] += len(ids) - len(set(ids))
                checks["visibility_violations"] += sum(1 for c in ranked if obs[c["evidence_id"]] > q["query_time"])
                checks["nan_or_inf_scores"] += sum(1 for c in ranked if not np.isfinite(c["score"]))
            b50, d50 = b100[:top50], dr[:top50]
            rec = {"query_id": qid, "split": split, "template": q["query_template_id"], "cve_id": q["cve_id"], "source_key": q["source_key"],
                   "cvss_version": q["cvss_version"], "censored": q["valid_from_censored"], "n_visible": n_visible,
                   "bm25": evaluate(b50, q), "dense": evaluate(d50, q), "hybrid": evaluate(hyb, q),
                   "dense_oracle_current_first": evaluate(oracle_rerank(d50, "current_first"), q),
                   "dense_oracle_temporal": evaluate(oracle_rerank(d50, "temporal"), q),
                   "hybrid_oracle_current_first": evaluate(oracle_rerank(hyb, "current_first"), q),
                   "hybrid_oracle_temporal": evaluate(oracle_rerank(hyb, "temporal"), q)}
            rec["achievable"] = rec["hybrid"]["target_in_top50"]
            per_query.append(rec)
            base = {"query_id": qid, "split": split, "query_time": q["query_time"], "current_evidence_ids": q["current_evidence_ids"],
                    "outdated_evidence_ids": q["outdated_evidence_ids"]}
            d100_rows.append({**base, "candidates": dr})
            d50_rows.append({**base, "candidates": d50})
            h50_rows.append({**base, "candidates": hyb})
        sizes[f"dense/{split}_top100.jsonl"] = write_lists(dense_dir / f"{split}_top100.jsonl", d100_rows)
        sizes[f"dense/{split}_top50.jsonl"] = write_lists(dense_dir / f"{split}_top50.jsonl", d50_rows)
        sizes[f"hybrid/{split}_top50.jsonl"] = write_lists(hybrid_dir / f"{split}_top50.jsonl", h50_rows)
        print(json.dumps({"split": split, "queries": len(qs), "dense_mrr": np.mean([p["dense"]["mrr@10"] for p in per_query if p["split"] == split]).round(4),
                          "hybrid_mrr": np.mean([p["hybrid"]["mrr@10"] for p in per_query if p["split"] == split]).round(4)}), flush=True)
    timing = {k: round(v, 1) for k, v in timing.items()}
    return per_query, {"timing_seconds": timing, "checks": checks, "list_file_bytes": sizes}

def smoke_gates(rep: dict[str, Any], extra: dict[str, Any], repro: dict[str, Any]) -> dict[str, Any]:
    ch = extra["checks"]
    gates = {
        "dense_recall@50_ok": rep["dense"]["all"]["recall@50"] >= SMOKE_GATES["dense_recall@50_min"],
        "hybrid_recall@50_ok": rep["hybrid"]["all"]["recall@50"] >= SMOKE_GATES["hybrid_recall@50_min"],
        "no_visibility_violation": ch["visibility_violations"] == 0,
        "no_nan_inf": ch["nan_or_inf_scores"] == 0 and ch["query_nan_or_inf"] == 0 and repro["embedding_nan_or_inf"] == 0,
        "ids_match_embedding_order": bool(repro["ids_match_corpus_order"]),
        "reproducible_same_seed": bool(ch["dense_repeat_identical"]) and repro["max_abs_diff_cached_vs_reencode"] < 1e-4,
        "no_missing_queries": len(ch["missing_queries"]) == 0 and rep["queries_total"] == 300,
        "no_duplicates": ch["duplicate_results"] == 0,
        "test_not_used_for_selection": True,
    }
    gates["all_passed"] = all(gates.values())
    return gates

def main(argv: list[str] | None = None) -> int:
    import torch

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage", choices=["smoke", "full", "all"], default="all")
    ap.add_argument("--force-embed", action="store_true")
    args = ap.parse_args(argv)
    cfg = load_retrieval_config()
    dcfg, hcfg = cfg["dense"], cfg["hybrid"]
    print(json.dumps(D.hardware_report(), indent=1), flush=True)
    corpus = D.load_corpus(cfg)
    encoder = D.Encoder(dcfg)
    print(json.dumps({"model": dcfg["model"], "revision": encoder.revision, "device": encoder.device}), flush=True)
    manifest = D.build_doc_embeddings(cfg, corpus, encoder, force=args.force_embed)
    print(json.dumps({"embed_seconds": manifest["embed_seconds"], "shape": manifest["embedding_shape"], "trunc": manifest["doc_stats"]["truncation_rate"]}), flush=True)
    index = D.DenseIndex(cfg, corpus, encoder.device)
    smoke_dir = paths.PROJECT_ROOT / dcfg["smoke_output_dir"]
    bm25_smoke_dir = paths.PROJECT_ROOT / cfg["smoke_test"]["output_dir"]
    bm25_full_dir = paths.PROJECT_ROOT / cfg["full_run"]["output_dir"]
    dense_dir, hybrid_dir = paths.PROJECT_ROOT / dcfg["output_dir"], paths.PROJECT_ROOT / hcfg["output_dir"]
    main_q = load_main_queries(cfg["full_run"]["main_splits"], cfg["full_run"]["role"])
    common = {"config": {"dense": dcfg, "hybrid": hcfg, "bm25_tie_break": cfg["bm25"]["tie_break"], "oracle": cfg["oracle"],
                         "source_groups": cfg["source_groups"], "smoke_gates": SMOKE_GATES},
              "embedding_manifest": manifest, "corpus_docs": len(corpus)}

    if args.stage in ("smoke", "all"):
        sampled = json.loads((bm25_smoke_dir / "sampled_queries.json").read_text(encoding="utf-8"))
        smoke_q = {s: [q for q in main_q[s] if q["query_id"] in set(ids)] for s, ids in sampled.items()}
        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()
        repro = D.reproducibility_checks(encoder, corpus, index.emb, dcfg)
        repro["embedding_nan_or_inf"] = manifest["nan_or_inf"]
        per_query, extra = run_stage(cfg, corpus, encoder, index, smoke_q, bm25_smoke_dir, smoke_dir / "dense", smoke_dir / "hybrid", repeat_check=True)
        rep = report(per_query, keys=METHOD_KEYS + ORACLE_KEYS, source_groups=cfg["source_groups"])
        gates = smoke_gates(rep, extra, repro)
        rep.update(common, **extra, reproducibility=repro, gates=gates, stage="smoke",
                   peak_memory={"gpu_gb": round(torch.cuda.max_memory_allocated() / 2**30, 3) if torch.cuda.is_available() else None, "rss_gb": peak_rss_gb()})
        smoke_dir.mkdir(parents=True, exist_ok=True)
        (smoke_dir / "report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (smoke_dir / "per_query.json").write_text(json.dumps(per_query, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"stage": "smoke", "gates": gates, **{k: rep[k]["all"] for k in METHOD_KEYS}}, indent=1), flush=True)
        if args.stage == "all" and not gates["all_passed"]:
            print("SMOKE GATES FAILED — full run not started", flush=True)
            return 2
    if args.stage in ("full", "all"):
        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()
        per_main, extra_main = run_stage(cfg, corpus, encoder, index, main_q, bm25_full_dir, dense_dir, hybrid_dir, repeat_check=False)
        fe_q = load_main_queries(["future_event"], cfg["full_run"]["role"])
        per_fe, extra_fe = run_stage(cfg, corpus, encoder, index, fe_q, bm25_full_dir, dense_dir, hybrid_dir, repeat_check=False)
        rep = {"main": report(per_main, keys=METHOD_KEYS + ORACLE_KEYS, source_groups=cfg["source_groups"]),
               "future_event_descriptive": report(per_fe, keys=METHOD_KEYS + ORACLE_KEYS),
               "main_run": extra_main, "future_event_run": extra_fe, "stage": "full",
               "peak_memory": {"gpu_gb": round(torch.cuda.max_memory_allocated() / 2**30, 3) if torch.cuda.is_available() else None, "rss_gb": peak_rss_gb()},
               "note": "future-event results are descriptive only and never merged with the main table", **common}
        hybrid_dir.mkdir(parents=True, exist_ok=True)
        (hybrid_dir / "dense_hybrid_report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (hybrid_dir / "per_query.json").write_text(json.dumps(per_main + per_fe, ensure_ascii=False) + "\n", encoding="utf-8")
        dense_dir.mkdir(parents=True, exist_ok=True)
        (dense_dir / "dense_report.json").write_text(json.dumps({"main": rep["main"]["dense"], "future_event_descriptive": rep["future_event_descriptive"]["dense"],
                                                                 "embedding_manifest": manifest, "timing_seconds": extra_main["timing_seconds"]},
                                                                ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"stage": "full", **{k: rep["main"][k]["all"] for k in METHOD_KEYS}, "timing": extra_main["timing_seconds"]}, indent=1), flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
