from __future__ import annotations

import argparse
import json
import sys
import time

from src import paths
from src.retrieval.bm25_runner import Bm25Index, load_main_queries, load_retrieval_config, run_queries

TOP100 = 100

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--smoke-only", action="store_true")
    args = ap.parse_args(argv)
    cfg = load_retrieval_config()
    seed = int(cfg["bm25"]["tie_break"]["seed"])
    index = Bm25Index(cfg)
    smoke_dir = paths.PROJECT_ROOT / cfg["smoke_test"]["output_dir"]
    full_dir = paths.PROJECT_ROOT / cfg["full_run"]["output_dir"]
    sampled = json.loads((smoke_dir / "sampled_queries.json").read_text(encoding="utf-8"))
    main_q = load_main_queries(cfg["full_run"]["main_splits"], cfg["full_run"]["role"])
    smoke_q = {s: [q for q in main_q[s] if q["query_id"] in set(ids)] for s, ids in sampled.items()}
    _, t = run_queries(index, smoke_q, smoke_dir, seed, TOP100, filename="{split}_top100.jsonl")
    print(json.dumps({"smoke_top100_seconds": round(t, 1), "load": round(index.t_load, 1), "index": round(index.t_index, 1)}))
    if args.smoke_only:
        return 0
    t0 = time.perf_counter()
    _, t_main = run_queries(index, main_q, full_dir, seed, TOP100, filename="{split}_top100.jsonl")
    fe_q = load_main_queries(["future_event"], cfg["full_run"]["role"])
    _, t_fe = run_queries(index, fe_q, full_dir, seed, TOP100, filename="{split}_top100.jsonl")
    (full_dir / "bm25_top100_timing.json").write_text(json.dumps({"search_main_seconds": round(t_main, 1), "search_future_event_seconds": round(t_fe, 1),
                                                                   "total_seconds": round(time.perf_counter() - t0, 1)}, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"full_top100_seconds": round(t_main, 1), "fe": round(t_fe, 1)}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
