from __future__ import annotations

import argparse
import json
import sys

from src import paths
from src.retrieval.bm25_runner import Bm25Index, load_main_queries, load_retrieval_config, report, run_queries

def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    cfg = load_retrieval_config()
    fcfg = cfg["full_run"]
    out_dir = paths.PROJECT_ROOT / fcfg["output_dir"]
    index = Bm25Index(cfg)
    seed, top_k = int(cfg["bm25"]["tie_break"]["seed"]), int(cfg["bm25"]["top_k"])
    main_q = load_main_queries(fcfg["main_splits"], fcfg["role"])
    fe_q = load_main_queries(["future_event"], fcfg["role"])
    per_main, t_main = run_queries(index, main_q, out_dir, seed, top_k)
    per_fe, t_fe = run_queries(index, fe_q, out_dir, seed, top_k)
    rep = {"main": report(per_main), "future_event_descriptive": report(per_fe),
           "config": {"bm25": cfg["bm25"], "full_run": fcfg, "oracle": cfg["oracle"]}, "corpus_docs": len(index.corpus),
           "timing_seconds": {"load_corpus": round(index.t_load, 1), "build_index": round(index.t_index, 1),
                              "search_main": round(t_main, 1), "search_future_event": round(t_fe, 1)},
           "note": "future-event results are descriptive only (18 CVEs / 19 queries) and never merged with the main table"}
    (out_dir / "bm25_report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "per_query.json").write_text(json.dumps(per_main + per_fe, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"main_bm25": rep["main"]["bm25"]["all"], "main_oracle_temporal": rep["main"]["oracle_temporal"]["all"],
                      "timing": rep["timing_seconds"]}, indent=1))
    return 0

if __name__ == "__main__":
    sys.exit(main())
