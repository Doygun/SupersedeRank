from __future__ import annotations

import argparse
import json
import sys

from src import paths
from src.retrieval.bm25_runner import (
    Bm25Index, load_main_queries, load_retrieval_config, report, run_queries, sample_cve_level,
)

from src.retrieval.bm25_runner import ORACLES, classify_candidate, evaluate, oracle_rerank, query_tokens, tokenize

ORACLE_RANK = ORACLES["current_first"]

def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    cfg = load_retrieval_config()
    smoke = cfg["smoke_test"]
    out_dir = paths.PROJECT_ROOT / smoke["output_dir"]
    index = Bm25Index(cfg)
    idx_bytes = index.save(paths.PROCESSED_DATA_DIR / "retrieval" / "bm25_full_corpus.pkl")
    queries = sample_cve_level(load_main_queries(smoke["splits"], smoke["role"]), int(smoke["queries_per_split"]), int(smoke["seed"]))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "sampled_queries.json").write_text(json.dumps({s: [q["query_id"] for q in qs] for s, qs in queries.items()}, indent=1), encoding="utf-8")
    per_query, t_search = run_queries(index, queries, out_dir, int(cfg["bm25"]["tie_break"]["seed"]), int(cfg["bm25"]["top_k"]))
    rep = report(per_query)
    rep.update({"config": {"bm25": cfg["bm25"], "smoke_test": smoke, "oracle": cfg["oracle"]}, "corpus_docs": len(index.corpus),
                "timing_seconds": {"load_corpus": round(index.t_load, 1), "build_index": round(index.t_index, 1), "search_and_label": round(t_search, 1)},
                "index_size_bytes": idx_bytes})
    (out_dir / "smoke_report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "per_query.json").write_text(json.dumps(per_query, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"bm25": rep["bm25"]["all"], "oracle_current_first": rep["oracle_current_first"]["all"],
                      "oracle_temporal": rep["oracle_temporal"]["all"], "timing": rep["timing_seconds"]}, indent=1))
    return 0

if __name__ == "__main__":
    sys.exit(main())
