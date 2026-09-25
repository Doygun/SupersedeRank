from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src import paths
from src.evidence.build_corpus import load_retrieval_config

def main(which: str) -> int:
    cfg = load_retrieval_config()
    d = paths.PROJECT_ROOT / (cfg["smoke_test"]["output_dir"] if which == "smoke" else cfg["full_run"]["output_dir"])
    splits = ["train", "dev", "test"] + ([] if which == "smoke" else ["future_event"])
    out = {"prefix_mismatch": 0, "score_mismatch": 0, "queries": 0}
    for s in splits:
        top50 = {r["query_id"]: r for r in map(json.loads, (d / f"{s}_top50.jsonl").open(encoding="utf-8"))}
        top100 = {r["query_id"]: r for r in map(json.loads, (d / f"{s}_top100.jsonl").open(encoding="utf-8"))}
        assert set(top50) == set(top100), s
        for qid, row in top100.items():
            out["queries"] += 1
            a, b = top50[qid]["candidates"], row["candidates"][:50]
            if [c["evidence_id"] for c in a] != [c["evidence_id"] for c in b]:
                out["prefix_mismatch"] += 1
            if any(abs(x["score"] - y["score"]) > 1e-9 for x, y in zip(a, b)):
                out["score_mismatch"] += 1
            assert len(row["candidates"]) <= 100 and all(c["rank"] == i + 1 for i, c in enumerate(row["candidates"]))
    print(json.dumps(out))
    return 0 if out["prefix_mismatch"] == 0 and out["score_mismatch"] == 0 else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "smoke"))
