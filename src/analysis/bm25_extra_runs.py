from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta

from src import paths
from src.evidence.build_evidence import load_config as load_query_config
from src.retrieval.bm25_runner import Bm25Index, load_main_queries, load_retrieval_config, run_queries
from src.timeline.config import load_timeline_config

OFFSETS = [1, 30, 90, 180, 365]

def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s)

def _iso(d: datetime) -> str:
    return d.isoformat(timespec="microseconds") if d.microsecond else d.isoformat()

def offset_cohorts(sampled: dict[str, list[dict]], corpus_by_id: dict[str, dict], templates: dict[str, str], window_end: str) -> tuple[dict[str, list[dict]], list[dict]]:
    cohorts: dict[str, list[dict]] = {}
    excluded: list[dict] = []
    for off in OFFSETS:
        rows = []
        for split, qs in sampled.items():
            for q in qs:
                cur = corpus_by_id[q["current_evidence_ids"][0]]
                t = _dt(cur["valid_from"]) + timedelta(days=off)
                reason = None
                if cur["valid_until"] is not None and t >= _dt(cur["valid_until"]):
                    reason = "CURRENT_INTERVAL_ENDS_BEFORE_OFFSET"
                elif t > _dt(window_end):
                    reason = "BEYOND_OBSERVATION_WINDOW"
                if reason:
                    excluded.append({"offset_days": off, "query_id": q["query_id"], "split": split, "reason": reason})
                    continue
                qt = _iso(t)
                text = templates[q["query_template_id"]].format(query_date=qt[:10], version=q["cvss_version"], source=q["source_key"], cve=q["cve_id"])
                rows.append({**q, "query_time": qt, "query_text": text, "offset_days": off, "original_split": split, "original_query_time": q["query_time"]})
        cohorts[f"offset_{off}"] = rows
    return cohorts, excluded

def main() -> int:
    cfg = load_retrieval_config()
    seed, top_k = int(cfg["bm25"]["tie_break"]["seed"]), int(cfg["bm25"]["top_k"])
    index = Bm25Index(cfg)
    corpus_by_id = {d["evidence_id"]: d for d in index.corpus}

    ctrl_dir = paths.PROJECT_ROOT / "results" / "experiments" / "pre_replacement_control"
    ctrl_q = load_main_queries(["train", "dev", "test"], "PRE_REPLACEMENT_CONTROL")
    per, t_ctrl = run_queries(index, ctrl_q, ctrl_dir, seed, top_k)
    (ctrl_dir / "per_query.json").write_text(json.dumps(per, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"control_queries": {s: len(v) for s, v in ctrl_q.items()}, "seconds": round(t_ctrl, 1)}), flush=True)

    smoke_ids = json.loads((paths.PROJECT_ROOT / cfg["smoke_test"]["output_dir"] / "sampled_queries.json").read_text(encoding="utf-8"))
    main_q = load_main_queries(["train", "dev", "test"], "POST_REPLACEMENT_MAIN")
    sampled = {s: [q for q in main_q[s] if q["query_id"] in set(ids)] for s, ids in smoke_ids.items()}
    qcfg = load_query_config()["queries"]
    window_end = load_timeline_config().window_end
    cohorts, excluded = offset_cohorts(sampled, corpus_by_id, qcfg["templates"], window_end)
    off_dir = paths.PROJECT_ROOT / "results" / "experiments" / "offset_sensitivity" / "smoke"
    off_dir.mkdir(parents=True, exist_ok=True)
    (off_dir / "excluded.json").write_text(json.dumps(excluded, indent=1) + "\n", encoding="utf-8")
    t0 = time.perf_counter()
    per_off, t_off = run_queries(index, cohorts, off_dir, seed, top_k, filename="{split}_top50.jsonl")
    (off_dir / "per_query.json").write_text(json.dumps(per_off, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"offset_cohorts": {k: len(v) for k, v in cohorts.items()}, "excluded": len(excluded), "seconds": round(t_off, 1),
                      "total_seconds": round(time.perf_counter() - t0, 1)}), flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
