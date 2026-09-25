from __future__ import annotations

import json
import sys
from collections import Counter
from typing import Any

from src import paths
from src.analysis.offset_sensitivity import OFFSETS, load_meta
from src.eval import metrics as M
from src.rerank import recency as R
from src.rerank.common import load_rerank_config, query_lookup, tie_seed
from src.retrieval.bm25_runner import evaluate, summarize

SPLITS = ("train", "dev", "test")

def summarize_methods(per: dict[str, list[dict]], groups: tuple[str, ...] = ("split", "censored")) -> dict[str, Any]:
    out = {}
    for m, rows in per.items():
        s = summarize([{"x": r} for r in rows], "x")
        s.update({k: v for k, v in M.summarize_stale_suppression(rows).items() if k != "queries"})
        for g in groups:
            s[f"by_{g}"] = {str(v): {k: x for k, x in summarize([{"x": r} for r in rows if str(r[g]) == str(v)], "x").items()
                                     if k in ("queries", "mrr@10", "ndcg@10", "stale@10", "top1_current_rate", "top1_outdated_rate", "ranking_failure_rate", "recall@50")}
                            for v in sorted({str(r[g]) for r in rows})}
        out[m] = s
    return out

def main() -> int:
    cfg = load_rerank_config()
    seed = tie_seed()
    sel = json.loads((paths.PROJECT_ROOT / cfg["recency"]["output_dir"] / "recency_manifest.json").read_text(encoding="utf-8"))["selected"]

    ctrl_dir = paths.PROJECT_ROOT / "results" / "experiments" / "pre_replacement_control"
    queries = query_lookup(SPLITS, "PRE_REPLACEMENT_CONTROL")
    rows_by_split = {s: [json.loads(l) for l in (ctrl_dir / f"{s}_top50.jsonl").open(encoding="utf-8")] for s in SPLITS}
    ids = {c["evidence_id"] for rows in rows_by_split.values() for r in rows for c in r["candidates"]}
    meta = load_meta(ids)
    per: dict[str, list[dict]] = {}
    checks = Counter()
    for split, rows in rows_by_split.items():
        for r in rows:
            q = queries[r["query_id"]]
            cands = r["candidates"]
            checks["queries"] += 1
            checks["visibility_violations"] += sum(1 for c in cands if meta[c["evidence_id"]]["observed_from"] > q["query_time"])
            checks["future_replacing_evidence_in_pool"] += any(c["evidence_id"] == q["replacing_new_evidence_id"] for c in cands)
            checks["outdated_in_pool"] += any(c["class"] == "TARGET_OUTDATED" for c in cands)
            checks["current_in_pool"] += any(c["class"] == "TARGET_CURRENT" for c in cands)
            checks["censored_target"] += bool(q["valid_from_censored"])
            lists = {"bm25": cands, "recency_only": R.recency_only(cands, meta, q["query_time"], seed, q["query_id"]),
                     "bm25_recency": R.bm25_recency(cands, meta, q["query_time"], seed, q["query_id"], sel["lambda"], sel["tau_days"])}
            for m, lst in lists.items():
                ev = evaluate(lst, q)
                ev.update(M.stale_suppression(lst, cands))
                per.setdefault(m, []).append({"split": split, "censored": q["valid_from_censored"], **ev})
    ctrl = {"role": "PRE_REPLACEMENT_CONTROL", "note": "negative control / data quality; not part of the main table; cross-encoder skipped (cache covers main pairs only)",
            "checks": dict(checks), "selected_recency": sel, "methods": summarize_methods(per)}
    (ctrl_dir / "pre_control_report.json").write_text(json.dumps(ctrl, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"control_checks": dict(checks), **{m: (ctrl["methods"][m]["mrr@10"], ctrl["methods"][m]["top1_current_rate"], ctrl["methods"][m]["ranking_failure_rate"]) for m in ctrl["methods"]}}), flush=True)

    off_dir = paths.PROJECT_ROOT / "results" / "experiments" / "offset_sensitivity"
    main_q = query_lookup(SPLITS, "POST_REPLACEMENT_MAIN")
    pool_fixed = json.loads((off_dir / "offset_sensitivity_pool_fixed.json").read_text(encoding="utf-8"))
    excluded = json.loads((off_dir / "smoke" / "excluded.json").read_text(encoding="utf-8"))
    smoke_ids = json.loads((paths.PROJECT_ROOT / "results" / "experiments" / "smoke_bm25" / "sampled_queries.json").read_text(encoding="utf-8"))
    smoke_set = {i for ids_ in smoke_ids.values() for i in ids_}
    orig_pool = {r["query_id"]: r for s in SPLITS for r in (json.loads(l) for l in (paths.PROJECT_ROOT / "results" / "experiments" / "smoke_bm25" / f"{s}_top50.jsonl").open(encoding="utf-8"))}
    comp: dict[str, Any] = {"queries_sampled": len(smoke_set), "cohorts": {}}
    for off in OFFSETS:
        rows = [json.loads(l) for l in (off_dir / "smoke" / f"offset_{off}_top50.jsonl").open(encoding="utf-8")]
        ids2 = {c["evidence_id"] for r in rows for c in r["candidates"]}
        meta2 = load_meta(ids2 - set(meta)) | meta if ids2 - set(meta) else meta
        per2: dict[str, list[dict]] = {}
        overlap = []
        for r in rows:
            q = dict(main_q[r["query_id"]]); q["query_time"] = r["query_time"]
            q["other_source_current_evidence_ids"] = [c["evidence_id"] for c in r["candidates"] if c["class"] == "OTHER_SOURCE_CURRENT"]
            cands = r["candidates"]
            overlap.append(len({c["evidence_id"] for c in cands} & {c["evidence_id"] for c in orig_pool[r["query_id"]]["candidates"]}) / max(1, len(cands)))
            lists = {"bm25": cands, "recency_only": R.recency_only(cands, meta2, r["query_time"], seed, r["query_id"]),
                     "bm25_recency": R.bm25_recency(cands, meta2, r["query_time"], seed, r["query_id"], sel["lambda"], sel["tau_days"])}
            for m, lst in lists.items():
                ev = evaluate(lst, q); ev.update(M.stale_suppression(lst, cands))
                per2.setdefault(m, []).append({"split": main_q[r["query_id"]]["split"], **ev})
        key = f"+{off}d"
        comp["cohorts"][key] = {"eligible_queries": len(rows), "excluded": dict(Counter(e["reason"] for e in excluded if e["offset_days"] == off)),
                                "mean_pool_overlap_with_original_top50": round(sum(overlap) / max(1, len(overlap)), 4),
                                "reretrieval": {m: {k: v for k, v in summarize([{"x": r} for r in rs], "x").items() if k in ("queries", "recall@50", "mrr@10", "ndcg@10", "stale@10", "top1_current_rate", "top1_outdated_rate")}
                                                for m, rs in per2.items()},
                                "pool_fixed_all_main": {m: {k: pool_fixed["cohorts"][key]["methods"][m][k] for k in ("queries", "mrr@10", "ndcg@10", "stale@10", "top1_current_rate", "top1_outdated_rate")}
                                                        for m in ("bm25", "recency_only", "bm25_recency")}}
        print(json.dumps({"offset": off, "n": len(rows), "overlap": comp["cohorts"][key]["mean_pool_overlap_with_original_top50"],
                          **{m: (comp["cohorts"][key]["reretrieval"][m]["mrr@10"], comp["cohorts"][key]["reretrieval"][m]["recall@50"], comp["cohorts"][key]["reretrieval"][m]["top1_current_rate"]) for m in per2}}), flush=True)
    (off_dir / "offset_sensitivity_smoke_reretrieval.json").write_text(json.dumps(comp, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    sys.exit(main())
