from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

import numpy as np

from src import paths
from src.eval import metrics as M
from src.label import query_time_labels as L
from src.rerank import recency as R
from src.rerank.common import load_pool, load_rerank_config, query_lookup, tie_seed
from src.retrieval.bm25_runner import classify_candidate, evaluate, summarize
from src.timeline.config import load_timeline_config

OFFSETS = [1, 30, 90, 180, 365]
SPLITS = ("train", "dev", "test")
OUT = paths.PROJECT_ROOT / "results" / "experiments" / "offset_sensitivity"
FIELDS = ("evidence_id", "cve_id", "source_key", "cvss_version", "observed_from", "valid_from", "valid_until", "valid_from_censored",
          "replacement_type", "chain_ambiguous")

def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s)

def _iso(d: datetime) -> str:
    return d.isoformat(timespec="microseconds") if d.microsecond else d.isoformat()

def load_meta(ids: set[str]) -> dict[str, dict[str, Any]]:
    from src.evidence.build_corpus import load_retrieval_config

    meta = {}
    with (paths.PROJECT_ROOT / load_retrieval_config()["corpus"]["source"]).open(encoding="utf-8") as h:
        for line in h:
            d = json.loads(line)
            if d["evidence_id"] in ids:
                meta[d["evidence_id"]] = {k: d[k] for k in FIELDS}
    return meta

def retime(q: dict, cands: list[dict], meta: dict, new_time: str) -> tuple[dict, list[dict]]:
    query = L.Query(cve_id=q["cve_id"], source_key=q["source_key"], cvss_version=q["cvss_version"], query_time=new_time)
    out = []
    for c in cands:
        d = meta[c["evidence_id"]]
        if d["observed_from"] > new_time:
            continue
        lbl, rel, cls = classify_candidate(d, query)
        out.append({**c, "rank": len(out) + 1, "label": lbl, "relation": rel, "class": cls})
    q2 = {**q, "query_time": new_time,
          "other_source_current_evidence_ids": [c["evidence_id"] for c in out if c["class"] == "OTHER_SOURCE_CURRENT"]}
    return q2, out

def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cfg = load_rerank_config()
    seed = tie_seed()
    sel = json.loads((paths.PROJECT_ROOT / cfg["recency"]["output_dir"] / "recency_manifest.json").read_text(encoding="utf-8"))["selected"]
    taus = [30, 180, 365]
    pool = load_pool(paths.PROJECT_ROOT / cfg["candidate_pool"]["source"], SPLITS)
    queries = query_lookup(SPLITS, "POST_REPLACEMENT_MAIN")
    ids = {c["evidence_id"] for rows in pool.values() for r in rows for c in r["candidates"]} | {q["current_evidence_ids"][0] for q in queries.values()}
    meta = load_meta(ids)
    window_end = load_timeline_config().window_end
    results: dict[str, Any] = {"offsets_days": OFFSETS, "selected": sel, "robustness_taus": taus, "lambda_fixed": sel["lambda"],
                               "pool": "stored BM25 top-50 of the original query, visibility-filtered and re-labelled at the new time", "cohorts": {}}
    for off in OFFSETS:
        excluded = Counter()
        per: dict[str, list[dict]] = {}
        newest_cur, gaps, n_cands, n = 0, [], [], 0
        for split, rows in pool.items():
            for r in rows:
                q = queries[r["query_id"]]
                cur = meta[q["current_evidence_ids"][0]]
                t = _dt(cur["valid_from"]) + timedelta(days=off)
                if cur["valid_until"] is not None and t >= _dt(cur["valid_until"]):
                    excluded["CURRENT_INTERVAL_ENDS_BEFORE_OFFSET"] += 1; continue
                if t > _dt(window_end):
                    excluded["BEYOND_OBSERVATION_WINDOW"] += 1; continue
                new_time = _iso(t)
                q2, cands = retime(q, r["candidates"], meta, new_time)
                if not any(c["class"] == "TARGET_CURRENT" for c in cands):
                    excluded["CURRENT_NOT_VISIBLE_IN_POOL"] += 1; continue
                n += 1; n_cands.append(len(cands))
                chain = [c for c in cands if c["class"] in ("TARGET_CURRENT", "TARGET_OUTDATED")]
                newest = max(chain, key=lambda c: meta[c["evidence_id"]]["observed_from"])
                newest_cur += newest["class"] == "TARGET_CURRENT"
                outd = [c for c in cands if c["class"] == "TARGET_OUTDATED"]
                if outd:
                    gaps.append((_dt(new_time) - _dt(meta[outd[0]["evidence_id"]]["observed_from"])).total_seconds() / 86400 - (_dt(new_time) - _dt(cur["observed_from"])).total_seconds() / 86400)
                lists = {"bm25": cands, "recency_only": R.recency_only(cands, meta, new_time, seed, q["query_id"]),
                         "bm25_recency": R.bm25_recency(cands, meta, new_time, seed, q["query_id"], sel["lambda"], sel["tau_days"])}
                for tau in taus:
                    lists[f"bm25_recency_tau{tau}"] = R.bm25_recency(cands, meta, new_time, seed, q["query_id"], sel["lambda"], tau)
                for m, lst in lists.items():
                    ev = evaluate(lst, q2)
                    ev.update(M.stale_suppression(lst, cands))
                    per.setdefault(m, []).append({"split": split, **ev})
        cohort = {"eligible_queries": n, "excluded": dict(excluded), "mean_visible_candidates": round(float(np.mean(n_cands)), 2) if n_cands else None,
                  "newest_chain_evidence_is_current_rate": round(newest_cur / n, 4) if n else None,
                  "outdated_minus_current_observed_age_days_mean": round(float(np.mean(gaps)), 2) if gaps else None,
                  "methods": {}}
        for m, rows in per.items():
            s = summarize([{"x": rw} for rw in rows], "x")
            s.update({k: v for k, v in M.summarize_stale_suppression(rows).items() if k != "queries"})
            s["by_split"] = {sp: {k: v for k, v in summarize([{"x": rw} for rw in rows if rw["split"] == sp], "x").items() if k in ("queries", "mrr@10", "ndcg@10", "stale@10", "top1_current_rate")} for sp in SPLITS}
            cohort["methods"][m] = s
        results["cohorts"][f"+{off}d"] = cohort
        print(json.dumps({"offset": off, "eligible": n, "excluded": dict(excluded),
                          **{m: (cohort["methods"][m]["mrr@10"], cohort["methods"][m]["ndcg@10"], cohort["methods"][m]["stale@10"], cohort["methods"][m]["top1_current_rate"]) for m in cohort["methods"]}}), flush=True)
    (OUT / "offset_sensitivity_pool_fixed.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    sys.exit(main())
