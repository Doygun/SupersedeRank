from __future__ import annotations

import json
import math
import sys
from collections import Counter
from datetime import datetime
from typing import Any

import numpy as np

from src import paths
from src.eval import metrics as M
from src.rerank.common import load_pool, load_rerank_config, query_lookup, rerank, tie_seed
from src.rerank.recency import recency_feature
from src.retrieval.bm25_runner import evaluate, oracle_rerank

SPLITS = ("train", "dev", "test")
OUT = paths.PROJECT_ROOT / "results" / "experiments" / "construct_validity"
FIELDS = ("evidence_id", "cve_id", "source_key", "cvss_version", "observed_from", "valid_from", "valid_until", "valid_from_censored", "replacement_type")

def days(a: str, b: str) -> float:
    return (datetime.fromisoformat(a) - datetime.fromisoformat(b)).total_seconds() / 86400.0

def stats(xs: list[float]) -> dict[str, float]:
    a = np.array(xs, dtype=float)
    return {"n": int(a.size), "min": round(float(a.min()), 4), "max": round(float(a.max()), 4), "mean": round(float(a.mean()), 4),
            "median": round(float(np.median(a)), 4), "p25": round(float(np.percentile(a, 25)), 4), "p75": round(float(np.percentile(a, 75)), 4)}

def load_meta(ids: set[str]) -> dict[str, dict[str, Any]]:
    from src.evidence.build_corpus import load_retrieval_config

    meta = {}

    with (paths.PROJECT_ROOT / load_retrieval_config()["corpus"]["source"]).open(encoding="utf-8") as h:
        for line in h:
            d = json.loads(line)
            if d["evidence_id"] in ids:
                meta[d["evidence_id"]] = {k: d[k] for k in FIELDS}
    return meta

def chain_newest_tiebreak(cands: list[dict], meta: dict[str, dict], seed: int, qid: str, q: dict) -> list[dict]:
    target = {c["evidence_id"] for c in cands if c["class"] in ("TARGET_CURRENT", "TARGET_OUTDATED")}
    scores = {}
    for c in cands:
        bonus = 0.0
        if c["evidence_id"] in target:
            bonus = 1e-6 * (1.0 - min(1.0, days(q["query_time"], meta[c["evidence_id"]]["observed_from"]) / 10000.0))
        scores[c["evidence_id"]] = c["score"] + bonus
    return rerank(cands, scores, seed, qid, "chain_newest_tiebreak")

def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cfg = load_rerank_config()
    seed = tie_seed()
    pool = load_pool(paths.PROJECT_ROOT / cfg["candidate_pool"]["source"], SPLITS)
    queries = query_lookup(SPLITS, "POST_REPLACEMENT_MAIN")
    ids = {c["evidence_id"] for rows in pool.values() for r in rows for c in r["candidates"]}
    ids |= {e for q in queries.values() for e in q["visible_evidence_ids"]} | {e for q in queries.values() for e in q["current_evidence_ids"] + q["outdated_evidence_ids"]}
    meta = load_meta(ids)
    rec_lists = {s: {r["query_id"]: r for r in (json.loads(l) for l in (paths.PROJECT_ROOT / cfg["recency"]["output_dir"] / f"{s}_bm25_recency_top50.jsonl").open(encoding="utf-8"))} for s in SPLITS}
    ro_lists = {s: {r["query_id"]: r for r in (json.loads(l) for l in (paths.PROJECT_ROOT / cfg["recency"]["output_dir"] / f"{s}_recency_only_top50.jsonl").open(encoding="utf-8"))} for s in SPLITS}
    ce_lists = {s: {r["query_id"]: r for r in (json.loads(l) for l in (paths.PROJECT_ROOT / cfg["cross_encoder"]["output_dir"] / f"{s}_top50.jsonl").open(encoding="utf-8"))} for s in SPLITS}
    sel = json.loads((paths.PROJECT_ROOT / cfg["recency"]["output_dir"] / "recency_manifest.json").read_text(encoding="utf-8"))["selected"]

    gap_event_query, gap_cur_out, cur_age, out_age = [], [], [], []
    exactly30, below30, outdated_censored, newest_is_current, newest_cve_is_current, exceptions = 0, 0, 0, 0, 0, []
    tie_rows, decomposition = [], Counter()
    ss_rows: dict[str, list[dict]] = {m: [] for m in ("bm25", "recency_only", "bm25_recency", "cross_encoder", "oracle_current_first", "oracle_temporal", "chain_newest_tiebreak")}
    ss_by_split: dict[str, dict[str, list[dict]]] = {m: {s: [] for s in SPLITS} for m in ss_rows}
    cnt_top1 = Counter()
    for split, rows in pool.items():
        for r in rows:
            q = queries[r["query_id"]]
            cur_id, out_ids = q["current_evidence_ids"][0], q["outdated_evidence_ids"]
            cur, out = meta[cur_id], meta[out_ids[0]]
            g = days(q["query_time"], cur["valid_from"])
            gap_event_query.append(g)
            exactly30 += abs(g - 30.0) < 1e-6
            below30 += g < 30.0 - 1e-6
            gap_cur_out.append(days(cur["observed_from"], out["observed_from"]))
            cur_age.append(days(q["query_time"], cur["observed_from"])); out_age.append(days(q["query_time"], out["observed_from"]))
            outdated_censored += bool(out["valid_from_censored"])
            vis_cve = [meta[e] for e in q["visible_evidence_ids"] if e in meta]
            vis = [e for e in vis_cve if e["source_key"] == q["source_key"] and e["cvss_version"] == q["cvss_version"]]
            newest = max(vis, key=lambda e: e["observed_from"])
            n_newest = sum(1 for e in vis if e["observed_from"] == newest["observed_from"])
            if newest["evidence_id"] in q["current_evidence_ids"] and n_newest == 1:
                newest_is_current += 1
            else:
                exceptions.append({"query_id": q["query_id"], "split": split, "newest": newest["evidence_id"], "current": q["current_evidence_ids"],
                                   "n_sharing_newest_time": n_newest, "visible_chain": [e["evidence_id"] for e in vis]})
            newest_cve = max(vis_cve, key=lambda e: e["observed_from"])
            newest_cve_is_current += newest_cve["evidence_id"] in q["current_evidence_ids"] and sum(1 for e in vis_cve if e["observed_from"] == newest_cve["observed_from"]) == 1
            cands = r["candidates"]
            b_cur = next((c for c in cands if c["class"] == "TARGET_CURRENT"), None); b_out = next((c for c in cands if c["class"] == "TARGET_OUTDATED"), None)
            tied = b_cur is not None and b_out is not None and abs(b_cur["score"] - b_out["score"]) < 1e-9
            lists = {"bm25": cands, "bm25_recency": rec_lists[split][r["query_id"]]["candidates"], "recency_only": ro_lists[split][r["query_id"]]["candidates"],
                     "cross_encoder": ce_lists[split][r["query_id"]]["candidates"], "oracle_current_first": oracle_rerank(cands, "current_first"),
                     "oracle_temporal": oracle_rerank(cands, "temporal"), "chain_newest_tiebreak": chain_newest_tiebreak(cands, meta, seed, r["query_id"], q)}
            for m, lst in lists.items():
                row = M.stale_suppression(lst, cands)
                ss_rows[m].append(row); ss_by_split[m][split].append(row)
                cnt_top1[(m, "top1_current")] += lst[0]["class"] == "TARGET_CURRENT"
            top1_rec = lists["bm25_recency"][0]["class"] == "TARGET_CURRENT"
            top1_bm = cands[0]["class"] == "TARGET_CURRENT"
            top1_cnt = lists["chain_newest_tiebreak"][0]["class"] == "TARGET_CURRENT"
            decomposition[("tied" if tied else "untied", "bm25_top1_current", top1_bm)] += 1
            decomposition[("tied" if tied else "untied", "bm25_recency_top1_current", top1_rec)] += 1
            decomposition[("tied" if tied else "untied", "chain_newest_tiebreak_top1_current", top1_cnt)] += 1
            decomposition[("agreement", "bm25_recency_vs_chain_newest_same_top1", lists["bm25_recency"][0]["evidence_id"] == lists["chain_newest_tiebreak"][0]["evidence_id"])] += 1

    n = len(gap_event_query)
    cur_feat = [recency_feature(a, sel["tau_days"]) for a in cur_age]; out_feat = [recency_feature(a, sel["tau_days"]) for a in out_age]
    audit = {
        "queries": n, "selected_recency": sel,
        "query_time_rule": "query_time = replacement_time + min(30 days, 0.5 * remaining CURRENT interval)  (config/queries.yaml)",
        "event_to_query_days": {**stats(gap_event_query), "exactly_30_days_rate": round(exactly30 / n, 4), "below_30_days_rate": round(below30 / n, 4)},
        "current_minus_outdated_observed_from_days": stats(gap_cur_out),
        "current_observed_age_days": stats(cur_age), "outdated_observed_age_days": stats(out_age),
        "outdated_left_censored_count": outdated_censored,
        "newest_visible_chain_evidence_is_current": {"rate": round(newest_is_current / n, 4), "count": newest_is_current, "exceptions": len(exceptions),
                                                     "exception_rows": exceptions[:50]},
        "newest_visible_same_cve_evidence_is_current": {"rate": round(newest_cve_is_current / n, 4), "count": newest_cve_is_current,
                                                         "note": "across every chain of the CVE (other sources/versions); relevant to recency-only"},
        "recency_feature_tau_selected": {"current_mean": round(float(np.mean(cur_feat)), 4), "outdated_mean": round(float(np.mean(out_feat)), 4),
                                         "current_gt_outdated_rate": round(float(np.mean([c > o for c, o in zip(cur_feat, out_feat)])), 4)},
        "tau_alignment": {"query_offset_upper_bound_days": 30, "selected_tau_days": sel["tau_days"],
                          "structurally_aligned": sel["tau_days"] == 30,
                          "note": "the recency bonus is monotone in observed age for every tau, so within a same-chain BM25 tie the newer (CURRENT) "
                                  "evidence wins for any tau; tau only changes the bonus gap against other-CVE candidates and the newest-vs-older margin"},
        "decomposition": {f"{a}|{b}|{c}": v for (a, b, c), v in sorted(decomposition.items(), key=str)},
        "top1_current_by_method": {m: round(v / n, 4) for (m, _), v in sorted(cnt_top1.items())},
    }
    (OUT / "recency_structural_audit.json").write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ss = {"pool": "BM25 top-50 (accepted run)", "k": 10, "pool_size": 50,
          "all": {m: M.summarize_stale_suppression(rows) for m, rows in ss_rows.items()},
          "by_split": {m: {s: M.summarize_stale_suppression(rows) for s, rows in d.items()} for m, d in ss_by_split.items()}}
    (OUT / "stale_suppression_metrics.json").write_text(json.dumps(ss, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: audit[k] for k in ("event_to_query_days", "newest_visible_chain_evidence_is_current", "tau_alignment", "decomposition", "top1_current_by_method")
                      if k != "newest_visible_chain_evidence_is_current"}, indent=1, default=str)[:3000])
    print(json.dumps({"newest_is_current": {k: v for k, v in audit["newest_visible_chain_evidence_is_current"].items() if k != "exception_rows"}}))
    print(json.dumps({m: ss["all"][m] for m in ss["all"]}, indent=1))
    return 0

if __name__ == "__main__":
    sys.exit(main())
