from __future__ import annotations

import math
from typing import Any

from src.rerank.common import minmax, observed_age_days, rerank

def recency_feature(age_days: float, tau: float) -> float:
    return math.exp(-age_days / tau)

def recency_only(candidates: list[dict[str, Any]], meta: dict[str, dict[str, Any]], query_time: str, seed: int, query_id: str) -> list[dict[str, Any]]:

    scores = {c["evidence_id"]: -observed_age_days(meta[c["evidence_id"]]["observed_from"], query_time) for c in candidates}
    return rerank(candidates, scores, seed, query_id, "recency_only")

def bm25_recency(candidates: list[dict[str, Any]], meta: dict[str, dict[str, Any]], query_time: str, seed: int, query_id: str,
                 lam: float, tau: float) -> list[dict[str, Any]]:
    norm = minmax([c["score"] for c in candidates])
    scores = {c["evidence_id"]: n + lam * recency_feature(observed_age_days(meta[c["evidence_id"]]["observed_from"], query_time), tau)
              for c, n in zip(candidates, norm)}
    return rerank(candidates, scores, seed, query_id, "bm25_recency")

def select_on_dev(dev_rows: list[dict[str, Any]], queries: dict[str, dict[str, Any]], meta: dict[str, dict[str, Any]], seed: int,
                  grid: dict[str, list[float]], objective: str = "ndcg@10", tie_breaker: str = "stale@10") -> dict[str, Any]:
    from src.eval.metrics import mean
    from src.rerank.common import evaluate

    table = []
    for tau in grid["tau_days"]:
        for lam in grid["lambda"]:
            evals = [evaluate(bm25_recency(r["candidates"], meta, r["query_time"], seed, r["query_id"], lam, tau), queries[r["query_id"]]) for r in dev_rows]
            table.append({"tau_days": tau, "lambda": lam, "queries": len(evals),
                          **{m: mean(e[m] for e in evals) for m in ("ndcg@10", "mrr@10", "stale@10", "recall@50")},
                          "top1_current_rate": mean(1.0 if e["top1_current"] else 0.0 for e in evals)})
    best = sorted(table, key=lambda t: (-t[objective], t[tie_breaker], t["tau_days"], t["lambda"]))[0]
    return {"split": "dev", "objective": objective, "tie_breaker": tie_breaker, "grid": grid, "table": table,
            "selected": {"tau_days": best["tau_days"], "lambda": best["lambda"]}}

__all__ = ["recency_feature", "recency_only", "bm25_recency", "select_on_dev"]
