from __future__ import annotations

import math
from typing import Iterable, Sequence

from src.label import query_time_labels as L

def relevance(label: str, relation: str, graded: bool = False) -> int:
    return L.graded_relevance(label, relation) if graded else L.binary_relevance(label, relation)

def dcg(gains: Sequence[int]) -> float:
    return sum(g / math.log2(i + 2) for i, g in enumerate(gains))

def ndcg_at_k(gains: Sequence[int], ideal_gains: Iterable[int], k: int) -> float:
    ideal = sorted(ideal_gains, reverse=True)[:k]
    idcg = dcg(ideal)
    return dcg(list(gains)[:k]) / idcg if idcg > 0 else 0.0

def mrr_at_k(binary: Sequence[int], k: int) -> float:
    for i, g in enumerate(list(binary)[:k]):
        if g:
            return 1.0 / (i + 1)
    return 0.0

def recall_at_k(retrieved_relevant_ids: Sequence[str], all_relevant_ids: Iterable[str], k: int) -> float:
    rel = set(all_relevant_ids)
    if not rel:
        return 0.0
    return len(set(list(retrieved_relevant_ids)[:k]) & rel) / len(rel)

def stale_rate_at_k(labels: Sequence[str], k: int) -> float:
    top = list(labels)[:k]
    return sum(1 for lbl in top if L.is_stale(lbl)) / k if top else 0.0

def mean(values: Iterable[float]) -> float | None:
    vals = list(values)
    return round(sum(vals) / len(vals), 4) if vals else None

def outdated_count_at_k(ranked: Sequence[dict], k: int = 10) -> int:
    return sum(1 for c in list(ranked)[:k] if c["class"] == "TARGET_OUTDATED")

def first_outdated_rank(ranked: Sequence[dict], pool_size: int = 50) -> int:
    for i, c in enumerate(ranked, start=1):
        if c["class"] == "TARGET_OUTDATED":
            return i
    return pool_size + 1

def outdated_suppression_at_k(ranked: Sequence[dict], baseline: Sequence[dict], k: int = 10) -> float | None:
    base_out = {c["evidence_id"] for c in list(baseline)[:k] if c["class"] == "TARGET_OUTDATED"}
    if not base_out:
        return None
    still = {c["evidence_id"] for c in list(ranked)[:k]} & base_out
    return 1.0 - len(still) / len(base_out)

def current_preservation_at_k(ranked: Sequence[dict], baseline: Sequence[dict], k: int = 10) -> float | None:
    base_cur = {c["evidence_id"] for c in list(baseline)[:k] if c["class"] == "TARGET_CURRENT"}
    if not base_cur:
        return None
    return 1.0 if any(c["class"] == "TARGET_CURRENT" for c in list(ranked)[:k]) else 0.0

def current_at_1_and_no_stale_at_k(ranked: Sequence[dict], k: int = 10) -> bool:
    r = list(ranked)
    return bool(r) and r[0]["class"] == "TARGET_CURRENT" and outdated_count_at_k(r, k) == 0

def stale_suppression(ranked: Sequence[dict], baseline: Sequence[dict], k: int = 10, pool_size: int = 50) -> dict:
    return {"outdated_count@10": outdated_count_at_k(ranked, k), "first_outdated_rank": first_outdated_rank(ranked, pool_size),
            "outdated_suppression@10": outdated_suppression_at_k(ranked, baseline, k),
            "current_preservation@10": current_preservation_at_k(ranked, baseline, k),
            "current_at1_and_no_stale@10": current_at_1_and_no_stale_at_k(ranked, k)}

def summarize_stale_suppression(rows: Sequence[dict], pool_size: int = 50) -> dict:
    rows = list(rows)
    sup = [r["outdated_suppression@10"] for r in rows if r["outdated_suppression@10"] is not None]
    pres = [r["current_preservation@10"] for r in rows if r["current_preservation@10"] is not None]
    return {"queries": len(rows), "outdated_count@10_mean": mean(r["outdated_count@10"] for r in rows),
            "first_outdated_rank_mean": mean(r["first_outdated_rank"] for r in rows),
            "first_outdated_rank_median": float(sorted(r["first_outdated_rank"] for r in rows)[len(rows) // 2]) if rows else None,
            "first_outdated_beyond_top10_rate": mean(1.0 if r["first_outdated_rank"] > 10 else 0.0 for r in rows),
            "first_outdated_not_in_pool_rate": mean(1.0 if r["first_outdated_rank"] > pool_size else 0.0 for r in rows),
            "outdated_suppression@10": mean(sup), "outdated_suppression@10_queries": len(sup),
            "current_preservation@10": mean(pres), "current_preservation@10_queries": len(pres),
            "current_at1_and_no_stale@10": mean(1.0 if r["current_at1_and_no_stale@10"] else 0.0 for r in rows)}
