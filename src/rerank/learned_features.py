from __future__ import annotations

import math
from typing import Any

from src.rerank.rule_inferred import ChainIndex, chain_key, inferred_superseded

TEMPLATES = ("base_vector", "cvssb_score", "base_severity", "combined")
RULE_FEATURE = "newer_different_base_vector_exists"
NUMERIC = ("normalized_bm25_score", "bm25_rank", "cross_encoder_score", "observed_age_days", "newer_visible_same_chain_count",
           "days_to_newest_visible_same_chain", "chain_position_observed")
BINARY = (RULE_FEATURE, "valid_from_censored", "same_cve", "same_source_key", "same_cvss_version", "base_vector_differs_from_chain_newest")

def days_between(later: str, earlier: str) -> float:
    from datetime import datetime
    return (datetime.fromisoformat(later) - datetime.fromisoformat(earlier)).total_seconds() / 86400.0

def is_target_chain(v: dict[str, Any], q: dict[str, Any]) -> bool:
    return v["cve_id"] == q["cve_id"] and v["source_key"] == q["source_key"] and str(v["cvss_version"]) == str(q["cvss_version"])

def candidate_features(c: dict[str, Any], q: dict[str, Any], norm_bm25: float, ce_score: float | None, all_index: ChainIndex, witness_index: ChainIndex,
                       source_map: dict[str, str], template_vocab: tuple[str, ...] = TEMPLATES) -> dict[str, Any]:
    v = all_index.view[c["evidence_id"]]
    qt = q["query_time"]
    chain = [e for e in all_index.chains.get(chain_key(v), ()) if e["observed_from"] <= qt]
    newer = [e for e in chain if e["observed_from"] > v["observed_from"]]
    newest = max(chain, key=lambda e: (e["observed_from"], e["evidence_id"])) if chain else v
    position = 1 + sum(1 for e in chain if e["observed_from"] < v["observed_from"] or (e["observed_from"] == v["observed_from"] and e["evidence_id"] < v["evidence_id"]))
    signal, _ = inferred_superseded(v, qt, witness_index)
    f: dict[str, Any] = {
        "normalized_bm25_score": norm_bm25, "bm25_rank": float(c["rank"]),
        "cross_encoder_score": ce_score if ce_score is not None else math.nan,
        "observed_age_days": days_between(qt, v["observed_from"]),
        "newer_visible_same_chain_count": float(len(newer)),
        "days_to_newest_visible_same_chain": days_between(newest["observed_from"], v["observed_from"]) if newer else 0.0,
        RULE_FEATURE: 1.0 if signal else 0.0,
        "chain_position_observed": float(position),
        "valid_from_censored": 1.0 if v["valid_from_censored"] else 0.0,
        "same_cve": 1.0 if v["cve_id"] == q["cve_id"] else 0.0,
        "same_source_key": 1.0 if v["source_key"] == q["source_key"] else 0.0,
        "same_cvss_version": 1.0 if str(v["cvss_version"]) == str(q["cvss_version"]) else 0.0,
        "base_vector_differs_from_chain_newest": 1.0 if newest["canonical_base_vector"] != v["canonical_base_vector"] else 0.0,
    }
    for t in template_vocab:
        f[f"template_{t}"] = 1.0 if q["query_template_id"] == t else 0.0
    groups = sorted(set(source_map.values()))
    g = source_map.get(v["source_key"], "OTHER_SOURCE")
    for name in groups:
        f[f"source_group_{name}"] = 1.0 if g == name else 0.0
    return f

def feature_order(source_map: dict[str, str], drop_rule_signal: bool = False) -> list[str]:
    cols = [c for c in NUMERIC] + [b for b in BINARY if not (drop_rule_signal and b == RULE_FEATURE)]
    cols += [f"template_{t}" for t in TEMPLATES] + [f"source_group_{g}" for g in sorted(set(source_map.values()))]
    return cols

def fit_source_map(train_queries: list[dict[str, Any]], k: int = 6) -> dict[str, str]:
    from collections import Counter
    top = [s for s, _ in Counter(q["source_key"] for q in train_queries).most_common(k)]
    return {s: s for s in top}

__all__ = ["TEMPLATES", "RULE_FEATURE", "NUMERIC", "BINARY", "is_target_chain", "candidate_features", "feature_order", "fit_source_map", "days_between"]
