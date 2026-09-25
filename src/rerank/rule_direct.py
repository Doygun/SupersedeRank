from __future__ import annotations

from typing import Any

from src.rerank.rule_inferred import block_rerank

def direct_superseded(row: dict[str, Any], query_time: str, observed_from_of: dict[str, str]) -> tuple[bool, str | None]:
    succ = row.get("superseded_by_evidence_id") or row.get("replaced_by_evidence_id")
    if not succ or succ not in observed_from_of:
        return False, None
    return (observed_from_of[succ] <= query_time), succ

def rule_direct(candidates: list[dict[str, Any]], query_time: str, rows: dict[str, dict[str, Any]], observed_from_of: dict[str, str]) -> list[dict[str, Any]]:
    flags = {c["evidence_id"]: direct_superseded(rows[c["evidence_id"]], query_time, observed_from_of)[0] for c in candidates}
    return block_rerank(candidates, flags, "rule_direct_upper_bound")

__all__ = ["direct_superseded", "rule_direct"]
