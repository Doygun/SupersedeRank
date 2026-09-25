from __future__ import annotations

from typing import Any

from src.rerank.rule_inferred import ChainIndex, block_rerank, inferred_superseded

def is_query_chain(v: dict[str, Any], q: dict[str, Any]) -> bool:
    return v["cve_id"] == q["cve_id"] and v["source_key"] == q["source_key"] and str(v["cvss_version"]) == str(q["cvss_version"])

def rule_target(candidates: list[dict[str, Any]], q: dict[str, Any], index: ChainIndex) -> tuple[list[dict[str, Any]], dict[str, str | None]]:
    flags, witnesses = {}, {}
    for c in candidates:
        v = index.view[c["evidence_id"]]
        if is_query_chain(v, q):
            sig, w = inferred_superseded(v, q["query_time"], index)
        else:
            sig, w = False, None
        flags[c["evidence_id"]] = sig
        witnesses[c["evidence_id"]] = w
    return block_rerank(candidates, flags, "rule_target"), witnesses

__all__ = ["is_query_chain", "rule_target"]
