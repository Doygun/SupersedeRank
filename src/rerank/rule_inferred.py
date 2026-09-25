from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from src import paths
from src.evidence.build_evidence import base_vector as base_only_vector
from src.normalize.cvss import canonical_vector

ALLOWED_RULE_FIELDS = ("evidence_id", "cve_id", "source_key", "cvss_version", "observed_from", "vector (Base part only)", "valid_from_censored")
ChainKey = tuple[str, str, str]

def chain_key(v: dict[str, Any]) -> ChainKey:
    return (str(v["cve_id"]), str(v["source_key"]), str(v["cvss_version"]))

def narrow_view(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("base_vector")
    if raw is None:
        raw = base_only_vector(str(row["cvss_version"]), row.get("vector") or "")
    return {"evidence_id": row["evidence_id"], "cve_id": row["cve_id"], "source_key": row["source_key"], "cvss_version": row["cvss_version"],
            "observed_from": row["observed_from"], "canonical_base_vector": canonical_vector(raw or ""),
            "valid_from_censored": bool(row.get("valid_from_censored", False))}

class ChainIndex:

    def __init__(self, views: Iterable[dict[str, Any]], witness_ids: set[str]):
        self.view: dict[str, dict[str, Any]] = {}
        self.chains: dict[ChainKey, list[dict[str, Any]]] = defaultdict(list)
        for v in views:
            self.view[v["evidence_id"]] = v
            if v["evidence_id"] in witness_ids:
                self.chains[chain_key(v)].append(v)
        for entries in self.chains.values():
            entries.sort(key=lambda x: (x["observed_from"], x["evidence_id"]))
        self.n_witnesses = sum(len(x) for x in self.chains.values())

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"|".join(k): [(e["observed_from"], e["canonical_base_vector"], e["evidence_id"]) for e in v] for k, v in self.chains.items()}
        path.write_text(json.dumps({"fields": ALLOWED_RULE_FIELDS, "chains": payload}), encoding="utf-8")

def inferred_superseded(e: dict[str, Any], query_time: str, index: ChainIndex) -> tuple[bool, str | None]:
    if e["observed_from"] > query_time:
        return False, None
    if not e["canonical_base_vector"]:
        return False, None
    for f in index.chains.get(chain_key(e), ()):
        if f["observed_from"] > query_time:
            break
        if f["evidence_id"] == e["evidence_id"] or f["observed_from"] <= e["observed_from"]:
            continue
        if f["canonical_base_vector"] and f["canonical_base_vector"] != e["canonical_base_vector"]:
            return True, f["evidence_id"]
    return False, None

def block_rerank(candidates: list[dict[str, Any]], flags: dict[str, bool], method: str) -> list[dict[str, Any]]:
    ids = [c["evidence_id"] for c in candidates]
    if set(ids) != set(flags) or len(ids) != len(set(ids)):
        raise RuntimeError(f"{method}: candidate set changed")
    ordered = [c for c in candidates if not flags[c["evidence_id"]]] + [c for c in candidates if flags[c["evidence_id"]]]

    return [{**{k: v for k, v in c.items() if k not in ("rank", "score", "bm25_rank", "suppressed")},
             "rank": r, "evidence_id": c["evidence_id"], "score": float(c["score"]), "bm25_rank": c["rank"], "suppressed": bool(flags[c["evidence_id"]])}
            for r, c in enumerate(ordered, start=1)]

def rule_inferred(candidates: list[dict[str, Any]], query_time: str, index: ChainIndex) -> tuple[list[dict[str, Any]], dict[str, str | None]]:
    flags, witnesses = {}, {}
    for c in candidates:
        sig, w = inferred_superseded(index.view[c["evidence_id"]], query_time, index)
        flags[c["evidence_id"]] = sig
        witnesses[c["evidence_id"]] = w
    return block_rerank(candidates, flags, "rule_inferred"), witnesses

def load_witness_ids(main_evidence_path: Path, cross_event_path: Path) -> tuple[set[str], set[str]]:
    main_ids = {json.loads(l)["evidence_id"] for l in main_evidence_path.open(encoding="utf-8")}
    cross_ids = {json.loads(l)["evidence_id"] for l in cross_event_path.open(encoding="utf-8")} if cross_event_path.exists() else set()
    return main_ids - cross_ids, cross_ids

def build_index(evidence_store: Path, main_evidence_path: Path, cross_event_path: Path) -> tuple[ChainIndex, set[str]]:
    witness_ids, cross_ids = load_witness_ids(main_evidence_path, cross_event_path)
    views = (narrow_view(json.loads(l)) for l in evidence_store.open(encoding="utf-8"))
    return ChainIndex(views, witness_ids), cross_ids

__all__ = ["ALLOWED_RULE_FIELDS", "chain_key", "narrow_view", "ChainIndex", "inferred_superseded", "block_rerank", "rule_inferred",
           "load_witness_ids", "build_index", "paths"]
