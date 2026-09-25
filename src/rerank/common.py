from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from src import paths
from src.evidence.build_corpus import load_retrieval_config
from src.retrieval.bm25_runner import evaluate, load_main_queries, oracle_rerank, tie_key

ALLOWED_CANDIDATE_FIELDS = ("evidence_id", "observed_from", "valid_from_censored", "evidence_text")

def load_rerank_config() -> dict[str, Any]:
    return yaml.safe_load((paths.PROJECT_ROOT / "config" / "rerank.yaml").read_text(encoding="utf-8"))

def tie_seed() -> int:
    return int(load_retrieval_config()["bm25"]["tie_break"]["seed"])

def load_pool(source_dir: Path, splits: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
    return {s: [json.loads(l) for l in (source_dir / f"{s}_top50.jsonl").open(encoding="utf-8")] for s in splits}

def load_candidate_meta(cfg_ret: dict[str, Any], needed_ids: set[str]) -> dict[str, dict[str, Any]]:
    meta: dict[str, dict[str, Any]] = {}
    with (paths.PROJECT_ROOT / cfg_ret["corpus"]["output"]).open(encoding="utf-8") as handle:
        for line in handle:
            d = json.loads(line)
            if d["evidence_id"] in needed_ids:
                meta[d["evidence_id"]] = {k: d[k] for k in ALLOWED_CANDIDATE_FIELDS}
    missing = needed_ids - set(meta)
    if missing:
        raise RuntimeError(f"{len(missing)} pool candidates missing from the corpus")
    return meta

def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)

def observed_age_days(observed_from: str, query_time: str) -> float:
    age = (parse_ts(query_time) - parse_ts(observed_from)).total_seconds() / 86400.0
    if age < 0:
        raise ValueError("candidate observed after query_time — visibility violation")
    return age

def rerank(candidates: list[dict[str, Any]], scores: dict[str, float], seed: int, query_id: str, method: str) -> list[dict[str, Any]]:
    ids = [c["evidence_id"] for c in candidates]
    if set(ids) != set(scores) or len(ids) != len(set(ids)):
        raise RuntimeError(f"{method}: candidate set changed (lost/added/duplicated)")
    order = sorted(candidates, key=lambda c: (-scores[c["evidence_id"]], tie_key(seed, query_id, c["evidence_id"])))
    out = [{"rank": r, "evidence_id": c["evidence_id"], "score": float(scores[c["evidence_id"]]), "bm25_rank": c["rank"],
            "label": c["label"], "relation": c["relation"], "class": c["class"]} for r, c in enumerate(order, start=1)]
    if [c["evidence_id"] for c in out] and set(c["evidence_id"] for c in out) != set(ids):
        raise RuntimeError(f"{method}: candidate loss after rerank")
    return out

def minmax(values: list[float]) -> list[float]:
    lo, hi = min(values), max(values)
    return [0.0 for _ in values] if hi - lo < 1e-12 else [(v - lo) / (hi - lo) for v in values]

def query_lookup(splits: Iterable[str], role: str) -> dict[str, dict[str, Any]]:
    q = load_main_queries(splits, role)
    return {row["query_id"]: row for rows in q.values() for row in rows}

def per_query_record(q: dict[str, Any], split: str, pool_row: dict[str, Any], method_lists: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    rec = {"query_id": q["query_id"], "split": split, "template": q["query_template_id"], "cve_id": q["cve_id"], "source_key": q["source_key"],
           "cvss_version": q["cvss_version"], "censored": q["valid_from_censored"], "n_candidates": len(pool_row["candidates"])}
    for name, ranked in method_lists.items():
        rec[name] = evaluate(ranked, q)
    rec["achievable"] = rec["bm25"]["target_in_top50"]
    return rec

def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path.stat().st_size

__all__ = ["load_rerank_config", "tie_seed", "load_pool", "load_candidate_meta", "observed_age_days", "rerank", "minmax", "query_lookup",
           "per_query_record", "write_jsonl", "evaluate", "oracle_rerank", "ALLOWED_CANDIDATE_FIELDS"]
