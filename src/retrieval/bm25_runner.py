from __future__ import annotations

import hashlib
import json
import pickle
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from rank_bm25 import BM25Okapi

from src import paths
from src.eval import metrics as M
from src.evidence.build_corpus import load_retrieval_config
from src.label import query_time_labels as L

TOKEN_RE = re.compile(r"[^a-z0-9.:@\-]+")
ORACLES = {
    "current_first": {"TARGET_CURRENT": 0, "OTHER_SOURCE_CURRENT": 1, "TARGET_OUTDATED": 2, "OTHER": 3},
    "temporal": {"TARGET_CURRENT": 0, "OTHER_SOURCE_CURRENT": 1, "OTHER": 2, "TARGET_OUTDATED": 3},
}

def tokenize(text: str) -> list[str]:
    text = text.lower().replace("/", " ")
    return [t.strip(".:-") for t in TOKEN_RE.split(text) if t.strip(".:-")]

def doc_tokens(doc: dict[str, Any], fields: dict[str, list[str]]) -> list[str]:
    identity = " ".join(str(doc[f]) for f in fields["identity"])
    content = " ".join(str(doc[f]) for f in fields["content"])
    return tokenize(identity + " " + content)

def query_tokens(q: dict[str, Any]) -> list[str]:
    return tokenize(f"{q['cve_id']} {q['source_key']} {q['cvss_version']} {q['query_text']}")

def tie_key(seed: int, query_id: str, evidence_id: str) -> str:
    return hashlib.sha256(f"{seed}|{query_id}|{evidence_id}".encode("utf-8")).hexdigest()

class Bm25Index:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.bcfg = cfg["bm25"]
        t0 = time.perf_counter()
        self.corpus = [json.loads(l) for l in (paths.PROJECT_ROOT / cfg["corpus"]["output"]).open(encoding="utf-8")]
        self.observed = np.array([d["observed_from"] for d in self.corpus])
        self.t_load = time.perf_counter() - t0
        t1 = time.perf_counter()
        tokenized = [doc_tokens(d, self.bcfg["fields"]) for d in self.corpus]
        self.bm25 = BM25Okapi(tokenized, k1=float(self.bcfg["k1"]), b=float(self.bcfg["b"]), epsilon=float(self.bcfg["epsilon"]))
        self.t_index = time.perf_counter() - t1

    def save(self, path: Path) -> int:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            pickle.dump({"config": self.bcfg, "doc_ids": [d["evidence_id"] for d in self.corpus], "bm25": self.bm25}, handle,
                        protocol=pickle.HIGHEST_PROTOCOL)
        return path.stat().st_size

    def rank(self, q: dict[str, Any], top_k: int, seed: int) -> tuple[list[dict[str, Any]], int]:
        scores = self.bm25.get_scores(query_tokens(q))
        visible = self.observed <= q["query_time"]
        scores = np.where(visible, scores, -np.inf)
        n_visible = int(visible.sum())
        if n_visible == 0:
            return [], 0
        k = min(top_k, n_visible)
        part = np.argpartition(-scores, k - 1)[:k]
        threshold = scores[part].min()

        cand = np.flatnonzero(scores >= threshold)
        query = L.Query(cve_id=q["cve_id"], source_key=q["source_key"], cvss_version=q["cvss_version"], query_time=q["query_time"])
        ordered = sorted(cand.tolist(), key=lambda i: (-scores[i], tie_key(seed, q["query_id"], self.corpus[i]["evidence_id"])))[:top_k]
        ranked = []
        for rank, i in enumerate(ordered, start=1):
            doc = self.corpus[i]
            lbl, rel, cls = classify_candidate(doc, query)
            ranked.append({"rank": rank, "evidence_id": doc["evidence_id"], "score": float(scores[i]),
                           "label": lbl, "relation": rel, "class": cls})
        return ranked, n_visible

def classify_candidate(doc: dict[str, Any], q: L.Query) -> tuple[str, str, str]:
    lbl = L.label(doc, q)
    rel = L.source_relation(doc, q)
    if lbl == L.CURRENT and rel == L.TARGET_SOURCE:
        cls = "TARGET_CURRENT"
    elif rel == L.OTHER_SOURCE_CURRENT:
        cls = "OTHER_SOURCE_CURRENT"
    elif lbl == L.OUTDATED:
        cls = "TARGET_OUTDATED"
    else:
        cls = "OTHER"
    return lbl, rel, cls

def oracle_rerank(ranked: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    order = ORACLES[kind]
    return sorted(ranked, key=lambda c: (order[c["class"]], c["rank"]))

def evaluate(ranked: list[dict[str, Any]], q: dict[str, Any], k: int = 10) -> dict[str, Any]:
    labels = [c["label"] for c in ranked]
    rels = [c["relation"] for c in ranked]
    binary = [M.relevance(lb, r) for lb, r in zip(labels, rels)]
    graded = [M.relevance(lb, r, graded=True) for lb, r in zip(labels, rels)]
    all_current = q["current_evidence_ids"]
    retrieved_current = [c["evidence_id"] for c in ranked if c["class"] == "TARGET_CURRENT"]
    top_ids = [c["evidence_id"] for c in ranked]
    return {
        "ndcg@10": M.ndcg_at_k(binary, [1] * len(all_current), k),
        "ndcg@10_graded": M.ndcg_at_k(graded, [2] * len(all_current) + [1] * len(q["other_source_current_evidence_ids"]), k),
        "mrr@10": M.mrr_at_k(binary, k),
        "recall@10": M.recall_at_k(retrieved_current, all_current, k),
        "recall@50": M.recall_at_k(retrieved_current, all_current, 50),
        "stale@10": M.stale_rate_at_k(labels, k),
        "target_in_top50": any(i in all_current for i in top_ids[:50]),
        "target_in_top10": any(i in all_current for i in top_ids[:10]),
        "outdated_in_top50": any(c["class"] == "TARGET_OUTDATED" for c in ranked[:50]),
        "outdated_in_top10": any(c["class"] == "TARGET_OUTDATED" for c in ranked[:10]),
        "other_source_current_in_top50": any(c["class"] == "OTHER_SOURCE_CURRENT" for c in ranked[:50]),
        "other_source_current_in_top10": any(c["class"] == "OTHER_SOURCE_CURRENT" for c in ranked[:10]),
        "top1_current": bool(ranked) and ranked[0]["class"] == "TARGET_CURRENT",
        "top1_outdated": bool(ranked) and ranked[0]["class"] == "TARGET_OUTDATED",
        "current_outdated_score_tie": _tie(ranked),
        "current_outdated_score_gap": _gap(ranked),
    }

def _tie(ranked: list[dict[str, Any]]) -> bool | None:
    cur = next((c for c in ranked if c["class"] == "TARGET_CURRENT"), None)
    out = next((c for c in ranked if c["class"] == "TARGET_OUTDATED"), None)
    if cur is None or out is None:
        return None
    return abs(cur["score"] - out["score"]) < 1e-9

def _gap(ranked: list[dict[str, Any]]) -> float | None:
    cur = next((c for c in ranked if c["class"] == "TARGET_CURRENT"), None)
    out = next((c for c in ranked if c["class"] == "TARGET_OUTDATED"), None)
    if cur is None or out is None:
        return None
    return cur["score"] - out["score"]

def summarize(per_query: list[dict[str, Any]], key: str) -> dict[str, Any]:
    rows = [p[key] for p in per_query]
    if not rows:
        return {}
    return {
        "queries": len(rows),
        "recall@10": M.mean(r["recall@10"] for r in rows),
        "recall@50": M.mean(r["recall@50"] for r in rows),
        "mrr@10": M.mean(r["mrr@10"] for r in rows),
        "ndcg@10": M.mean(r["ndcg@10"] for r in rows),
        "ndcg@10_graded": M.mean(r["ndcg@10_graded"] for r in rows),
        "stale@10": M.mean(r["stale@10"] for r in rows),
        "retrieval_failure_rate": M.mean(0.0 if r["target_in_top50"] else 1.0 for r in rows),
        "ranking_failure_rate": M.mean(1.0 if (r["target_in_top50"] and not r["target_in_top10"]) else 0.0 for r in rows),
        "outdated_same_chain_in_top50": M.mean(1.0 if r["outdated_in_top50"] else 0.0 for r in rows),
        "outdated_same_chain_in_top10": M.mean(1.0 if r["outdated_in_top10"] else 0.0 for r in rows),
        "current_and_outdated_in_top50": M.mean(1.0 if (r["target_in_top50"] and r["outdated_in_top50"]) else 0.0 for r in rows),
        "other_source_current_in_top50": M.mean(1.0 if r["other_source_current_in_top50"] else 0.0 for r in rows),
        "current_and_outdated_in_top10": M.mean(1.0 if (r["target_in_top10"] and r["outdated_in_top10"]) else 0.0 for r in rows),
        "other_source_current_in_top10": M.mean(1.0 if r.get("other_source_current_in_top10") else 0.0 for r in rows),
        "top1_current_rate": M.mean(1.0 if r["top1_current"] else 0.0 for r in rows),
        "top1_outdated_rate": M.mean(1.0 if r["top1_outdated"] else 0.0 for r in rows),
        "current_outdated_score_tie_rate": M.mean(1.0 if r["current_outdated_score_tie"] else 0.0 for r in rows if r["current_outdated_score_tie"] is not None),
        "current_outdated_mean_score_gap": M.mean(r["current_outdated_score_gap"] for r in rows if r.get("current_outdated_score_gap") is not None),
        "current_outdated_both_in_list": sum(1 for r in rows if r.get("current_outdated_score_gap") is not None),
    }

def run_queries(index: Bm25Index, queries: dict[str, list[dict]], out_dir: Path, seed: int, top_k: int,
                filename: str = "{split}_top50.jsonl") -> tuple[list[dict[str, Any]], float]:
    out_dir.mkdir(parents=True, exist_ok=True)
    per_query: list[dict[str, Any]] = []
    t0 = time.perf_counter()
    for split, qs in queries.items():
        with (out_dir / filename.format(split=split)).open("w", encoding="utf-8") as handle:
            for q in qs:
                ranked, n_visible = index.rank(q, top_k, seed)
                rec = {"query_id": q["query_id"], "split": split, "template": q["query_template_id"], "cve_id": q["cve_id"],
                       "source_key": q["source_key"], "cvss_version": q["cvss_version"], "censored": q["valid_from_censored"],
                       "n_visible": n_visible, "bm25": evaluate(ranked, q),
                       "oracle_current_first": evaluate(oracle_rerank(ranked, "current_first"), q),
                       "oracle_temporal": evaluate(oracle_rerank(ranked, "temporal"), q)}
                rec["achievable"] = rec["bm25"]["target_in_top50"]
                per_query.append(rec)
                handle.write(json.dumps({"query_id": q["query_id"], "split": split, "query_time": q["query_time"],
                                         "current_evidence_ids": q["current_evidence_ids"], "outdated_evidence_ids": q["outdated_evidence_ids"],
                                         "candidates": ranked}, ensure_ascii=False) + "\n")
    return per_query, time.perf_counter() - t0

def source_group(source_key: str, groups: dict[str, Any] | None) -> str:
    if not groups:
        return source_key
    return source_key if source_key in groups["named"] else groups["other"]

def report(per_query: list[dict[str, Any]], keys: Iterable[str] = ("bm25", "oracle_current_first", "oracle_temporal"),
           source_groups: dict[str, Any] | None = None) -> dict[str, Any]:
    splits = sorted({p["split"] for p in per_query})
    templates = sorted({p["template"] for p in per_query})
    out: dict[str, Any] = {"queries_total": len(per_query),
                           "achievable_rate": M.mean(1.0 if p["achievable"] else 0.0 for p in per_query),
                           "mean_visible_docs_by_split": {s: round(float(np.mean([p.get("n_visible", p.get("n_candidates", 0)) for p in per_query if p["split"] == s])), 1) for s in splits}}
    for key in keys:
        out[key] = {"all": summarize(per_query, key),
                    "by_split": {s: summarize([p for p in per_query if p["split"] == s], key) for s in splits},
                    "by_template": {t: summarize([p for p in per_query if p["template"] == t], key) for t in templates},
                    "by_censored": {str(c): summarize([p for p in per_query if p["censored"] == c], key) for c in (False, True)},
                    "by_version": {v: summarize([p for p in per_query if p["cvss_version"] == v], key) for v in sorted({p["cvss_version"] for p in per_query})}}
        if source_groups:
            groups = sorted({source_group(p["source_key"], source_groups) for p in per_query})
            out[key]["by_source_group"] = {g: summarize([p for p in per_query if source_group(p["source_key"], source_groups) == g], key) for g in groups}
    return out

def load_main_queries(splits: Iterable[str], role: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for split in splits:
        rows = [json.loads(l) for l in (paths.PROCESSED_DATA_DIR / "queries" / f"{split}_queries.jsonl").open(encoding="utf-8")]
        out[split] = [q for q in rows if q["query_role"] == role]
    return out

def sample_cve_level(queries: dict[str, list[dict]], per_split: int, seed: int) -> dict[str, list[dict]]:
    import random

    rng = random.Random(seed)
    out: dict[str, list[dict]] = {}
    for split, qs in queries.items():
        by_cve: defaultdict[str, list[dict]] = defaultdict(list)
        for q in qs:
            by_cve[q["cve_id"]].append(q)
        chosen = rng.sample(sorted(by_cve), min(per_split, len(by_cve)))
        out[split] = [min(by_cve[c], key=lambda q: q["query_id"]) for c in sorted(chosen)]
    return out

__all__ = ["Bm25Index", "source_group", "tokenize", "query_tokens", "tie_key", "classify_candidate", "oracle_rerank", "evaluate",
           "summarize", "run_queries", "report", "load_main_queries", "sample_cve_level", "load_retrieval_config", "ORACLES"]
