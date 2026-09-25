from __future__ import annotations

import hashlib
import json
import random
import time
from pathlib import Path
from typing import Any

import numpy as np

from src import paths
from src.rerank.common import rerank
from src.retrieval.dense_runner import hardware_report, sha256_file

MODEL_FILES = ["config.json", "model.safetensors", "pytorch_model.bin", "tokenizer.json", "tokenizer_config.json", "vocab.txt", "special_tokens_map.json"]

def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def cache_key(query_id: str, evidence_id: str, model_rev: str, tok_rev: str, max_length: int, transform: str, qtext: str, etext: str) -> str:
    raw = "|".join([query_id, evidence_id, model_rev, tok_rev, str(max_length), transform, text_hash(qtext), text_hash(etext)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

class CrossEncoder:
    def __init__(self, ccfg: dict[str, Any], device: str | None = None):
        import torch
        from huggingface_hub import snapshot_download
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.ccfg = ccfg
        random.seed(int(ccfg["seed"])); np.random.seed(int(ccfg["seed"])); torch.manual_seed(int(ccfg["seed"]))
        torch.backends.cuda.matmul.allow_tf32 = False
        torch.backends.cudnn.allow_tf32 = False
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
        local = Path(snapshot_download(ccfg["model"], revision=ccfg.get("revision") or None, allow_patterns=MODEL_FILES))
        self.local_dir = local
        self.revision = local.name if local.parent.name == "snapshots" else None
        if ccfg.get("revision") and self.revision != ccfg["revision"]:
            raise RuntimeError(f"pinned revision {ccfg['revision']} != resolved {self.revision}")
        self.file_hashes = {f: sha256_file(local / f) for f in MODEL_FILES if (local / f).exists()}
        self.tokenizer = AutoTokenizer.from_pretrained(local)
        self.model = AutoModelForSequenceClassification.from_pretrained(local, dtype=torch.float32)
        self.model.eval()
        for p in self.model.parameters():
            p.requires_grad_(False)
        self.n_params = int(sum(p.numel() for p in self.model.parameters()))
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.max_length = int(ccfg["max_length"])
        self.transform = ccfg["score_transformation"]
        assert self.transform == "raw_logit" and ccfg["dtype"] == "float32"
        assert self.model.config.num_labels == 1

    def score_pairs(self, pairs: list[tuple[str, str]], batch_size: int) -> tuple[np.ndarray, dict[str, Any]]:
        import torch

        out = np.empty(len(pairs), dtype=np.float32)
        truncated, batch_size = 0, int(batch_size)
        oom: list[dict[str, int]] = []
        while True:
            try:
                with torch.inference_mode():
                    for start in range(0, len(pairs), batch_size):
                        chunk = pairs[start:start + batch_size]
                        lens = self.tokenizer([q for q, _ in chunk], [e for _, e in chunk], padding=False, truncation=False)["input_ids"]
                        truncated += sum(1 for ids in lens if len(ids) > self.max_length)
                        enc = self.tokenizer([q for q, _ in chunk], [e for _, e in chunk], padding=True, truncation=True,
                                             max_length=self.max_length, return_tensors="pt").to(self.device)
                        logits = self.model(**enc).logits.squeeze(-1)
                        out[start:start + len(chunk)] = logits.float().cpu().numpy()
                break
            except torch.cuda.OutOfMemoryError:
                if batch_size <= 1:
                    raise
                torch.cuda.empty_cache()
                oom.append({"batch_size": batch_size, "new_batch_size": batch_size // 2})
                batch_size //= 2
                truncated = 0
        return out, {"pairs": len(pairs), "truncated": truncated, "batch_size_used": batch_size, "oom_events": oom}

class ScoreCache:

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.scores: dict[str, float] = {}
        if path.exists():
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        row = json.loads(line)
                        self.scores[row["key"]] = float(row["score"])
        self.loaded = len(self.scores)

    def append(self, rows: list[dict[str, Any]]) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
                self.scores[row["key"]] = float(row["score"])

def score_pool(ce: CrossEncoder, cache: ScoreCache, rows: list[dict[str, Any]], queries: dict[str, dict[str, Any]],
               meta: dict[str, dict[str, Any]], batch_size: int, flush_every: int = 2048) -> dict[str, Any]:
    tok_rev = ce.revision
    todo: list[tuple[str, str, str, str, str]] = []
    for r in rows:
        qtext = queries[r["query_id"]]["query_text"]
        for c in r["candidates"]:
            etext = meta[c["evidence_id"]]["evidence_text"]
            k = cache_key(r["query_id"], c["evidence_id"], ce.revision, tok_rev, ce.max_length, ce.transform, qtext, etext)
            if k not in cache.scores:
                todo.append((k, r["query_id"], c["evidence_id"], qtext, etext))
    t0 = time.perf_counter()
    truncated, batch_used, oom = 0, batch_size, []
    for start in range(0, len(todo), flush_every):
        chunk = todo[start:start + flush_every]
        scores, st = ce.score_pairs([(q, e) for _, _, _, q, e in chunk], batch_size)
        truncated += st["truncated"]; batch_used = st["batch_size_used"]; oom += st["oom_events"]
        cache.append([{"key": k, "query_id": qid, "evidence_id": eid, "score": float(s)} for (k, qid, eid, _, _), s in zip(chunk, scores)])
    return {"pairs_requested": sum(len(r["candidates"]) for r in rows), "pairs_scored_now": len(todo), "pairs_from_cache": sum(len(r["candidates"]) for r in rows) - len(todo),
            "truncated": truncated, "truncation_rate": round(truncated / max(1, len(todo)), 6) if todo else 0.0,
            "batch_size_used": batch_used, "oom_events": oom, "scoring_seconds": round(time.perf_counter() - t0, 1)}

def rerank_with_cache(ce: CrossEncoder, cache: ScoreCache, row: dict[str, Any], query: dict[str, Any], meta: dict[str, dict[str, Any]], seed: int) -> list[dict[str, Any]]:
    scores = {}
    for c in row["candidates"]:
        k = cache_key(row["query_id"], c["evidence_id"], ce.revision, ce.revision, ce.max_length, ce.transform, query["query_text"], meta[c["evidence_id"]]["evidence_text"])
        if k not in cache.scores:
            raise RuntimeError(f"missing cache entry for {row['query_id']} / {c['evidence_id']}")
        scores[c["evidence_id"]] = cache.scores[k]
    if any(not np.isfinite(v) for v in scores.values()):
        raise RuntimeError(f"NaN/inf cross-encoder score for {row['query_id']}")
    return rerank(row["candidates"], scores, seed, row["query_id"], "cross_encoder")

def determinism_check(ce: CrossEncoder, rows: list[dict[str, Any]], queries: dict[str, dict[str, Any]], meta: dict[str, dict[str, Any]],
                      batch_sizes: list[int], seed: int) -> dict[str, Any]:
    pairs, spans = [], []
    for r in rows:
        spans.append((len(pairs), len(pairs) + len(r["candidates"])))
        pairs += [(queries[r["query_id"]]["query_text"], meta[c["evidence_id"]]["evidence_text"]) for c in r["candidates"]]
    a, _ = ce.score_pairs(pairs, batch_sizes[0])
    b, _ = ce.score_pairs(pairs, batch_sizes[1])
    top10_same, top50_same = 0, 0
    for r, (s, e) in zip(rows, spans):
        la = rerank(r["candidates"], {c["evidence_id"]: float(a[s + i]) for i, c in enumerate(r["candidates"])}, seed, r["query_id"], "ce")
        lb = rerank(r["candidates"], {c["evidence_id"]: float(b[s + i]) for i, c in enumerate(r["candidates"])}, seed, r["query_id"], "ce")
        top50_same += set(c["evidence_id"] for c in la) == set(c["evidence_id"] for c in lb)
        top10_same += [c["evidence_id"] for c in la[:10]] == [c["evidence_id"] for c in lb[:10]]
    return {"queries": len(rows), "pairs": len(pairs), "batch_sizes": batch_sizes, "max_abs_score_diff": float(np.abs(a - b).max()),
            "top50_set_identical": top50_same, "top10_order_identical": top10_same}

def manifest(ce: CrossEncoder, ccfg: dict[str, Any], cache: ScoreCache, extra: dict[str, Any]) -> dict[str, Any]:
    return {"model": {"name": ccfg["model"], "revision": ce.revision, "tokenizer_revision": ce.revision, "local_dir": str(ce.local_dir),
                      "file_sha256": ce.file_hashes, "n_params": ce.n_params, "max_length": ce.max_length, "score_transformation": ce.transform,
                      "dtype": ccfg["dtype"], "input": ccfg["input"], "license": "Apache-2.0"},
            "environment": hardware_report(), "device": ce.device, "seed": int(ccfg["seed"]),
            "cache": {"file": paths.relative_to_project(cache.path), "entries": len(cache.scores), "bytes": cache.path.stat().st_size if cache.path.exists() else 0,
                      "key": ccfg["cache_key"]}, **extra}

__all__ = ["CrossEncoder", "ScoreCache", "cache_key", "text_hash", "score_pool", "rerank_with_cache", "determinism_check", "manifest"]
