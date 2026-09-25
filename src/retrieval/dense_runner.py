from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import time
from pathlib import Path
from typing import Any

import numpy as np

from src import paths
from src.retrieval.bm25_runner import classify_candidate, tie_key
from src.label import query_time_labels as L

MODEL_FILES = ["config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json", "vocab.txt", "special_tokens_map.json"]

def hardware_report() -> dict[str, Any]:
    import psutil
    import torch

    rep: dict[str, Any] = {"platform": platform.platform(), "python": platform.python_version(),
                           "cpu_count": os.cpu_count(), "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
                           "torch": torch.__version__, "cuda_available": torch.cuda.is_available(), "torch_cuda": torch.version.cuda}
    if torch.cuda.is_available():
        p = torch.cuda.get_device_properties(0)
        rep.update({"gpu": p.name, "vram_gb": round(p.total_memory / 2**30, 1), "gpu_count": torch.cuda.device_count()})
    try:
        import transformers
        rep["transformers"] = transformers.__version__
    except ImportError:
        rep["transformers"] = None
    return rep

def set_deterministic(seed: int) -> None:
    import torch

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

class Encoder:

    def __init__(self, dcfg: dict[str, Any], device: str | None = None):
        import torch
        from huggingface_hub import snapshot_download
        from transformers import AutoModel, AutoTokenizer

        self.dcfg = dcfg
        set_deterministic(int(dcfg["seed"]))

        local = Path(snapshot_download(dcfg["model"], revision=dcfg.get("revision") or None, allow_patterns=MODEL_FILES))
        self.local_dir = local
        self.revision = local.name if local.parent.name == "snapshots" else None
        if dcfg.get("revision") and self.revision != dcfg["revision"]:
            raise RuntimeError(f"pinned revision {dcfg['revision']} != resolved {self.revision}")
        self.file_hashes = {f: sha256_file(local / f) for f in MODEL_FILES if (local / f).exists()}
        self.tokenizer = AutoTokenizer.from_pretrained(local)
        self.model = AutoModel.from_pretrained(local, dtype=torch.float32)
        self.model.eval()
        for p in self.model.parameters():
            p.requires_grad_(False)
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.max_length = int(dcfg["max_length"])
        self.dim = int(self.model.config.hidden_size)
        assert dcfg["pooling"] == "mean" and dcfg["normalize"] == "l2" and dcfg["dtype"] == "float32"

    def encode(self, texts: list[str], batch_size: int, prefix: str = "") -> tuple[np.ndarray, dict[str, Any]]:
        import torch

        out = np.empty((len(texts), self.dim), dtype=np.float32)
        truncated = 0
        token_lengths: list[int] = []
        batch_size = int(batch_size)
        while True:
            try:
                with torch.inference_mode():
                    for start in range(0, len(texts), batch_size):
                        chunk = [prefix + t for t in texts[start:start + batch_size]]
                        full = self.tokenizer(chunk, padding=False, truncation=False, add_special_tokens=True)["input_ids"]
                        lens = [len(ids) for ids in full]
                        token_lengths.extend(lens)
                        truncated += sum(1 for n in lens if n > self.max_length)
                        enc = self.tokenizer(chunk, padding=True, truncation=True, max_length=self.max_length, return_tensors="pt").to(self.device)
                        hidden = self.model(**enc).last_hidden_state
                        mask = enc["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                        pooled = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
                        pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
                        out[start:start + len(chunk)] = pooled.float().cpu().numpy()
                break
            except torch.cuda.OutOfMemoryError:
                if batch_size <= 1:
                    raise
                torch.cuda.empty_cache()
                self.oom_events = getattr(self, "oom_events", []) + [{"batch_size": batch_size, "new_batch_size": batch_size // 2}]
                batch_size //= 2
                truncated, token_lengths = 0, []
        stats = {"texts": len(texts), "truncated": truncated, "truncation_rate": round(truncated / max(1, len(texts)), 6),
                 "max_tokens": max(token_lengths) if token_lengths else 0,
                 "mean_tokens": round(float(np.mean(token_lengths)), 1) if token_lengths else 0.0,
                 "batch_size_used": batch_size, "oom_events": getattr(self, "oom_events", [])}
        return out, stats

def load_corpus(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    return [json.loads(l) for l in (paths.PROJECT_ROOT / cfg["corpus"]["output"]).open(encoding="utf-8")]

def build_doc_embeddings(cfg: dict[str, Any], corpus: list[dict[str, Any]], encoder: Encoder, force: bool = False) -> dict[str, Any]:
    import torch

    dcfg = cfg["dense"]
    emb_dir = paths.PROJECT_ROOT / dcfg["embeddings_dir"]
    emb_dir.mkdir(parents=True, exist_ok=True)
    man_path = emb_dir / "manifest.json"
    if man_path.exists() and not force:
        man = json.loads(man_path.read_text(encoding="utf-8"))
        if man["model"]["revision"] == encoder.revision and man["n_docs"] == len(corpus):
            return man
    ids = [d["evidence_id"] for d in corpus]
    texts = [d[dcfg["doc_input"]] for d in corpus]
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()
    t0 = time.perf_counter()
    emb, stats = encoder.encode(texts, int(dcfg["batch_size"]), prefix=dcfg["doc_prefix"])
    t_embed = time.perf_counter() - t0
    np.save(emb_dir / "embeddings.npy", emb)
    (emb_dir / "ids.json").write_text(json.dumps(ids), encoding="utf-8")
    man = {
        "model": {"name": dcfg["model"], "revision": encoder.revision, "local_dir": str(encoder.local_dir), "file_sha256": encoder.file_hashes,
                  "hidden_size": encoder.dim, "pooling": dcfg["pooling"], "normalize": dcfg["normalize"], "similarity": dcfg["similarity"],
                  "max_length": encoder.max_length, "query_prefix": dcfg["query_prefix"], "doc_prefix": dcfg["doc_prefix"], "dtype": dcfg["dtype"]},
        "environment": hardware_report(), "device": encoder.device, "seed": int(dcfg["seed"]),
        "n_docs": len(corpus), "embedding_shape": list(emb.shape), "embedding_dtype": str(emb.dtype),
        "embedding_file": paths.relative_to_project(emb_dir / "embeddings.npy"), "embedding_bytes": (emb_dir / "embeddings.npy").stat().st_size,
        "embedding_sha256": sha256_file(emb_dir / "embeddings.npy"), "ids_file": paths.relative_to_project(emb_dir / "ids.json"),
        "doc_stats": stats, "nan_or_inf": int((~np.isfinite(emb)).sum()),
        "norm_min_max": [float(np.linalg.norm(emb, axis=1).min()), float(np.linalg.norm(emb, axis=1).max())],
        "embed_seconds": round(t_embed, 1),
        "peak_gpu_memory_gb": round(torch.cuda.max_memory_allocated() / 2**30, 3) if torch.cuda.is_available() else None,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    man_path.write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return man

def reproducibility_checks(encoder: Encoder, corpus: list[dict[str, Any]], emb: np.ndarray, dcfg: dict[str, Any], n: int = 512) -> dict[str, Any]:
    rng = random.Random(int(dcfg["seed"]))
    rows = sorted(rng.sample(range(len(corpus)), min(n, len(corpus))))
    texts = [corpus[i][dcfg["doc_input"]] for i in rows]
    a, _ = encoder.encode(texts, int(dcfg["batch_size"]), prefix=dcfg["doc_prefix"])
    b, _ = encoder.encode(texts, 8, prefix=dcfg["doc_prefix"])
    return {"sample_rows": len(rows), "max_abs_diff_cached_vs_reencode": float(np.abs(a - emb[rows]).max()),
            "max_abs_diff_batch128_vs_batch8": float(np.abs(a - b).max()),
            "ids_match_corpus_order": json.loads((paths.PROJECT_ROOT / dcfg["embeddings_dir"] / "ids.json").read_text(encoding="utf-8"))
            == [d["evidence_id"] for d in corpus]}

class DenseIndex:
    def __init__(self, cfg: dict[str, Any], corpus: list[dict[str, Any]], device: str):
        import torch

        dcfg = cfg["dense"]
        emb_dir = paths.PROJECT_ROOT / dcfg["embeddings_dir"]
        ids = json.loads((emb_dir / "ids.json").read_text(encoding="utf-8"))
        if ids != [d["evidence_id"] for d in corpus]:
            raise RuntimeError("ids.json does not match the corpus order")
        self.emb = np.load(emb_dir / "embeddings.npy", mmap_mode="r")
        if self.emb.shape[0] != len(corpus):
            raise RuntimeError("embedding rows != corpus size")
        self.corpus = corpus
        self.observed = np.array([d["observed_from"] for d in corpus])
        self.device = device

        self.D = torch.from_numpy(np.array(self.emb, dtype=np.float32, copy=True)).to(device)
        self.seed = int(cfg["bm25"]["tie_break"]["seed"])

    def rank_batch(self, queries: list[dict[str, Any]], q_emb: np.ndarray, top_k: int) -> list[tuple[list[dict[str, Any]], int]]:
        import torch

        Q = torch.from_numpy(q_emb).to(self.device)
        S = (Q @ self.D.T).cpu().numpy().astype(np.float64)
        results = []
        for row, q in enumerate(queries):
            scores = S[row]
            visible = self.observed <= q["query_time"]
            scores = np.where(visible, scores, -np.inf)
            n_visible = int(visible.sum())
            if n_visible == 0:
                results.append(([], 0))
                continue
            k = min(top_k, n_visible)
            part = np.argpartition(-scores, k - 1)[:k]
            threshold = scores[part].min()
            cand = np.flatnonzero(scores >= threshold)
            query = L.Query(cve_id=q["cve_id"], source_key=q["source_key"], cvss_version=q["cvss_version"], query_time=q["query_time"])
            ordered = sorted(cand.tolist(), key=lambda i: (-scores[i], tie_key(self.seed, q["query_id"], self.corpus[i]["evidence_id"])))[:top_k]
            ranked = []
            for rank, i in enumerate(ordered, start=1):
                doc = self.corpus[i]
                lbl, rel, cls = classify_candidate(doc, query)
                ranked.append({"rank": rank, "evidence_id": doc["evidence_id"], "score": float(scores[i]), "label": lbl, "relation": rel, "class": cls})
            results.append((ranked, n_visible))
        return results

def rrf_fuse(lists: dict[str, list[dict[str, Any]]], k: int, seed: int, query_id: str, top_k: int) -> list[dict[str, Any]]:
    scores: dict[str, float] = {}
    meta: dict[str, dict[str, Any]] = {}
    ranks: dict[str, dict[str, int]] = {}
    for name, ranked in lists.items():
        for c in ranked:
            eid = c["evidence_id"]
            scores[eid] = scores.get(eid, 0.0) + 1.0 / (k + c["rank"])
            ranks.setdefault(eid, {})[name] = c["rank"]
            meta.setdefault(eid, {"evidence_id": eid, "label": c["label"], "relation": c["relation"], "class": c["class"]})
    order = sorted(scores, key=lambda e: (-scores[e], tie_key(seed, query_id, e)))[:top_k]
    return [{"rank": r, **meta[e], "score": scores[e], "input_ranks": ranks[e]} for r, e in enumerate(order, start=1)]

def load_lists(path: Path) -> dict[str, dict[str, Any]]:
    return {row["query_id"]: row for row in (json.loads(l) for l in path.open(encoding="utf-8"))}

__all__ = ["Encoder", "DenseIndex", "build_doc_embeddings", "reproducibility_checks", "rrf_fuse", "load_corpus", "load_lists",
           "hardware_report", "set_deterministic", "sha256_file", "MODEL_FILES"]
