from __future__ import annotations

import json

import pytest

from src import paths
from src.evidence.build_corpus import load_retrieval_config
from src.retrieval import dense_runner as D
from src.retrieval.bm25_runner import tie_key

CFG = load_retrieval_config()

def _c(rank, eid, cls="OTHER", label="NOT_TARGET_CHAIN", rel="OTHER_CVE"):
    return {"rank": rank, "evidence_id": eid, "score": 1.0 / rank, "label": label, "relation": rel, "class": cls}

@pytest.mark.unit
def test_rrf_formula_and_missing_list_contribution():
    bm25 = [_c(1, "a"), _c(2, "b"), _c(3, "c")]
    dense = [_c(1, "b"), _c(2, "d")]
    fused = D.rrf_fuse({"bm25": bm25, "dense": dense}, 60, 1, "q", 10)
    by = {c["evidence_id"]: c for c in fused}
    assert by["b"]["score"] == pytest.approx(1 / 62 + 1 / 61)
    assert by["a"]["score"] == pytest.approx(1 / 61) and by["d"]["score"] == pytest.approx(1 / 62)
    assert by["c"]["score"] == pytest.approx(1 / 63)
    assert [c["evidence_id"] for c in fused] == ["b", "a", "d", "c"]
    assert by["b"]["input_ranks"] == {"bm25": 2, "dense": 1} and by["a"]["input_ranks"] == {"bm25": 1}
    assert [c["rank"] for c in fused] == [1, 2, 3, 4]

@pytest.mark.unit
def test_rrf_ties_use_time_blind_hash_not_labels():

    bm25 = [_c(1, "cur", "TARGET_CURRENT", "CURRENT", "TARGET_SOURCE"), _c(2, "old", "TARGET_OUTDATED", "OUTDATED", "TARGET_SOURCE")]
    dense = [_c(1, "old", "TARGET_OUTDATED", "OUTDATED", "TARGET_SOURCE"), _c(2, "cur", "TARGET_CURRENT", "CURRENT", "TARGET_SOURCE")]
    fused = D.rrf_fuse({"bm25": bm25, "dense": dense}, 60, 5, "qx", 10)
    assert fused[0]["score"] == pytest.approx(fused[1]["score"])
    expected = sorted(["cur", "old"], key=lambda e: tie_key(5, "qx", e))
    assert [c["evidence_id"] for c in fused] == expected
    assert D.rrf_fuse({"bm25": bm25, "dense": dense}, 60, 5, "qx", 1)[0]["evidence_id"] == expected[0]

@pytest.mark.unit
def test_config_fixed_single_setting():
    d, h = CFG["dense"], CFG["hybrid"]
    assert d["model"] == "BAAI/bge-base-en-v1.5" and d["pooling"] == "mean" and d["normalize"] == "l2" and d["similarity"] == "inner_product"
    assert d["query_prefix"] == "Represent this sentence for searching relevant passages: " and d["doc_prefix"] == ""
    assert d["max_length"] == 512 and d["dtype"] == "float32" and d["candidates_top_k"] == 100 and d["eval_top_k"] == 50
    assert h["method"] == "rrf" and h["rrf_k"] == 60 and h["output_top_k"] == 50 and h["inputs"] == ["bm25_top100", "dense_top100"]

@pytest.mark.unit
def test_sha256_file_and_model_file_list(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"chronorank")
    import hashlib
    assert D.sha256_file(p) == hashlib.sha256(b"chronorank").hexdigest()
    assert "model.safetensors" in D.MODEL_FILES and "pytorch_model.bin" not in D.MODEL_FILES

@pytest.mark.full_data
def test_smoke_dense_hybrid_artifacts():
    rep_path = paths.PROJECT_ROOT / CFG["dense"]["smoke_output_dir"] / "report.json"
    if not rep_path.exists():
        pytest.skip("dense/hybrid smoke çıktısı yok")
    rep = json.loads(rep_path.read_text(encoding="utf-8"))
    assert rep["queries_total"] == 300 and rep["gates"]["all_passed"]
    assert rep["checks"]["visibility_violations"] == 0 and rep["checks"]["duplicate_results"] == 0 and rep["checks"]["nan_or_inf_scores"] == 0
    assert rep["embedding_manifest"]["n_docs"] == rep["corpus_docs"] and rep["embedding_manifest"]["nan_or_inf"] == 0
    assert rep["embedding_manifest"]["model"]["revision"] and rep["embedding_manifest"]["model"]["file_sha256"]["model.safetensors"]

    acc = json.loads((paths.PROJECT_ROOT / CFG["smoke_test"]["output_dir"] / "smoke_report.json").read_text(encoding="utf-8"))
    for m in ("recall@10", "recall@50", "mrr@10", "ndcg@10", "stale@10", "top1_current_rate", "current_outdated_score_tie_rate"):
        assert rep["bm25"]["all"][m] == acc["bm25"]["all"][m], m
    for m in ("ndcg@10", "mrr@10"):
        assert rep["hybrid_oracle_current_first"]["all"][m] >= rep["hybrid"]["all"][m]
    assert rep["hybrid_oracle_temporal"]["all"]["stale@10"] <= rep["hybrid"]["all"]["stale@10"]

@pytest.mark.full_data
def test_full_dense_hybrid_artifacts():
    rep_path = paths.PROJECT_ROOT / CFG["hybrid"]["output_dir"] / "dense_hybrid_report.json"
    if not rep_path.exists():
        pytest.skip("dense/hybrid tam koşu çıktısı yok")
    rep = json.loads(rep_path.read_text(encoding="utf-8"))
    assert rep["main"]["queries_total"] == 3537 and rep["future_event_descriptive"]["queries_total"] == 19
    assert rep["main_run"]["checks"]["visibility_violations"] == 0 and rep["main_run"]["checks"]["missing_queries"] == []
    acc = json.loads((paths.PROJECT_ROOT / CFG["full_run"]["output_dir"] / "bm25_report.json").read_text(encoding="utf-8"))
    for m in ("recall@10", "recall@50", "mrr@10", "ndcg@10", "stale@10", "top1_current_rate", "top1_outdated_rate", "current_outdated_score_tie_rate",
              "current_and_outdated_in_top50"):
        assert rep["main"]["bm25"]["all"][m] == acc["main"]["bm25"]["all"][m], m

@pytest.mark.unit
def test_memmap_copy_is_identical_and_writable(tmp_path):
    import warnings
    import numpy as np
    import torch

    arr = np.random.default_rng(0).standard_normal((7, 4)).astype(np.float32)
    np.save(tmp_path / "e.npy", arr)
    mm = np.load(tmp_path / "e.npy", mmap_mode="r")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        t = torch.from_numpy(np.array(mm, dtype=np.float32, copy=True))
    assert t.numpy().flags.writeable and np.array_equal(t.numpy(), arr) and np.array_equal(np.asarray(mm), arr)

@pytest.mark.full_data
def test_dense_index_reproduces_stored_lists_spot_check():
    pytest.importorskip("torch")
    from src.retrieval.bm25_runner import load_main_queries

    dense_dir = paths.PROJECT_ROOT / CFG["dense"]["output_dir"]
    if not (dense_dir / "dev_top100.jsonl").exists():
        pytest.skip("dense tam koşu çıktısı yok")
    stored = [json.loads(l) for l in (dense_dir / "dev_top100.jsonl").open(encoding="utf-8")][:3]
    qs = {q["query_id"]: q for q in load_main_queries(["dev"], CFG["full_run"]["role"])["dev"]}
    queries = [qs[r["query_id"]] for r in stored]
    corpus = D.load_corpus(CFG)
    enc = D.Encoder(CFG["dense"])
    index = D.DenseIndex(CFG, corpus, enc.device)
    q_emb, _ = enc.encode([q["query_text"] for q in queries], 8, prefix=CFG["dense"]["query_prefix"])
    tol = 1e-5
    for row, (ranked, _) in zip(stored, index.rank_batch(queries, q_emb, int(CFG["dense"]["candidates_top_k"]))):
        got = {c["evidence_id"]: c["score"] for c in ranked}
        exp = {c["evidence_id"]: c["score"] for c in row["candidates"]}
        assert set(got) == set(exp)
        assert max(abs(got[i] - exp[i]) for i in exp) < tol
        exp_rank = {c["evidence_id"]: c["rank"] for c in row["candidates"]}
        for c in ranked:
            if c["rank"] != exp_rank[c["evidence_id"]]:
                other = row["candidates"][c["rank"] - 1]
                assert abs(other["score"] - exp[c["evidence_id"]]) < tol
