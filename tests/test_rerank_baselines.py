from __future__ import annotations

import inspect
import json

import pytest

from src import paths
from src.rerank import common as C
from src.rerank import cross_encoder as CE
from src.rerank import recency as R

CFG = C.load_rerank_config()
SEED = 7

def _cands(n=50, cur_rank=2):
    out = []
    for i in range(1, n + 1):
        cls = "TARGET_CURRENT" if i == cur_rank else ("TARGET_OUTDATED" if i == 1 else "OTHER")
        lbl = "CURRENT" if cls == "TARGET_CURRENT" else ("OUTDATED" if cls == "TARGET_OUTDATED" else "NOT_TARGET_CHAIN")
        out.append({"rank": i, "evidence_id": f"CVE-1|3.1|NVD|{i}", "score": 60.0 - (0.0 if i <= 2 else i), "label": lbl,
                    "relation": "TARGET_SOURCE" if i <= 2 else "OTHER_CVE", "class": cls})
    return out

def _meta(cands, newest="CVE-1|3.1|NVD|2"):
    return {c["evidence_id"]: {"evidence_id": c["evidence_id"], "observed_from": "2024-06-01T00:00:00+00:00" if c["evidence_id"] == newest else "2024-01-15T00:00:00+00:00",
                               "valid_from_censored": False, "evidence_text": f"text {c['evidence_id']}"} for c in cands}

@pytest.mark.unit
def test_rerank_keeps_exact_candidate_set_and_hash_ties():
    cands = _cands()
    scores = {c["evidence_id"]: 1.0 for c in cands}
    out = C.rerank(cands, scores, SEED, "q", "x")
    assert [c["evidence_id"] for c in out] == sorted((c["evidence_id"] for c in cands), key=lambda e: C.tie_key(SEED, "q", e))
    assert [c["rank"] for c in out] == list(range(1, 51)) and {c["evidence_id"] for c in out} == {c["evidence_id"] for c in cands}
    with pytest.raises(RuntimeError):
        C.rerank(cands, {k: v for k, v in list(scores.items())[:49]}, SEED, "q", "x")
    with pytest.raises(RuntimeError):
        C.rerank(cands, {**scores, "CVE-9|3.1|NVD|1": 5.0}, SEED, "q", "x")

@pytest.mark.unit
def test_observed_age_and_no_future_evidence():
    assert C.observed_age_days("2024-01-01T00:00:00+00:00", "2024-01-31T00:00:00+00:00") == 30.0
    with pytest.raises(ValueError):
        C.observed_age_days("2024-02-01T00:00:00+00:00", "2024-01-31T00:00:00+00:00")
    assert "true_age" not in inspect.getsource(R) and "true_age" not in inspect.getsource(C)
    assert CFG["recency"]["age_name"] == "observed_age_days"

@pytest.mark.unit
def test_recency_reads_only_allowed_fields():
    assert set(C.ALLOWED_CANDIDATE_FIELDS) == {"evidence_id", "observed_from", "valid_from_censored", "evidence_text"}
    src = inspect.getsource(R)
    for forbidden in ("valid_until", "replaced_by", "replacement_event", "replacement_type", "OUTDATED", "CURRENT", "label"):
        assert forbidden not in src.replace("labels, valid_until and replacement", ""), forbidden
    cands = _cands()
    meta = _meta(cands)
    ro = R.recency_only(cands, meta, "2024-07-01T00:00:00+00:00", SEED, "q")
    assert ro[0]["evidence_id"] == "CVE-1|3.1|NVD|2"
    assert ro[0]["class"] == "TARGET_CURRENT" and ro[0]["bm25_rank"] == 2 and len(ro) == 50

@pytest.mark.unit
def test_bm25_recency_formula_and_selection_on_dev_only():
    cands = _cands()
    meta = _meta(cands)
    qt = "2024-07-01T00:00:00+00:00"
    br = R.bm25_recency(cands, meta, qt, SEED, "q", lam=0.3, tau=180.0)
    norm = C.minmax([c["score"] for c in cands])
    exp = {c["evidence_id"]: n + 0.3 * R.recency_feature(C.observed_age_days(meta[c["evidence_id"]]["observed_from"], qt), 180.0) for c, n in zip(cands, norm)}
    assert br[0]["evidence_id"] == "CVE-1|3.1|NVD|2" and abs(br[0]["score"] - exp["CVE-1|3.1|NVD|2"]) < 1e-12
    assert R.recency_feature(0.0, 30.0) == 1.0 and R.recency_feature(30.0, 30.0) < R.recency_feature(0.0, 30.0)

    assert "dev_rows" in inspect.signature(R.select_on_dev).parameters and CFG["recency"]["main"]["selection"]["split"] == "dev"
    q = {"query_id": "q", "current_evidence_ids": ["CVE-1|3.1|NVD|2"], "other_source_current_evidence_ids": []}
    row = {"query_id": "q", "query_time": qt, "candidates": cands}
    sel = R.select_on_dev([row], {"q": q}, meta, SEED, {"tau_days": [30, 180], "lambda": [0.1, 0.5]})
    assert len(sel["table"]) == 4 and sel["split"] == "dev" and set(sel["selected"]) == {"tau_days", "lambda"}

@pytest.mark.unit
def test_cross_encoder_cache_key_and_resume(tmp_path):
    k1 = CE.cache_key("q", "e", "rev1", "rev1", 512, "raw_logit", "Q", "E")
    assert k1 != CE.cache_key("q", "e", "rev2", "rev1", 512, "raw_logit", "Q", "E")
    assert k1 != CE.cache_key("q", "e", "rev1", "rev1", 256, "raw_logit", "Q", "E") and k1 != CE.cache_key("q", "e", "rev1", "rev1", 512, "raw_logit", "Q2", "E")
    cache = CE.ScoreCache(tmp_path / "scores.jsonl")
    cache.append([{"key": k1, "query_id": "q", "evidence_id": "e", "score": 0.5}])
    again = CE.ScoreCache(tmp_path / "scores.jsonl")
    assert again.loaded == 1 and again.scores[k1] == 0.5
    assert CFG["cross_encoder"]["input"] == ["query_text", "evidence_text"] and "metadata" not in CFG["cross_encoder"]["input"]

@pytest.mark.unit
def test_cross_encoder_uses_only_text_pair():
    src = inspect.getsource(CE.score_pool) + inspect.getsource(CE.rerank_with_cache)
    assert "query_text" in src and "evidence_text" in src
    for forbidden in ("valid_until", "replaced_by", "replacement_event", "timeline_status", "observed_from", "label"):
        assert forbidden not in src, forbidden

@pytest.mark.full_data
def test_rerank_smoke_and_full_artifacts():
    comp = paths.PROJECT_ROOT / CFG["comparison"]["output_dir"]
    if not (comp / "smoke_report.json").exists():
        pytest.skip("reranking baseline çıktısı yok")
    sm = json.loads((comp / "smoke_report.json").read_text(encoding="utf-8"))
    assert sm["queries_total"] == 300 and sm["gates"]["all_passed"]
    acc = json.loads((paths.PROJECT_ROOT / "results/experiments/smoke_bm25/smoke_report.json").read_text(encoding="utf-8"))
    for m in ("recall@50", "mrr@10", "ndcg@10", "stale@10"):
        assert sm["bm25"]["all"][m] == acc["bm25"]["all"][m]
    for meth in ("recency_only", "bm25_recency", "cross_encoder"):
        assert sm[meth]["all"]["recall@50"] == sm["bm25"]["all"]["recall@50"]
    det = sm["determinism_check"]
    assert det["top50_set_identical"] == det["queries"] and det["max_abs_score_diff"] < 1e-3
    if (comp / "baseline_comparison.json").exists():
        full = json.loads((comp / "baseline_comparison.json").read_text(encoding="utf-8"))
        assert full["main"]["queries_total"] == 3537 and full["future_event_descriptive"]["queries_total"] == 19 and full["gates"]["all_passed"]
        accf = json.loads((paths.PROJECT_ROOT / "results/experiments/bm25_full/bm25_report.json").read_text(encoding="utf-8"))
        assert full["main"]["bm25"]["all"]["mrr@10"] == accf["main"]["bm25"]["all"]["mrr@10"]
        for meth in ("recency_only", "bm25_recency", "cross_encoder"):
            assert full["main"][meth]["all"]["recall@50"] == 1.0 and full["main"][meth]["all"]["retrieval_failure_rate"] == 0.0
        sel = json.loads((paths.PROJECT_ROOT / CFG["recency"]["output_dir"] / "recency_dev_selection.json").read_text(encoding="utf-8"))
        assert sel["split"] == "dev" and len(sel["table"]) == 9 and all(t["queries"] == 312 for t in sel["table"])
        man = json.loads((paths.PROJECT_ROOT / CFG["cross_encoder"]["output_dir"] / "cross_encoder_manifest.json").read_text(encoding="utf-8"))
        assert man["model"]["revision"] and man["scoring"]["truncated"] == 0

        for d in ("recency", "cross_encoder"):
            assert (paths.PROJECT_ROOT / CFG[d]["output_dir"]).glob("future_event*_top50.jsonl")
