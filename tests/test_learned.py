from __future__ import annotations

import ast
import inspect
import json

import numpy as np
import pytest

from src import paths
from src.rerank import learned_features as F
from src.rerank import learned_run as LR
from src.rerank import rule_inferred as RI

QT = "2024-06-01T00:00:00+00:00"
VA, VB = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"

def _v(eid, cve="CVE-1", src="NVD", ver="3.1", obs="2024-02-01T00:00:00+00:00", vec=VA, cens=False):
    return RI.narrow_view({"evidence_id": eid, "cve_id": cve, "source_key": src, "cvss_version": ver, "observed_from": obs, "base_vector": vec, "valid_from_censored": cens})

def _q():
    return {"query_id": "q", "cve_id": "CVE-1", "source_key": "NVD", "cvss_version": "3.1", "query_time": QT, "query_template_id": "combined"}

def _cands():
    return [{"rank": 1, "evidence_id": "CVE-1|3.1|NVD|1", "score": 9.0, "label": "OUTDATED", "relation": "TARGET_SOURCE", "class": "TARGET_OUTDATED"},
            {"rank": 2, "evidence_id": "CVE-1|3.1|NVD|2", "score": 9.0, "label": "CURRENT", "relation": "TARGET_SOURCE", "class": "TARGET_CURRENT"},
            {"rank": 3, "evidence_id": "CVE-1|3.1|cna@x|1", "score": 5.0, "label": "NOT_TARGET_CHAIN", "relation": "OTHER_SOURCE_CURRENT", "class": "OTHER_SOURCE_CURRENT"},
            {"rank": 4, "evidence_id": "CVE-9|3.1|NVD|1", "score": 4.0, "label": "NOT_TARGET_CHAIN", "relation": "OTHER_CVE", "class": "OTHER"}]

@pytest.mark.unit
def test_feature_module_reads_only_allowed_fields_and_no_label_package():
    tree = ast.parse(inspect.getsource(F))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            assert not (getattr(node, "module", "") or "").startswith("src.label")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.add(node.value)
        if isinstance(node, (ast.Name, ast.Attribute)):
            names.add(getattr(node, "id", getattr(node, "attr", "")))
    docs = {n.value.value for n in ast.walk(tree) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
    names -= docs
    forbidden = {"valid_until", "replaced_by_evidence_id", "replaces_evidence_id", "superseded_by_evidence_id", "replacement_type", "replacement_event_id",
                 "termination_event_id", "timeline_status", "temporal_label", "label", "is_active", "CURRENT", "OUTDATED"}
    assert not (names & forbidden), names & forbidden

@pytest.mark.unit
def test_features_and_target_chain_scoping():
    views = [_v("CVE-1|3.1|NVD|1"), _v("CVE-1|3.1|NVD|2", obs="2024-03-01T00:00:00+00:00", vec=VB), _v("CVE-1|3.1|cna@x|1", src="cna@x"), _v("CVE-9|3.1|NVD|1", cve="CVE-9")]
    all_idx = RI.ChainIndex(views, {v["evidence_id"] for v in views}); wit = RI.ChainIndex(views, {v["evidence_id"] for v in views})
    q, cands = _q(), _cands()
    smap = {"NVD": "NVD"}
    f_old = F.candidate_features(cands[0], q, 1.0, 0.3, all_idx, wit, smap)
    f_new = F.candidate_features(cands[1], q, 1.0, 0.3, all_idx, wit, smap)
    f_osc = F.candidate_features(cands[2], q, 0.4, None, all_idx, wit, smap)
    assert f_old[F.RULE_FEATURE] == 1.0 and f_old["newer_visible_same_chain_count"] == 1.0 and f_old["chain_position_observed"] == 1.0 and f_old["base_vector_differs_from_chain_newest"] == 1.0
    assert f_new[F.RULE_FEATURE] == 0.0 and f_new["newer_visible_same_chain_count"] == 0.0 and f_new["chain_position_observed"] == 2.0
    assert f_osc["same_source_key"] == 0.0 and np.isnan(f_osc["cross_encoder_score"]) and f_osc["template_combined"] == 1.0
    assert F.is_target_chain(all_idx.view["CVE-1|3.1|NVD|1"], q) and not F.is_target_chain(all_idx.view["CVE-1|3.1|cna@x|1"], q) and not F.is_target_chain(all_idx.view["CVE-9|3.1|NVD|1"], q)
    assert F.RULE_FEATURE in F.feature_order(smap) and F.RULE_FEATURE not in F.feature_order(smap, drop_rule_signal=True)
    assert "label" not in f_old and "class" not in f_old

@pytest.mark.unit
def test_examples_only_target_chain_and_preproc_train_only():
    views = [_v("CVE-1|3.1|NVD|1"), _v("CVE-1|3.1|NVD|2", obs="2024-03-01T00:00:00+00:00", vec=VB), _v("CVE-1|3.1|cna@x|1", src="cna@x"), _v("CVE-9|3.1|NVD|1", cve="CVE-9")]
    idx = RI.ChainIndex(views, {v["evidence_id"] for v in views})
    fz = LR.Featurizer(idx, idx, {}, {"NVD": "NVD"})
    feats, y, meta = LR.build_examples([{"query_id": "q", "query_time": QT, "candidates": _cands()}], {"q": _q()}, fz)
    assert len(feats) == 2 and y.tolist() == [0, 1] and {m["evidence_id"] for m in meta} == {"CVE-1|3.1|NVD|1", "CVE-1|3.1|NVD|2"}
    pre = LR.Preproc(F.feature_order({"NVD": "NVD"})).fit(feats)
    X = pre.transform(feats)
    assert X.shape == (2, len(pre.cols)) and np.isfinite(X).all()
    st = pre.state(); assert set(st["median"]) == set(pre.numeric) and "label" not in st

@pytest.mark.unit
def test_block_policy_suppresses_only_target_chain_and_keeps_bm25_order():
    cands = _cands()
    p = {"CVE-1|3.1|NVD|1": 0.1, "CVE-1|3.1|NVD|2": 0.9, "CVE-1|3.1|cna@x|1": 0.05, "CVE-9|3.1|NVD|1": 0.05}
    target = {"CVE-1|3.1|NVD|1": True, "CVE-1|3.1|NVD|2": True, "CVE-1|3.1|cna@x|1": False, "CVE-9|3.1|NVD|1": False}
    out = LR.rerank_learned(cands, p, target, "block", None, 1, "q")
    assert [c["evidence_id"] for c in out] == ["CVE-1|3.1|NVD|2", "CVE-1|3.1|cna@x|1", "CVE-9|3.1|NVD|1", "CVE-1|3.1|NVD|1"]
    assert [c["suppressed"] for c in out] == [False, False, False, True] and {c["evidence_id"] for c in out} == {c["evidence_id"] for c in cands}
    alpha = LR.rerank_learned(cands, p, target, "alpha", 0.5, 1, "q")
    ids = [c["evidence_id"] for c in alpha]
    assert ids[0] == "CVE-1|3.1|NVD|2" and ids.index("CVE-1|3.1|NVD|1") > ids.index("CVE-1|3.1|NVD|2")
    assert {c["evidence_id"] for c in alpha} == {c["evidence_id"] for c in cands} and not any(c["suppressed"] for c in alpha if c["evidence_id"].startswith("CVE-9"))
    assert LR.rerank_learned(cands, p, target, "block", None, 1, "q") == out

@pytest.mark.unit
def test_selection_guard_rejects_test():
    from src.label.splits import assert_selection_split
    assert assert_selection_split("dev") == "dev"
    with pytest.raises(ValueError):
        assert_selection_split("test")
    with pytest.raises(ValueError):
        assert_selection_split("future_event")

@pytest.mark.full_data
def test_learned_smoke_artifacts():
    rep_path = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_learned" / "smoke_report.json"
    if not rep_path.exists():
        pytest.skip("learned smoke çıktısı yok")
    rep = json.loads(rep_path.read_text(encoding="utf-8"))
    assert rep["queries_total"] == 300 and rep["gates"]["all_passed"]
    man = json.loads((rep_path.parent / "learned_manifest.json").read_text(encoding="utf-8"))
    assert man["class_weight"] is None and man["models"]["learned_full"]["C"] in (0.1, 1.0, 10.0) and F.RULE_FEATURE not in man["models"]["learned_no_rule_signal"]["feature_order"]
    assert man["train_examples"]["current"] == 1719 and man["dev_examples"]["current"] == 312
    for m in ("learned_full", "learned_no_rule_signal"):
        assert rep[m]["all"]["recall@50"] == rep["bm25"]["all"]["recall@50"] and rep[m]["stale_suppression"]["current_preservation@10"] == 1.0
    assert rep["rule_agreement"]["same_target_chain_decisions"] == 300
