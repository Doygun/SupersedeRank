from __future__ import annotations

import ast
import inspect
import json
import random

import pytest

from src import paths
from src.rerank import rule_direct as RD
from src.rerank import rule_inferred as RI

QT = "2024-06-01T00:00:00+00:00"
VEC_A = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VEC_B = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"

def _v(eid="CVE-1|3.1|NVD|1", cve="CVE-1", src="NVD", ver="3.1", obs="2024-02-01T00:00:00+00:00", vec=VEC_A, cens=False):
    return RI.narrow_view({"evidence_id": eid, "cve_id": cve, "source_key": src, "cvss_version": ver, "observed_from": obs, "base_vector": vec, "valid_from_censored": cens})

def _index(*views, witnesses=None):
    return RI.ChainIndex(list(views), witnesses if witnesses is not None else {v["evidence_id"] for v in views})

def _cands(*eids):
    out = []
    for i, e in enumerate(eids, start=1):
        cls = "TARGET_CURRENT" if e.endswith("|2") and "NVD" in e else ("TARGET_OUTDATED" if e.endswith("|1") and "NVD" in e else "OTHER_SOURCE_CURRENT")
        out.append({"rank": i, "evidence_id": e, "score": 10.0 - i, "label": "x", "relation": "y", "class": cls})
    return out

@pytest.mark.unit
def test_signal_newer_different_vector_same_chain():
    old, new = _v(), _v("CVE-1|3.1|NVD|2", obs="2024-03-01T00:00:00+00:00", vec=VEC_B)
    idx = _index(old, new)
    assert RI.inferred_superseded(old, QT, idx) == (True, "CVE-1|3.1|NVD|2")
    assert RI.inferred_superseded(new, QT, idx) == (False, None)

@pytest.mark.unit
def test_same_vector_readd_gives_no_signal():
    old, readd = _v(), _v("CVE-1|3.1|NVD|2", obs="2024-03-01T00:00:00+00:00", vec="CVSS:3.1/" + VEC_A)
    assert RI.inferred_superseded(old, QT, _index(old, readd)) == (False, None)

@pytest.mark.unit
def test_no_signal_across_source_version_or_cve_or_future():
    old = _v()
    other_src = _v("CVE-1|3.1|cna@x|1", src="cna@x", obs="2024-03-01T00:00:00+00:00", vec=VEC_B)
    other_ver = _v("CVE-1|4.0|NVD|1", ver="4.0", obs="2024-03-01T00:00:00+00:00", vec=VEC_B)
    other_cve = _v("CVE-2|3.1|NVD|1", cve="CVE-2", obs="2024-03-01T00:00:00+00:00", vec=VEC_B)
    future = _v("CVE-1|3.1|NVD|2", obs="2024-07-01T00:00:00+00:00", vec=VEC_B)
    for w in (other_src, other_ver, other_cve, future):
        assert RI.inferred_superseded(old, QT, _index(old, w)) == (False, None)
    assert RI.inferred_superseded(old, "2024-08-01T00:00:00+00:00", _index(old, future)) == (True, "CVE-1|3.1|NVD|2")

@pytest.mark.unit
def test_other_source_current_and_censored_not_suppressed_by_themselves():
    old, new = _v(cens=True, obs="2024-01-01T00:00:00+00:00"), _v("CVE-1|3.1|NVD|2", obs="2024-03-01T00:00:00+00:00", vec=VEC_B)
    osc = _v("CVE-1|3.1|cna@x|1", src="cna@x", obs="2024-01-01T00:00:00+00:00", cens=True)
    idx = _index(old, new, osc)
    ranked, _ = RI.rule_inferred(_cands("CVE-1|3.1|NVD|1", "CVE-1|3.1|NVD|2", "CVE-1|3.1|cna@x|1"), QT, idx)
    by = {c["evidence_id"]: c for c in ranked}
    assert not by["CVE-1|3.1|cna@x|1"]["suppressed"] and not by["CVE-1|3.1|NVD|2"]["suppressed"]
    assert by["CVE-1|3.1|NVD|1"]["suppressed"]
    lone_censored = _v(cens=True, obs="2024-01-01T00:00:00+00:00")
    assert RI.inferred_superseded(lone_censored, QT, _index(lone_censored)) == (False, None)

@pytest.mark.unit
def test_forbidden_fields_and_labels_do_not_change_output():
    rows = [{"evidence_id": "CVE-1|3.1|NVD|1", "cve_id": "CVE-1", "source_key": "NVD", "cvss_version": "3.1", "observed_from": "2024-02-01T00:00:00+00:00",
             "base_vector": VEC_A, "valid_from_censored": False, "valid_until": None, "replaced_by_evidence_id": None, "replacement_type": None},
            {"evidence_id": "CVE-1|3.1|NVD|2", "cve_id": "CVE-1", "source_key": "NVD", "cvss_version": "3.1", "observed_from": "2024-03-01T00:00:00+00:00",
             "base_vector": VEC_B, "valid_from_censored": False, "valid_until": None, "replaced_by_evidence_id": None, "replacement_type": None}]
    idx_a = _index(*(RI.narrow_view(r) for r in rows))
    rng = random.Random(1)
    perturbed = [{**r, "valid_until": rng.choice([None, "2024-02-15T00:00:00+00:00"]), "replaced_by_evidence_id": rng.choice([None, "Q"]),
                  "replacement_type": "STRICT_SAME_CHANGE", "timeline_status": "REPLACED"} for r in rows]
    idx_b = _index(*(RI.narrow_view(r) for r in perturbed))
    cands = _cands("CVE-1|3.1|NVD|1", "CVE-1|3.1|NVD|2")
    shuffled = [dict(c, label="OUTDATED" if c["class"] == "TARGET_CURRENT" else "CURRENT", **{"class": "OTHER"}) for c in cands]
    a = [c["evidence_id"] for c in RI.rule_inferred(cands, QT, idx_a)[0]]
    assert a == [c["evidence_id"] for c in RI.rule_inferred(cands, QT, idx_b)[0]] == [c["evidence_id"] for c in RI.rule_inferred(shuffled, QT, idx_a)[0]]
    assert a == ["CVE-1|3.1|NVD|2", "CVE-1|3.1|NVD|1"]

@pytest.mark.unit
def test_cross_event_ids_are_excluded_from_witnesses():
    old, cross_new = _v(), _v("CVE-1|3.1|NVD|2", obs="2024-03-01T00:00:00+00:00", vec=VEC_B)
    idx = _index(old, cross_new, witnesses={"CVE-1|3.1|NVD|1"})
    assert RI.inferred_superseded(old, QT, idx) == (False, None)

@pytest.mark.unit
def test_block_order_preserves_bm25_order_and_candidate_set():
    cands = _cands("CVE-1|3.1|NVD|1", "CVE-1|3.1|cna@x|1", "CVE-1|3.1|NVD|2", "CVE-9|3.1|NVD|1")
    flags = {"CVE-1|3.1|NVD|1": True, "CVE-1|3.1|cna@x|1": False, "CVE-1|3.1|NVD|2": False, "CVE-9|3.1|NVD|1": True}
    out = RI.block_rerank(cands, flags, "t")
    assert [c["evidence_id"] for c in out] == ["CVE-1|3.1|cna@x|1", "CVE-1|3.1|NVD|2", "CVE-1|3.1|NVD|1", "CVE-9|3.1|NVD|1"]
    assert [c["rank"] for c in out] == [1, 2, 3, 4] and [c["bm25_rank"] for c in out] == [2, 3, 1, 4]
    assert all(out[i]["class"] == next(c["class"] for c in cands if c["evidence_id"] == out[i]["evidence_id"]) for i in range(4))
    with pytest.raises(RuntimeError):
        RI.block_rerank(cands, {k: v for k, v in list(flags.items())[:3]}, "t")

@pytest.mark.unit
def test_rule_direct_is_separate_and_uses_visible_link_only():
    assert RD.__name__ == "src.rerank.rule_direct"
    rows = {"CVE-1|3.1|NVD|1": {"superseded_by_evidence_id": "CVE-1|3.1|NVD|2"}, "CVE-1|3.1|NVD|2": {"superseded_by_evidence_id": None}}
    obs = {"CVE-1|3.1|NVD|2": "2024-03-01T00:00:00+00:00"}
    assert RD.direct_superseded(rows["CVE-1|3.1|NVD|1"], QT, obs) == (True, "CVE-1|3.1|NVD|2")
    assert RD.direct_superseded(rows["CVE-1|3.1|NVD|1"], "2024-02-15T00:00:00+00:00", obs) == (False, "CVE-1|3.1|NVD|2")
    out = RD.rule_direct(_cands("CVE-1|3.1|NVD|1", "CVE-1|3.1|NVD|2"), QT, rows, obs)
    assert [c["evidence_id"] for c in out] == ["CVE-1|3.1|NVD|2", "CVE-1|3.1|NVD|1"]

@pytest.mark.unit
def test_static_no_label_package_and_no_forbidden_names_in_rule_code():
    src = inspect.getsource(RI)
    tree = ast.parse(src)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and not (isinstance(getattr(node, "parent", None), ast.Expr)):
            names.add(node.value)
        if isinstance(node, (ast.Name, ast.Attribute)):
            names.add(getattr(node, "id", getattr(node, "attr", "")))
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = getattr(node, "module", "") or ""
            assert not mod.startswith("src.label"), "rule imports the label package"
            for a in node.names:
                assert not a.name.startswith("src.label")

    doc_texts = {n.value.value for n in ast.walk(tree) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
    names -= doc_texts
    forbidden = {"valid_until", "superseded_by_evidence_id", "replaced_by_evidence_id", "replaces_evidence_id", "replacement_type", "replacement_event_id", "timeline_status",
                 "termination_event_id", "label", "is_active", "CURRENT", "OUTDATED", "temporal_label"}
    assert not (names & forbidden), names & forbidden
    assert set(RI.ALLOWED_RULE_FIELDS) == {"evidence_id", "cve_id", "source_key", "cvss_version", "observed_from", "vector (Base part only)", "valid_from_censored"}

@pytest.mark.unit
def test_determinism_same_input_same_output():
    old, mid, new = _v(), _v("CVE-1|3.1|NVD|2", obs="2024-03-01T00:00:00+00:00", vec=VEC_B), _v("CVE-1|3.1|NVD|3", obs="2024-04-01T00:00:00+00:00", vec=VEC_A)
    idx = _index(old, mid, new)
    a = RI.rule_inferred(_cands("CVE-1|3.1|NVD|3", "CVE-1|3.1|NVD|1", "CVE-1|3.1|NVD|2"), QT, idx)
    b = RI.rule_inferred(_cands("CVE-1|3.1|NVD|3", "CVE-1|3.1|NVD|1", "CVE-1|3.1|NVD|2"), QT, idx)
    assert a == b and a[1]["CVE-1|3.1|NVD|1"] == "CVE-1|3.1|NVD|2" and a[1]["CVE-1|3.1|NVD|2"] == "CVE-1|3.1|NVD|3"

@pytest.mark.full_data
def test_negative_controls_on_real_store():
    store = paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl"
    if not store.exists():
        pytest.skip("evidence store yok")
    index, cross_ids = RI.build_index(store, paths.PROCESSED_DATA_DIR / "evidence" / "evidence.jsonl", paths.PROCESSED_DATA_DIR / "sensitivity" / "cross_event_replacements.jsonl")
    assert len(cross_ids) == 131 and not any(e["evidence_id"] in cross_ids for c in index.chains.values() for e in c)
    readds = [json.loads(l) for l in (paths.PROCESSED_DATA_DIR / "negative_controls" / "same_value_readds.jsonl").open(encoding="utf-8")]
    assert len(readds) == 7672
    same_vec_signal = 0
    for r in readds:
        v = index.view[r["evidence_id"]]
        sig, w = RI.inferred_superseded(v, "2099-01-01T00:00:00+00:00", index)
        if sig and index.view[w]["canonical_base_vector"] == v["canonical_base_vector"]:
            same_vec_signal += 1
    assert same_vec_signal == 0
    rep_path = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_rule" / "smoke_report.json"
    if rep_path.exists():
        rep = json.loads(rep_path.read_text(encoding="utf-8"))
        assert rep["gates"]["all_passed"] and rep["queries_total"] == 300
        d = rep["diagnostics"]
        assert d.get("suppressed_by_cross_event_witness", 0) == 0 and d.get("suppressed_by_same_vector_witness", 0) == 0
        assert d.get("suppressed_current", 0) == 0 and d.get("suppressed_other_source_current", 0) == 0 and d.get("suppressed_with_chain_mismatch", 0) == 0
