from __future__ import annotations

import ast
import inspect
import json

import pytest

from src import paths
from src.rerank import rule_inferred as RI
from src.rerank import rule_target as RT

QT = "2024-06-01T00:00:00+00:00"
VA, VB = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"

def _v(eid, cve="CVE-1", src="NVD", ver="3.1", obs="2024-02-01T00:00:00+00:00", vec=VA, cens=False):
    return RI.narrow_view({"evidence_id": eid, "cve_id": cve, "source_key": src, "cvss_version": ver, "observed_from": obs, "base_vector": vec, "valid_from_censored": cens})

Q = {"query_id": "q", "cve_id": "CVE-1", "source_key": "NVD", "cvss_version": "3.1", "query_time": QT}

def _c(rank, eid, cls):
    return {"rank": rank, "evidence_id": eid, "score": 10.0 - rank, "label": "x", "relation": "y", "class": cls}

def _setup():
    views = [_v("CVE-1|3.1|NVD|1"), _v("CVE-1|3.1|NVD|2", obs="2024-03-01T00:00:00+00:00", vec=VB),
             _v("CVE-1|3.1|cna@x|1", src="cna@x"), _v("CVE-1|3.1|cna@x|2", src="cna@x", obs="2024-03-01T00:00:00+00:00", vec=VB),
             _v("CVE-1|4.0|NVD|1", ver="4.0"), _v("CVE-1|4.0|NVD|2", ver="4.0", obs="2024-03-01T00:00:00+00:00", vec=VB),
             _v("CVE-9|3.1|NVD|1", cve="CVE-9"), _v("CVE-9|3.1|NVD|2", cve="CVE-9", obs="2024-03-01T00:00:00+00:00", vec=VB)]
    idx = RI.ChainIndex(views, {v["evidence_id"] for v in views})
    cands = [_c(1, "CVE-9|3.1|NVD|1", "OTHER"), _c(2, "CVE-1|3.1|NVD|1", "TARGET_OUTDATED"), _c(3, "CVE-1|3.1|cna@x|1", "OTHER"), _c(4, "CVE-1|4.0|NVD|1", "OTHER"),
             _c(5, "CVE-1|3.1|NVD|2", "TARGET_CURRENT"), _c(6, "CVE-1|3.1|cna@x|2", "OTHER_SOURCE_CURRENT")]
    return idx, cands

@pytest.mark.unit
def test_target_scope_suppresses_only_query_chain():
    idx, cands = _setup()
    tgt, wit = RT.rule_target(cands, Q, idx)
    corpus, _ = RI.rule_inferred(cands, QT, idx)
    assert [c["evidence_id"] for c in tgt] == ["CVE-9|3.1|NVD|1", "CVE-1|3.1|cna@x|1", "CVE-1|4.0|NVD|1", "CVE-1|3.1|NVD|2", "CVE-1|3.1|cna@x|2", "CVE-1|3.1|NVD|1"]
    assert [c["suppressed"] for c in tgt] == [False, False, False, False, False, True] and wit["CVE-1|3.1|NVD|1"] == "CVE-1|3.1|NVD|2"

    assert {c["evidence_id"] for c in corpus if c["suppressed"]} == {"CVE-9|3.1|NVD|1", "CVE-1|3.1|NVD|1", "CVE-1|3.1|cna@x|1", "CVE-1|4.0|NVD|1"}
    assert {c["evidence_id"] for c in tgt} == {c["evidence_id"] for c in cands}

@pytest.mark.unit
def test_target_same_signal_and_bm25_order_within_blocks():
    idx, cands = _setup()
    tgt, _ = RT.rule_target(cands, Q, idx)
    kept = [c["bm25_rank"] for c in tgt if not c["suppressed"]]; sup = [c["bm25_rank"] for c in tgt if c["suppressed"]]
    assert kept == sorted(kept) and sup == sorted(sup) and [c["rank"] for c in tgt] == list(range(1, 7))
    assert RT.rule_target(cands, Q, idx)[0] == tgt

    views = [_v("CVE-1|3.1|NVD|1"), _v("CVE-1|3.1|NVD|2", obs="2024-03-01T00:00:00+00:00", vec="CVSS:3.1/" + VA), _v("CVE-1|3.1|NVD|3", obs="2024-07-01T00:00:00+00:00", vec=VB)]
    idx2 = RI.ChainIndex(views, {v["evidence_id"] for v in views})
    out, _ = RT.rule_target([_c(1, "CVE-1|3.1|NVD|1", "TARGET_OUTDATED"), _c(2, "CVE-1|3.1|NVD|2", "TARGET_CURRENT")], Q, idx2)
    assert not any(c["suppressed"] for c in out)
    assert RT.is_query_chain(idx.view["CVE-1|3.1|NVD|1"], Q) and not RT.is_query_chain(idx.view["CVE-1|4.0|NVD|1"], Q) and not RT.is_query_chain(idx.view["CVE-1|3.1|cna@x|1"], Q)

@pytest.mark.unit
def test_target_module_static_safety():
    tree = ast.parse(inspect.getsource(RT))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            assert not (getattr(node, "module", "") or "").startswith("src.label")
        if isinstance(node, (ast.Name, ast.Attribute)):
            names.add(getattr(node, "id", getattr(node, "attr", "")))
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.add(node.value)
    names -= {n.value.value for n in ast.walk(tree) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
    assert not (names & {"valid_until", "superseded_by_evidence_id", "replaced_by_evidence_id", "replacement_type", "timeline_status", "label", "is_active", "CURRENT", "OUTDATED"})

@pytest.mark.full_data
def test_rule_target_full_artifacts():
    p = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_rule_target" / "rule_target_report.json"
    if not p.exists():
        pytest.skip("Rule-Target çıktısı yok")
    rep = json.loads(p.read_text(encoding="utf-8"))
    assert rep["main"]["queries_total"] == 3537 and rep["future_event_descriptive"]["queries_total"] == 19 and rep["gates"]["all_passed"]
    d = rep["diagnostics_main"]
    assert d["suppressed_non_target"] == 0 and d["suppressed_current"] == 0 and d["suppressed_other_source_current"] == 0 and d["suppressed_other_cve"] == 0
    for m in ("rule_corpus", "rule_target"):
        assert rep["main"][m]["all"]["recall@50"] == rep["main"]["bm25"]["all"]["recall@50"] and rep["main"][m]["stale_suppression"]["current_preservation@10"] == 1.0
    acc = json.loads((paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_rule" / "full_report.json").read_text(encoding="utf-8"))
    assert rep["main"]["rule_corpus"]["all"]["mrr@10"] == acc["main"]["rule_inferred"]["all"]["mrr@10"]
