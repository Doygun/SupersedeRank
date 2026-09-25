from __future__ import annotations

import pytest

from src.label import query_time_labels as L

pytestmark = pytest.mark.unit

W = "2024-01-01T00:00:00+00:00"
T = "2024-05-01T00:00:00+00:00"

def ev(**kw):
    base = dict(evidence_id="e", cve_id="CVE-1", source_key="NVD", cvss_version="3.1", observed_from=W, valid_until=None,
                replacement_type=None, chain_ambiguous=False, valid_from_censored=False)
    base.update(kw)
    return base

def q(source="NVD", cve="CVE-1", version="3.1", t=T):
    return L.Query(cve_id=cve, source_key=source, cvss_version=version, query_time=t)

def test_labels_are_binary_for_target_chain():
    old = ev(valid_from_censored=True, valid_until="2024-08-01T00:00:00+00:00", replacement_type="STRICT_SAME_CHANGE")
    assert L.label(old, q(t="2024-05-01T00:00:00+00:00")) == L.CURRENT
    assert L.label(old, q(t="2024-09-01T00:00:00+00:00")) == L.OUTDATED
    assert {L.CURRENT, L.OUTDATED} == {L.label(old, q(t=t)) for t in ("2024-05-01T00:00:00+00:00", "2024-09-01T00:00:00+00:00")}

def test_evidence_after_query_time_is_not_visible():
    new = ev(observed_from="2024-08-01T00:00:00+00:00")
    assert L.label(new, q()) == L.NOT_VISIBLE
    assert L.label(new, q(t="2024-08-01T00:00:00+00:00")) == L.CURRENT

def test_withdrawn_or_cross_event_never_outdated():
    gone = ev(valid_until="2024-06-01T00:00:00+00:00", replacement_type=None)
    assert L.label(gone, q(t="2024-07-01T00:00:00+00:00")) == L.NOT_LABELABLE
    cross = ev(valid_until="2024-06-01T00:00:00+00:00", replacement_type="HIGH_CONFIDENCE_CROSS_EVENT")
    assert L.label(cross, q(t="2024-07-01T00:00:00+00:00")) == L.NOT_LABELABLE
    assert L.label(cross, q()) == L.CURRENT

def test_other_source_is_metadata_not_a_label():
    nvd = ev(evidence_id="a", source_key="NVD")
    cna = ev(evidence_id="b", source_key="cna@x")
    other_cve = ev(evidence_id="c", cve_id="CVE-2")
    target = q("NVD")
    assert L.label(nvd, target) == L.CURRENT
    assert L.label(cna, target) == L.NOT_TARGET_CHAIN
    assert L.source_relation(cna, target) == L.OTHER_SOURCE_CURRENT
    assert L.source_relation(nvd, target) == L.TARGET_SOURCE
    assert L.source_relation(other_cve, target) == L.OTHER_CVE
    inactive = ev(evidence_id="d", source_key="cna@x", valid_until="2024-02-01T00:00:00+00:00")
    assert L.source_relation(inactive, target) == L.OTHER_SOURCE_INACTIVE

    assert L.graded_relevance(L.CURRENT, L.TARGET_SOURCE) == 2
    assert L.graded_relevance(L.NOT_TARGET_CHAIN, L.OTHER_SOURCE_CURRENT) == 1
    assert L.graded_relevance(L.OUTDATED, L.TARGET_SOURCE) == 0
    assert L.binary_relevance(L.CURRENT, L.TARGET_SOURCE) == 1 and L.binary_relevance(L.NOT_TARGET_CHAIN, L.OTHER_SOURCE_CURRENT) == 0
    assert L.is_stale(L.OUTDATED) and not L.is_stale(L.NOT_TARGET_CHAIN)

def test_source_agnostic_query_treats_all_chains_as_target():
    nvd, cna = ev(evidence_id="a", source_key="NVD"), ev(evidence_id="b", source_key="cna@x")
    agn = L.Query(cve_id="CVE-1", source_key=None, cvss_version=None, query_time=T)
    assert L.label(nvd, agn) == L.CURRENT and L.label(cna, agn) == L.CURRENT
    assert [e["evidence_id"] for e in L.current_evidence([nvd, cna], T, cve_id="CVE-1")] == ["a", "b"]
    assert [e["evidence_id"] for e in L.current_evidence([nvd, cna], T, source_key="NVD")] == ["a"]

def test_version_is_part_of_the_target_chain():
    v4 = ev(evidence_id="x", cvss_version="4.0")
    assert L.label(v4, q(version="3.1")) == L.NOT_TARGET_CHAIN
    assert L.label(v4, q(version="4.0")) == L.CURRENT

def test_ambiguous_chain_is_excluded():
    assert L.label(ev(chain_ambiguous=True), q()) == L.EXCLUDED_AMBIGUOUS
