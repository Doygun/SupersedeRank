from __future__ import annotations

import json

import pytest

from src import paths
from src.label import query_time_labels as L
from src.timeline.config import load_timeline_config

Q = L.Query(cve_id="CVE-1", source_key="NVD", cvss_version="3.1", query_time="2024-06-01T00:00:00+00:00")

def _e(**kw):
    base = dict(evidence_id="CVE-1|3.1|NVD|1", cve_id="CVE-1", source_key="NVD", cvss_version="3.1", observed_from="2024-02-01T00:00:00+00:00",
                valid_until=None, replacement_type=None, chain_ambiguous=False, valid_from_censored=False)
    base.update(kw)
    return base

@pytest.mark.unit
def test_same_value_readd_is_never_supersession():
    ended_no_replacement = _e(valid_until="2024-03-01T00:00:00+00:00", replacement_type=None)
    assert L.label(ended_no_replacement, Q) == L.NOT_LABELABLE and not L.is_stale(L.label(ended_no_replacement, Q))

@pytest.mark.unit
def test_cross_event_replacement_is_not_a_main_label():
    e = _e(valid_until="2024-03-01T00:00:00+00:00", replacement_type="HIGH_CONFIDENCE_CROSS_EVENT")
    assert L.label(e, Q) == L.NOT_LABELABLE
    assert L.label(_e(valid_until="2024-03-01T00:00:00+00:00", replacement_type="STRICT_SAME_CHANGE"), Q) == L.OUTDATED

@pytest.mark.unit
def test_other_source_current_is_not_stale():
    other = _e(evidence_id="CVE-1|3.1|cna@x|1", source_key="cna@x")
    assert L.label(other, Q) == L.NOT_TARGET_CHAIN and L.source_relation(other, Q) == L.OTHER_SOURCE_CURRENT
    assert not L.is_stale(L.label(other, Q))
    inactive_other = _e(evidence_id="CVE-1|3.1|cna@x|1", source_key="cna@x", valid_until="2024-03-01T00:00:00+00:00", replacement_type="STRICT_SAME_CHANGE")
    assert L.label(inactive_other, Q) == L.NOT_TARGET_CHAIN and L.source_relation(inactive_other, Q) == L.OTHER_SOURCE_INACTIVE

@pytest.mark.unit
def test_left_censored_observed_from_is_window_start_not_true_age():
    tcfg = load_timeline_config()
    e = _e(observed_from=tcfg.window_start, valid_from_censored=True)
    assert L.label(e, Q) == L.CURRENT and e["valid_from_censored"]
    from src.rerank.common import observed_age_days
    lower_bound = observed_age_days(e["observed_from"], Q.query_time)
    assert lower_bound > 0 and observed_age_days("2023-01-01T00:00:00+00:00", Q.query_time) > lower_bound

@pytest.mark.unit
def test_non_base_only_events_are_outside_base_queries():
    path = paths.PROCESSED_DATA_DIR / "splits" / "base_query_eligible_manifest.json"
    if not path.exists():
        pytest.skip("manifest yok")
    m = json.loads(path.read_text(encoding="utf-8"))
    text = json.dumps(m)
    assert "THREAT_ONLY_CHANGE" in text and "SUPPLEMENTAL_ONLY_CHANGE" in text and "ENVIRONMENTAL_ONLY_CHANGE" in text

@pytest.mark.full_data
def test_negative_control_set_counts():
    root = paths.PROCESSED_DATA_DIR
    readds = root / "negative_controls" / "same_value_readds.jsonl"
    cross = root / "sensitivity" / "cross_event_replacements.jsonl"
    excluded = root / "splits" / "base_query" / "excluded_events.jsonl"
    if not (readds.exists() and cross.exists() and excluded.exists()):
        pytest.skip("negatif kontrol dosyaları yok")
    rows_r = [json.loads(l) for l in readds.open(encoding="utf-8")]
    rows_c = [json.loads(l) for l in cross.open(encoding="utf-8")]
    rows_x = [json.loads(l) for l in excluded.open(encoding="utf-8")]
    assert len(rows_r) == 7672 and all(r["is_supersession"] is False for r in rows_r)
    assert len(rows_c) == 131 and all(r["in_main_dataset"] is False and r["replacement_type"] == "HIGH_CONFIDENCE_CROSS_EVENT" for r in rows_c)
    assert len(rows_x) == 93 and {r["exclusion_detail"] for r in rows_x} <= {"THREAT_ONLY_CHANGE", "SUPPLEMENTAL_ONLY_CHANGE", "ENVIRONMENTAL_ONLY_CHANGE", "NO_BASE_COMPONENT_CHANGE"}

    main_ids = set()
    for s in ("train", "dev", "test", "future_event"):
        for l in (root / "queries" / f"{s}_queries.jsonl").open(encoding="utf-8"):
            q = json.loads(l)
            if q["query_role"] == "POST_REPLACEMENT_MAIN":
                main_ids.update(q["current_evidence_ids"])
    assert not any(r.get("new_evidence_id") in main_ids for r in rows_x if r.get("new_evidence_id"))

@pytest.mark.full_data
def test_other_source_current_never_counted_stale_in_stored_lists():
    path = paths.PROJECT_ROOT / "results" / "experiments" / "bm25_full" / "dev_top50.jsonl"
    if not path.exists():
        pytest.skip("BM25 listeleri yok")
    for line in path.open(encoding="utf-8"):
        row = json.loads(line)
        for c in row["candidates"]:
            if c["class"] == "OTHER_SOURCE_CURRENT":
                assert not L.is_stale(c["label"]) and c["label"] != L.OUTDATED
