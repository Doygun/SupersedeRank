from __future__ import annotations

import json

import pytest

from src import paths
from src.label import query_time_labels as L
from src.label import splits as sp

CFG = sp.load_config()

@pytest.mark.unit
def test_label_ignores_events_after_query_time():

    e = dict(evidence_id="x", cve_id="CVE-1", source_key="NVD", observed_from="2024-03-01T00:00:00+00:00",
             valid_until="2025-06-01T00:00:00+00:00", replacement_type="STRICT_SAME_CHANGE",
             chain_ambiguous=False, valid_from_censored=False)
    assert L.label(e, "2025-05-31T23:59:59+00:00") == L.CURRENT
    assert L.label(e, "2025-06-01T00:00:00+00:00") == L.OUTDATED
    successor = dict(e, evidence_id="y", observed_from="2025-06-01T00:00:00+00:00", valid_until=None, replacement_type=None)
    assert L.label(successor, "2025-05-31T23:59:59+00:00") == L.NOT_VISIBLE

@pytest.mark.unit
def test_queries_never_before_observation_window():
    from src.timeline.config import load_timeline_config
    cfg = load_timeline_config()
    assert cfg.left_censoring["generate_queries_before_window"] is False
    e = dict(evidence_id="x", cve_id="CVE-1", source_key="NVD", observed_from=cfg.window_start, valid_until=None,
             replacement_type=None, chain_ambiguous=False, valid_from_censored=True)
    assert L.label(e, "2023-12-31T23:59:59+00:00") == L.NOT_VISIBLE

@pytest.mark.full_data
def test_split_periods_do_not_leak():
    split_dir = paths.PROCESSED_DATA_DIR / "splits"
    if not (split_dir / "test.jsonl").exists():
        pytest.skip("Split henüz üretilmedi")
    train_years = set(CFG["periods"]["train_years"]); test_years = set(CFG["periods"]["test_years"])
    for name, years in (("train", train_years), ("dev", train_years), ("test", test_years), ("future_event", test_years)):
        rows = [json.loads(l) for l in (split_dir / f"{name}.jsonl").open(encoding="utf-8")]
        assert rows, name
        assert all(int(r["event_time"][:4]) in years for r in rows), name

    test_cves = {json.loads(l)["cve_id"] for l in (split_dir / "test.jsonl").open(encoding="utf-8")}
    evidences = sp.read_evidence(paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl")
    for ev in sp.main_replacement_events(evidences, CFG):
        if ev.cve_id in test_cves:
            assert ev.year in test_years
