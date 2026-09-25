from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.ingest import nvd_history as reader

def write_page(path: Path, changes: list) -> Path:
    path.write_text(json.dumps({"cveChanges": changes}), encoding="utf-8")
    return path

@pytest.mark.unit
def test_normalize_utc():
    assert reader.normalize_utc("2024-01-01T01:15:20.317") == "2024-01-01T01:15:20.317000+00:00"
    assert reader.normalize_utc("2024-01-01T03:00:00+02:00") == "2024-01-01T01:00:00+00:00"
    assert reader.normalize_utc("2024-01-01T00:00:00Z") == "2024-01-01T00:00:00+00:00"
    assert reader.normalize_utc("not a date") == "not a date"
    assert reader.normalize_utc(None) == reader.MISSING

@pytest.mark.unit
def test_records_are_traceable_and_ordered(tmp_path: Path):
    page = write_page(
        tmp_path / "b.json",
        [
            {"change": {"cveId": "CVE-1", "eventName": "CVE Modified", "cveChangeId": "c1",
                        "sourceIdentifier": "nvd@nist.gov", "created": "2024-01-01T00:00:00.000",
                        "details": [
                            {"action": "Removed", "type": "CVSS V3.1", "oldValue": "NIST AV:N"},
                            {"action": "Added", "type": "CVSS V3.1", "newValue": "NIST AV:L"},
                        ]}},
            {"change": {"cveId": "CVE-2", "eventName": "CVE Status Change", "cveChangeId": "c2",
                        "sourceIdentifier": "x", "created": "2024-01-02T00:00:00.000", "details": []}},
        ],
    )
    stats = reader.ReaderStats()
    records = list(reader.iter_history_records(files=[page], stats=stats))

    assert [r.detail_index for r in records] == [0, 1, -1]
    assert records[0].old_value == "NIST AV:N" and records[0].new_value is None
    assert records[1].action == "Added" and records[1].detail_type == "CVSS V3.1"
    assert records[2].action is None and records[2].cve_id == "CVE-2"
    assert all(r.created.endswith("+00:00") for r in records)
    assert all(r.source_file.endswith("b.json") for r in records)
    assert (stats.files, stats.changes, stats.details, stats.empty_detail_changes) == (1, 2, 2, 1)
    assert stats.issue_count == 0

@pytest.mark.unit
def test_malformed_input_is_reported_not_skipped_silently(tmp_path: Path):
    bad_json = tmp_path / "a.json"
    bad_json.write_text("{not json", encoding="utf-8")
    page = write_page(
        tmp_path / "c.json",
        [
            "not a dict",
            {"change": {"cveId": "CVE-3", "cveChangeId": "c3", "created": "??", "details": "nope"}},
            {"change": {"cveId": "CVE-4", "cveChangeId": "c4", "created": "2024-01-01T00:00:00",
                        "details": [5, {"action": "Added", "type": "Reference", "newValue": "u"}]}},
        ],
    )
    stats = reader.ReaderStats()
    records = list(reader.iter_history_records(files=[bad_json, page], stats=stats))

    kinds = sorted(issue.kind for issue in stats.issues)
    assert kinds == ["CHANGE_NOT_DICT", "CREATED_UNPARSEABLE", "DETAILS_NOT_LIST", "DETAIL_NOT_DICT", "PAGE_READ_ERROR"]
    assert len(records) == 1 and records[0].cve_id == "CVE-4" and records[0].detail_index == 1
    assert stats.changes == 2

@pytest.mark.unit
def test_grouping_by_change(tmp_path: Path):
    page = write_page(
        tmp_path / "d.json",
        [
            {"change": {"cveId": "CVE-1", "cveChangeId": "c1", "created": "2024-01-01T00:00:00",
                        "details": [{"action": "Added", "type": "A"}, {"action": "Added", "type": "B"}]}},
            {"change": {"cveId": "CVE-1", "cveChangeId": "c2", "created": "2024-01-01T00:00:01", "details": []}},
        ],
    )
    groups = list(reader.iter_changes_grouped(files=[page]))
    assert [len(g) for g in groups] == [2, 1]
    assert groups[0][0].change_id == "c1" and groups[1][0].change_id == "c2"

@pytest.mark.full_data
def test_reader_counts_match_profile(history_dir):
    stats = reader.ReaderStats()
    n_records = sum(1 for _ in reader.iter_history_records(history_dir, stats))
    assert stats.files == 322
    assert stats.changes == 1_590_753
    assert stats.details == 3_249_766
    assert stats.empty_detail_changes == 356_079
    assert stats.issue_count == 0
    assert n_records == stats.details + stats.empty_detail_changes
