from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.normalize import cvss
from src.timeline import cvss_replacements as cr

def _change(cve, change_id, event, details, created="2025-03-01T10:00:00.000", source="nvd@nist.gov"):
    return {"change": {"cveId": cve, "eventName": event, "cveChangeId": change_id,
                       "sourceIdentifier": source, "created": created, "details": details}}

def _page(tmp_path: Path, name: str, changes: list) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"cveChanges": changes}), encoding="utf-8")
    return path

V31_A = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V31_B = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

@pytest.mark.unit
def test_parser_basics():
    assert "AV" not in cvss.vector_components("NIST AV:N/AC:L")
    src, vec = cvss.extract_vector_and_source("NIST AV:N/AC:L/Au:N/C:P/I:P/A:P")
    assert (src, vec) == ("NIST", "AV:N/AC:L/Au:N/C:P/I:P/A:P")
    assert cvss.identify_cvss_version("CVSS V2", vec) == "2.0"
    assert cvss.identify_cvss_version("CVSS V3.1", V31_A) == "3.1"
    assert cvss.changed_components(V31_A, V31_B) == ["I"]
    assert cvss.is_vector_parseable("CVSS:4.0/AV:N/AC:L/AT:N") and not cvss.is_vector_parseable("x")

@pytest.mark.unit
def test_strict_replacement_from_records(tmp_path: Path):
    page = _page(tmp_path, "p.json", [
        _change("CVE-2025-1", "c1", "CVE Modified", [
            {"action": "Removed", "type": "CVSS V3.1", "oldValue": V31_A},
            {"action": "Added", "type": "CVSS V3.1", "newValue": V31_B},
            {"action": "Added", "type": "Reference", "newValue": "https://x"},
        ]),
    ])
    reps = list(cr.iter_replacements(files=[page]))
    assert len(reps) == 1
    r = reps[0]
    assert r.tier == "STRICT" and r.exclusion_reasons == []
    assert r.changed_components == ["I"] and r.cvss_version == "3.1"
    assert (r.removed_detail_index, r.added_detail_index) == (0, 1)
    assert r.replacement_id == "CVE-2025-1|c1|CVSS V3.1" and r.year == "2025"
    assert r.same_source is False

@pytest.mark.unit
@pytest.mark.parametrize(
    "details, event, expected_tier, reason",
    [

        ([{"action": "Added", "type": "Reference", "newValue": "u"}], "CVE Modified", None, None),

        ([{"action": "Added", "type": "CVSS V3.1", "newValue": V31_A}], "CVE Modified", None, None),

        ([{"action": "Removed", "type": "CVSS V3.1", "oldValue": V31_A},
          {"action": "Added", "type": "CVSS V3.1", "newValue": V31_A}], "CVE Modified", "EXCLUDED", "NO_METRIC_CHANGE"),

        ([{"action": "Removed", "type": "CVSS V3.1", "oldValue": V31_A.replace("3.1", "3.0")},
          {"action": "Added", "type": "CVSS V3.1", "newValue": V31_B}], "CVE Modified", "EXCLUDED", "CVSS_VERSION_CHANGED"),

        ([{"action": "Removed", "type": "CVSS V3.1", "oldValue": V31_A},
          {"action": "Added", "type": "CVSS V3.1", "newValue": V31_B}], "Initial Analysis", "EXCLUDED", "ADMINISTRATIVE_OR_BULK_EVENT"),

        ([{"action": "Removed", "type": "CVSS V3.1", "oldValue": V31_A},
          {"action": "Removed", "type": "CVSS V3.1", "oldValue": V31_B},
          {"action": "Added", "type": "CVSS V3.1", "newValue": V31_B}], "CVE Modified", "EXCLUDED", "REMOVED_COUNT_NOT_ONE"),

        ([{"action": "Removed", "type": "CVSS V3.1", "oldValue": V31_A},
          {"action": "Added", "type": "CVSS V3.1", "newValue": V31_B}], "CVE Status Change", "MODERATE", None),
    ],
)
def test_negative_controls(tmp_path: Path, details, event, expected_tier, reason):
    page = _page(tmp_path, "n.json", [_change("CVE-2025-9", "c9", event, details)])
    reps = list(cr.iter_replacements(files=[page]))
    if expected_tier is None:
        assert reps == []
        return
    assert len(reps) == 1 and reps[0].tier == expected_tier
    if reason:
        assert reason in reps[0].exclusion_reasons

@pytest.mark.unit
def test_different_types_and_cves_are_not_matched(tmp_path: Path):
    page = _page(tmp_path, "m.json", [
        _change("CVE-2025-1", "c1", "CVE Modified", [{"action": "Removed", "type": "CVSS V3.1", "oldValue": V31_A}]),
        _change("CVE-2025-1", "c2", "CVE Modified", [{"action": "Added", "type": "CVSS V3.1", "newValue": V31_B}]),
        _change("CVE-2025-2", "c3", "CVE Modified", [
            {"action": "Removed", "type": "CVSS V3.1", "oldValue": V31_A},
            {"action": "Added", "type": "CVSS V4.0", "newValue": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"},
        ]),
    ])
    assert list(cr.iter_replacements(files=[page])) == []

@pytest.mark.full_data
def test_replacement_regression(history_dir):
    stats = cr.ReaderStats()
    reps = list(cr.iter_replacements(history_dir, stats))
    summary = cr.profile(reps, stats)
    assert summary["history_files"] == 322
    assert summary["total_changes"] == 1_590_753
    assert summary["reader_issues"] == 0
    assert summary["candidates"] == 3_653
    assert summary["tier_counts"] == {"STRICT": 3_651, "EXCLUDED": 2}
    assert summary["year_tier_counts"]["STRICT"] == {"2024": 781, "2025": 1_306, "2026": 1_564}
    assert summary["year_tier_counts"]["EXCLUDED"] == {"2024": 2}
    assert summary["unique_cves_by_tier"]["STRICT"] == 3_250
    assert summary["detail_type_tier_counts"]["STRICT"] == {"CVSS V3.1": 3_179, "CVSS V4.0": 387, "CVSS V2": 68, "CVSS V3": 17}
    assert len({r.replacement_id for r in reps}) == len(reps)
