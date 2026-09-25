from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.profile import common
from tools.profile import profile_cvss_replacement_candidates as cvss

pytestmark = pytest.mark.unit

def test_normalize_whitespace_keeps_newlines_and_collapses_runs():
    assert common.normalize_whitespace("  a \t b\r\n\r\nc  ") == "a b\nc"
    assert common.normalize_whitespace(None) == ""
    assert common.normalize_whitespace({"b": 1, "a": [2]}) == '{"a":[2],"b":1}'

def test_normalize_whitespace_html_unescape_is_opt_in():
    assert common.normalize_whitespace("a &amp; b") == "a &amp; b"
    assert common.normalize_whitespace("a &amp; b", unescape_html=True) == "a & b"

def test_compact_text_variants():
    assert common.compact_text(None) == "[NULL]"
    assert common.compact_text("x &lt;y&gt;\n  z") == "x <y> z"
    assert common.compact_text("abcdef", limit=3) == "abc...[TRUNCATED]"

    assert common.compact_normalized_text(None) == "[EMPTY]"
    assert common.compact_normalized_text("   ") == "[EMPTY]"
    assert common.compact_normalized_text("a\n\nb") == "a\nb"
    assert common.compact_normalized_text("abcdef", limit=4) == "abcd...[TRUNCATED]"

def test_value_shape_and_year():
    assert [common.value_shape(v) for v in (None, {}, [], True, 1, 1.0, "s")] == [
        "null", "dict", "list", "bool", "int", "float", "string",
    ]
    assert common.parse_timestamp_year("2026-01-02T03:04:05") == "2026"
    assert common.parse_timestamp_year("") == "[UNKNOWN]"
    assert common.parse_timestamp_year("abcd") == "[UNKNOWN]"

def test_iter_changes_strict_and_lenient(tmp_path: Path):
    good = tmp_path / "a.json"
    good.write_text(json.dumps({"cveChanges": [{"change": {"cveId": "CVE-1"}}, {"x": 1}, 3]}), encoding="utf-8")
    assert [c["cveId"] for c in common.iter_changes(good)] == ["CVE-1"]

    bad = tmp_path / "b.json"
    bad.write_text(json.dumps({"cveChanges": "nope"}), encoding="utf-8")
    assert list(common.iter_changes(bad)) == []
    with pytest.raises(ValueError):
        list(common.iter_changes(bad, strict=True))

    bom = tmp_path / "c.json"
    bom.write_bytes(b"\xef\xbb\xbf" + json.dumps({"cveChanges": []}).encode("utf-8"))
    assert list(common.iter_changes(bom, strict=True)) == []

def test_sorted_json_files_is_deterministic(tmp_path: Path):
    for name in ("b.json", "a.json", "c.txt"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    assert [p.name for p in common.sorted_json_files(tmp_path)] == ["a.json", "b.json"]

def test_add_counter_section_format():
    from collections import Counter

    lines: list[str] = []
    common.add_counter_section(lines, "T", Counter({("a", "b"): 1200, "c": 3}))
    assert lines[:4] == ["", "=" * 100, "T", "=" * 100]
    assert lines[4:] == ["a\tb\t1,200", "c\t3"]

def test_file_ref_is_project_relative():
    from src.paths import NVD_HISTORY_DIR

    assert common.file_ref(NVD_HISTORY_DIR / "x.json") == str(Path("data") / "raw" / "nvd" / "history" / "x.json")

def test_extract_vector_and_source_with_and_without_source_prefix():
    assert cvss.extract_vector_and_source("NIST AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == (
        "NIST", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    )
    assert cvss.extract_vector_and_source("CVSS:3.1/AV:N/AC:L") == ("", "CVSS:3.1/AV:N/AC:L")
    assert cvss.extract_vector_and_source("Red Hat, Inc. (AV:L/AC:L)") == ("Red Hat, Inc.", "AV:L/AC:L")
    assert cvss.extract_vector_and_source("no vector here") == ("no vector here", "")
    assert cvss.extract_vector_and_source(None) == ("", "")

def test_vector_components_and_changes():
    assert cvss.vector_components("CVSS:3.1/AV:N/AC:L/PR:N") == {"AV": "N", "AC": "L", "PR": "N"}
    assert cvss.vector_components("AV:N/AC:L") == {"AV": "N", "AC": "L"}
    assert cvss.changed_components("AV:N/AC:L", "AV:N/AC:H") == ["AC"]
    assert cvss.changed_components("AV:N/AC:L", "AV:N/AC:L") == []
    assert cvss.identify_cvss_version("CVSS V3.1", "CVSS:3.0/AV:N") == "3.0"
    assert cvss.identify_cvss_version("CVSS V2", "AV:N") == "2.0"

def _classify(**overrides):
    kwargs = dict(
        event_name="CVE Modified",
        detail_type="CVSS V3.1",
        old_source="NIST",
        new_source="NIST",
        old_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        new_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        removed_count=1,
        added_count=1,
    )
    kwargs.update(overrides)
    return cvss.classify_event_confidence(**kwargs)

def test_strict_replacement_happy_path():
    assert _classify() == ("STRICT", [])

def test_source_name_is_not_a_strict_condition():

    assert _classify(old_source="", new_source="")[0] == "STRICT"
    assert _classify(old_source="NIST", new_source="CISA-ADP")[0] == "STRICT"

@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}, "NO_METRIC_CHANGE"),
        ({"old_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}, "CVSS_VERSION_CHANGED"),
        ({"removed_count": 2}, "REMOVED_COUNT_NOT_ONE"),
        ({"added_count": 0}, "ADDED_COUNT_NOT_ONE"),
        ({"event_name": "Initial Analysis"}, "ADMINISTRATIVE_OR_BULK_EVENT"),
        ({"event_name": "Data Remediation"}, "ADMINISTRATIVE_OR_BULK_EVENT"),
        ({"event_name": "CPE Deprecation Remap"}, "ADMINISTRATIVE_OR_BULK_EVENT"),
        ({"old_vector": ""}, "OLD_VECTOR_NOT_FOUND"),
        ({"new_vector": "garbage"}, "NEW_VECTOR_NOT_PARSEABLE"),
        ({"detail_type": "CVSS V4.0 Score"}, "UNSUPPORTED_CVSS_DETAIL_TYPE"),
    ],
)
def test_excluded_replacements(overrides, reason):
    tier, reasons = _classify(**overrides)
    assert tier == "EXCLUDED"
    assert reason in reasons

def test_unlisted_event_name_is_not_strict():

    tier, _ = _classify(event_name="CVE Status Change")
    assert tier == "MODERATE"
