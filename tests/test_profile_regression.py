from __future__ import annotations

import re
from pathlib import Path

import pytest

EXPECTED = {
    "history_files": 322,
    "changes": 1_590_753,
    "details": 3_249_766,
    "changed_details": 148_651,
    "changed_same_after_normalization": 5_054,
    "multi_detail_changes": 525_682,
    "removed_added_changes": 18_909,
    "malformed_details": 0,
    "read_errors": 0,
    "cvss_candidates": 3_653,
    "strict": 3_651,
    "moderate": 0,
    "excluded": 2,
    "strict_unique_cves": 3_250,
    "year_total": {"2024": 783, "2025": 1_306, "2026": 1_564},
    "year_strict": {"2024": 781, "2025": 1_306, "2026": 1_564},
    "year_excluded": {"2024": 2},
    "details_empty_list": 356_079,
    "event_names": {
        "CVE Modified": 1_190_858,
        "New CVE Received": 156_330,
        "Initial Analysis": 95_658,
        "CVE Status Change": 94_219,
        "CPE Deprecation Remap": 23_650,
        "Modified Analysis": 8_400,
        "CVE Translated": 7_123,
        "CVE Rejected": 4_646,
        "Data Remediation": 4_614,
        "Reanalysis": 3_106,
        "CVE CISA KEV Update": 1_259,
        "Reference Tag Update": 844,
        "CVE Unrejected": 40,
        "CVE Source Update": 6,
    },
}

def _int(text: str) -> int:
    return int(text.replace(",", "").replace(".", ""))

def scalar(report: str, label: str) -> int:
    match = re.search(rf"^{re.escape(label)}:\s*([\d,\.]+)\s*$", report, re.MULTILINE)
    assert match, f"'{label}' satiri raporda yok"
    return _int(match.group(1))

def section(report: str, title: str) -> list[str]:
    lines = report.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == title:
            body: list[str] = []
            for candidate in lines[index + 1:]:
                if candidate.startswith("=") or candidate.startswith("-"):
                    if body:
                        break
                    continue
                if not candidate.strip():
                    if body:
                        break
                    continue
                body.append(candidate)
            return body
    raise AssertionError(f"'{title}' bolumu raporda yok")

def tab_counter(report: str, title: str) -> dict[tuple[str, ...], int]:
    result: dict[tuple[str, ...], int] = {}
    for line in section(report, title):
        parts = line.split("\t")
        result[tuple(parts[:-1])] = _int(parts[-1])
    return result

@pytest.fixture(scope="module")
def reports(data_profile_dir: Path) -> dict[str, str]:
    names = {
        "history": "nvd_history_profile.txt",
        "patterns": "nvd_change_pattern_report.txt",
        "cvss": "cvss_replacement_candidate_report.txt",
        "empty": "empty_nvd_details_report.txt",
    }
    loaded: dict[str, str] = {}
    for key, name in names.items():
        path = data_profile_dir / name
        if not path.exists():
            pytest.skip(f"Baseline raporu yok: {path}")
        loaded[key] = path.read_text(encoding="utf-8")
    return loaded

@pytest.mark.unit
def test_baseline_history_profile(reports):
    report = reports["history"]
    assert scalar(report, "Dosya sayisi") == EXPECTED["history_files"]
    assert scalar(report, "Change sayisi") == EXPECTED["changes"]
    assert scalar(report, "Detail sayisi") == EXPECTED["details"]
    assert scalar(report, "OldValue ve NewValue birlikte bulunan detail") == EXPECTED["changed_details"]
    assert scalar(report, "Bozuk change sayisi") == 0
    assert scalar(report, "Bozuk detail sayisi") == 0
    assert scalar(report, "Dosya okuma hatasi") == EXPECTED["read_errors"]

    events = {key[0]: count for key, count in tab_counter(report, "EVENT NAME DAGILIMI").items()}
    assert events == EXPECTED["event_names"]

@pytest.mark.unit
def test_baseline_change_patterns(reports):
    report = reports["patterns"]
    assert scalar(report, "Dosya sayisi") == EXPECTED["history_files"]
    assert scalar(report, "Change sayisi") == EXPECTED["changes"]
    assert scalar(report, "Detail sayisi") == EXPECTED["details"]
    assert scalar(report, "Changed detail sayisi") == EXPECTED["changed_details"]
    assert scalar(report, "Normalize edilince ayni kalan Changed detail") == EXPECTED["changed_same_after_normalization"]
    assert scalar(report, "Birden fazla detail iceren change") == EXPECTED["multi_detail_changes"]
    assert scalar(report, "Hem Removed hem Added iceren change") == EXPECTED["removed_added_changes"]
    assert scalar(report, "Bozuk detail sayisi") == EXPECTED["malformed_details"]
    assert scalar(report, "Dosya okuma hatasi") == EXPECTED["read_errors"]

@pytest.mark.unit
def test_baseline_cvss_replacements(reports):
    report = reports["cvss"]
    assert scalar(report, "History dosya sayisi") == EXPECTED["history_files"]
    assert scalar(report, "Toplam incelenen change") == EXPECTED["changes"]
    assert scalar(report, "CVSS Removed+Added adayi") == EXPECTED["cvss_candidates"]
    assert scalar(report, "STRICT aday") == EXPECTED["strict"]
    assert scalar(report, "MODERATE aday") == EXPECTED["moderate"]
    assert scalar(report, "EXCLUDED aday") == EXPECTED["excluded"]
    assert scalar(report, "Dosya okuma hatasi") == EXPECTED["read_errors"]
    assert scalar(report, "STRICT") == EXPECTED["strict_unique_cves"]

    years = {key[0]: count for key, count in tab_counter(report, "YIL DAGILIMI").items()}
    assert years == EXPECTED["year_total"]

    year_tier = tab_counter(report, "YIL + TIER DAGILIMI")
    strict_by_year = {year: count for (year, tier), count in year_tier.items() if tier == "STRICT"}
    excluded_by_year = {year: count for (year, tier), count in year_tier.items() if tier == "EXCLUDED"}
    assert strict_by_year == EXPECTED["year_strict"]
    assert excluded_by_year == EXPECTED["year_excluded"]

    assert EXPECTED["year_total"]["2024"] == EXPECTED["year_strict"]["2024"] + EXPECTED["year_excluded"]["2024"]

@pytest.mark.unit
def test_baseline_empty_details(reports):
    report = reports["empty"]
    match = re.search(r"^Toplam change:\s*([\d,]+)", report, re.MULTILINE)
    assert match and _int(match.group(1)) == EXPECTED["changes"]
    reasons = {key[0]: count for key, count in tab_counter(report, "BOS SIGNATURE NEDENLERI").items()}
    assert reasons == {"DETAILS_EMPTY_LIST": EXPECTED["details_empty_list"]}

@pytest.mark.full_data
def test_refactored_history_profile_matches_baseline(history_dir):
    from tools.profile import profile_nvd_history as module

    summary = module.run(history_dir, verbose=False)
    assert summary["file_count"] == EXPECTED["history_files"]
    assert summary["total_changes"] == EXPECTED["changes"]
    assert summary["total_details"] == EXPECTED["details"]
    assert summary["details_with_both_values"] == EXPECTED["changed_details"]
    assert summary["read_error_count"] == EXPECTED["read_errors"]
    assert dict(summary["event_names"]) == EXPECTED["event_names"]

@pytest.mark.full_data
def test_refactored_change_patterns_match_baseline(history_dir):
    from tools.profile import analyze_nvd_change_patterns as module

    summary = module.run(history_dir, verbose=False)
    assert summary["total_changes"] == EXPECTED["changes"]
    assert summary["total_details"] == EXPECTED["details"]
    assert summary["total_changed_details"] == EXPECTED["changed_details"]
    assert summary["total_changed_same_normalized"] == EXPECTED["changed_same_after_normalization"]
    assert summary["total_multi_detail_changes"] == EXPECTED["multi_detail_changes"]
    assert summary["total_removed_added_changes"] == EXPECTED["removed_added_changes"]
    assert summary["read_error_count"] == EXPECTED["read_errors"]

@pytest.mark.full_data
def test_refactored_cvss_replacements_match_baseline(history_dir):
    from src.profile.common import sorted_json_files
    from tools.profile import profile_cvss_replacement_candidates as module

    files = sorted_json_files(history_dir)
    rows, read_errors, total_changes = module.collect_candidates(files, verbose=False)
    summary = module.summarize(files, rows, read_errors, total_changes)

    assert summary["file_count"] == EXPECTED["history_files"]
    assert summary["total_changes"] == EXPECTED["changes"]
    assert summary["candidate_count"] == EXPECTED["cvss_candidates"]
    assert summary["tier_counts"] == {"STRICT": EXPECTED["strict"], "EXCLUDED": EXPECTED["excluded"]}
    assert summary["read_error_count"] == EXPECTED["read_errors"]
    assert summary["year_counts"] == EXPECTED["year_total"]
    assert summary["year_tier_counts"]["STRICT"] == EXPECTED["year_strict"]
    assert summary["year_tier_counts"]["EXCLUDED"] == EXPECTED["year_excluded"]
    assert summary["unique_cves_by_tier"]["STRICT"] == EXPECTED["strict_unique_cves"]

@pytest.mark.full_data
def test_refactored_empty_details_match_baseline(history_dir):
    from tools.profile import inspect_empty_nvd_details as module

    summary = module.run(history_dir, verbose=False)
    assert summary["total_changes"] == EXPECTED["changes"]
    assert dict(summary["reason_counts"]) == {"DETAILS_EMPTY_LIST": EXPECTED["details_empty_list"]}
