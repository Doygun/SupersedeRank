from __future__ import annotations

import json
from collections import Counter

import pytest

from src import paths
from src.normalize.cvss import base_score, base_severity

@pytest.mark.unit
@pytest.mark.parametrize(
    "version, vector, score, severity",
    [
        ("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
        ("3.1", "AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N", 6.6, "MEDIUM"),
        ("3.1", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
        ("3.1", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
        ("3.0", "AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.4, "MEDIUM"),
        ("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, "HIGH"),
        ("2.0", "AV:L/AC:H/Au:M/C:N/I:N/A:N", 0.0, "LOW"),
    ],
)
def test_known_scores(version, vector, score, severity):
    assert base_score(version, vector) == score
    assert base_severity(version, score) == severity

@pytest.mark.unit
def test_unsupported_or_wildcard_vectors_return_none():
    assert base_score("4.0", "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == 9.3
    assert base_score("4.0", "AV:N/AC:L") is None
    assert base_score("3.1", "AV:*/AC:*/PR:*/UI:R/S:*/C:*/I:*/A:*") is None
    assert base_severity("3.1", None) is None

@pytest.mark.full_data
def test_calculator_matches_nvd_published_scores():
    files = sorted(paths.NVD_CVE_DIR.glob("*.json"))
    if not files:
        pytest.skip("NVD CVE verisi yok")
    checked: Counter[str] = Counter()
    mismatches: list[tuple] = []
    for path in files[:40]:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        for item in payload["vulnerabilities"]:
            metrics = item["cve"].get("metrics", {})
            for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
                for entry in metrics.get(key, []):
                    data = entry["cvssData"]
                    calc = base_score(version, data["vectorString"])
                    published_severity = entry.get("baseSeverity") or data.get("baseSeverity")
                    checked[version] += 1
                    if calc != data["baseScore"] or base_severity(version, calc) != published_severity:
                        mismatches.append((version, data["vectorString"], data["baseScore"], calc))
    assert sum(checked.values()) > 50_000
    assert mismatches == []
