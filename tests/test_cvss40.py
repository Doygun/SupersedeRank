from __future__ import annotations

import json

import pytest

from src import paths
from src.normalize import cvss40

B = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

@pytest.mark.unit
def test_parser_reads_all_metric_groups():
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:Red"
    m = cvss40.parse_vector_v40(v)
    assert [m[k] for k in cvss40.BASE_METRICS] == list("NLNHNHHHNNN")
    assert m["E"] == "P" and m["U"] == "Red" and m["MSI"] == "X"
    assert cvss40.parse_vector_v40("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")["E"] == "X"

@pytest.mark.unit
@pytest.mark.parametrize("vector", ["CVSS:4.0/AV:N/AC:L", "CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"])
def test_parser_rejects_invalid(vector):
    with pytest.raises(cvss40.Cvss40ParseError):
        cvss40.parse_vector_v40(vector)

@pytest.mark.unit
def test_macro_vector_and_lookup_edges():
    assert cvss40.macro_vector(cvss40.parse_vector_v40(B)) == "000100"
    assert cvss40.base_score_v40(B) == 10.0
    assert cvss40.base_score_v40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N") == 0.0
    assert cvss40.base_score_v40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == 9.3
    assert cvss40.base_score_v40("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N") < 2.0

@pytest.mark.unit
def test_threat_metrics_ignored_in_base_score_but_used_in_full_score():
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"
    assert cvss40.base_score_v40(v) == 9.3
    assert cvss40.score_v40(v) == 8.9 and cvss40.score_v40(v) < cvss40.base_score_v40(v)

@pytest.mark.unit
def test_rounding_is_js_math_round():
    assert cvss40._js_round1(8.85) == 8.9 and cvss40._js_round1(8.84) == 8.8 and cvss40._js_round1(0.05) == 0.1

@pytest.mark.unit
def test_tables_reference_version_recorded():
    assert cvss40.REFERENCE_VERSION.startswith("HEAD c5b0d409")
    from src.normalize.cvss40_tables import CVSS_LOOKUP
    assert len(CVSS_LOOKUP) == 270 and CVSS_LOOKUP["000000"] == 10.0 and CVSS_LOOKUP["000001"] == 9.9

@pytest.mark.full_data
def test_base_score_matches_nvd_when_no_threat_or_env_metrics():
    files = sorted(paths.NVD_CVE_DIR.glob("*.json"))[:30]
    checked = exact = 0
    boundary_cases = []
    for path in files:
        for item in json.loads(path.read_text(encoding="utf-8-sig"))["vulnerabilities"]:
            for entry in item["cve"].get("metrics", {}).get("cvssMetricV40", []):
                vec = entry["cvssData"]["vectorString"]
                base, full = cvss40.base_score_v40(vec), cvss40.score_v40(vec)
                if base != full:
                    continue
                checked += 1
                nvd = float(entry["cvssData"]["baseScore"])
                if base == nvd:
                    exact += 1
                    continue

                sel = cvss40.parse_vector_v40(vec)
                base_only = {m: sel[m] for m in cvss40.BASE_METRICS} | {m: "X" for m in cvss40.THREAT_METRICS + cvss40.ENV_METRICS + cvss40.SUPPLEMENTAL_METRICS}
                original = cvss40._js_round1
                cvss40._js_round1 = lambda v: v
                try:
                    raw10 = cvss40.score_from_metrics(base_only) * 10
                finally:
                    cvss40._js_round1 = original
                assert abs(raw10 - (round(raw10) + 0.5 if raw10 - round(raw10) > 0 else round(raw10) - 0.5)) < 1e-6 or abs(raw10 - (int(raw10) + 0.5)) < 1e-6, (item["cve"]["id"], vec, nvd, base, raw10)
                assert abs(base - nvd) <= 0.1 + 1e-9
                boundary_cases.append(item["cve"]["id"])
    assert checked > 1000 and exact / checked > 0.999, (checked, exact, boundary_cases)
