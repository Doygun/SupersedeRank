from __future__ import annotations

import json
from pathlib import Path

import pytest

from src import paths
from src.label import query_time_labels as L
from src.label import splits as sp
from src.normalize import cvss40
from src.normalize.cvss import classify_changed_components
from src.timeline import replay as rp
from src.timeline.config import load_timeline_config
from src.timeline.reported_scores import classify_reported, score_fields

CFG = load_timeline_config()
BOUNDARY = "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N"
WITH_E = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"

@pytest.mark.unit
@pytest.mark.parametrize("x, expected", [(5.6499999999999995, 5.7), (4.949999999999999, 5.0), (8.549999999999999, 8.6),
                                         (5.64, 5.6), (5.65, 5.7), (0.05, 0.1), (9.95, 10.0), (0.0, 0.0)])
def test_1_decimal_half_up(x, expected):
    assert cvss40._decimal_round1(x) == expected

@pytest.mark.unit
def test_2_3_boundary_vector_decimal_vs_js():
    assert cvss40.base_score_v40(BOUNDARY, "decimal") == 5.7
    assert cvss40.base_score_v40(BOUNDARY, "js") == 5.6
    assert cvss40.base_score_v40(BOUNDARY) == 5.7
    assert cvss40.score_from_metrics(cvss40.parse_vector_v40(BOUNDARY), "none") == pytest.approx(5.65, abs=1e-9)

@pytest.mark.full_data
def test_2b_all_boundary_cases_match_nvd_with_decimal_policy():
    path = paths.PROJECT_ROOT / "results" / "quality_assurance" / "cvss40_score_validation.json"
    if not path.exists():
        pytest.skip("Doğrulama JSON'u yok")
    v = json.loads(path.read_text(encoding="utf-8"))
    t = v["counts"]["reported_score_type"]
    assert (v["counts"]["total_vectors"], v["counts"]["parseable"], v["counts"]["comparable"]) == (36_207, 36_207, 36_207)
    assert t == {"CVSS-B": 26_800, "CVSS-BT": 9_386, "ROUNDING_BOUNDARY_EQUIVALENT": 21, "UNRESOLVED": 0}
    assert v["counts"]["not_computable"] == 0 and v["counts"]["nvd_score_missing"] == 0
    for row in v["rounding_boundary_cases"]:
        assert row["decimal_exact_base_score"] == float(row["reported"]) and row["reference_js_base_score"] != float(row["reported"])
        assert abs(row["decimal_exact_base_score"] - row["reference_js_base_score"]) == pytest.approx(0.1)

@pytest.mark.unit
def test_4_5_base_and_bt_separated():
    assert cvss40.base_score_v40(WITH_E) == 8.7 and cvss40.bt_score_v40(WITH_E) == 7.4
    assert cvss40.threat_metric(WITH_E) == "P" and cvss40.threat_metric(BOUNDARY) is None
    f = score_fields("4.0", WITH_E, cvss40.parse_vector_v40(WITH_E) and WITH_E[9:], None, "CVE-1", "cna@x")
    assert f["score_type"] == "CVSS-B" and f["base_score"] == 8.7
    assert f["threat_metric_present"] and f["threat_metric_value"] == "P" and f["bt_score"] == 7.4 and f["bt_score_available"]
    assert f["reported_score"] is None and f["reported_score_type"] == "NOT_AVAILABLE_IN_HISTORY"
    assert classify_reported("4.0", WITH_E, 8.7, 7.4, "HIGH") == ("CVSS-BT", True)
    assert classify_reported("4.0", WITH_E, 8.7, 8.7, "HIGH") == ("CVSS-B", True)
    assert classify_reported("4.0", BOUNDARY, 5.7, 5.7, "MEDIUM") == ("ROUNDING_BOUNDARY_EQUIVALENT", True)
    assert classify_reported("4.0", WITH_E, 8.7, 1.0, "LOW") == ("UNRESOLVED", False)

@pytest.mark.unit
def test_6_evidence_base_score_is_computed_not_reported(tmp_path: Path):
    page = tmp_path / "p.json"
    page.write_text(json.dumps({"cveChanges": [
        {"change": {"cveId": "CVE-2025-1", "eventName": "CVE Modified", "cveChangeId": "c1", "sourceIdentifier": "cna@x",
                    "created": "2025-03-01T10:00:00.000", "details": [{"action": "Added", "type": "CVSS V4.0", "newValue": WITH_E}]}},
    ]}), encoding="utf-8")
    index = {("CVE-2025-1", "cna@x", "4.0", cvss40.parse_vector_v40(WITH_E) and __import__("src.normalize.cvss", fromlist=["canonical_vector"]).canonical_vector(WITH_E)):
             {"reported_score": 7.4, "reported_severity": "HIGH", "vector_string": WITH_E}}
    replayer = rp.ChainReplayer(("CVE-2025-1", "4.0", "cna@x"), CFG, index)
    events = [ev for group in rp.iter_cvss_events(tmp_path, CFG, files=[page]) for ev in group]
    replayer.replay(events)
    e = replayer.evidences[0]
    assert e.base_score == 8.7 and e.base_severity == "HIGH" and e.score_type == "CVSS-B"
    assert e.reported_score == 7.4 and e.reported_score_type == "CVSS-BT" and e.reported_score_matches
    assert e.bt_score == 7.4 and e.threat_metric_present

@pytest.mark.unit
def test_7_8_threat_only_vs_base_change(tmp_path: Path):
    v_a = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X"
    v_e = v_a.replace("E:X", "E:P")
    v_b = v_a.replace("PR:L", "PR:N")
    t = ["2025-03-01T10:00:00.000", "2025-04-01T10:00:00.000", "2025-05-01T10:00:00.000"]
    page = tmp_path / "p.json"
    page.write_text(json.dumps({"cveChanges": [
        {"change": {"cveId": "CVE-2025-7", "eventName": "CVE Modified", "cveChangeId": "c1", "sourceIdentifier": "cna@x", "created": t[0],
                    "details": [{"action": "Added", "type": "CVSS V4.0", "newValue": v_a}]}},
        {"change": {"cveId": "CVE-2025-7", "eventName": "CVE Modified", "cveChangeId": "c2", "sourceIdentifier": "cna@x", "created": t[1],
                    "details": [{"action": "Removed", "type": "CVSS V4.0", "oldValue": v_a}, {"action": "Added", "type": "CVSS V4.0", "newValue": v_e}]}},
        {"change": {"cveId": "CVE-2025-7", "eventName": "CVE Modified", "cveChangeId": "c3", "sourceIdentifier": "cna@x", "created": t[2],
                    "details": [{"action": "Removed", "type": "CVSS V4.0", "oldValue": v_e}, {"action": "Added", "type": "CVSS V4.0", "newValue": v_b.replace("E:X", "E:P")}]}},
    ]}), encoding="utf-8")
    evidences, reports, _, _ = rp.replay_all(files=[page], cfg=CFG, use_reported_index=False)
    first, second = evidences[0], evidences[1]
    assert first.replacement_type == "STRICT_SAME_CHANGE" and first.threat_only_change and not first.base_components_changed
    assert first.changed_threat_components == ["E"] and first.base_score == second.base_score
    assert second.replacement_type == "STRICT_SAME_CHANGE" and second.base_components_changed and second.changed_base_components == ["PR"]
    rows = [e.to_dict() for e in evidences]
    cfg = dict(sp.load_config()); cfg["dev"] = {"fraction_of_train_cves": 0.0, "seed": 1}
    events = sp.main_replacement_events(rows, cfg)
    assert [sp.base_query_eligible(e) for e in events] == [False, True]

@pytest.mark.unit
def test_7b_component_classification_for_v3():
    assert classify_changed_components("3.1", ["E", "RC"])["threat_only_change"]
    assert not classify_changed_components("3.1", ["AV"])["threat_only_change"]
    assert classify_changed_components("3.1", ["AV", "E"])["base_components_changed"]

@pytest.mark.unit
def test_9_10_binary_target():
    assert L.MAIN_LABELS == {L.CURRENT, L.OUTDATED}
    assert L.OTHER_SOURCE_CURRENT not in L.MAIN_LABELS and L.NOT_TARGET_CHAIN not in L.MAIN_LABELS
    e = dict(evidence_id="b", cve_id="CVE-1", source_key="cna@x", cvss_version="3.1", observed_from="2024-01-01T00:00:00+00:00",
             valid_until=None, replacement_type=None, chain_ambiguous=False, valid_from_censored=False)
    q = L.Query(cve_id="CVE-1", source_key="NVD", cvss_version="3.1", query_time="2024-05-01T00:00:00+00:00")
    assert L.label(e, q) not in L.MAIN_LABELS and L.source_relation(e, q) == L.OTHER_SOURCE_CURRENT
    assert not L.is_stale(L.NOT_TARGET_CHAIN) and L.graded_relevance(L.NOT_TARGET_CHAIN, L.OTHER_SOURCE_CURRENT) == 1

@pytest.mark.full_data
def test_full_atomic_counts_preserved_and_base_query_manifest():
    split_dir = paths.PROCESSED_DATA_DIR / "splits"
    if not (split_dir / "base_query_eligible_manifest.json").exists():
        pytest.skip("Base-query manifest yok")
    atomic = json.loads((split_dir / "atomic_replacement_manifest.json").read_text(encoding="utf-8"))
    bq = json.loads((split_dir / "base_query_eligible_manifest.json").read_text(encoding="utf-8"))
    assert atomic["scope"]["timeline_eligible_events"] == 3_649 and atomic["scope"]["main_split_events"] == 3_630
    assert bq["atomic_events_total"] == 3_649
    assert bq["main_split_events"] + bq["counts"]["future_event"]["events"] + bq["excluded_events"] == 3_649
    excluded = [json.loads(l) for l in (split_dir / "base_query" / "excluded_events.jsonl").open(encoding="utf-8")]
    assert len(excluded) == bq["excluded_events"] and all(r["exclusion_reason"] == "EXCLUDED_FROM_BASE_QUERY" for r in excluded)
    for name in ("train", "dev", "test"):
        rows = [json.loads(l) for l in (split_dir / "base_query" / f"{name}.jsonl").open(encoding="utf-8")]
        assert all(r["base_components_changed"] for r in rows)
