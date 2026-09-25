from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.timeline import replay as rp
from src.timeline.config import load_timeline_config

CFG = load_timeline_config()
V_A = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V_B = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
V_C = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

def change(cve, cid, created, details, event="CVE Modified", source="nvd@nist.gov"):
    return {"change": {"cveId": cve, "eventName": event, "cveChangeId": cid, "sourceIdentifier": source,
                       "created": created, "details": details}}

def rem(v, t="CVSS V3.1"):
    return {"action": "Removed", "type": t, "oldValue": v}

def add(v, t="CVSS V3.1"):
    return {"action": "Added", "type": t, "newValue": v}

def run(tmp_path: Path, changes: list):
    page = tmp_path / "p.json"
    page.write_text(json.dumps({"cveChanges": changes}), encoding="utf-8")
    evidences, reports, candidates, pair_stats = rp.replay_all(files=[page], cfg=CFG)
    return evidences, reports, candidates, pair_stats

T1, T2, T3, T4 = "2024-03-01T10:00:00.000", "2024-05-01T10:00:00.000", "2024-07-01T10:00:00.000", "2024-09-01T10:00:00.000"

@pytest.mark.unit
def test_strict_same_change_replacement_creates_supersession(tmp_path):
    ev, reports, cands, _ = run(tmp_path, [
        change("CVE-1", "c1", T1, [add(V_A)]),
        change("CVE-1", "c2", T2, [rem(V_A), add(V_B)]),
    ])
    assert [e.timeline_status for e in ev] == ["REPLACED", "ACTIVE"]
    old, new = ev
    assert old.replacement_type == "STRICT_SAME_CHANGE" and old.superseded_by_evidence_id == new.evidence_id
    assert old.valid_from is not None and not old.valid_from_censored and old.valid_until == new.valid_from
    assert new.replaces_evidence_id == old.evidence_id and new.valid_until is None and new.valid_until_censored
    assert reports[0].strict_same_change == 1 and not reports[0].ambiguous and cands == []
    assert old.base_score == 7.5 and new.base_score == 9.1 and new.base_severity == "CRITICAL"

@pytest.mark.unit
def test_first_observed_removal_infers_left_censored_initial_state(tmp_path):
    ev, reports, _, _ = run(tmp_path, [change("CVE-2", "c1", T2, [rem(V_A), add(V_B)])])
    old = ev[0]
    assert old.valid_from is None and old.valid_from_censored and old.inferred_initial_state
    assert old.inference_rule == "FIRST_OBSERVED_EVENT_IS_REMOVAL"
    assert old.observed_from == CFG.window_start >= "2024-01-01"
    assert old.first_observed_event_time.startswith("2024-05-01") and old.valid_until.startswith("2024-05-01")
    assert old.replacement_type == "STRICT_SAME_CHANGE"
    assert reports[0].first_event_action == "Removed"

@pytest.mark.unit
def test_first_observed_addition_does_not_invent_prior_value(tmp_path):
    ev, reports, _, _ = run(tmp_path, [change("CVE-3", "c1", T1, [add(V_A)])])
    assert len(ev) == 1 and ev[0].timeline_status == "INITIAL_ADDITION"
    assert not ev[0].valid_from_censored and ev[0].valid_from.startswith("2024-03-01")
    assert ev[0].replacement_type is None and reports[0].first_event_action == "Added"

@pytest.mark.unit
def test_lone_removal_without_replacement_is_withdrawn_not_outdated(tmp_path):
    ev, reports, _, _ = run(tmp_path, [change("CVE-4", "c1", T1, [add(V_A)]), change("CVE-4", "c2", T2, [rem(V_A)])])
    assert ev[0].timeline_status == "WITHDRAWN_WITHOUT_REPLACEMENT"
    assert ev[0].replacement_type is None and ev[0].superseded_by_evidence_id is None
    assert ev[0].valid_until.startswith("2024-05-01")

@pytest.mark.unit
def test_cross_event_candidate_is_reported_but_not_supersession(tmp_path):
    ev, reports, cands, _ = run(tmp_path, [
        change("CVE-5", "c1", T1, [add(V_A)]),
        change("CVE-5", "c2", T2, [rem(V_A)]),
        change("CVE-5", "c3", T3, [add(V_B)]),
    ])
    old, new = ev
    assert old.timeline_status == "REPLACED" and old.replacement_type == "HIGH_CONFIDENCE_CROSS_EVENT"
    assert old.superseded_by_evidence_id is None
    assert new.replaces_evidence_id == old.evidence_id
    assert len(cands) == 1 and cands[0].gap_days == pytest.approx(61.0) and cands[0].changed_components == ["I"]
    assert reports[0].cross_event_candidates == 1

@pytest.mark.unit
def test_same_value_readded_is_not_reversal(tmp_path):
    ev, reports, cands, _ = run(tmp_path, [
        change("CVE-6", "c1", T1, [add(V_A)]),
        change("CVE-6", "c2", T2, [rem(V_A)]),
        change("CVE-6", "c3", T3, [add(V_A)]),
    ])
    assert ev[0].timeline_status == "WITHDRAWN_WITHOUT_REPLACEMENT"
    assert ev[1].readded_same_value and not ev[1].explicit_reversal and cands == []
    assert reports[0].same_value_readds == 1 and reports[0].reversals == 0

@pytest.mark.unit
def test_reversal_a_b_a_is_flagged_not_error(tmp_path):
    ev, reports, _, _ = run(tmp_path, [
        change("CVE-7", "c1", T1, [add(V_A)]),
        change("CVE-7", "c2", T2, [rem(V_A), add(V_B)]),
        change("CVE-7", "c3", T3, [rem(V_B), add(V_A)]),
    ])
    assert [e.vector for e in ev] == [V_A, V_B, V_A]
    assert ev[2].explicit_reversal and reports[0].reversals == 1 and not reports[0].ambiguous
    assert ev[0].superseded_by_evidence_id == ev[1].evidence_id and ev[1].superseded_by_evidence_id == ev[2].evidence_id

@pytest.mark.unit
def test_sources_are_separate_chains_and_never_supersede_each_other(tmp_path):
    ev, reports, _, _ = run(tmp_path, [
        change("CVE-8", "c1", T1, [add(V_A)], source="nvd@nist.gov"),
        change("CVE-8", "c2", T2, [add(V_B)], source="cna@example.org"),
    ])
    assert len(reports) == 2 and {r.source_key for r in reports} == {"NVD", "cna@example.org"}
    assert all(e.timeline_status == "INITIAL_ADDITION" and e.valid_until is None for e in ev)

@pytest.mark.unit
def test_duplicate_rewrite_and_competing_values(tmp_path):
    ev, reports, _, _ = run(tmp_path, [
        change("CVE-9", "c1", T1, [add(V_A)]),
        change("CVE-9", "c2", T2, [rem(V_A), add(V_A)]),
        change("CVE-9", "c3", T3, [add(V_C)]),
    ])
    r = reports[0]
    assert r.duplicate_rewrites == 1 and r.excluded_same_change == 1
    assert "MULTIPLE_COMPETING_ACTIVE_VALUES" in r.ambiguity_reasons and all(e.chain_ambiguous for e in ev)
    assert len(ev) == 2 and ev[0].valid_until is None

@pytest.mark.unit
def test_version_change_is_split_across_chains(tmp_path):
    ev, reports, _, pair_stats = run(tmp_path, [
        change("CVE-10", "c1", T1, [add("CVSS:3.0/" + V_A)]),
        change("CVE-10", "c2", T2, [rem("CVSS:3.0/" + V_A), add("CVSS:3.1/" + V_B)]),
    ])
    assert pair_stats.get("version_change") == 1
    assert {r.cvss_version for r in reports} == {"3.0", "3.1"}
    assert all(e.replacement_type != "STRICT_SAME_CHANGE" for e in ev)

@pytest.mark.unit
def test_prefix_difference_does_not_break_chain(tmp_path):
    v4a = "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    v4b = v4a.replace("PR:L", "PR:N")
    ev, reports, _, _ = run(tmp_path, [
        change("CVE-11", "c1", T1, [rem(v4a, "CVSS V4.0"), add("CVSS:4.0/" + v4b, "CVSS V4.0")]),
        change("CVE-11", "c2", T2, [rem(v4b, "CVSS V4.0"), add(v4a, "CVSS V4.0")]),
    ])
    assert [e.timeline_status for e in ev] == ["REPLACED", "REPLACED", "ACTIVE"]
    assert reports[0].strict_same_change == 2 and reports[0].unmatched_removed == 0
    assert ev[1].base_score == 9.3 and ev[2].base_score == 8.7

@pytest.mark.unit
def test_observation_window_comes_from_config():
    assert CFG.window_start == "2024-01-01T00:00:00+00:00"
    assert CFG.left_censoring["generate_queries_before_window"] is False
    assert CFG.source_key("nvd@nist.gov") == "NVD" and CFG.source_key("unknown@x") == "unknown@x"

@pytest.mark.full_data
def test_replay_regression(history_dir):
    stats = rp.ReaderStats()
    evidences, reports, candidates, pair_stats = rp.replay_all(history_dir, CFG, stats)
    summary = rp.profile(evidences, reports, candidates, pair_stats, stats, CFG)
    assert summary["same_change"]["candidates"] == 3_653
    assert summary["same_change"]["strict"] == 3_651
    assert summary["same_change"]["excluded"] == 2
    assert summary["replacement_type_counts"]["STRICT_SAME_CHANGE"] == 3_651
    assert summary["reader_issues"] == 0

    assert summary["same_change"]["source_prefix_change"] == 2
    strict_old = [e for e in evidences if e.replacement_type == "STRICT_SAME_CHANGE"]
    assert sum(1 for e in strict_old if e.valid_from_censored) + sum(1 for e in strict_old if not e.valid_from_censored) == 3_651
    assert summary["same_timestamp_conflicts"] == 0 and summary["competing_active_events"] == 0

    by_id = {e.evidence_id: e for e in evidences}
    for e in evidences:
        if e.replacement_type == "STRICT_SAME_CHANGE":
            new = by_id[e.superseded_by_evidence_id]
            assert new.chain_id == e.chain_id and e.valid_until == new.valid_from and new.valid_from > (e.valid_from or "")

    assert all((e.valid_until is None) == e.valid_until_censored for e in evidences)
