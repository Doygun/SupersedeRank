from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from src import paths
from src.evidence import build_evidence as BE
from src.label import query_time_labels as L
from src.queries import build_queries as BQ

CFG = BE.load_config()
QDIR = paths.PROCESSED_DATA_DIR / "queries"
EDIR = paths.PROCESSED_DATA_DIR / "evidence"
SPLITS = ("train", "dev", "test", "future_event")
FORBIDDEN = re.compile("|".join(re.escape(w) for w in CFG["evidence"]["forbidden_words_in_text"]), re.IGNORECASE)

def _rows(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.open(encoding="utf-8")]

def _need_files():
    if not (QDIR / "query_manifest.json").exists() or not (EDIR / "evidence.jsonl").exists():
        pytest.skip("Evidence/sorgu dosyaları üretilmedi")

@pytest.fixture(scope="module")
def data():
    _need_files()
    ev = _rows(EDIR / "evidence.jsonl")
    return {
        "ev": ev, "by_id": {e["evidence_id"]: e for e in ev},
        "q": {s: _rows(QDIR / f"{s}_queries.jsonl") for s in SPLITS},
        "manifest": json.loads((QDIR / "query_manifest.json").read_text(encoding="utf-8")),
        "excluded": _rows(QDIR / "excluded_queries.jsonl"),
        "bq_excluded": _rows(paths.PROCESSED_DATA_DIR / "splits" / "base_query" / "excluded_events.jsonl"),
    }

def _all(d):
    return [q for s in SPLITS for q in d["q"][s]]

def _ev(**kw):
    base = dict(evidence_id="CVE-1|3.1|NVD|1", cve_id="CVE-1", source_identifier_raw="nvd@nist.gov", source_key="NVD",
                cvss_version="3.1", vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", vector_raw="NIST AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=9.8, base_severity="CRITICAL", valid_from="2024-03-01T00:00:00+00:00", valid_until=None,
                valid_from_censored=False, observed_from="2024-03-01T00:00:00+00:00")
    base.update(kw)
    row = dict(base)
    row["base_vector"] = BE.base_vector(row["cvss_version"], row["vector"])
    return row

@pytest.mark.unit
def test_15_16_17_evidence_text_templates():
    active = _ev()
    text = BE.evidence_text(active, CFG)
    assert text.startswith("As of 2024-03-01, NVD assessed CVE-1 under CVSS 3.1 with Base metric vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert "9.8" in text and "Critical severity" in text and not FORBIDDEN.search(text)
    censored = _ev(valid_from=None, valid_from_censored=True, observed_from="2024-01-01T00:00:00+00:00")
    ctext = BE.evidence_text(censored, CFG)
    assert ctext.startswith("At the beginning of the observation window, NVD had an active CVSS 3.1 Base assessment for CVE-1")
    assert "2024-01-01" not in ctext and not FORBIDDEN.search(ctext)
    no_score = _ev(base_score=None, base_severity=None)
    assert "score" not in BE.evidence_text(no_score, CFG)

@pytest.mark.unit
def test_23_24_base_vector_strips_non_base_metrics():
    assert BE.base_vector("4.0", "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:X/S:X") == \
        "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert BE.base_vector("3.1", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C") == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert BE.base_vector("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C") == "AV:N/AC:L/Au:N/C:P/I:P/A:P"

@pytest.mark.unit
def test_19_20_query_time_rules():
    rule = CFG["queries"]["post_replacement"]
    t, why = BQ.query_time_post("2025-01-01T00:00:00+00:00", "2025-01-11T00:00:00+00:00", "2026-09-14T23:59:59+00:00", rule)
    assert why is None and t == "2025-01-06T00:00:00+00:00"
    t2, _ = BQ.query_time_post("2025-01-01T00:00:00+00:00", None, "2026-09-14T23:59:59+00:00", rule)
    assert t2 == "2025-01-31T00:00:00+00:00"
    t3, why3 = BQ.query_time_post("2025-01-01T00:00:00+00:00", "2025-01-01T00:00:01+00:00", "2026-09-14T23:59:59+00:00", rule)
    assert t3 is None and why3 == "NEW_INTERVAL_TOO_SHORT"
    pre = CFG["queries"]["pre_replacement_control"]
    tp, _ = BQ.query_time_pre("2024-01-05T00:00:00+00:00", "2024-01-01T00:00:00+00:00", "2024-01-01T00:00:00+00:00", pre)
    assert tp == "2024-01-03T00:00:00+00:00" and tp >= "2024-01-01T00:00:00+00:00"

@pytest.mark.unit
def test_14_other_source_current_is_not_a_temporal_label():
    assert L.MAIN_LABELS == {L.CURRENT, L.OUTDATED} and L.OTHER_SOURCE_CURRENT not in L.MAIN_LABELS

@pytest.mark.unit
def test_21_query_generation_is_reproducible(tmp_path: Path):
    split_dir = tmp_path / "splits"; (split_dir / "base_query").mkdir(parents=True)
    old = _ev(evidence_id="CVE-9|3.1|NVD|1", cve_id="CVE-9", valid_until="2025-02-01T00:00:00+00:00")
    new = _ev(evidence_id="CVE-9|3.1|NVD|2", cve_id="CVE-9", vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", base_score=8.8, base_severity="HIGH",
              valid_from="2025-02-01T00:00:00+00:00", observed_from="2025-02-01T00:00:00+00:00")
    for e in (old, new):
        e.update(dict(replacement_type="STRICT_SAME_CHANGE" if e is old else None, chain_ambiguous=False,
                      superseded_by_evidence_id=new["evidence_id"] if e is old else None, split="train", evidence_role="x",
                      activation_event_id="a#0", termination_event_id="b#0" if e is old else None))
    evp = tmp_path / "evidence.jsonl"
    evp.write_text("\n".join(json.dumps(e) for e in (old, new)) + "\n", encoding="utf-8")
    event = {"event_time": old["valid_until"], "cve_id": "CVE-9", "cvss_version": "3.1", "source_key": "NVD",
             "old_evidence_id": old["evidence_id"], "new_evidence_id": new["evidence_id"], "termination_event_id": "b#0", "year": 2025}
    for s in SPLITS:
        (split_dir / "base_query" / f"{s}.jsonl").write_text(json.dumps(event) + "\n" if s == "train" else "", encoding="utf-8")
    out1, ex1, m1 = BQ.build(evp, split_dir, CFG)
    out2, ex2, m2 = BQ.build(evp, split_dir, CFG)
    assert out1 == out2 and ex1 == ex2 and m1["config_sha256"] == m2["config_sha256"]
    main = [q for q in out1["train"] if q["query_role"] == "POST_REPLACEMENT_MAIN"]
    assert len(main) == 1 and main[0]["current_evidence_ids"] == [new["evidence_id"]] and main[0]["outdated_evidence_ids"] == [old["evidence_id"]]
    assert main[0]["answer_base_score"] == 8.8 and main[0]["query_time"] > old["valid_until"]

@pytest.mark.full_data
def test_01_02_03_ids_unique_and_single_split(data):
    ev, all_q = data["ev"], _all(data)
    assert len({e["evidence_id"] for e in ev}) == len(ev)
    assert len({q["query_id"] for q in all_q}) == len(all_q)
    assert all(q["split"] == s for s in SPLITS for q in data["q"][s])

@pytest.mark.full_data
def test_04_05_06_targets(data):
    by_id = data["by_id"]
    for q in _all(data):
        t = by_id[q["answer_evidence_id"]]
        assert (t["cve_id"], t["source_key"], t["cvss_version"]) == (q["cve_id"], q["source_key"], q["cvss_version"])
        assert q["current_evidence_ids"]
        if q["query_role"] == "POST_REPLACEMENT_MAIN":
            assert q["outdated_evidence_ids"]
            assert all(by_id[i]["replacement_type"] == "STRICT_SAME_CHANGE" and by_id[i]["valid_until"] <= q["query_time"] for i in q["outdated_evidence_ids"])

@pytest.mark.full_data
def test_07_no_future_evidence_visible(data):
    by_id = data["by_id"]
    for q in _all(data):
        assert all(by_id[i]["observed_from"] <= q["query_time"] for i in q["visible_evidence_ids"])
        assert by_id[q["replacing_new_evidence_id"]]["observed_from"] > q["query_time"] or q["query_role"] == "POST_REPLACEMENT_MAIN" or q["replacing_new_evidence_id"] not in q["visible_evidence_ids"]

@pytest.mark.full_data
def test_08_09_split_isolation(data):
    q = data["q"]
    assert not ({x["cve_id"] for x in q["test"]} & {x["cve_id"] for x in q["train"] + q["dev"]})
    assert not ({x["query_id"] for x in q["future_event"]} & {x["query_id"] for x in q["test"]})
    assert all(x["split"] == "future_event" for x in q["future_event"])

@pytest.mark.full_data
def test_10_11_no_queries_from_threat_or_supplemental_only_events(data):
    excluded_events = {r["event_id"] for r in data["bq_excluded"]}
    assert len(excluded_events) == 93
    assert all(q["source_event_id"] not in excluded_events for q in _all(data))
    by_detail = {}
    for r in data["bq_excluded"]:
        by_detail.setdefault(r["exclusion_detail"], 0); by_detail[r["exclusion_detail"]] += 1
    assert by_detail["THREAT_ONLY_CHANGE"] == 70 and sum(by_detail.values()) == 93

@pytest.mark.full_data
def test_12_13_answers_are_computed_cvssb(data):
    by_id = data["by_id"]
    from src.normalize.cvss import base_score
    for q in _all(data):
        t = by_id[q["answer_evidence_id"]]
        assert t["score_type"] == "CVSS-B" and q["answer_base_score"] == t["base_score"]
        assert base_score(t["cvss_version"], t["base_vector"]) == t["base_score"]
        if t["bt_score"] is not None and t["bt_score"] != t["base_score"]:
            assert q["answer_base_score"] != t["bt_score"]
        assert t["reported_score"] is None or q["answer_base_score"] == t["base_score"]

@pytest.mark.full_data
def test_15_16_17_18_evidence_text_and_boundaries(data):
    for e in data["ev"]:
        assert not FORBIDDEN.search(e["evidence_text"]), e["evidence_id"]
        assert (e["replaced_by_evidence_id"] or "\x00") not in e["evidence_text"]
        assert e["evidence_text"].startswith("At the beginning of the observation window") == bool(e["valid_from_censored"])
        if not e["valid_from_censored"]:
            assert e["valid_from"] is not None and e["activation_event_id"] is not None and e["valid_from"][:10] in e["evidence_text"]
        else:
            assert e["valid_from"] is None and "2024-01-01" not in e["evidence_text"]

@pytest.mark.full_data
def test_19_20_query_times(data):
    m, by_id = data["manifest"], data["by_id"]
    for q in _all(data):
        assert m["observation_window"]["start"] <= q["query_time"] <= m["observation_window"]["end"]
        new = by_id[q["replacing_new_evidence_id"]]
        old = by_id[q["replaced_old_evidence_id"]]
        if q["query_role"] == "POST_REPLACEMENT_MAIN":
            assert new["valid_from"] <= q["query_time"] and (new["valid_until"] is None or q["query_time"] < new["valid_until"])
        else:
            assert old["observed_from"] <= q["query_time"] < old["valid_until"]

@pytest.mark.full_data
def test_22_manifest_matches_files(data):
    m = data["manifest"]
    assert all(m["counts"][s] == len(data["q"][s]) for s in SPLITS)
    assert m["excluded"] == len(data["excluded"])
    assert m["eligible_events"] == 3_556
    assert m["main_queries_total"] == sum(1 for q in _all(data) if q["query_role"] == "POST_REPLACEMENT_MAIN" and q["split"] != "future_event")

@pytest.mark.full_data
def test_23_24_answer_consistency_and_v40(data):
    from src.normalize.cvss import base_severity
    by_id = data["by_id"]
    for q in _all(data):
        t = by_id[q["answer_evidence_id"]]
        assert q["answer_base_vector"] == t["base_vector"] and q["answer_base_severity"] == t["base_severity"]
        assert base_severity(t["cvss_version"], q["answer_base_score"]) == q["answer_base_severity"]
        if t["cvss_version"] == "4.0":
            assert "E:" not in q["answer_base_vector"] and "CR:" not in q["answer_base_vector"]
            if t["threat_metric_present"]:
                assert t["bt_score"] is not None and t["bt_score_available"] if "bt_score_available" in t else True
