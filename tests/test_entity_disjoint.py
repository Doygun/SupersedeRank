from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from src import paths
from src.label import splits as sp

CFG = sp.load_config()

def ev(cve, when, src="NVD", ver="3.1", seq=1, censored=False, amb=False, rtype="STRICT_SAME_CHANGE"):
    old_id, new_id = f"{cve}|{ver}|{src}|{seq}", f"{cve}|{ver}|{src}|{seq + 1}"
    old = dict(evidence_id=old_id, cve_id=cve, cvss_version=ver, source_key=src, vector="A", valid_from=None if censored else "2024-01-05T00:00:00+00:00",
               valid_from_censored=censored, valid_until=when, replacement_type=rtype, superseded_by_evidence_id=new_id,
               termination_event_id="t", chain_ambiguous=amb, readded_same_value=False)
    new = dict(evidence_id=new_id, cve_id=cve, cvss_version=ver, source_key=src, vector="B", valid_from=when,
               valid_from_censored=False, valid_until=None, replacement_type=None, superseded_by_evidence_id=None,
               termination_event_id=None, chain_ambiguous=amb, readded_same_value=False)
    return [old, new]

@pytest.mark.unit
def test_cve_level_assignment_and_cohorts():
    rows = (ev("CVE-A", "2024-06-01T00:00:00+00:00") + ev("CVE-B", "2025-06-01T00:00:00+00:00")
            + ev("CVE-C", "2026-02-01T00:00:00+00:00")
            + ev("CVE-D", "2025-03-01T00:00:00+00:00") + ev("CVE-D", "2026-03-01T00:00:00+00:00", src="cna", seq=1)
            + ev("CVE-E", "2026-05-01T00:00:00+00:00", amb=True)
            + ev("CVE-F", "2026-05-01T00:00:00+00:00", rtype="HIGH_CONFIDENCE_CROSS_EVENT"))
    cfg = dict(CFG); cfg["dev"] = {"fraction_of_train_cves": 0.0, "seed": 1}
    events = sp.main_replacement_events(rows, cfg)
    assert {e.cve_id for e in events} == {"CVE-A", "CVE-B", "CVE-C", "CVE-D"}
    assignment = sp.assign_splits(events, sorted({r["cve_id"] for r in rows}), cfg)
    assert assignment == {"CVE-A": "train", "CVE-B": "train", "CVE-C": "test", "CVE-D": "train",
                          "CVE-E": "corpus_only", "CVE-F": "corpus_only"}
    by_split = sp.events_by_split(events, assignment, cfg)
    assert [e.cve_id for e in by_split["test"]] == ["CVE-C"]
    assert [e.cve_id for e in by_split["future_event"]] == ["CVE-D"]
    assert sorted(e.cve_id for e in by_split["train"]) == ["CVE-A", "CVE-B", "CVE-D"]

@pytest.mark.unit
def test_dev_is_cve_disjoint_and_seeded():
    rows = []
    for i in range(20):
        rows += ev(f"CVE-{i}", "2024-06-01T00:00:00+00:00")
    cfg = dict(CFG); cfg["dev"] = {"fraction_of_train_cves": 0.25, "seed": 7}
    events = sp.main_replacement_events(rows, cfg)
    a1 = sp.assign_splits(events, sorted({r["cve_id"] for r in rows}), cfg)
    a2 = sp.assign_splits(events, sorted({r["cve_id"] for r in rows}), cfg)
    assert a1 == a2 and sum(1 for s in a1.values() if s == "dev") == 5
    assert set(a1.values()) == {"train", "dev"}

@pytest.mark.full_data
def test_real_split_is_entity_disjoint():
    split_dir = paths.PROCESSED_DATA_DIR / "splits"
    if not (split_dir / "temporal_split.json").exists():
        pytest.skip("Split henüz üretilmedi")
    assignment = json.loads((split_dir / "temporal_split.json").read_text(encoding="utf-8"))
    per_split = {name: [json.loads(l) for l in (split_dir / f"{name}.jsonl").open(encoding="utf-8")]
                 for name in ("train", "dev", "test", "future_event")}
    cves = {name: {e["cve_id"] for e in evs} for name, evs in per_split.items()}
    assert not (cves["train"] & cves["test"]) and not (cves["dev"] & cves["test"]) and not (cves["train"] & cves["dev"])
    assert cves["future_event"].isdisjoint(cves["test"])

    for name in ("train", "dev", "test"):
        assert all(assignment[e["cve_id"]] == name for e in per_split[name])

    evidences = sp.read_evidence(paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl")
    splits_per_cve = defaultdict(set)
    for e in evidences:
        splits_per_cve[e["cve_id"]].add(assignment[e["cve_id"]])
    assert all(len(s) == 1 for s in splits_per_cve.values())

    assert sum(len(v) for v in per_split.values()) == 3_649
