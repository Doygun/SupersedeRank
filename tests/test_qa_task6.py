from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from src import paths
from src.label import query_time_labels as L
from src.label import splits as sp
from src.timeline.config import load_timeline_config

SPLIT_DIR = paths.PROCESSED_DATA_DIR / "splits"
SRC_FILES = [p for p in paths.PROJECT_ROOT.glob("src/**/*.py")] + [p for p in paths.PROJECT_ROOT.glob("tools/**/*.py")]

def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.open(encoding="utf-8")]

def _need_split():
    if not (SPLIT_DIR / "manifest.json").exists():
        pytest.skip("Split henüz üretilmedi")

@pytest.mark.unit
def test_1_window_dates_and_seed_not_hardcoded_in_code():
    timeline = yaml.safe_load((paths.CONFIG_DIR / "timeline.yaml").read_text(encoding="utf-8"))
    split = yaml.safe_load((paths.CONFIG_DIR / "temporal_split.yaml").read_text(encoding="utf-8"))
    literals = {timeline["observation_window"]["start"][:10], timeline["observation_window"]["end"][:10], str(split["dev"]["seed"])}
    offenders = []
    for path in SRC_FILES:
        text = path.read_text(encoding="utf-8")
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        for lit in literals:
            if re.search(rf"(?<![\w-]){re.escape(lit)}(?![\w-])", code):
                offenders.append((path.relative_to(paths.PROJECT_ROOT).as_posix(), lit))
    assert offenders == [], f"Config sabitleri kodda tekrar ediyor: {offenders}"

@pytest.mark.unit
def test_2_observation_window_read_from_config(tmp_path: Path):
    custom = tmp_path / "timeline.yaml"
    custom.write_text(
        (paths.CONFIG_DIR / "timeline.yaml").read_text(encoding="utf-8")
        .replace('start: "2024-01-01T00:00:00+00:00"', 'start: "2023-06-01T00:00:00+00:00"'),
        encoding="utf-8",
    )
    cfg = load_timeline_config(timeline_path=custom)
    assert cfg.window_start == "2023-06-01T00:00:00+00:00"
    default = load_timeline_config()
    yaml_cfg = yaml.safe_load((paths.CONFIG_DIR / "timeline.yaml").read_text(encoding="utf-8"))
    assert default.window_start == yaml_cfg["observation_window"]["start"]
    assert default.window_end == yaml_cfg["observation_window"]["end"]

@pytest.mark.full_data
def test_2b_censored_evidence_uses_config_window():
    cfg = load_timeline_config()
    rows = _rows(paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl")
    censored = [r for r in rows if r["valid_from_censored"]]
    assert censored and all(r["observed_from"] == cfg.window_start and r["valid_from"] is None for r in censored)
    assert all(r["observation_window_start"] == cfg.window_start for r in rows)

@pytest.mark.full_data
def test_3_4_future_event_kept_out_of_main_splits():
    _need_split()
    main = {name: _rows(SPLIT_DIR / f"{name}.jsonl") for name in ("train", "dev", "test")}
    fe = _rows(SPLIT_DIR / "future_event.jsonl")
    main_ids = {r["old_evidence_id"] for evs in main.values() for r in evs}
    assert main_ids.isdisjoint({r["old_evidence_id"] for r in fe})
    assert {r["cve_id"] for r in fe}.isdisjoint({r["cve_id"] for r in main["test"]})
    assert all(r["year"] == 2026 for r in fe) and len(fe) == 19 and len({r["cve_id"] for r in fe}) == 18
    for name, evs in main.items():
        others = {r["cve_id"] for n, e in main.items() if n != name for r in e}
        assert {r["cve_id"] for r in evs}.isdisjoint(others), name

@pytest.mark.full_data
def test_5_cross_event_sensitivity_not_in_main_set():
    _need_split()
    sens = _rows(paths.PROCESSED_DATA_DIR / "sensitivity" / "cross_event_replacements.jsonl")
    assert len(sens) == 131 and all(r["exclusion_reason"] == "NON_ATOMIC_CROSS_EVENT_REPLACEMENT" for r in sens)
    main_ids = {r["old_evidence_id"] for n in ("train", "dev", "test", "future_event") for r in _rows(SPLIT_DIR / f"{n}.jsonl")}
    assert main_ids.isdisjoint({r["evidence_id"] for r in sens})
    assert all(L.label(r, "2026-09-14T00:00:00+00:00") != L.OUTDATED for r in sens)

@pytest.mark.full_data
def test_6_same_value_readds_produce_no_replacement():
    _need_split()
    neg = _rows(paths.PROCESSED_DATA_DIR / "negative_controls" / "same_value_readds.jsonl")
    assert len(neg) == 7_672
    by_id = {r["evidence_id"]: r for r in _rows(paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl")}
    main_new = {r["new_evidence_id"] for n in ("train", "dev", "test", "future_event") for r in _rows(SPLIT_DIR / f"{n}.jsonl")}
    for r in neg:
        assert r["readded_same_value"] and r["replaces_evidence_id"] is None and not r["explicit_reversal"]
        assert r["evidence_id"] not in main_new
        prev = by_id[f"{r['chain_id']}|{r['sequence'] - 1}"]
        assert prev["vector"] == r["vector"] and prev["replacement_type"] is None and prev["superseded_by_evidence_id"] is None

@pytest.mark.full_data
def test_7_scope_regression_levels():
    _need_split()
    cands = _rows(paths.PROCESSED_DATA_DIR / "cvss_replacements.jsonl")
    assert sum(1 for r in cands if r["tier"] == "STRICT") == 3_651
    manifest = json.loads((SPLIT_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["scope"]["timeline_eligible_events"] == 3_649
    assert manifest["scope"]["main_split_events"] == 3_630
    assert manifest["scope"]["future_event_events"] == 19
    assert manifest["scope"]["timeline_excluded_events"] == 2
    excluded = _rows(SPLIT_DIR / "excluded_main_events.jsonl")
    assert len(excluded) == 2 and all(r["exclusion_reason"] == "TIMELINE_CHAIN_AMBIGUITY" for r in excluded)
    assert all(r["cve_id"] and r["change_id"] and r["source_key"] and r["event_time"] and r["source_file"] and r["why_not_replayable"] for r in excluded)
    counts = manifest["counts"]
    assert (counts["train"], counts["dev"], counts["test"]) == ({"cves": 1_578, "events": 1_768}, {"cves": 279, "events": 318}, {"cves": 1_392, "events": 1_544})
    assert manifest["dev"]["fraction_of_train_cves"] == 0.15 and len(manifest["dev"]["dev_cve_sha256"]) == 64

@pytest.mark.full_data
def test_8_no_query_before_window_for_censored_evidence():
    cfg = load_timeline_config()
    assert cfg.left_censoring["generate_queries_before_window"] is False
    rows = _rows(paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl")
    before = "2023-12-31T23:59:59+00:00"
    assert all(L.label(r, before) == L.NOT_VISIBLE for r in rows if r["valid_from_censored"])
    assert all(r["observed_from"] >= cfg.window_start for r in rows)

@pytest.mark.full_data
def test_9_supersession_never_crosses_source_chains():
    by_id = {r["evidence_id"]: r for r in _rows(paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl")}
    n = 0
    for r in by_id.values():
        if r["superseded_by_evidence_id"]:
            new = by_id[r["superseded_by_evidence_id"]]
            assert (r["cve_id"], r["cvss_version"], r["source_key"]) == (new["cve_id"], new["cvss_version"], new["source_key"])
            n += 1
    assert n == 3_651

@pytest.mark.unit
def test_10_test_split_cannot_be_used_for_selection():
    assert sp.assert_selection_split("train") == "train" and sp.assert_selection_split("dev") == "dev"
    with pytest.raises(ValueError):
        sp.assert_selection_split("test")
    with pytest.raises(ValueError):
        sp.assert_selection_split("future_event")
    manifest_path = SPLIT_DIR / "manifest.json"
    if manifest_path.exists():
        assert "never used" in json.loads(manifest_path.read_text(encoding="utf-8"))["test_usage_policy"]
