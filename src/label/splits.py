from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from src import paths

SPLIT_CONFIG = paths.CONFIG_DIR / "temporal_split.yaml"
TRAIN, DEV, TEST, FUTURE_EVENT, CORPUS_ONLY = "train", "dev", "test", "future_event", "corpus_only"

@dataclass(frozen=True)
class ReplacementEvent:

    event_time: str
    cve_id: str
    cvss_version: str
    source_key: str
    old_evidence_id: str
    new_evidence_id: str
    old_vector: str
    new_vector: str
    old_valid_from_censored: bool
    termination_event_id: str
    year: int
    changed_components: list[str] = field(default_factory=list)
    changed_base_components: list[str] = field(default_factory=list)
    changed_threat_components: list[str] = field(default_factory=list)
    changed_environmental_components: list[str] = field(default_factory=list)
    changed_supplemental_components: list[str] = field(default_factory=list)
    base_components_changed: bool = True
    threat_only_change: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

BASE_QUERY_EXCLUSION = "EXCLUDED_FROM_BASE_QUERY"
THREAT_ONLY, SUPPLEMENTAL_ONLY, ENVIRONMENTAL_ONLY, NO_BASE = (
    "THREAT_ONLY_CHANGE", "SUPPLEMENTAL_ONLY_CHANGE", "ENVIRONMENTAL_ONLY_CHANGE", "NO_BASE_COMPONENT_CHANGE",
)

def base_query_eligible(ev: "ReplacementEvent") -> bool:
    return bool(ev.base_components_changed)

def base_query_exclusion_reason(ev: "ReplacementEvent") -> str:
    groups = {
        THREAT_ONLY: bool(ev.changed_threat_components),
        SUPPLEMENTAL_ONLY: bool(ev.changed_supplemental_components),
        ENVIRONMENTAL_ONLY: bool(ev.changed_environmental_components),
    }
    present = [reason for reason, flag in groups.items() if flag]
    return present[0] if len(present) == 1 else NO_BASE

def load_config(path: Path = SPLIT_CONFIG) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))

def read_evidence(path: Path) -> list[dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]

def main_replacement_events(evidences: Iterable[dict[str, Any]], cfg: dict[str, Any]) -> list[ReplacementEvent]:
    flt = cfg["main_event_filter"]
    by_id = {e["evidence_id"]: e for e in evidences}
    events: list[ReplacementEvent] = []
    for old in by_id.values():
        if old["replacement_type"] != flt["replacement_type"]:
            continue
        if flt.get("exclude_ambiguous_chains", True) and old["chain_ambiguous"]:
            continue
        new = by_id[old["superseded_by_evidence_id"]]
        events.append(
            ReplacementEvent(
                event_time=old["valid_until"],
                cve_id=old["cve_id"],
                cvss_version=old["cvss_version"],
                source_key=old["source_key"],
                old_evidence_id=old["evidence_id"],
                new_evidence_id=new["evidence_id"],
                old_vector=old["vector"],
                new_vector=new["vector"],
                old_valid_from_censored=bool(old["valid_from_censored"]),
                termination_event_id=old["termination_event_id"],
                year=int(old["valid_until"][:4]),
                changed_components=list(old.get("changed_components", [])),
                changed_base_components=list(old.get("changed_base_components", [])),
                changed_threat_components=list(old.get("changed_threat_components", [])),
                changed_environmental_components=list(old.get("changed_environmental_components", [])),
                changed_supplemental_components=list(old.get("changed_supplemental_components", [])),
                base_components_changed=bool(old.get("base_components_changed", True)),
                threat_only_change=bool(old.get("threat_only_change", False)),
            )
        )
    events.sort(key=lambda ev: (ev.event_time, ev.cve_id, ev.source_key, ev.cvss_version))
    return events

TIMELINE_EXCLUSION_REASON = "TIMELINE_CHAIN_AMBIGUITY"
AMBIGUITY_EXPLANATIONS = {
    "REMOVAL_OF_INACTIVE_VALUE": "A Removed event referenced a value that was not active in the chain at that time "
                                 "(e.g. one change removed several assessors' entries), so the chain state could not be replayed reliably.",
    "REMOVAL_OF_UNOBSERVED_VALUE_AFTER_OTHER_EVENTS": "A value never observed as Added was removed after other events; the inference "
                                 "rule for pre-window values applies only to a chain's first observed event.",
    "STRICT_PAIR_OLD_VALUE_NOT_ACTIVE": "The STRICT pair removed a value that was not the active value of the chain.",
    "MULTI_REMOVED_OR_ADDED_IN_ONE_CHANGE": "One change removed/added several values of the same CVSS type.",
    "MULTIPLE_COMPETING_ACTIVE_VALUES": "Two different values were active in the same chain at the same time.",
}

def excluded_main_events(evidences: Iterable[dict[str, Any]], cfg: dict[str, Any]) -> list[dict[str, Any]]:
    flt = cfg["main_event_filter"]
    out = []
    for old in evidences:
        if old["replacement_type"] != flt["replacement_type"] or not old["chain_ambiguous"]:
            continue
        reasons = list(old.get("ambiguity_reason", []))
        out.append({
            "cve_id": old["cve_id"],
            "change_id": (old["termination_event_id"] or "").split("#")[0],
            "source_key": old["source_key"],
            "source_identifier_raw": old["source_identifier_raw"],
            "cvss_version": old["cvss_version"],
            "event_time": old["valid_until"],
            "old_evidence_id": old["evidence_id"],
            "new_evidence_id": old["superseded_by_evidence_id"],
            "exclusion_reason": TIMELINE_EXCLUSION_REASON,
            "ambiguity_type": reasons,
            "source_file": old["source_file"],
            "why_not_replayable": " ".join(AMBIGUITY_EXPLANATIONS.get(r, r) for r in reasons),
            "counted_in_candidate_regression": True,
            "counted_in_timeline_eligible": False,
        })
    out.sort(key=lambda r: (r["event_time"], r["cve_id"]))
    return out

def dev_selection_hash(dev_cves: Iterable[str]) -> str:
    import hashlib
    return hashlib.sha256("\n".join(sorted(dev_cves)).encode("utf-8")).hexdigest()

def assign_splits(events: list[ReplacementEvent], all_cves: Iterable[str], cfg: dict[str, Any]) -> dict[str, str]:
    train_years = set(cfg["periods"]["train_years"])
    test_years = set(cfg["periods"]["test_years"])
    years_by_cve: defaultdict[str, set[int]] = defaultdict(set)
    for ev in events:
        years_by_cve[ev.cve_id].add(ev.year)

    train_period = {c for c, ys in years_by_cve.items() if ys & train_years}
    test_period = {c for c, ys in years_by_cve.items() if ys & test_years}
    future_entity = sorted(test_period - train_period)
    future_event = sorted(test_period & train_period)

    rng = random.Random(int(cfg["dev"]["seed"]))
    train_cves = sorted(train_period)
    n_dev = int(round(len(train_cves) * float(cfg["dev"]["fraction_of_train_cves"])))
    dev_cves = set(rng.sample(train_cves, n_dev)) if n_dev else set()

    assignment: dict[str, str] = {}
    for cve in all_cves:
        if cve in dev_cves:
            assignment[cve] = DEV
        elif cve in train_period:
            assignment[cve] = TRAIN
        elif cve in future_entity:
            assignment[cve] = TEST
        else:
            assignment[cve] = CORPUS_ONLY

    for cve in future_event:
        assignment[cve] = assignment[cve]
    return assignment

def events_by_split(events: list[ReplacementEvent], assignment: dict[str, str], cfg: dict[str, Any]) -> dict[str, list[ReplacementEvent]]:
    train_years = set(cfg["periods"]["train_years"])
    test_years = set(cfg["periods"]["test_years"])
    out: dict[str, list[ReplacementEvent]] = {TRAIN: [], DEV: [], TEST: [], FUTURE_EVENT: []}
    for ev in events:
        split = assignment[ev.cve_id]
        if split in (TRAIN, DEV):
            if ev.year in train_years:
                out[split].append(ev)
            elif ev.year in test_years:
                out[FUTURE_EVENT].append(ev)
        elif split == TEST:
            if ev.year in test_years:
                out[TEST].append(ev)
    return out

def profile(events: list[ReplacementEvent], assignment: dict[str, str], by_split: dict[str, list[ReplacementEvent]],
            evidences: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    cves_with_events = {ev.cve_id for ev in events}
    years_by_cve: defaultdict[str, set[int]] = defaultdict(set)
    for ev in events:
        years_by_cve[ev.cve_id].add(ev.year)
    train_years = set(cfg["periods"]["train_years"]); test_years = set(cfg["periods"]["test_years"])
    train_period = {c for c, ys in years_by_cve.items() if ys & train_years}
    test_period = {c for c, ys in years_by_cve.items() if ys & test_years}

    def stats(evs: list[ReplacementEvent]) -> dict[str, Any]:
        return {
            "events": len(evs),
            "cves": len({e.cve_id for e in evs}),
            "chains": len({(e.cve_id, e.cvss_version, e.source_key) for e in evs}),
            "censored_old_events": sum(1 for e in evs if e.old_valid_from_censored),
            "censored_ratio": round(sum(1 for e in evs if e.old_valid_from_censored) / len(evs), 4) if evs else None,
            "by_year": dict(sorted(Counter(e.year for e in evs).items())),
            "by_version": dict(Counter(e.cvss_version for e in evs)),
            "by_source_key": dict(Counter(e.source_key for e in evs).most_common(8)),
            "nvd_only_events": sum(1 for e in evs if e.source_key == "NVD"),
        }

    chains_per_cve_split: Counter[str] = Counter()
    for e in evidences:
        chains_per_cve_split[(e["cve_id"], assignment.get(e["cve_id"], CORPUS_ONLY))] += 0

    return {
        "config": cfg,
        "main_events_total": len(events),
        "cves_with_main_events": len(cves_with_events),
        "cves_total_in_timeline": len(assignment),
        "cves_corpus_only": sum(1 for s in assignment.values() if s == CORPUS_ONLY),
        "period_membership": {
            "train_period_cves": len(train_period),
            "test_period_cves": len(test_period),
            "overlap_cves": len(train_period & test_period),
            "future_entity_cves": len(test_period - train_period),
        },
        "split_cves": dict(Counter(s for s in assignment.values() if s != CORPUS_ONLY)),
        "splits": {name: stats(evs) for name, evs in by_split.items()},
        "held_out_cohorts": {
            "future_event": {"cves": len({e.cve_id for e in by_split[FUTURE_EVENT]}), "events": len(by_split[FUTURE_EVENT])},
        },
        "sanity": {
            "events_assigned": sum(len(v) for v in by_split.values()),
            "events_unassigned": len(events) - sum(len(v) for v in by_split.values()),
        },
    }

def export_side_files(evidences: list[dict[str, Any]], out_root: Path) -> dict[str, int]:
    sens = out_root / "sensitivity" / "cross_event_replacements.jsonl"
    neg = out_root / "negative_controls" / "same_value_readds.jsonl"
    sens.parent.mkdir(parents=True, exist_ok=True); neg.parent.mkdir(parents=True, exist_ok=True)
    n_sens = n_neg = 0
    with sens.open("w", encoding="utf-8") as hs, neg.open("w", encoding="utf-8") as hn:
        for e in evidences:
            if e["replacement_type"] == "HIGH_CONFIDENCE_CROSS_EVENT":
                row = dict(e); row["exclusion_reason"] = "NON_ATOMIC_CROSS_EVENT_REPLACEMENT"; row["in_main_dataset"] = False
                hs.write(json.dumps(row, ensure_ascii=False) + "\n"); n_sens += 1
            if e.get("readded_same_value"):
                row = dict(e); row["negative_control"] = "SAME_VALUE_REMOVED_AND_READDED"; row["is_supersession"] = False
                hn.write(json.dumps(row, ensure_ascii=False) + "\n"); n_neg += 1
    return {"cross_event_sensitivity": n_sens, "same_value_readds": n_neg}

def run(evidence_path: Path, cfg: dict[str, Any], out_root: Path, profile_dir: Path) -> dict[str, Any]:
    evidences = read_evidence(evidence_path)
    events = main_replacement_events(evidences, cfg)
    all_cves = sorted({e["cve_id"] for e in evidences})
    assignment = assign_splits(events, all_cves, cfg)
    by_split = events_by_split(events, assignment, cfg)
    summary = profile(events, assignment, by_split, evidences, cfg)
    summary["side_files"] = export_side_files(evidences, out_root)
    excluded = excluded_main_events(evidences, cfg)
    summary["timeline_excluded_events"] = excluded
    summary["scope"] = {
        "candidate_strict_same_change": None,
        "timeline_eligible_events": len(events),
        "main_split_events": sum(len(by_split[k]) for k in (TRAIN, DEV, TEST)),
        "future_event_events": len(by_split[FUTURE_EVENT]),
        "timeline_excluded_events": len(excluded),
    }

    split_dir = out_root / "splits"; split_dir.mkdir(parents=True, exist_ok=True)
    (split_dir / "temporal_split.json").write_text(json.dumps(assignment, indent=0, sort_keys=True) + "\n", encoding="utf-8")
    with (split_dir / "excluded_main_events.jsonl").open("w", encoding="utf-8") as handle:
        for row in excluded:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    dev_cves = sorted(c for c, sp_ in assignment.items() if sp_ == DEV)
    manifest = {
        "split_unit": "cve_id",
        "period_membership": "time of main-set STRICT_SAME_CHANGE replacement events in non-ambiguous chains",
        "main_test_cohort": "future_entity",
        "secondary_cohort": "future_event (held out; secondary analysis only)",
        "dev": {
            "fraction_of_train_cves": cfg["dev"]["fraction_of_train_cves"],
            "seed": cfg["dev"]["seed"],
            "sampling": "random.Random(seed).sample over the sorted list of train-period CVEs",
            "stratification": "none",
            "n_dev_cves": len(dev_cves),
            "dev_cve_sha256": dev_selection_hash(dev_cves),
        },
        "test_usage_policy": "never used for model, feature, threshold or hyperparameter selection",
        "counts": {name: {"cves": len({e.cve_id for e in evs}), "events": len(evs)} for name, evs in by_split.items()},
        "scope": summary["scope"],
    }
    manifest["manifest_kind"] = "atomic_replacement_manifest"
    (split_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (split_dir / "atomic_replacement_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    bq_dir = split_dir / "base_query"
    bq_dir.mkdir(parents=True, exist_ok=True)
    bq_by_split: dict[str, list[ReplacementEvent]] = {}
    excluded_bq: list[dict[str, Any]] = []
    for name, evs in by_split.items():
        keep = []
        for ev in evs:
            if base_query_eligible(ev):
                keep.append(ev)
            else:
                row = {
                    "event_id": ev.termination_event_id,
                    "cve_id": ev.cve_id,
                    "source_key": ev.source_key,
                    "cvss_version": ev.cvss_version,
                    "changed_base_components": ev.changed_base_components,
                    "changed_threat_components": ev.changed_threat_components,
                    "changed_environmental_components": ev.changed_environmental_components,
                    "changed_supplemental_components": ev.changed_supplemental_components,
                    "exclusion_reason": BASE_QUERY_EXCLUSION,
                    "exclusion_detail": base_query_exclusion_reason(ev),
                    "split": name,
                    "event_time": ev.event_time,
                    "source_file": None,
                    "old_evidence_id": ev.old_evidence_id,
                    "new_evidence_id": ev.new_evidence_id,
                }
                excluded_bq.append(row)
        bq_by_split[name] = keep
        with (bq_dir / f"{name}.jsonl").open("w", encoding="utf-8") as handle:
            for ev in keep:
                handle.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
    source_files = {e["evidence_id"]: e["source_file"] for e in evidences}
    for row in excluded_bq:
        row["source_file"] = source_files.get(row["old_evidence_id"])
    with (bq_dir / "excluded_events.jsonl").open("w", encoding="utf-8") as handle:
        for row in excluded_bq:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    threat_only_atomic = sum(1 for ev in events if ev.threat_only_change)
    bq_manifest = {
        "manifest_kind": "base_query_eligible_manifest",
        "derived_from": "atomic_replacement_manifest (same CVE assignment; events filtered, CVEs never re-split)",
        "eligibility_rule": "at least one changed BASE metric between the replaced and replacing vector",
        "atomic_events_total": len(events),
        "threat_only_atomic_events": threat_only_atomic,
        "excluded_events": len(excluded_bq),
        "excluded_by_detail": dict(Counter(r["exclusion_detail"] for r in excluded_bq)),
        "excluded_by_split": dict(Counter(r["split"] for r in excluded_bq)),
        "counts": {name: {"cves": len({e.cve_id for e in evs}), "events": len(evs)} for name, evs in bq_by_split.items()},
        "main_split_events": sum(len(bq_by_split[k]) for k in (TRAIN, DEV, TEST)),
        "by_version": {name: dict(Counter(e.cvss_version for e in evs)) for name, evs in bq_by_split.items()},
    }
    (split_dir / "base_query_eligible_manifest.json").write_text(json.dumps(bq_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary["base_query"] = bq_manifest
    for name, evs in by_split.items():
        with (split_dir / f"{name}.jsonl").open("w", encoding="utf-8") as handle:
            for ev in evs:
                handle.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "temporal_split_profile.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence", type=Path, default=paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl")
    parser.add_argument("--out-root", type=Path, default=paths.PROCESSED_DATA_DIR)
    parser.add_argument("--profile-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    parser.add_argument("--config", type=Path, default=SPLIT_CONFIG)
    args = parser.parse_args(argv)
    summary = run(args.evidence, load_config(args.config), args.out_root, args.profile_dir)
    print(json.dumps({k: v for k, v in summary.items() if k != "config"}, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())

SELECTION_SPLITS: tuple[str, ...] = (TRAIN, DEV)

def assert_selection_split(split: str) -> str:
    if split not in SELECTION_SPLITS:
        raise ValueError(f"'{split}' kümesi model/eşik/özellik seçiminde kullanılamaz; izin verilen: {SELECTION_SPLITS}")
    return split
