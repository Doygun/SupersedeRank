from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from src import paths
from src.ingest.nvd_history import HistoryRecord, ReaderStats, iter_changes_grouped
from src.normalize.cvss import (
    canonical_vector,
    changed_components,
    classify_changed_components,
    extract_vector_and_source,
    identify_cvss_version,
    is_vector_parseable,
    normalize_cvss_vector,
)
from src.timeline.config import TimelineConfig, load_timeline_config
from src.timeline.cvss_replacements import classify
from src.timeline.reported_scores import build_reported_index, score_fields

ACTIVE = "ACTIVE"
REMOVED_PENDING = "REMOVED_PENDING_REPLACEMENT"
REPLACED = "REPLACED"
WITHDRAWN = "WITHDRAWN_WITHOUT_REPLACEMENT"
INITIAL_ADDITION = "INITIAL_ADDITION"
EXCLUDED_AMBIGUOUS = "EXCLUDED_AMBIGUOUS"

STRICT_SAME_CHANGE = "STRICT_SAME_CHANGE"
CROSS_EVENT = "HIGH_CONFIDENCE_CROSS_EVENT"

RULE_FIRST_REMOVAL = "FIRST_OBSERVED_EVENT_IS_REMOVAL"

@dataclass
class CvssEvent:

    event_id: str
    change_id: str
    cve_id: str
    event_name: str
    created: str
    action: str
    detail_type: str
    cvss_version: str
    source_identifier_raw: str
    source_key: str
    vector: str
    vector_normalized: str
    vector_raw: str
    source_prefix: str
    source_file: str
    detail_index: int

    @property
    def chain_key(self) -> tuple[str, str, str]:
        return (self.cve_id, self.cvss_version, self.source_key)

@dataclass
class Evidence:
    evidence_id: str
    chain_id: str
    cve_id: str
    cvss_version: str
    detail_type: str
    source_identifier_raw: str
    source_key: str
    vector: str
    vector_raw: str
    base_score: float | None
    base_severity: str | None
    valid_from: str | None
    valid_from_censored: bool
    observed_from: str
    first_observed_event_time: str
    valid_until: str | None
    valid_until_censored: bool
    observation_window_start: str
    activation_event_id: str | None
    termination_event_id: str | None
    replacement_type: str | None
    superseded_by_evidence_id: str | None
    replaces_evidence_id: str | None
    timeline_status: str
    ambiguity_reason: list[str]
    chain_ambiguous: bool
    inferred_initial_state: bool
    inference_rule: str | None
    explicit_reversal: bool
    readded_same_value: bool
    sequence: int
    source_file: str

    score_type: str = "CVSS-B"
    threat_metric_present: bool = False
    threat_metric_value: str | None = None
    bt_score: float | None = None
    bt_severity: str | None = None
    bt_score_available: bool = False
    reported_score: float | None = None
    reported_score_type: str = "NOT_AVAILABLE_IN_HISTORY"
    reported_score_matches: bool = False

    changed_components: list[str] = field(default_factory=list)
    changed_base_components: list[str] = field(default_factory=list)
    changed_threat_components: list[str] = field(default_factory=list)
    changed_environmental_components: list[str] = field(default_factory=list)
    changed_supplemental_components: list[str] = field(default_factory=list)
    base_components_changed: bool = False
    threat_only_change: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class ChainReport:
    chain_id: str
    cve_id: str
    cvss_version: str
    source_key: str
    n_events: int = 0
    first_event_action: str | None = None
    same_change_pairs: int = 0
    strict_same_change: int = 0
    excluded_same_change: int = 0
    cross_event_candidates: int = 0
    unmatched_removed: int = 0
    unmatched_added: int = 0
    duplicate_rewrites: int = 0
    duplicate_readds: int = 0
    reversals: int = 0
    same_value_readds: int = 0
    same_timestamp_conflicts: int = 0
    competing_active: int = 0
    ambiguity_reasons: list[str] = field(default_factory=list)

    @property
    def ambiguous(self) -> bool:
        return bool(self.ambiguity_reasons)

@dataclass
class CrossEventCandidate:
    cve_id: str
    cvss_version: str
    source_key: str
    removed_event_id: str
    added_event_id: str
    removed_at: str
    added_at: str
    gap_days: float
    old_vector: str
    new_vector: str
    changed_components: list[str]
    year: str

def _days_between(a: str, b: str) -> float:
    return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 86400.0

def cvss_events_from_group(group: list[HistoryRecord], cfg: TimelineConfig) -> list[CvssEvent]:
    events: list[CvssEvent] = []
    for record in group:
        if record.detail_type not in cfg.supported_detail_types or record.action not in ("Removed", "Added"):
            continue
        raw = record.old_value if record.action == "Removed" else record.new_value
        prefix, vector = extract_vector_and_source(raw)
        normalized = normalize_cvss_vector(vector)
        events.append(
            CvssEvent(
                event_id=f"{record.change_id}#{record.detail_index}",
                change_id=record.change_id,
                cve_id=record.cve_id,
                event_name=record.event_name,
                created=record.created,
                action=record.action,
                detail_type=record.detail_type,
                cvss_version=identify_cvss_version(record.detail_type, normalized),
                source_identifier_raw=record.source_identifier,
                source_key=cfg.source_key(record.source_identifier),
                vector=canonical_vector(normalized),
                vector_normalized=normalized,
                vector_raw=str(raw) if raw is not None else "",
                source_prefix=prefix,
                source_file=record.source_file,
                detail_index=record.detail_index,
            )
        )
    return events

def iter_cvss_events(history_dir: Path, cfg: TimelineConfig, stats: ReaderStats | None = None,
                     files: list[Path] | None = None) -> Iterator[list[CvssEvent]]:
    for group in iter_changes_grouped(history_dir, stats, files):
        events = cvss_events_from_group(group, cfg)
        if events:
            yield events

class ChainReplayer:

    def __init__(self, chain_key: tuple[str, str, str], cfg: TimelineConfig,
                 reported_index: dict | None = None) -> None:
        self.cve_id, self.cvss_version, self.source_key = chain_key
        self.cfg = cfg
        self.reported_index = reported_index
        self.chain_id = f"{self.cve_id}|{self.cvss_version}|{self.source_key}"
        self.report = ChainReport(self.chain_id, self.cve_id, self.cvss_version, self.source_key)
        self.evidences: list[Evidence] = []
        self.active: dict[str, Evidence] = {}
        self.pending: Evidence | None = None
        self.last_event_was_pending_removal = False
        self.seen_vectors: set[str] = set()
        self.cross_candidates: list[CrossEventCandidate] = []
        self.global_counts: Counter[str] = Counter()
        self._seq = 0
        self._last_created: str | None = None
        self._last_change: str | None = None
        self._n_events = 0

    def _flag(self, reason: str) -> None:
        if reason not in self.report.ambiguity_reasons:
            self.report.ambiguity_reasons.append(reason)

    def _new_evidence(self, ev: CvssEvent, *, valid_from: str | None, censored: bool,
                      activation: str | None, inferred: bool = False, rule: str | None = None) -> Evidence:
        self._seq += 1
        scores = score_fields(self.cvss_version, ev.vector_raw, ev.vector, self.reported_index,
                              self.cve_id, ev.source_identifier_raw)
        score = scores["base_score"]
        evidence = Evidence(
            evidence_id=f"{self.chain_id}|{self._seq}",
            chain_id=self.chain_id,
            cve_id=self.cve_id,
            cvss_version=self.cvss_version,
            detail_type=ev.detail_type,
            source_identifier_raw=ev.source_identifier_raw,
            source_key=self.source_key,
            vector=ev.vector,
            vector_raw=ev.vector_raw,
            base_score=score,
            base_severity=scores["base_severity"],
            valid_from=valid_from,
            valid_from_censored=censored,
            observed_from=self.cfg.window_start if censored else (valid_from or self.cfg.window_start),
            first_observed_event_time=ev.created,
            valid_until=None,
            valid_until_censored=False,
            observation_window_start=self.cfg.window_start,
            activation_event_id=activation,
            termination_event_id=None,
            replacement_type=None,
            superseded_by_evidence_id=None,
            replaces_evidence_id=None,
            timeline_status=ACTIVE,
            ambiguity_reason=[],
            chain_ambiguous=False,
            inferred_initial_state=inferred,
            inference_rule=rule,
            explicit_reversal=False,
            readded_same_value=False,
            sequence=self._seq,
            source_file=ev.source_file,
            **{k: v for k, v in scores.items() if k not in ("base_score", "base_severity")},
        )
        self.evidences.append(evidence)
        return evidence

    def _open(self, ev: CvssEvent, *, reversal_check: bool = True) -> Evidence:
        evidence = self._new_evidence(ev, valid_from=ev.created, censored=False, activation=ev.event_id)
        if reversal_check and ev.vector in self.seen_vectors:
            evidence.explicit_reversal = True
            self.report.reversals += 1
        self.seen_vectors.add(ev.vector)
        self.active[ev.vector] = evidence
        return evidence

    def _inferred_initial(self, ev: CvssEvent) -> Evidence:
        evidence = self._new_evidence(ev, valid_from=None, censored=True, activation=None,
                                      inferred=True, rule=RULE_FIRST_REMOVAL)
        self.seen_vectors.add(ev.vector)
        self.active[ev.vector] = evidence
        return evidence

    def _close(self, evidence: Evidence, ev: CvssEvent, status: str, replacement_type: str | None = None) -> None:
        evidence.valid_until = ev.created
        evidence.termination_event_id = ev.event_id
        evidence.timeline_status = status
        evidence.replacement_type = replacement_type
        if replacement_type is not None:
            self._set_change_metadata(evidence, ev.vector)
        self.active.pop(evidence.vector, None)

    def _set_change_metadata(self, old: Evidence, new_vector: str) -> None:
        comps = changed_components(old.vector, new_vector)
        groups = classify_changed_components(self.cvss_version, comps)
        old.changed_components = comps
        for key, value in groups.items():
            setattr(old, key, value)

    def _check_competing(self) -> None:
        if len(self.active) > 1:
            self.report.competing_active += 1
            self._flag("MULTIPLE_COMPETING_ACTIVE_VALUES")
            for evidence in self.active.values():
                if "MULTIPLE_COMPETING_ACTIVE_VALUES" not in evidence.ambiguity_reason:
                    evidence.ambiguity_reason.append("MULTIPLE_COMPETING_ACTIVE_VALUES")

    def _track_order(self, ev: CvssEvent) -> None:
        self._n_events += 1
        if self.report.first_event_action is None:
            self.report.first_event_action = ev.action
        if self._last_created == ev.created and self._last_change != ev.change_id:
            self.report.same_timestamp_conflicts += 1
        self._last_created, self._last_change = ev.created, ev.change_id

    def _removed(self, ev: CvssEvent, *, same_change: bool = False) -> Evidence | None:
        current = self.active.get(ev.vector)
        if current is None:
            if self._n_events == 1 and not self.active and not self.seen_vectors:

                current = self._inferred_initial(ev)
            elif ev.vector not in self.seen_vectors:

                self.report.unmatched_removed += 1
                self._flag("REMOVAL_OF_UNOBSERVED_VALUE_AFTER_OTHER_EVENTS")
                return None
            else:
                self.report.unmatched_removed += 1
                self._flag("REMOVAL_OF_INACTIVE_VALUE")
                return None
        if not same_change:
            self._close(current, ev, REMOVED_PENDING)
            self.pending = current
            self.last_event_was_pending_removal = True
        return current

    def _added(self, ev: CvssEvent) -> Evidence:
        if ev.vector in self.active:
            self.report.duplicate_readds += 1
            self.last_event_was_pending_removal = False
            return self.active[ev.vector]

        pending = self.pending if self.last_event_was_pending_removal else None
        self.last_event_was_pending_removal = False

        if pending is not None and pending.vector == ev.vector:

            pending.timeline_status = WITHDRAWN
            self.pending = None
            evidence = self._open(ev, reversal_check=False)
            evidence.readded_same_value = True
            self.report.same_value_readds += 1
            return evidence

        if pending is not None:
            changed = changed_components(pending.vector, ev.vector)
            if (is_vector_parseable(pending.vector) and is_vector_parseable(ev.vector)
                    and changed and pending.valid_until is not None and pending.valid_until < ev.created):

                pending.timeline_status = REPLACED
                pending.replacement_type = CROSS_EVENT
                self._set_change_metadata(pending, ev.vector)
                evidence = self._open(ev)
                evidence.replaces_evidence_id = pending.evidence_id
                self.report.cross_event_candidates += 1
                self.cross_candidates.append(
                    CrossEventCandidate(
                        self.cve_id, self.cvss_version, self.source_key,
                        pending.termination_event_id or "", ev.event_id,
                        pending.valid_until, ev.created, round(_days_between(pending.valid_until, ev.created), 3),
                        pending.vector, ev.vector, changed, ev.created[:4],
                    )
                )
                self.pending = None
                return evidence
            pending.timeline_status = WITHDRAWN
            self.pending = None

        first_in_chain = not self.evidences
        evidence = self._open(ev)
        if first_in_chain:
            evidence.timeline_status = INITIAL_ADDITION
        else:
            self.report.unmatched_added += 1
            self._check_competing()
        return evidence

    def _same_change_pair(self, removed: CvssEvent, added: CvssEvent) -> None:
        self.report.same_change_pairs += 1
        tier, reasons = classify(
            event_name=added.event_name, detail_type=added.detail_type,
            old_source=removed.source_prefix, new_source=added.source_prefix,
            old_vector=removed.vector_normalized, new_vector=added.vector_normalized,
            removed_count=1, added_count=1,
        )
        if tier == "STRICT":
            self.report.strict_same_change += 1
            old = self.active.get(removed.vector)
            if old is None and self._n_events == 2 and not self.active and not self.seen_vectors:
                old = self._inferred_initial(removed)
            elif old is None:

                old = self._inferred_initial(removed)
                self._flag("STRICT_PAIR_OLD_VALUE_NOT_ACTIVE")
            self._close(old, added, REPLACED, STRICT_SAME_CHANGE)
            self.pending = None
            self.last_event_was_pending_removal = False
            new = self._open(added)
            new.replaces_evidence_id = old.evidence_id
            old.superseded_by_evidence_id = new.evidence_id
            self._check_competing()
            return

        self.report.excluded_same_change += 1
        if "NO_METRIC_CHANGE" in reasons and removed.vector == added.vector:

            self.report.duplicate_rewrites += 1
            if removed.vector not in self.active:
                if self._n_events <= 2 and not self.active and not self.seen_vectors:
                    self._inferred_initial(removed)
                else:
                    self._added(added)
            self.last_event_was_pending_removal = False
            return

        self._removed(removed)
        self._added(added)

    def replay(self, events: list[CvssEvent]) -> None:
        events = sorted(events, key=lambda e: (e.created, e.change_id, e.detail_index))
        self.report.n_events = len(events)
        by_change: dict[str, list[CvssEvent]] = defaultdict(list)
        order: list[str] = []
        for ev in events:
            if ev.change_id not in by_change:
                order.append(ev.change_id)
            by_change[ev.change_id].append(ev)

        for change_id in order:
            group = by_change[change_id]
            for ev in group:
                self._track_order(ev)
            removed = [e for e in group if e.action == "Removed"]
            added = [e for e in group if e.action == "Added"]
            if len(removed) == 1 and len(added) == 1:
                self._same_change_pair(removed[0], added[0])
                continue
            if removed and added:
                self._flag("MULTI_REMOVED_OR_ADDED_IN_ONE_CHANGE")
            for ev in removed:
                self._removed(ev)
            for ev in added:
                self._added(ev)

        for evidence in self.active.values():
            evidence.timeline_status = evidence.timeline_status if evidence.timeline_status == INITIAL_ADDITION else ACTIVE
            evidence.valid_until_censored = True
        if self.pending is not None and self.pending.timeline_status == REMOVED_PENDING:
            self.pending.timeline_status = WITHDRAWN
        for evidence in self.evidences:
            if evidence.timeline_status == REMOVED_PENDING:
                evidence.timeline_status = WITHDRAWN
            evidence.chain_ambiguous = self.report.ambiguous
            if self.report.ambiguous:
                for reason in self.report.ambiguity_reasons:
                    if reason not in evidence.ambiguity_reason:
                        evidence.ambiguity_reason.append(reason)

def replay_all(
    history_dir: Path = paths.NVD_HISTORY_DIR,
    cfg: TimelineConfig | None = None,
    stats: ReaderStats | None = None,
    files: list[Path] | None = None,
    use_reported_index: bool = True,
) -> tuple[list[Evidence], list[ChainReport], list[CrossEventCandidate], dict[str, Any]]:
    cfg = cfg or load_timeline_config()
    stats = stats if stats is not None else ReaderStats()

    reported_index = build_reported_index() if (files is None and use_reported_index) else None
    chains: dict[tuple[str, str, str], list[CvssEvent]] = defaultdict(list)
    pair_stats: Counter[str] = Counter()

    for change_events in iter_cvss_events(history_dir, cfg, stats, files):

        by_type: dict[str, dict[str, list[CvssEvent]]] = defaultdict(lambda: {"Removed": [], "Added": []})
        for ev in change_events:
            by_type[ev.detail_type][ev.action].append(ev)
            chains[ev.chain_key].append(ev)
        for detail_type, acts in by_type.items():
            if len(acts["Removed"]) == 1 and len(acts["Added"]) == 1:
                r, a = acts["Removed"][0], acts["Added"][0]
                pair_stats["candidates"] += 1
                if r.cvss_version != a.cvss_version:
                    pair_stats["version_change"] += 1
                if r.source_prefix and a.source_prefix and r.source_prefix.lower() != a.source_prefix.lower():
                    pair_stats["source_prefix_change"] += 1
            elif acts["Removed"] and acts["Added"]:
                pair_stats["candidates"] += 1
                pair_stats["multi_removed_or_added"] += 1

    evidences: list[Evidence] = []
    reports: list[ChainReport] = []
    candidates: list[CrossEventCandidate] = []
    for key in sorted(chains):
        replayer = ChainReplayer(key, cfg, reported_index)
        replayer.replay(chains[key])
        evidences.extend(replayer.evidences)
        reports.append(replayer.report)
        candidates.extend(replayer.cross_candidates)
    return evidences, reports, candidates, dict(pair_stats)

def profile(evidences: list[Evidence], reports: list[ChainReport], candidates: list[CrossEventCandidate],
            pair_stats: dict[str, Any], stats: ReaderStats, cfg: TimelineConfig) -> dict[str, Any]:
    status = Counter(e.timeline_status for e in evidences)
    repl = Counter(e.replacement_type for e in evidences if e.replacement_type)
    sources_per_cve: defaultdict[str, set[str]] = defaultdict(set)
    for r in reports:
        sources_per_cve[r.cve_id].add(r.source_key)
    n_sources = Counter(min(len(s), 3) for s in sources_per_cve.values())

    active_chains_per_cve: Counter[str] = Counter()
    for e in evidences:
        if e.valid_until is None and not e.chain_ambiguous:
            active_chains_per_cve[e.cve_id] += 1
    multi_current = sum(1 for v in active_chains_per_cve.values() if v > 1)

    censored = [e for e in evidences if e.valid_from_censored]
    strict_old = [e for e in evidences if e.replacement_type == STRICT_SAME_CHANGE]
    ambiguous_chains = [r for r in reports if r.ambiguous]
    alias_unresolved = sorted({r.source_key for r in reports if r.source_key not in cfg.aliases.values()})

    return {
        "history_files": stats.files,
        "total_changes": stats.changes,
        "reader_issues": stats.issue_count,
        "observation_window": {"start": cfg.window_start, "end": cfg.window_end},
        "source_alias_mapping_version": cfg.mapping_version,
        "chains": len(reports),
        "chains_nvd_only": sum(1 for r in reports if r.source_key == "NVD"),
        "cves": len(sources_per_cve),
        "cves_by_source_count": {"1": n_sources.get(1, 0), "2": n_sources.get(2, 0), "3+": n_sources.get(3, 0)},
        "cves_with_multiple_current_at_window_end": multi_current,
        "evidence_intervals": len(evidences),
        "timeline_status_counts": dict(status),
        "replacement_type_counts": dict(repl),
        "same_change": {
            "candidates": pair_stats.get("candidates", 0),
            "strict": sum(r.strict_same_change for r in reports),
            "excluded": sum(r.excluded_same_change for r in reports),
            "version_change": pair_stats.get("version_change", 0),
            "source_prefix_change": pair_stats.get("source_prefix_change", 0),
            "multi_removed_or_added": pair_stats.get("multi_removed_or_added", 0),
        },
        "cross_event_candidates": {
            "count": len(candidates),
            "by_year": dict(Counter(c.year for c in candidates)),
            "gap_days": _quantiles([c.gap_days for c in candidates]),
            "by_source_key": dict(Counter(c.source_key for c in candidates).most_common(10)),
        },
        "unmatched_removed": sum(r.unmatched_removed for r in reports),
        "unmatched_added": sum(r.unmatched_added for r in reports),
        "duplicate_rewrites": sum(r.duplicate_rewrites for r in reports),
        "duplicate_readds": sum(r.duplicate_readds for r in reports),
        "same_value_readds": sum(r.same_value_readds for r in reports),
        "reversals": sum(r.reversals for r in reports),
        "same_timestamp_conflicts": sum(r.same_timestamp_conflicts for r in reports),
        "competing_active_events": sum(r.competing_active for r in reports),
        "ambiguous_chains": len(ambiguous_chains),
        "ambiguity_reasons": dict(Counter(reason for r in ambiguous_chains for reason in r.ambiguity_reasons)),
        "chains_first_event_removed": sum(1 for r in reports if r.first_event_action == "Removed"),
        "chains_first_event_added": sum(1 for r in reports if r.first_event_action == "Added"),
        "left_censoring": {
            "censored_intervals": len(censored),
            "uncensored_intervals": len(evidences) - len(censored),
            "censored_then_strict_replaced": sum(1 for e in censored if e.replacement_type == STRICT_SAME_CHANGE),
            "strict_replaced_uncensored": sum(1 for e in strict_old if not e.valid_from_censored),
            "strict_replaced_by_year": dict(Counter((e.valid_until or "")[:4] for e in strict_old)),
            "strict_replaced_censored_by_year": dict(Counter((e.valid_until or "")[:4] for e in strict_old if e.valid_from_censored)),
        },
        "base_score_available": sum(1 for e in evidences if e.base_score is not None),
        "base_score_missing_by_version": dict(Counter(e.cvss_version for e in evidences if e.base_score is None)),
        "source_keys_unmapped_count": len(alias_unresolved),
        "top_source_keys": dict(Counter(e.source_key for e in evidences).most_common(12)),
        "source_conditioned_eligible_chains": sum(1 for r in reports if not r.ambiguous and r.strict_same_change > 0),
    }

def _quantiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {}
    s = sorted(values)
    q = lambda p: s[min(len(s) - 1, int(p * len(s)))]
    return {"min": s[0], "p25": q(0.25), "median": q(0.5), "p75": q(0.75), "p90": q(0.9), "max": s[-1]}

def write_outputs(evidences: list[Evidence], candidates: list[CrossEventCandidate], summary: dict[str, Any],
                  out_path: Path, profile_dir: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for e in evidences:
            handle.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "timeline_profile.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (profile_dir / "cross_event_candidates.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = list(CrossEventCandidate.__dataclass_fields__)
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for c in candidates:
            row = asdict(c)
            row["changed_components"] = ",".join(c.changed_components)
            writer.writerow(row)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--history-dir", type=Path, default=paths.NVD_HISTORY_DIR)
    parser.add_argument("--out", type=Path, default=paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl")
    parser.add_argument("--profile-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    args = parser.parse_args(argv)

    cfg = load_timeline_config()
    stats = ReaderStats()
    evidences, reports, candidates, pair_stats = replay_all(args.history_dir, cfg, stats)
    summary = profile(evidences, reports, candidates, pair_stats, stats, cfg)
    write_outputs(evidences, candidates, summary, args.out, args.profile_dir)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"JSONL: {args.out.resolve()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
