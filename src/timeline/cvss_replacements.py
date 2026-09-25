from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

from src import paths
from src.ingest.nvd_history import HistoryRecord, ReaderStats, iter_changes_grouped
from src.normalize.cvss import (
    CVSS_DETAIL_TYPES,
    UNKNOWN_VERSION,
    changed_components,
    compare_sources,
    extract_vector_and_source,
    identify_cvss_version,
    is_vector_parseable,
    normalize_cvss_vector,
)
from src.profile.common import compact_normalized_text, parse_timestamp_year

ALLOWED_EVENT_NAMES = {"CVE Modified", "Modified Analysis", "Reanalysis"}
BULK_OR_ADMINISTRATIVE_EVENT_NAMES = {
    "Data Remediation",
    "CPE Deprecation Remap",
    "Initial Analysis",
    "CVE Translated",
    "CVE CISA KEV Update",
    "CVE Source Update",
}
EXCLUDED_REASONS = {
    "REMOVED_COUNT_NOT_ONE",
    "ADDED_COUNT_NOT_ONE",
    "UNSUPPORTED_CVSS_DETAIL_TYPE",
    "OLD_VECTOR_NOT_FOUND",
    "NEW_VECTOR_NOT_FOUND",
    "OLD_VECTOR_NOT_PARSEABLE",
    "NEW_VECTOR_NOT_PARSEABLE",
    "CVSS_VERSION_CHANGED",
    "NO_METRIC_CHANGE",
    "ADMINISTRATIVE_OR_BULK_EVENT",
}

@dataclass(frozen=True)
class CvssReplacement:
    replacement_id: str
    cve_id: str
    event_name: str
    change_id: str
    source_identifier: str
    created: str
    year: str
    detail_type: str
    cvss_version: str
    old_vector: str
    new_vector: str
    old_source: str
    new_source: str
    same_source: bool
    changed_components: list[str]
    tier: str
    exclusion_reasons: list[str]
    removed_count: int
    added_count: int
    source_file: str
    removed_detail_index: int
    added_detail_index: int
    old_raw: str
    new_raw: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def classify(
    event_name: str,
    detail_type: str,
    old_source: str,
    new_source: str,
    old_vector: str,
    new_vector: str,
    removed_count: int,
    added_count: int,
) -> tuple[str, list[str]]:
    reasons: list[str] = []

    if removed_count != 1:
        reasons.append("REMOVED_COUNT_NOT_ONE")
    if added_count != 1:
        reasons.append("ADDED_COUNT_NOT_ONE")
    if detail_type not in CVSS_DETAIL_TYPES:
        reasons.append("UNSUPPORTED_CVSS_DETAIL_TYPE")
    if not old_vector:
        reasons.append("OLD_VECTOR_NOT_FOUND")
    if not new_vector:
        reasons.append("NEW_VECTOR_NOT_FOUND")

    old_parseable = is_vector_parseable(old_vector)
    new_parseable = is_vector_parseable(new_vector)
    if old_vector and not old_parseable:
        reasons.append("OLD_VECTOR_NOT_PARSEABLE")
    if new_vector and not new_parseable:
        reasons.append("NEW_VECTOR_NOT_PARSEABLE")

    old_version = identify_cvss_version(detail_type, old_vector)
    new_version = identify_cvss_version(detail_type, new_vector)
    if old_version != UNKNOWN_VERSION and new_version != UNKNOWN_VERSION and old_version != new_version:
        reasons.append("CVSS_VERSION_CHANGED")

    if not compare_sources(old_source, new_source):
        reasons.append("SOURCE_CHANGED_OR_MISSING")

    changed = changed_components(old_vector, new_vector)
    if not changed:
        reasons.append("NO_METRIC_CHANGE")

    if event_name in BULK_OR_ADMINISTRATIVE_EVENT_NAMES:
        reasons.append("ADMINISTRATIVE_OR_BULK_EVENT")

    structured = (
        removed_count == 1
        and added_count == 1
        and detail_type in CVSS_DETAIL_TYPES
        and old_parseable
        and new_parseable
        and bool(changed)
    )

    if structured and old_version == new_version and event_name in ALLOWED_EVENT_NAMES:
        return "STRICT", []
    if any(reason in EXCLUDED_REASONS for reason in reasons):
        return "EXCLUDED", reasons
    if structured:
        return "MODERATE", reasons
    return "EXCLUDED", reasons

def _candidate_from_group(
    group: list[HistoryRecord],
    detail_type: str,
    removed: list[HistoryRecord],
    added: list[HistoryRecord],
) -> CvssReplacement:
    head = group[0]
    removed_count, added_count = len(removed), len(added)
    old_raw = removed[0].old_value if removed_count == 1 else [r.old_value for r in removed]
    new_raw = added[0].new_value if added_count == 1 else [r.new_value for r in added]

    old_source, old_vector = extract_vector_and_source(old_raw)
    new_source, new_vector = extract_vector_and_source(new_raw)
    old_vector = normalize_cvss_vector(old_vector)
    new_vector = normalize_cvss_vector(new_vector)

    tier, reasons = classify(
        head.event_name, detail_type, old_source, new_source, old_vector, new_vector, removed_count, added_count
    )
    version = identify_cvss_version(detail_type, new_vector)
    created_raw = head.created

    return CvssReplacement(
        replacement_id=f"{head.cve_id}|{head.change_id}|{detail_type}",
        cve_id=head.cve_id,
        event_name=head.event_name,
        change_id=head.change_id,
        source_identifier=head.source_identifier,
        created=created_raw,
        year=parse_timestamp_year(created_raw),
        detail_type=detail_type,
        cvss_version=version,
        old_vector=old_vector,
        new_vector=new_vector,
        old_source=old_source,
        new_source=new_source,
        same_source=compare_sources(old_source, new_source),
        changed_components=changed_components(old_vector, new_vector),
        tier=tier,
        exclusion_reasons=reasons,
        removed_count=removed_count,
        added_count=added_count,
        source_file=head.source_file,
        removed_detail_index=removed[0].detail_index if removed_count == 1 else -1,
        added_detail_index=added[0].detail_index if added_count == 1 else -1,
        old_raw=compact_normalized_text(old_raw, limit=2000),
        new_raw=compact_normalized_text(new_raw, limit=2000),
    )

def iter_replacements(
    history_dir: Path = paths.NVD_HISTORY_DIR,
    stats: ReaderStats | None = None,
    files: list[Path] | None = None,
) -> Iterator[CvssReplacement]:
    for group in iter_changes_grouped(history_dir, stats, files):
        removed_by_type: defaultdict[str, list[HistoryRecord]] = defaultdict(list)
        added_by_type: defaultdict[str, list[HistoryRecord]] = defaultdict(list)

        for record in group:
            if record.detail_type not in CVSS_DETAIL_TYPES:
                continue
            if record.action == "Removed":
                removed_by_type[record.detail_type].append(record)
            elif record.action == "Added":
                added_by_type[record.detail_type].append(record)

        for detail_type in sorted(set(removed_by_type) & set(added_by_type)):
            yield _candidate_from_group(group, detail_type, removed_by_type[detail_type], added_by_type[detail_type])

def profile(replacements: list[CvssReplacement], stats: ReaderStats) -> dict[str, Any]:
    tiers = Counter(r.tier for r in replacements)
    year_tier: defaultdict[str, Counter[str]] = defaultdict(Counter)
    type_tier: defaultdict[str, Counter[str]] = defaultdict(Counter)
    reasons: Counter[str] = Counter()
    cves: defaultdict[str, set[str]] = defaultdict(set)

    for r in replacements:
        year_tier[r.tier][r.year] += 1
        type_tier[r.tier][r.detail_type] += 1
        cves[r.tier].add(r.cve_id)
        reasons.update(r.exclusion_reasons)

    return {
        "history_files": stats.files,
        "total_changes": stats.changes,
        "reader_issues": stats.issue_count,
        "candidates": len(replacements),
        "tier_counts": dict(tiers),
        "year_tier_counts": {tier: dict(sorted(c.items())) for tier, c in year_tier.items()},
        "detail_type_tier_counts": {tier: dict(c) for tier, c in type_tier.items()},
        "unique_cves_by_tier": {tier: len(s) for tier, s in cves.items()},
        "exclusion_reason_counts": dict(reasons),
    }

def write_outputs(replacements: list[CvssReplacement], summary: dict[str, Any], jsonl_path: Path, profile_dir: Path) -> None:
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for r in replacements:
            handle.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")

    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "cvss_replacement_profile.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    fieldnames = [f for f in CvssReplacement.__dataclass_fields__ if f not in {"old_raw", "new_raw"}]
    with (profile_dir / "cvss_replacement_profile.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for r in replacements:
            row = {k: v for k, v in r.to_dict().items() if k in fieldnames}
            row["changed_components"] = ",".join(r.changed_components)
            row["exclusion_reasons"] = "|".join(r.exclusion_reasons)
            writer.writerow(row)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--history-dir", type=Path, default=paths.NVD_HISTORY_DIR)
    parser.add_argument("--out", type=Path, default=paths.PROCESSED_DATA_DIR / "cvss_replacements.jsonl")
    parser.add_argument("--profile-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    args = parser.parse_args(argv)

    stats = ReaderStats()
    replacements = list(iter_replacements(args.history_dir, stats))
    summary = profile(replacements, stats)
    write_outputs(replacements, summary, args.out, args.profile_dir)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"JSONL: {args.out.resolve()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
