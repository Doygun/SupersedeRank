from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    import _bootstrap
else:
    from . import _bootstrap

from src import paths
from src.profile.common import (
    add_counter_section,
    compact_normalized_text,
    file_ref,
    format_read_error,
    iter_changes,
    parse_timestamp_year,
    progress,
    sorted_json_files,
    write_csv_rows,
    write_json_summary,
    write_text_report,
)

REPORT_NAME = "cvss_replacement_candidate_report.txt"
CANDIDATES_NAME = "cvss_replacement_candidates.csv"
EXCLUDED_NAME = "cvss_replacement_excluded.csv"
SUMMARY_NAME = "cvss_replacement_candidate_report.summary.json"

MAX_EXAMPLES_PER_GROUP = 10

from src.normalize.cvss import CVSS_DETAIL_TYPES, CVSS_SCORE_DETAIL_TYPES

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

CSV_FIELDNAMES = [
    "file",
    "cve_id",
    "event_name",
    "change_id",
    "source_identifier",
    "created",
    "year",
    "detail_type",
    "removed_count",
    "added_count",
    "old_source",
    "new_source",
    "same_source",
    "old_cvss_version",
    "new_cvss_version",
    "old_vector",
    "new_vector",
    "old_parseable",
    "new_parseable",
    "changed_component_count",
    "changed_components",
    "confidence_tier",
    "exclusion_reasons",
    "old_raw",
    "new_raw",
]

from src.normalize.cvss import (
    changed_components,
    compare_sources,
    extract_vector_and_source,
    identify_cvss_version,
    is_vector_parseable,
    normalize_cvss_vector,
    vector_components,
)

def classify_event_confidence(
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

    if old_version != "[UNKNOWN]" and new_version != "[UNKNOWN]" and old_version != new_version:
        reasons.append("CVSS_VERSION_CHANGED")

    if not compare_sources(old_source, new_source):
        reasons.append("SOURCE_CHANGED_OR_MISSING")

    changed_metrics = changed_components(old_vector, new_vector)

    if not changed_metrics:
        reasons.append("NO_METRIC_CHANGE")

    if event_name in BULK_OR_ADMINISTRATIVE_EVENT_NAMES:
        reasons.append("ADMINISTRATIVE_OR_BULK_EVENT")

    strict_conditions = (
        removed_count == 1
        and added_count == 1
        and detail_type in CVSS_DETAIL_TYPES
        and old_parseable
        and new_parseable
        and old_version == new_version
        and bool(changed_metrics)
        and event_name in ALLOWED_EVENT_NAMES
    )

    if strict_conditions:
        return "STRICT", []

    if any(reason in EXCLUDED_REASONS for reason in reasons):
        return "EXCLUDED", reasons

    moderate_conditions = (
        removed_count == 1
        and added_count == 1
        and detail_type in CVSS_DETAIL_TYPES
        and old_parseable
        and new_parseable
        and bool(changed_metrics)
    )

    if moderate_conditions:
        return "MODERATE", reasons

    return "EXCLUDED", reasons

def build_candidate_row(
    file_path: Path,
    change: dict[str, Any],
    detail_type: str,
    removed_values: list[Any],
    added_values: list[Any],
) -> dict[str, Any]:
    cve_id = str(change.get("cveId", "[MISSING]"))
    event_name = str(change.get("eventName", "[MISSING]"))
    change_id = str(change.get("cveChangeId", "[MISSING]"))
    source_identifier = str(change.get("sourceIdentifier", "[MISSING]"))
    created = str(change.get("created", "[MISSING]"))

    removed_count = len(removed_values)
    added_count = len(added_values)

    old_raw = removed_values[0] if removed_count == 1 else removed_values
    new_raw = added_values[0] if added_count == 1 else added_values

    old_source, old_vector = extract_vector_and_source(old_raw)
    new_source, new_vector = extract_vector_and_source(new_raw)

    old_vector_normalized = normalize_cvss_vector(old_vector)
    new_vector_normalized = normalize_cvss_vector(new_vector)

    old_version = identify_cvss_version(detail_type, old_vector_normalized)
    new_version = identify_cvss_version(detail_type, new_vector_normalized)

    changed_metrics = changed_components(old_vector_normalized, new_vector_normalized)

    confidence_tier, exclusion_reasons = classify_event_confidence(
        event_name=event_name,
        detail_type=detail_type,
        old_source=old_source,
        new_source=new_source,
        old_vector=old_vector_normalized,
        new_vector=new_vector_normalized,
        removed_count=removed_count,
        added_count=added_count,
    )

    return {
        "file": file_ref(file_path),
        "cve_id": cve_id,
        "event_name": event_name,
        "change_id": change_id,
        "source_identifier": source_identifier,
        "created": created,
        "year": parse_timestamp_year(created),
        "detail_type": detail_type,
        "removed_count": removed_count,
        "added_count": added_count,
        "old_source": old_source,
        "new_source": new_source,
        "same_source": compare_sources(old_source, new_source),
        "old_cvss_version": old_version,
        "new_cvss_version": new_version,
        "old_vector": old_vector_normalized,
        "new_vector": new_vector_normalized,
        "old_parseable": is_vector_parseable(old_vector_normalized),
        "new_parseable": is_vector_parseable(new_vector_normalized),
        "changed_component_count": len(changed_metrics),
        "changed_components": ",".join(changed_metrics),
        "confidence_tier": confidence_tier,
        "exclusion_reasons": "|".join(exclusion_reasons),
        "old_raw": compact_normalized_text(old_raw, limit=2000),
        "new_raw": compact_normalized_text(new_raw, limit=2000),
    }

def collect_candidates(
    files: list[Path],
    verbose: bool = True,
) -> tuple[list[dict[str, Any]], list[str], int]:
    rows: list[dict[str, Any]] = []
    read_errors: list[str] = []
    total_changes = 0

    for file_index, file_path in enumerate(files, start=1):
        try:
            for change in iter_changes(file_path, strict=True):
                total_changes += 1
                details = change.get("details", [])

                if not isinstance(details, list):
                    continue

                removed_by_type: defaultdict[str, list[Any]] = defaultdict(list)
                added_by_type: defaultdict[str, list[Any]] = defaultdict(list)

                for detail in details:
                    if not isinstance(detail, dict):
                        continue

                    action = str(detail.get("action", "[MISSING]"))
                    detail_type = str(detail.get("type", "[MISSING]"))

                    if detail_type not in CVSS_DETAIL_TYPES:
                        continue

                    if action == "Removed":
                        removed_by_type[detail_type].append(detail.get("oldValue"))
                    elif action == "Added":
                        added_by_type[detail_type].append(detail.get("newValue"))

                for detail_type in sorted(set(removed_by_type) & set(added_by_type)):
                    rows.append(
                        build_candidate_row(
                            file_path=file_path,
                            change=change,
                            detail_type=detail_type,
                            removed_values=removed_by_type[detail_type],
                            added_values=added_by_type[detail_type],
                        )
                    )

        except Exception as error:
            read_errors.append(format_read_error(file_path, error))

        if verbose:
            progress(file_index, len(files))

    return rows, read_errors, total_changes

def summarize(
    files: list[Path],
    rows: list[dict[str, Any]],
    read_errors: list[str],
    total_changes: int,
) -> dict[str, Any]:
    tier_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    event_counts: Counter[str] = Counter()
    year_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    changed_component_counts: Counter[str] = Counter()
    type_tier_counts: Counter[tuple[str, str]] = Counter()
    event_tier_counts: Counter[tuple[str, str]] = Counter()
    year_tier_counts: Counter[tuple[str, str]] = Counter()
    exclusion_reason_counts: Counter[str] = Counter()
    unique_cves_by_tier: defaultdict[str, set[str]] = defaultdict(set)

    for row in rows:
        tier = str(row["confidence_tier"])
        detail_type = str(row["detail_type"])
        event_name = str(row["event_name"])
        year = str(row["year"])

        tier_counts[tier] += 1
        type_counts[detail_type] += 1
        event_counts[event_name] += 1
        year_counts[year] += 1
        source_counts[str(row["old_source"])] += 1
        type_tier_counts[(detail_type, tier)] += 1
        event_tier_counts[(event_name, tier)] += 1
        year_tier_counts[(year, tier)] += 1
        unique_cves_by_tier[tier].add(str(row["cve_id"]))

        for component in str(row["changed_components"]).split(","):
            if component:
                changed_component_counts[component] += 1

        for reason in str(row["exclusion_reasons"]).split("|"):
            if reason:
                exclusion_reason_counts[reason] += 1

    year_tier_nested: dict[str, dict[str, int]] = defaultdict(dict)
    for (year, tier), count in year_tier_counts.items():
        year_tier_nested[tier][year] = count

    return {
        "file_count": len(files),
        "total_changes": total_changes,
        "candidate_count": len(rows),
        "read_error_count": len(read_errors),
        "read_errors": read_errors,
        "tier_counts": dict(tier_counts),
        "type_counts": type_counts,
        "event_counts": event_counts,
        "year_counts": dict(year_counts),
        "source_counts": source_counts,
        "changed_component_counts": changed_component_counts,
        "type_tier_counts": type_tier_counts,
        "event_tier_counts": event_tier_counts,
        "year_tier_counts": dict(year_tier_nested),
        "_year_tier_counter": year_tier_counts,
        "exclusion_reason_counts": exclusion_reason_counts,
        "unique_cves_by_tier": {tier: len(cves) for tier, cves in unique_cves_by_tier.items()},
    }

def build_report(
    files: list[Path],
    rows: list[dict[str, Any]],
    read_errors: list[str],
    total_changes: int,
) -> str:
    s = summarize(files, rows, read_errors, total_changes)
    tier_rows = {tier: [row for row in rows if row["confidence_tier"] == tier] for tier in ("STRICT", "MODERATE", "EXCLUDED")}

    lines: list[str] = []
    lines.append("NVD CVSS REPLACEMENT CANDIDATE REPORT")
    lines.append("=" * 100)
    lines.append(f"History dosya sayisi: {len(files):,}")
    lines.append(f"Toplam incelenen change: {total_changes:,}")
    lines.append(f"CVSS Removed+Added adayi: {len(rows):,}")
    lines.append(f"STRICT aday: {len(tier_rows['STRICT']):,}")
    lines.append(f"MODERATE aday: {len(tier_rows['MODERATE']):,}")
    lines.append(f"EXCLUDED aday: {len(tier_rows['EXCLUDED']):,}")
    lines.append(f"Dosya okuma hatasi: {len(read_errors):,}")

    lines.append("")
    lines.append("BENZERSIZ CVE SAYILARI")
    lines.append("-" * 100)
    for tier in ("STRICT", "MODERATE", "EXCLUDED"):
        lines.append(f"{tier}: {s['unique_cves_by_tier'].get(tier, 0):,}")

    add_counter_section(lines, "CONFIDENCE TIER DAGILIMI", Counter(s["tier_counts"]))
    add_counter_section(lines, "DETAIL TYPE DAGILIMI", s["type_counts"])
    add_counter_section(lines, "DETAIL TYPE + TIER DAGILIMI", s["type_tier_counts"])
    add_counter_section(lines, "EVENT NAME DAGILIMI", s["event_counts"])
    add_counter_section(lines, "EVENT NAME + TIER DAGILIMI", s["event_tier_counts"])
    add_counter_section(lines, "YIL DAGILIMI", Counter(s["year_counts"]))
    add_counter_section(lines, "YIL + TIER DAGILIMI", s["_year_tier_counter"])
    add_counter_section(lines, "ESKI DEGER KAYNAGI - ILK 100", Counter(dict(s["source_counts"].most_common(100))))
    add_counter_section(lines, "DEGISEN CVSS BILESENLERI", s["changed_component_counts"])
    add_counter_section(lines, "DISLAMA NEDENLERI", s["exclusion_reason_counts"])

    lines.append("")
    lines.append("=" * 100)
    lines.append("STRICT ORNEKLER")
    lines.append("=" * 100)

    strict_examples_by_type: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in tier_rows["STRICT"]:
        detail_type = str(row["detail_type"])
        if len(strict_examples_by_type[detail_type]) < MAX_EXAMPLES_PER_GROUP:
            strict_examples_by_type[detail_type].append(row)

    if not strict_examples_by_type:
        lines.append("STRICT ornek bulunamadi.")

    for detail_type in sorted(strict_examples_by_type):
        lines.append("")
        lines.append(f"--- {detail_type} ---")
        for index, row in enumerate(strict_examples_by_type[detail_type], start=1):
            lines.append(f"Ornek {index}")
            lines.append(f"  CVE: {row['cve_id']}")
            lines.append(f"  Event: {row['event_name']}")
            lines.append(f"  Created: {row['created']}")
            lines.append(f"  Source: {row['old_source']}")
            lines.append(f"  Changed components: {row['changed_components']}")
            lines.append(f"  Old: {row['old_vector']}")
            lines.append(f"  New: {row['new_vector']}")

    if read_errors:
        lines.append("")
        lines.append("=" * 100)
        lines.append("DOSYA OKUMA HATALARI")
        lines.append("=" * 100)
        lines.extend(read_errors)

    return "\n".join(lines) + "\n"

def json_summary(s: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in s.items()
        if key not in {"_year_tier_counter", "type_tier_counts", "event_tier_counts", "source_counts", "read_errors"}
    } | {
        "type_tier_counts": {f"{t}\t{tier}": c for (t, tier), c in s["type_tier_counts"].items()},
        "event_tier_counts": {f"{e}\t{tier}": c for (e, tier), c in s["event_tier_counts"].items()},
    }

def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--history-dir", type=Path, default=paths.NVD_HISTORY_DIR)
    parser.add_argument("--output-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    files = sorted_json_files(args.history_dir)

    if not files:
        raise FileNotFoundError(f"NVD History JSON bulunamadi: {args.history_dir.resolve()}")

    print(f"NVD History dosya sayisi: {len(files):,}")

    rows, read_errors, total_changes = collect_candidates(files)

    accepted_rows = [row for row in rows if row["confidence_tier"] in {"STRICT", "MODERATE"}]
    excluded_rows = [row for row in rows if row["confidence_tier"] == "EXCLUDED"]

    candidates_path = args.output_dir / CANDIDATES_NAME
    excluded_path = args.output_dir / EXCLUDED_NAME
    report_path = args.output_dir / REPORT_NAME

    write_csv_rows(candidates_path, accepted_rows, CSV_FIELDNAMES)
    write_csv_rows(excluded_path, excluded_rows, CSV_FIELDNAMES)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(build_report(files, rows, read_errors, total_changes), encoding="utf-8")
    write_json_summary(args.output_dir / SUMMARY_NAME, json_summary(summarize(files, rows, read_errors, total_changes)))

    tier_counts = Counter(str(row["confidence_tier"]) for row in rows)

    print()
    print("CVSS replacement profili tamamlandi.")
    print(f"Toplam aday: {len(rows):,}")
    print(f"STRICT: {tier_counts['STRICT']:,}")
    print(f"MODERATE: {tier_counts['MODERATE']:,}")
    print(f"EXCLUDED: {tier_counts['EXCLUDED']:,}")
    print(f"Dosya okuma hatasi: {len(read_errors):,}")
    print()
    print(f"Rapor: {report_path.resolve()}")
    print(f"Kabul edilen adaylar: {candidates_path.resolve()}")
    print(f"Dislanan adaylar: {excluded_path.resolve()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
