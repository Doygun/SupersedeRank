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
    add_section,
    compact_text,
    file_ref,
    format_read_error,
    iter_changes,
    normalize_whitespace,
    progress,
    sorted_json_files,
    value_shape,
    write_csv_rows,
    write_json_summary,
    write_text_report,
)

REPORT_NAME = "nvd_change_pattern_report.txt"
EXAMPLES_NAME = "nvd_change_examples.csv"
SUMMARY_NAME = "nvd_change_pattern_report.summary.json"

MAX_EXAMPLES_PER_GROUP = 5

CVSS_TYPES = {
    "CVSS V2",
    "CVSS V2 Metadata",
    "CVSS V3",
    "CVSS V3.1",
    "CVSS V4.0",
    "CVSS V4.0 Score",
}

EXAMPLE_FIELDNAMES = [
    "file",
    "cve_id",
    "event_name",
    "change_id",
    "source",
    "created",
    "action",
    "detail_type",
    "old_shape",
    "new_shape",
    "same_after_normalization",
    "old_value",
    "new_value",
]

def normalize_value(value: Any) -> str:
    return normalize_whitespace(value, unescape_html=True)

def build_example(
    path: Path,
    cve_id: str,
    event_name: str,
    change_id: str,
    source: str,
    created: str,
    action: str,
    detail_type: str,
    old_shape: str,
    new_shape: str,
    same_after_normalization: bool,
    old_value: Any,
    new_value: Any,
) -> dict[str, Any]:
    return {
        "file": file_ref(path),
        "cve_id": cve_id,
        "event_name": event_name,
        "change_id": change_id,
        "source": source,
        "created": created,
        "action": action,
        "detail_type": detail_type,
        "old_shape": old_shape,
        "new_shape": new_shape,
        "same_after_normalization": same_after_normalization,
        "old_value": compact_text(old_value),
        "new_value": compact_text(new_value),
    }

def run(history_dir: Path, verbose: bool = True) -> dict[str, Any]:
    files = sorted_json_files(history_dir)

    if not files:
        raise FileNotFoundError(f"NVD History JSON bulunamadi: {Path(history_dir).resolve()}")

    changed_by_type: Counter[str] = Counter()
    changed_by_event_type: Counter[tuple[str, str]] = Counter()
    changed_by_source_type: Counter[tuple[str, str]] = Counter()
    changed_by_year_type: Counter[tuple[str, str]] = Counter()
    changed_same_after_normalization: Counter[str] = Counter()
    changed_value_shapes: Counter[tuple[str, str, str]] = Counter()
    action_type_counts: Counter[tuple[str, str]] = Counter()
    change_action_signature_counts: Counter[tuple[tuple[str, str], ...]] = Counter()
    removed_added_same_type: Counter[str] = Counter()
    removed_added_pair_counts: Counter[tuple[str, int, int]] = Counter()
    cvss_change_event_counts: Counter[str] = Counter()
    cvss_change_signatures: Counter[tuple[str, int, int]] = Counter()
    examples: defaultdict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    cvss_event_examples: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)

    total_changes = 0
    total_details = 0
    total_changed_details = 0
    total_changed_same_normalized = 0
    total_multi_detail_changes = 0
    total_removed_added_changes = 0
    malformed_details = 0
    read_errors: list[str] = []

    for file_index, path in enumerate(files, start=1):
        try:
            for change in iter_changes(path):
                total_changes += 1

                cve_id = str(change.get("cveId", "[EKSIK]"))
                event_name = str(change.get("eventName", "[EKSIK]"))
                change_id = str(change.get("cveChangeId", "[EKSIK]"))
                source = str(change.get("sourceIdentifier", "[EKSIK]"))
                created = str(change.get("created", "[EKSIK]"))
                year = created[:4] if len(created) >= 4 else "[EKSIK]"

                details = change.get("details", [])

                if not isinstance(details, list):
                    continue

                total_details += len(details)

                if len(details) > 1:
                    total_multi_detail_changes += 1

                per_change_action_types: list[tuple[str, str]] = []
                removed_by_type: defaultdict[str, list[Any]] = defaultdict(list)
                added_by_type: defaultdict[str, list[Any]] = defaultdict(list)

                for detail in details:
                    if not isinstance(detail, dict):
                        malformed_details += 1
                        continue

                    action = str(detail.get("action", "[EKSIK]"))
                    detail_type = str(detail.get("type", "[EKSIK]"))

                    action_type_counts[(action, detail_type)] += 1
                    per_change_action_types.append((action, detail_type))

                    if action == "Removed":
                        removed_by_type[detail_type].append(detail.get("oldValue"))

                    elif action == "Added":
                        added_by_type[detail_type].append(detail.get("newValue"))

                    elif action == "Changed":
                        total_changed_details += 1
                        changed_by_type[detail_type] += 1
                        changed_by_event_type[(event_name, detail_type)] += 1
                        changed_by_source_type[(source, detail_type)] += 1
                        changed_by_year_type[(year, detail_type)] += 1

                        old_value = detail.get("oldValue")
                        new_value = detail.get("newValue")
                        old_shape = value_shape(old_value)
                        new_shape = value_shape(new_value)
                        changed_value_shapes[(detail_type, old_shape, new_shape)] += 1

                        same_after_normalization = normalize_value(old_value) == normalize_value(new_value)

                        if same_after_normalization:
                            total_changed_same_normalized += 1
                            changed_same_after_normalization[detail_type] += 1

                        group_key = ("Changed", detail_type)

                        if len(examples[group_key]) < MAX_EXAMPLES_PER_GROUP:
                            examples[group_key].append(
                                build_example(
                                    path=path,
                                    cve_id=cve_id,
                                    event_name=event_name,
                                    change_id=change_id,
                                    source=source,
                                    created=created,
                                    action=action,
                                    detail_type=detail_type,
                                    old_shape=old_shape,
                                    new_shape=new_shape,
                                    same_after_normalization=same_after_normalization,
                                    old_value=old_value,
                                    new_value=new_value,
                                )
                            )

                signature = tuple(sorted(per_change_action_types))
                change_action_signature_counts[signature] += 1

                has_removed = any(action == "Removed" for action, _ in per_change_action_types)
                has_added = any(action == "Added" for action, _ in per_change_action_types)

                if has_removed and has_added:
                    total_removed_added_changes += 1

                common_types = set(removed_by_type) & set(added_by_type)

                for detail_type in common_types:
                    removed_values = removed_by_type[detail_type]
                    added_values = added_by_type[detail_type]

                    removed_added_same_type[detail_type] += 1
                    removed_added_pair_counts[(detail_type, len(removed_values), len(added_values))] += 1

                    if detail_type not in CVSS_TYPES:
                        continue

                    cvss_change_event_counts[detail_type] += 1
                    cvss_change_signatures[(detail_type, len(removed_values), len(added_values))] += 1

                    if len(cvss_event_examples[detail_type]) >= MAX_EXAMPLES_PER_GROUP:
                        continue

                    cvss_event_examples[detail_type].append(
                        {
                            "file": file_ref(path),
                            "cve_id": cve_id,
                            "event_name": event_name,
                            "change_id": change_id,
                            "source": source,
                            "created": created,
                            "action": "Removed+Added",
                            "detail_type": detail_type,
                            "old_shape": f"list[{len(removed_values)}]",
                            "new_shape": f"list[{len(added_values)}]",
                            "same_after_normalization": False,
                            "old_value": compact_text(removed_values, limit=1000),
                            "new_value": compact_text(added_values, limit=1000),
                        }
                    )

        except Exception as error:
            read_errors.append(format_read_error(path, error))

        if verbose:
            progress(file_index, len(files))

    return {
        "file_count": len(files),
        "total_changes": total_changes,
        "total_details": total_details,
        "total_changed_details": total_changed_details,
        "total_changed_same_normalized": total_changed_same_normalized,
        "total_multi_detail_changes": total_multi_detail_changes,
        "total_removed_added_changes": total_removed_added_changes,
        "malformed_details": malformed_details,
        "read_error_count": len(read_errors),
        "read_errors": read_errors,
        "action_type_counts": action_type_counts,
        "changed_by_type": changed_by_type,
        "changed_same_after_normalization": changed_same_after_normalization,
        "changed_by_event_type": changed_by_event_type,
        "changed_by_year_type": changed_by_year_type,
        "changed_by_source_type": changed_by_source_type,
        "changed_value_shapes": changed_value_shapes,
        "removed_added_same_type": removed_added_same_type,
        "removed_added_pair_counts": removed_added_pair_counts,
        "cvss_change_event_counts": cvss_change_event_counts,
        "cvss_change_signatures": cvss_change_signatures,
        "change_action_signature_counts": change_action_signature_counts,
        "examples": examples,
        "cvss_event_examples": cvss_event_examples,
    }

def _example_block(example: dict[str, Any], old_label: str, new_label: str, with_norm: bool) -> list[str]:
    lines = [
        f"  CVE: {example['cve_id']}",
        f"  Event: {example['event_name']}",
        f"  Change ID: {example['change_id']}",
        f"  Source: {example['source']}",
        f"  Created: {example['created']}",
    ]
    if with_norm:
        lines.append(f"  Normalize edilince ayni: {example['same_after_normalization']}")
    lines.append(f"  {old_label}: {example['old_value']}")
    lines.append(f"  {new_label}: {example['new_value']}")
    return lines

def render_report(s: dict[str, Any]) -> list[str]:
    lines: list[str] = []

    add_section(lines, "GENEL OZET")
    lines.extend(
        [
            f"Dosya sayisi: {s['file_count']:,}",
            f"Change sayisi: {s['total_changes']:,}",
            f"Detail sayisi: {s['total_details']:,}",
            f"Changed detail sayisi: {s['total_changed_details']:,}",
            f"Normalize edilince ayni kalan Changed detail: {s['total_changed_same_normalized']:,}",
            f"Birden fazla detail iceren change: {s['total_multi_detail_changes']:,}",
            f"Hem Removed hem Added iceren change: {s['total_removed_added_changes']:,}",
            f"Bozuk detail sayisi: {s['malformed_details']:,}",
            f"Dosya okuma hatasi: {s['read_error_count']:,}",
        ]
    )

    add_section(lines, "ACTION + DETAIL TYPE DAGILIMI")
    for (action, detail_type), count in s["action_type_counts"].most_common():
        lines.append(f"{action}\t{detail_type}\t{count}")

    add_section(lines, "CHANGED DETAIL TYPE DAGILIMI")
    for detail_type, count in s["changed_by_type"].most_common():
        same_count = s["changed_same_after_normalization"][detail_type]
        lines.append(f"{detail_type}\t{count}\tnormalize_edilince_ayni={same_count}")

    add_section(lines, "CHANGED EVENT NAME + DETAIL TYPE")
    for (event_name, detail_type), count in s["changed_by_event_type"].most_common():
        lines.append(f"{event_name}\t{detail_type}\t{count}")

    add_section(lines, "CHANGED YEAR + DETAIL TYPE")
    sorted_year_types = sorted(
        s["changed_by_year_type"].items(),
        key=lambda item: (item[0][0], -item[1], item[0][1]),
    )
    for (year, detail_type), count in sorted_year_types:
        lines.append(f"{year}\t{detail_type}\t{count}")

    add_section(lines, "CHANGED SOURCE + DETAIL TYPE - ILK 200")
    for (source, detail_type), count in s["changed_by_source_type"].most_common(200):
        lines.append(f"{source}\t{detail_type}\t{count}")

    add_section(lines, "CHANGED VALUE SHAPES")
    for (detail_type, old_shape, new_shape), count in s["changed_value_shapes"].most_common():
        lines.append(f"{detail_type}\t{old_shape}->{new_shape}\t{count}")

    add_section(lines, "AYNI CHANGE ICINDE REMOVED + ADDED BULUNAN AYNI TYPE")
    for detail_type, count in s["removed_added_same_type"].most_common():
        lines.append(f"{detail_type}\tchange_sayisi={count}")

    add_section(lines, "REMOVED + ADDED ESLESME COKLUKLARI")
    for (detail_type, removed_count, added_count), count in s["removed_added_pair_counts"].most_common():
        lines.append(f"{detail_type}\tremoved={removed_count}\tadded={added_count}\tchange_sayisi={count}")

    add_section(lines, "CVSS REMOVED + ADDED DEGISIM ADAYLARI")
    if s["cvss_change_event_counts"]:
        for detail_type, count in s["cvss_change_event_counts"].most_common():
            lines.append(f"{detail_type}\tchange_sayisi={count}")
    else:
        lines.append("Bulunamadi.")

    add_section(lines, "CVSS REMOVED + ADDED SIGNATURE")
    if s["cvss_change_signatures"]:
        for (detail_type, removed_count, added_count), count in s["cvss_change_signatures"].most_common():
            lines.append(f"{detail_type}\tremoved={removed_count}\tadded={added_count}\tchange_sayisi={count}")
    else:
        lines.append("Bulunamadi.")

    add_section(lines, "EN YAYGIN CHANGE ACTION SIGNATURE - ILK 100")
    for signature, count in s["change_action_signature_counts"].most_common(100):
        signature_text = " | ".join(f"{action}:{detail_type}" for action, detail_type in signature)
        lines.append(f"{count}\t{signature_text or '[BOS SIGNATURE]'}")

    add_section(lines, "CHANGED ORNEKLERI")
    for group_key in sorted(s["examples"]):
        action, detail_type = group_key
        lines.append("")
        lines.append(f"--- {action} / {detail_type} ---")
        for index, example in enumerate(s["examples"][group_key], start=1):
            lines.append(f"Ornek {index}")
            lines.extend(_example_block(example, "Old", "New", with_norm=True))

    add_section(lines, "CVSS REMOVED + ADDED ORNEKLERI")
    for detail_type in sorted(s["cvss_event_examples"]):
        lines.append("")
        lines.append(f"--- {detail_type} ---")
        for index, example in enumerate(s["cvss_event_examples"][detail_type], start=1):
            lines.append(f"Ornek {index}")
            lines.extend(_example_block(example, "Removed", "Added", with_norm=False))

    if s["read_errors"]:
        add_section(lines, "DOSYA OKUMA HATALARI")
        lines.extend(s["read_errors"])

    return lines

def all_examples(s: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group in s["examples"].values():
        rows.extend(group)
    for group in s["cvss_event_examples"].values():
        rows.extend(group)
    return rows

def json_summary(s: dict[str, Any]) -> dict[str, Any]:
    scalar_keys = [
        "file_count", "total_changes", "total_details", "total_changed_details",
        "total_changed_same_normalized", "total_multi_detail_changes",
        "total_removed_added_changes", "malformed_details", "read_error_count",
    ]
    return {key: s[key] for key in scalar_keys} | {
        "changed_by_type": s["changed_by_type"],
        "cvss_change_event_counts": s["cvss_change_event_counts"],
        "action_type_counts": {f"{a}\t{t}": c for (a, t), c in s["action_type_counts"].items()},
    }

def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--history-dir", type=Path, default=paths.NVD_HISTORY_DIR)
    parser.add_argument("--output-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    s = run(args.history_dir)

    report_path = args.output_dir / REPORT_NAME
    examples_path = args.output_dir / EXAMPLES_NAME
    write_text_report(report_path, render_report(s))
    write_csv_rows(examples_path, all_examples(s), EXAMPLE_FIELDNAMES)
    write_json_summary(args.output_dir / SUMMARY_NAME, json_summary(s))

    print()
    print("Analiz tamamlandi.")
    print(f"Rapor: {report_path.resolve()}")
    print(f"Ornekler: {examples_path.resolve()}")
    print(f"Changed detail sayisi: {s['total_changed_details']:,}")
    print(f"Ayni change icinde Removed+Added bulunan change: {s['total_removed_added_changes']:,}")
    print(f"Dosya okuma hatasi: {s['read_error_count']:,}")
    print()
    print("CVSS Removed+Added adaylari:")
    if s["cvss_change_event_counts"]:
        for detail_type, count in s["cvss_change_event_counts"].most_common():
            print(f"  {detail_type}: {count:,}")
    else:
        print("  Bulunamadi.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
