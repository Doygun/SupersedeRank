from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    import _bootstrap
else:
    from . import _bootstrap

from src import paths
from src.profile.common import (
    format_read_error,
    load_json,
    progress,
    sorted_json_files,
    write_json_summary,
    write_text_report,
)

REPORT_NAME = "nvd_history_profile.txt"
SUMMARY_NAME = "nvd_history_profile.summary.json"

def run(history_dir: Path, verbose: bool = True) -> dict[str, Any]:
    files = sorted_json_files(history_dir)

    if not files:
        raise SystemExit(f"NVD History dosyasi bulunamadi: {Path(history_dir).resolve()}")

    event_names: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    detail_types: Counter[str] = Counter()
    action_type_pairs: Counter[tuple[str, str]] = Counter()

    total_changes = 0
    total_details = 0
    details_with_old_value = 0
    details_with_new_value = 0
    details_with_both_values = 0
    malformed_changes = 0
    malformed_details = 0
    read_errors: list[str] = []

    for index, path in enumerate(files, start=1):
        try:
            payload = load_json(path)
        except Exception as error:
            read_errors.append(format_read_error(path, error))
            continue

        changes = payload.get("cveChanges", [])

        if not isinstance(changes, list):
            read_errors.append(f"{path}: cveChanges bir liste degil")
            continue

        for wrapper in changes:
            if not isinstance(wrapper, dict):
                malformed_changes += 1
                continue

            change = wrapper.get("change")

            if not isinstance(change, dict):
                malformed_changes += 1
                continue

            total_changes += 1
            event_names[str(change.get("eventName", "[EKSIK]"))] += 1

            details = change.get("details", [])

            if not isinstance(details, list):
                malformed_changes += 1
                continue

            for detail in details:
                if not isinstance(detail, dict):
                    malformed_details += 1
                    continue

                total_details += 1

                action = str(detail.get("action", "[EKSIK]"))
                detail_type = str(detail.get("type", "[EKSIK]"))

                actions[action] += 1
                detail_types[detail_type] += 1
                action_type_pairs[(action, detail_type)] += 1

                has_old = "oldValue" in detail and detail.get("oldValue") is not None
                has_new = "newValue" in detail and detail.get("newValue") is not None

                if has_old:
                    details_with_old_value += 1
                if has_new:
                    details_with_new_value += 1
                if has_old and has_new:
                    details_with_both_values += 1

        if verbose:
            progress(index, len(files))

    return {
        "file_count": len(files),
        "total_changes": total_changes,
        "total_details": total_details,
        "details_with_old_value": details_with_old_value,
        "details_with_new_value": details_with_new_value,
        "details_with_both_values": details_with_both_values,
        "malformed_changes": malformed_changes,
        "malformed_details": malformed_details,
        "read_error_count": len(read_errors),
        "read_errors": read_errors,
        "event_names": event_names,
        "actions": actions,
        "detail_types": detail_types,
        "action_type_pairs": action_type_pairs,
    }

def render_report(summary: dict[str, Any]) -> list[str]:
    lines: list[str] = []

    lines.append("NVD HISTORY PROFIL RAPORU")
    lines.append("=" * 80)
    lines.append(f"Dosya sayisi: {summary['file_count']:,}")
    lines.append(f"Change sayisi: {summary['total_changes']:,}")
    lines.append(f"Detail sayisi: {summary['total_details']:,}")
    lines.append(f"OldValue bulunan detail: {summary['details_with_old_value']:,}")
    lines.append(f"NewValue bulunan detail: {summary['details_with_new_value']:,}")
    lines.append(
        "OldValue ve NewValue birlikte bulunan detail: "
        f"{summary['details_with_both_values']:,}"
    )
    lines.append(f"Bozuk change sayisi: {summary['malformed_changes']:,}")
    lines.append(f"Bozuk detail sayisi: {summary['malformed_details']:,}")
    lines.append(f"Dosya okuma hatasi: {summary['read_error_count']:,}")

    for title, counter in (
        ("EVENT NAME DAGILIMI", summary["event_names"]),
        ("ACTION DAGILIMI", summary["actions"]),
        ("DETAIL TYPE DAGILIMI", summary["detail_types"]),
    ):
        lines.append("")
        lines.append(title)
        lines.append("-" * 80)
        for name, count in counter.most_common():
            lines.append(f"{name}\t{count}")

    lines.append("")
    lines.append("ACTION + TYPE DAGILIMI")
    lines.append("-" * 80)
    for (action, detail_type), count in summary["action_type_pairs"].most_common():
        lines.append(f"{action}\t{detail_type}\t{count}")

    if summary["read_errors"]:
        lines.append("")
        lines.append("OKUMA HATALARI")
        lines.append("-" * 80)
        lines.extend(summary["read_errors"])

    return lines

def json_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in summary.items()
        if key not in {"action_type_pairs", "read_errors"}
    } | {
        "action_type_pairs": {f"{a}\t{t}": c for (a, t), c in summary["action_type_pairs"].items()},
    }

def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--history-dir", type=Path, default=paths.NVD_HISTORY_DIR)
    parser.add_argument("--output-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = run(args.history_dir)

    report_path = args.output_dir / REPORT_NAME
    write_text_report(report_path, render_report(summary))
    write_json_summary(args.output_dir / SUMMARY_NAME, json_summary(summary))

    print()
    print(f"Rapor kaydedildi: {report_path.resolve()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
