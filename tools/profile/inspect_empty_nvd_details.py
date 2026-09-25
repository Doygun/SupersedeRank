from __future__ import annotations

import argparse
import json
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
    file_ref,
    iter_changes,
    progress,
    sorted_json_files,
    write_json_summary,
    write_text_report,
)

REPORT_NAME = "empty_nvd_details_report.txt"
SUMMARY_NAME = "empty_nvd_details_report.summary.json"
MAX_EXAMPLES = 10

def classify_details(change: dict[str, Any]) -> str | None:
    details = change.get("details", None)

    if "details" not in change:
        return "DETAILS_KEY_MISSING"
    if details is None:
        return "DETAILS_NULL"
    if not isinstance(details, list):
        return f"DETAILS_NOT_LIST:{type(details).__name__}"
    if len(details) == 0:
        return "DETAILS_EMPTY_LIST"
    if not any(isinstance(item, dict) for item in details):
        return "NO_DICT_DETAIL"
    return None

def run(history_dir: Path, verbose: bool = True, max_examples: int = MAX_EXAMPLES) -> dict[str, Any]:
    files = sorted_json_files(history_dir)

    reason_counts: Counter[str] = Counter()
    event_counts: Counter[tuple[str, str]] = Counter()
    examples: list[dict[str, Any]] = []
    total_changes = 0
    progress_lines: list[str] = []

    for file_index, path in enumerate(files, start=1):

        for change in iter_changes(path):
            total_changes += 1
            reason = classify_details(change)

            if reason is None:
                continue

            reason_counts[reason] += 1
            event_name = str(change.get("eventName", "[EKSIK]"))
            event_counts[(reason, event_name)] += 1

            if len(examples) < max_examples:
                examples.append(
                    {
                        "file": file_ref(path),
                        "cveId": change.get("cveId"),
                        "eventName": event_name,
                        "cveChangeId": change.get("cveChangeId"),
                        "sourceIdentifier": change.get("sourceIdentifier"),
                        "created": change.get("created"),
                        "reason": reason,
                        "details": change.get("details", None),
                    }
                )

        if file_index % 25 == 0 or file_index == len(files):
            progress_lines.append(f"Islenen dosya: {file_index}/{len(files)}")
            if verbose:
                progress(file_index, len(files), thousands=False)

    return {
        "file_count": len(files),
        "total_changes": total_changes,
        "reason_counts": reason_counts,
        "event_counts": event_counts,
        "examples": examples,
        "progress_lines": progress_lines,
    }

def render_report(summary: dict[str, Any], include_progress: bool = True) -> list[str]:
    lines: list[str] = []

    if include_progress:
        lines.extend(summary["progress_lines"])

    lines.append("")
    lines.append(f"Toplam change: {summary['total_changes']:,}")
    lines.append("")
    lines.append("BOS SIGNATURE NEDENLERI")
    lines.append("-" * 80)

    for reason, count in summary["reason_counts"].most_common():
        lines.append(f"{reason}\t{count:,}")

    lines.append("")
    lines.append("EVENT NAME DAGILIMI")
    lines.append("-" * 80)

    for (reason, event_name), count in summary["event_counts"].most_common():
        lines.append(f"{reason}\t{event_name}\t{count:,}")

    lines.append("")
    lines.append("ORNEKLER")
    lines.append("-" * 80)

    for example in summary["examples"]:
        lines.append(json.dumps(example, ensure_ascii=False, indent=2))
        lines.append("-" * 80)

    return lines

def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--history-dir", type=Path, default=paths.NVD_HISTORY_DIR)
    parser.add_argument("--output-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = run(args.history_dir)

    report_lines = render_report(summary, include_progress=False)
    print("\n".join(report_lines))

    write_text_report(args.output_dir / REPORT_NAME, render_report(summary, include_progress=True))
    write_json_summary(
        args.output_dir / SUMMARY_NAME,
        {
            "file_count": summary["file_count"],
            "total_changes": summary["total_changes"],
            "reason_counts": summary["reason_counts"],
            "event_counts": {f"{r}\t{e}": c for (r, e), c in summary["event_counts"].items()},
        },
    )
    print(f"Rapor kaydedildi: {(args.output_dir / REPORT_NAME).resolve()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
