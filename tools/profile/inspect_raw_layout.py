from __future__ import annotations

import argparse
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    import _bootstrap
else:
    from . import _bootstrap

from src import paths
from src.profile.common import file_ref, write_text_report

REPORT_NAME = "raw_layout_report.txt"

EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
}

SAMPLE_LIMIT_PER_EXTENSION = 5

COMPOUND_EXTENSIONS = [".csv.gz", ".json.gz", ".jsonl.gz", ".tar.gz", ".parquet.gz"]

def format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.3f} {unit}"
        value /= 1024

    return f"{size} B"

def normalize_extension(path: Path) -> str:
    name = path.name.lower()

    for extension in COMPOUND_EXTENSIONS:
        if name.endswith(extension):
            return extension

    if path.suffix:
        return path.suffix.lower()

    return "[uzantisiz]"

def scan_source(source_directory: Path, raw_root: Path) -> dict[str, Any]:
    file_count = 0
    directory_count = 0
    total_bytes = 0
    extension_counts: Counter[str] = Counter()
    extension_bytes: Counter[str] = Counter()
    samples: dict[str, list[str]] = defaultdict(list)
    errors: list[str] = []

    for current_root, directory_names, file_names in os.walk(source_directory, topdown=True):
        directory_names[:] = [name for name in directory_names if name not in EXCLUDED_DIRECTORY_NAMES]
        directory_count += len(directory_names)
        current_path = Path(current_root)

        for file_name in file_names:
            file_path = current_path / file_name

            try:
                size = file_path.stat().st_size
            except OSError as exc:
                errors.append(f"{file_path}: {exc}")
                continue

            extension = normalize_extension(file_path)
            relative_path = file_path.relative_to(raw_root)

            file_count += 1
            total_bytes += size
            extension_counts[extension] += 1
            extension_bytes[extension] += size

            if len(samples[extension]) < SAMPLE_LIMIT_PER_EXTENSION:
                samples[extension].append(str(relative_path))

    return {
        "source": source_directory.name,
        "file_count": file_count,
        "directory_count": directory_count,
        "total_bytes": total_bytes,
        "extension_counts": extension_counts,
        "extension_bytes": extension_bytes,
        "samples": samples,
        "errors": errors,
    }

def top_level_structure_lines(source_directory: Path) -> list[str]:
    lines = [f"\n[KLASOR] {file_ref(source_directory)}"]

    try:
        children = sorted(source_directory.iterdir(), key=lambda path: (not path.is_dir(), path.name.lower()))
    except OSError as exc:
        lines.append(f"  [HATA] {exc}")
        return lines

    visible_children = [child for child in children if child.name not in EXCLUDED_DIRECTORY_NAMES]

    if not visible_children:
        lines.append("  [BOS]")
        return lines

    for child in visible_children[:50]:
        item_type = "DIR " if child.is_dir() else "FILE"
        lines.append(f"  [{item_type}] {child.name}")

    if len(visible_children) > 50:
        lines.append(f"  ... {len(visible_children) - 50} oge daha var")

    return lines

def report_lines(report: dict[str, Any]) -> list[str]:
    lines = ["\n" + "=" * 80, f"KAYNAK: {report['source']}", "=" * 80]
    lines.append(f"Alt klasor sayisi : {report['directory_count']:,}")
    lines.append(f"Veri dosyasi      : {report['file_count']:,}")
    lines.append(f"Toplam veri boyutu: {format_bytes(report['total_bytes'])}")
    lines.append("\nUzanti dagilimi:")

    sorted_extensions = sorted(
        report["extension_counts"],
        key=lambda extension: (-report["extension_counts"][extension], extension),
    )

    if not sorted_extensions:
        lines.append("  Dosya bulunamadi.")

    for extension in sorted_extensions:
        count = report["extension_counts"][extension]
        size = report["extension_bytes"][extension]
        lines.append(f"  {extension:<15} dosya={count:>10,} boyut={format_bytes(size):>14}")

        for sample in report["samples"].get(extension, []):
            lines.append(f"      ornek: {sample}")

    if report["errors"]:
        lines.append(f"\nOkuma hatasi sayisi: {len(report['errors']):,}")
        for error in report["errors"][:10]:
            lines.append(f"  {error}")
        if len(report["errors"]) > 10:
            lines.append(f"  ... {len(report['errors']) - 10} hata daha var")
    else:
        lines.append("\nOkuma hatasi: 0")

    return lines

def run(raw_root: Path, verbose: bool = True) -> list[str]:
    raw_root = Path(raw_root)

    if not raw_root.exists():
        raise SystemExit(f"Ham veri klasoru bulunamadi: {raw_root.resolve()}")

    if not raw_root.is_dir():
        raise SystemExit(f"Beklenen yol klasor degil: {raw_root.resolve()}")

    source_directories = sorted(
        [path for path in raw_root.iterdir() if path.is_dir() and path.name not in EXCLUDED_DIRECTORY_NAMES],
        key=lambda path: path.name.lower(),
    )

    if not source_directories:
        raise SystemExit(f"Kaynak klasoru bulunamadi: {raw_root.resolve()}")

    lines: list[str] = []
    lines.append(f"Ham veri kok dizini: {raw_root.resolve()}")
    lines.append(f"Kaynak sayisi      : {len(source_directories)}")
    lines.append("\nUST DUZEY YAPI")
    lines.append("-" * 80)

    for source_directory in source_directories:
        lines.extend(top_level_structure_lines(source_directory))

    reports = []

    for source_directory in source_directories:
        lines.append(f"\nTaraniyor: {source_directory.name}")
        if verbose:
            print(f"Taraniyor: {source_directory.name}", file=sys.stderr)
        reports.append(scan_source(source_directory, raw_root))

    lines.append("\n\nAYRINTILI RAPOR")

    for report in reports:
        lines.extend(report_lines(report))

    lines.append("\n" + "=" * 80)
    lines.append("GENEL OZET")
    lines.append("=" * 80)

    grand_file_count = sum(report["file_count"] for report in reports)
    grand_directory_count = sum(report["directory_count"] for report in reports)
    grand_total_bytes = sum(report["total_bytes"] for report in reports)

    for report in reports:
        lines.append(
            f"{report['source']:<15} "
            f"dosya={report['file_count']:>10,} "
            f"klasor={report['directory_count']:>10,} "
            f"boyut={format_bytes(report['total_bytes']):>14}"
        )

    lines.append("-" * 80)
    lines.append(
        f"{'TOPLAM':<15} "
        f"dosya={grand_file_count:>10,} "
        f"klasor={grand_directory_count:>10,} "
        f"boyut={format_bytes(grand_total_bytes):>14}"
    )

    return lines

def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-root", type=Path, default=paths.RAW_DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    lines = run(args.raw_root)
    print("\n".join(lines))
    write_text_report(args.output_dir / REPORT_NAME, lines)
    return 0

if __name__ == "__main__":
    sys.exit(main())
