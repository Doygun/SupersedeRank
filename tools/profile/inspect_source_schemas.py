from __future__ import annotations

import argparse
import csv
import gzip
import sys
from pathlib import Path
from typing import Any, Callable

import pyarrow.parquet as pq

if __package__ in (None, ""):
    import _bootstrap
else:
    from . import _bootstrap

from src import paths
from src.profile.common import add_section, file_ref, load_json, write_text_report

REPORT_NAME = "source_schema_report.txt"

def short_repr(value: Any, limit: int = 400) -> str:
    text = repr(value)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text

def describe_value(value: Any, depth: int = 0, max_depth: int = 3) -> list[str]:
    lines: list[str] = []
    prefix = "  " * depth

    if depth > max_depth:
        lines.append(f"{prefix}<maksimum derinlik>")
        return lines

    if isinstance(value, dict):
        lines.append(f"{prefix}dict, anahtar sayisi={len(value)}")

        for index, (key, child) in enumerate(value.items()):
            if index >= 20:
                lines.append(f"{prefix}... {len(value) - 20} anahtar daha var")
                break

            if isinstance(child, dict):
                lines.append(f"{prefix}- {key}: dict, anahtar sayisi={len(child)}")
                lines.extend(describe_value(child, depth=depth + 1, max_depth=max_depth))

            elif isinstance(child, list):
                lines.append(f"{prefix}- {key}: list, oge sayisi={len(child)}")
                if child:
                    lines.append(f"{prefix}  ilk oge tipi={type(child[0]).__name__}")
                    lines.extend(describe_value(child[0], depth=depth + 1, max_depth=max_depth))

            else:
                lines.append(f"{prefix}- {key}: {type(child).__name__} = {short_repr(child)}")

        return lines

    if isinstance(value, list):
        lines.append(f"{prefix}list, oge sayisi={len(value)}")

        for index, child in enumerate(value[:3]):
            lines.append(f"{prefix}- [{index}] tip={type(child).__name__}")
            lines.extend(describe_value(child, depth=depth + 1, max_depth=max_depth))

        return lines

    lines.append(f"{prefix}{type(value).__name__} = {short_repr(value)}")
    return lines

def inspect_json(lines: list[str], title: str, path: Path | None, max_depth: int = 3) -> None:
    add_section(lines, title)

    if path is None:
        lines.append("DOSYA BULUNAMADI")
        return

    lines.append(f"Dosya: {file_ref(path)}")
    lines.append(f"Boyut: {path.stat().st_size:,} bayt")

    try:
        data = load_json(path)
    except Exception as error:
        lines.append(f"HATA: {type(error).__name__}: {error}")
        return

    lines.append("Sema:")
    lines.extend(describe_value(data, max_depth=max_depth))

def inspect_nvd(lines: list[str], raw_root: Path) -> None:
    cve_files = sorted((raw_root / "nvd" / "cves").glob("*.json"))
    history_files = sorted((raw_root / "nvd" / "history").glob("*.json"))

    add_section(lines, "NVD DOSYA DAGILIMI")
    lines.append(f"CVE JSON dosyasi: {len(cve_files):,}")
    lines.append(f"History JSON dosyasi: {len(history_files):,}")

    if cve_files:
        lines.append(f"Ilk CVE dosyasi: {file_ref(cve_files[0])}")
        lines.append(f"Son CVE dosyasi: {file_ref(cve_files[-1])}")

    if history_files:
        lines.append(f"Ilk History dosyasi: {file_ref(history_files[0])}")
        lines.append(f"Son History dosyasi: {file_ref(history_files[-1])}")

    inspect_json(lines, "NVD CVE ORNEK SEMASI", cve_files[0] if cve_files else None, max_depth=4)
    inspect_json(lines, "NVD HISTORY ORNEK SEMASI", history_files[0] if history_files else None, max_depth=5)

def inspect_ghsa(lines: list[str], raw_root: Path) -> None:
    add_section(lines, "GHSA KOLEKSIYON YAPISI")
    advisory_root = raw_root / "ghsa" / "advisories"

    if not advisory_root.exists():
        lines.append(f"Advisory klasoru bulunamadi: {advisory_root}")
        return

    collections = sorted([p for p in advisory_root.iterdir() if p.is_dir()], key=lambda p: p.name.lower())
    lines.append(f"Koleksiyon sayisi: {len(collections)}")

    for collection in collections:
        lines.append("")
        lines.append(f"Koleksiyon: {collection.name}")

        sample_path = next(collection.rglob("*.json"), None)

        if sample_path is None:
            lines.append("Ornek JSON bulunamadi.")
            continue

        lines.append(f"Ornek JSON: {file_ref(sample_path)}")

        try:
            data = load_json(sample_path)
        except Exception as error:
            lines.append(f"HATA: {type(error).__name__}: {error}")
            continue

        if isinstance(data, dict):
            lines.append("Ust duzey anahtarlar: " + ", ".join(data.keys()))

        lines.append("Ornek sema:")
        lines.extend(describe_value(data, depth=1, max_depth=4))

def inspect_epss(lines: list[str], raw_root: Path) -> None:
    add_section(lines, "EPSS ORNEK SEMASI")
    epss_files = sorted((raw_root / "epss").glob("epss_scores-*.csv.gz"))
    lines.append(f"EPSS dosya sayisi: {len(epss_files):,}")

    if not epss_files:
        lines.append("EPSS dosyasi bulunamadi.")
        return

    sample_path = epss_files[0]
    lines.append(f"Ornek dosya: {file_ref(sample_path)}")

    try:
        with gzip.open(sample_path, "rt", encoding="utf-8-sig", newline="") as file:
            first_lines: list[str] = []
            for _ in range(5):
                line = file.readline()
                if not line:
                    break
                first_lines.append(line.rstrip("\r\n"))

        lines.append("Ilk satirlar:")
        for index, line in enumerate(first_lines, start=1):
            lines.append(f"{index}: {line[:500]}")

        with gzip.open(sample_path, "rt", encoding="utf-8-sig", newline="") as file:
            data_lines = (line for line in file if not line.lstrip().startswith("#"))
            reader = csv.DictReader(data_lines)
            first_row = next(reader, None)
            lines.append(f"CSV alanlari: {reader.fieldnames}")
            lines.append(f"Ilk veri satiri: {short_repr(first_row)}")

    except Exception as error:
        lines.append(f"HATA: {type(error).__name__}: {error}")

def inspect_hoh(lines: list[str], raw_root: Path) -> None:
    add_section(lines, "HOH PARQUET SEMASI")
    parquet_files = sorted((raw_root / "hoh").glob("*.parquet"))

    if not parquet_files:
        lines.append("HoH Parquet dosyasi bulunamadi.")
        return

    sample_path = parquet_files[0]
    lines.append(f"Dosya: {file_ref(sample_path)}")

    try:
        parquet_file = pq.ParquetFile(sample_path)
        lines.append(f"Satir sayisi: {parquet_file.metadata.num_rows:,}")
        lines.append(f"Satir grubu sayisi: {parquet_file.metadata.num_row_groups:,}")
        lines.append("Arrow semasi:")
        lines.append(str(parquet_file.schema_arrow))

        first_batch = next(parquet_file.iter_batches(batch_size=1), None)

        if first_batch is not None:
            lines.append("Ilk kayit:")
            lines.extend(describe_value(first_batch.to_pylist()[0], depth=1, max_depth=4))

    except Exception as error:
        lines.append(f"HATA: {type(error).__name__}: {error}")

def inspect_debian(lines: list[str], raw_root: Path) -> None:
    files = sorted((raw_root / "debian" / "json").glob("*.json"))
    inspect_json(lines, "DEBIAN ORNEK SEMASI", files[0] if files else None, max_depth=4)

def inspect_kev(lines: list[str], raw_root: Path) -> None:
    files = sorted((raw_root / "kev").glob("*.json"))
    inspect_json(lines, "CISA KEV ORNEK SEMASI", files[0] if files else None, max_depth=4)

INSPECTORS: list[tuple[str, Callable[[list[str], Path], None]]] = [
    ("NVD", inspect_nvd),
    ("GHSA", inspect_ghsa),
    ("EPSS", inspect_epss),
    ("HoH", inspect_hoh),
    ("Debian", inspect_debian),
    ("CISA KEV", inspect_kev),
]

def run(raw_root: Path) -> list[str]:
    raw_root = Path(raw_root)

    if not raw_root.is_dir():
        raise SystemExit(f"Ham veri klasoru bulunamadi: {raw_root.resolve()}")

    lines: list[str] = ["CHRONORANK KAYNAK SEMA RAPORU", f"Ham veri kok dizini: {raw_root.resolve()}"]
    errors: list[str] = []

    for source_name, inspector in INSPECTORS:
        try:
            inspector(lines, raw_root)
        except Exception as error:
            message = f"{source_name} incelenirken HATA: {type(error).__name__}: {error}"
            errors.append(message)
            add_section(lines, f"{source_name} INCELEME HATASI")
            lines.append(message)

    add_section(lines, "RAPOR SONU")
    lines.append(f"Beklenmeyen kaynak hatasi sayisi: {len(errors)}")
    lines.extend(errors)
    return lines

def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-root", type=Path, default=paths.RAW_DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    lines = run(args.raw_root)
    report_path = args.output_dir / REPORT_NAME
    write_text_report(report_path, lines)
    print("\n".join(lines) + "\n")
    print(f"Rapor kaydedildi: {report_path.resolve()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
