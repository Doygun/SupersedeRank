from __future__ import annotations

import csv
import html
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from src.paths import relative_to_project

PROGRESS_EVERY = 25

class ProfileReadError(Exception):

    def __init__(self, path: Path, error: BaseException) -> None:
        self.path = path
        self.error = error
        super().__init__(format_read_error(path, error))

def format_read_error(path: Path, error: BaseException) -> str:
    return f"{path}: {type(error).__name__}: {error}"

def sorted_json_files(directory: Path) -> list[Path]:
    return sorted(Path(directory).glob("*.json"))

def load_json(path: Path, require_dict: bool = False) -> Any:
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        payload = json.load(handle)

    if require_dict and not isinstance(payload, dict):
        raise ValueError(f"JSON ust duzeyi dict degil: {path}")

    return payload

def iter_changes(path: Path, strict: bool = False) -> Iterator[dict[str, Any]]:
    payload = load_json(path, require_dict=strict)
    wrappers = payload.get("cveChanges", [])

    if not isinstance(wrappers, list):
        if strict:
            raise ValueError(f"cveChanges liste degil: {path}")
        return

    for wrapper in wrappers:
        if not isinstance(wrapper, dict):
            continue

        change = wrapper.get("change")

        if isinstance(change, dict):
            yield change

def progress(index: int, total: int, every: int = PROGRESS_EVERY, thousands: bool = True) -> None:
    if index % every == 0 or index == total:
        if thousands:
            print(f"Islenen dosya: {index:,}/{total:,}")
        else:
            print(f"Islenen dosya: {index}/{total}")

def _to_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)

def normalize_whitespace(value: Any, unescape_html: bool = False) -> str:
    if value is None:
        return ""

    text = _to_text(value)

    if unescape_html:
        text = html.unescape(text)

    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n+", "\n", text)

    return text.strip()

def compact_text(value: Any, limit: int = 500) -> str:
    if value is None:
        return "[NULL]"

    text = html.unescape(_to_text(value))
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) > limit:
        return text[:limit] + "...[TRUNCATED]"

    return text

def compact_normalized_text(value: Any, limit: int = 1200) -> str:
    text = normalize_whitespace(value)

    if not text:
        return "[EMPTY]"

    if len(text) > limit:
        return text[:limit] + "...[TRUNCATED]"

    return text

def value_shape(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, dict):
        return "dict"
    if isinstance(value, list):
        return "list"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    return "string"

def parse_timestamp_year(created: str) -> str:
    if len(created) >= 4:
        year = created[:4]
        if year.isdigit():
            return year
    return "[UNKNOWN]"

def add_section(lines: list[str], title: str, width: int = 100) -> None:
    lines.append("")
    lines.append("=" * width)
    lines.append(title)
    lines.append("=" * width)

def add_counter_section(
    lines: list[str],
    title: str,
    counter: Counter[Any],
    width: int = 100,
) -> None:
    add_section(lines, title, width)

    if not counter:
        lines.append("Kayit bulunamadi.")
        return

    for key, count in counter.most_common():
        key_text = "\t".join(str(part) for part in key) if isinstance(key, tuple) else str(key)
        lines.append(f"{key_text}\t{count:,}")

def write_text_report(path: Path, lines: list[str]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")

def write_csv_rows(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

def write_json_summary(path: Path, summary: dict[str, Any]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True, default=_json_default) + "\n",
        encoding="utf-8",
    )

def _json_default(value: Any) -> Any:
    if isinstance(value, Counter):
        return dict(value)
    if isinstance(value, Path):
        return relative_to_project(value)
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"JSON'a cevrilemiyor: {type(value).__name__}")

def file_ref(path: Path) -> str:
    return relative_to_project(path)
