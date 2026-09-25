from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from src.paths import NVD_HISTORY_DIR, relative_to_project

MISSING = "[MISSING]"

@dataclass(frozen=True)
class HistoryRecord:
    cve_id: str
    event_name: str
    change_id: str
    source_identifier: str
    created: str
    action: str | None
    detail_type: str | None
    old_value: Any
    new_value: Any
    source_file: str
    detail_index: int

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

@dataclass
class ReaderIssue:
    source_file: str
    kind: str
    message: str
    change_id: str | None = None
    detail_index: int | None = None

@dataclass
class ReaderStats:
    files: int = 0
    changes: int = 0
    details: int = 0
    empty_detail_changes: int = 0
    issues: list[ReaderIssue] = field(default_factory=list)

    @property
    def issue_count(self) -> int:
        return len(self.issues)

def normalize_utc(timestamp: Any) -> str:
    if not isinstance(timestamp, str) or not timestamp:
        return MISSING

    text = timestamp.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return timestamp

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed.isoformat()

def history_files(history_dir: Path = NVD_HISTORY_DIR) -> list[Path]:
    return sorted(Path(history_dir).glob("*.json"))

def _load_page(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("JSON ust duzeyi dict degil")
    return payload

def iter_history_records(
    history_dir: Path = NVD_HISTORY_DIR,
    stats: ReaderStats | None = None,
    files: list[Path] | None = None,
) -> Iterator[HistoryRecord]:
    stats = stats if stats is not None else ReaderStats()
    pages = files if files is not None else history_files(history_dir)

    for path in pages:
        source_file = relative_to_project(path)
        stats.files += 1

        try:
            payload = _load_page(path)
        except Exception as error:
            stats.issues.append(ReaderIssue(source_file, "PAGE_READ_ERROR", f"{type(error).__name__}: {error}"))
            continue

        wrappers = payload.get("cveChanges")
        if not isinstance(wrappers, list):
            stats.issues.append(ReaderIssue(source_file, "CVE_CHANGES_NOT_LIST", type(wrappers).__name__))
            continue

        for wrapper_index, wrapper in enumerate(wrappers):
            change = wrapper.get("change") if isinstance(wrapper, dict) else None
            if not isinstance(change, dict):
                stats.issues.append(ReaderIssue(source_file, "CHANGE_NOT_DICT", f"wrapper #{wrapper_index}"))
                continue

            stats.changes += 1
            change_id = str(change.get("cveChangeId", MISSING))
            created_raw = change.get("created")
            created = normalize_utc(created_raw)
            if created == created_raw and created_raw is not None:
                stats.issues.append(ReaderIssue(source_file, "CREATED_UNPARSEABLE", str(created_raw), change_id))

            base = dict(
                cve_id=str(change.get("cveId", MISSING)),
                event_name=str(change.get("eventName", MISSING)),
                change_id=change_id,
                source_identifier=str(change.get("sourceIdentifier", MISSING)),
                created=created,
                source_file=source_file,
            )

            details = change.get("details", [])
            if details is None:
                details = []
            if not isinstance(details, list):
                stats.issues.append(ReaderIssue(source_file, "DETAILS_NOT_LIST", type(details).__name__, change_id))
                continue

            if not details:
                stats.empty_detail_changes += 1
                yield HistoryRecord(action=None, detail_type=None, old_value=None, new_value=None, detail_index=-1, **base)
                continue

            for detail_index, detail in enumerate(details):
                if not isinstance(detail, dict):
                    stats.issues.append(ReaderIssue(source_file, "DETAIL_NOT_DICT", type(detail).__name__, change_id, detail_index))
                    continue

                stats.details += 1
                yield HistoryRecord(
                    action=detail.get("action"),
                    detail_type=detail.get("type"),
                    old_value=detail.get("oldValue"),
                    new_value=detail.get("newValue"),
                    detail_index=detail_index,
                    **base,
                )

def iter_changes_grouped(
    history_dir: Path = NVD_HISTORY_DIR,
    stats: ReaderStats | None = None,
    files: list[Path] | None = None,
) -> Iterator[list[HistoryRecord]]:
    current: list[HistoryRecord] = []
    current_key: tuple[str, str] | None = None

    for record in iter_history_records(history_dir, stats, files):
        key = (record.source_file, record.change_id)
        if current and key != current_key:
            yield current
            current = []
        current.append(record)
        current_key = key

    if current:
        yield current
