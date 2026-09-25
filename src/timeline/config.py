from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.paths import CONFIG_DIR

TIMELINE_CONFIG = CONFIG_DIR / "timeline.yaml"
SOURCE_ALIASES = CONFIG_DIR / "source_aliases.yaml"

@dataclass(frozen=True)
class TimelineConfig:
    window_start: str
    window_end: str
    supported_detail_types: frozenset[str]
    main_replacement_types: frozenset[str]
    left_censoring: dict[str, Any]
    aliases: dict[str, str]
    alias_records: list[dict[str, Any]]
    mapping_version: int

    def source_key(self, raw: str) -> str:
        return self.aliases.get(raw, raw)

def _iso_utc(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"Config tarihinde saat dilimi yok: {value}")
    return parsed.astimezone(timezone.utc).isoformat()

def load_timeline_config(
    timeline_path: Path = TIMELINE_CONFIG,
    aliases_path: Path = SOURCE_ALIASES,
) -> TimelineConfig:
    timeline = yaml.safe_load(Path(timeline_path).read_text(encoding="utf-8"))
    aliases = yaml.safe_load(Path(aliases_path).read_text(encoding="utf-8")) or {}
    records = aliases.get("aliases", []) or []

    window = timeline["observation_window"]
    return TimelineConfig(
        window_start=_iso_utc(window["start"]),
        window_end=_iso_utc(window["end"]),
        supported_detail_types=frozenset(timeline["timeline"]["supported_detail_types"]),
        main_replacement_types=frozenset(timeline["timeline"]["main_replacement_types"]),
        left_censoring=dict(timeline.get("left_censoring", {})),
        aliases={r["raw_identifier"]: r["normalized_source_key"] for r in records},
        alias_records=records,
        mapping_version=int(aliases.get("mapping_version", 0)),
    )
