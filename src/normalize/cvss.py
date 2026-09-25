from __future__ import annotations

import re
from typing import Any

from src.profile.common import normalize_whitespace

CVSS_DETAIL_TYPES = {"CVSS V2", "CVSS V3", "CVSS V3.1", "CVSS V4.0"}
CVSS_SCORE_DETAIL_TYPES = {"CVSS V4.0 Score"}

DETAIL_TYPE_VERSION = {"CVSS V4.0": "4.0", "CVSS V3.1": "3.1", "CVSS V3": "3.0", "CVSS V2": "2.0"}
VECTOR_PREFIX_VERSION = (("CVSS:4.0/", "4.0"), ("CVSS:3.1/", "3.1"), ("CVSS:3.0/", "3.0"))
UNKNOWN_VERSION = "[UNKNOWN]"

_VECTOR_START_PATTERNS = [r"CVSS:4\.0/", r"CVSS:3\.1/", r"CVSS:3\.0/", r"\(AV:", r"\bAV:"]

def extract_vector_and_source(raw_value: Any) -> tuple[str, str]:
    text = normalize_whitespace(raw_value)

    if not text:
        return "", ""

    positions = [m.start() for pattern in _VECTOR_START_PATTERNS if (m := re.search(pattern, text))]

    if not positions:
        return text, ""

    vector_start = min(positions)
    source = text[:vector_start].strip().rstrip(":-").strip()
    vector = text[vector_start:].strip()

    if vector.startswith("(") and vector.endswith(")"):
        vector = vector[1:-1].strip()

    return source, vector

def normalize_cvss_vector(vector: Any) -> str:
    value = normalize_whitespace(vector)

    if not value:
        return ""

    if value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()

    return value.replace(" ", "")

def vector_components(vector: str) -> dict[str, str]:
    normalized = normalize_cvss_vector(vector)

    if not normalized:
        return {}

    parts = normalized.split("/")[1:] if normalized.startswith("CVSS:") else normalized.split("/")
    components: dict[str, str] = {}

    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key, value = key.strip(), value.strip()
        if key and value:
            components[key] = value

    return components

def changed_components(old_vector: str, new_vector: str) -> list[str]:
    old_components = vector_components(old_vector)
    new_components = vector_components(new_vector)
    return [
        key
        for key in sorted(set(old_components) | set(new_components))
        if old_components.get(key) != new_components.get(key)
    ]

def identify_cvss_version(detail_type: str, vector: str) -> str:
    normalized = normalize_cvss_vector(vector)

    for prefix, version in VECTOR_PREFIX_VERSION:
        if normalized.startswith(prefix):
            return version

    return DETAIL_TYPE_VERSION.get(detail_type, UNKNOWN_VERSION)

def is_vector_parseable(vector: str) -> bool:
    return "AV" in vector_components(vector)

def compare_sources(old_source: str, new_source: str) -> bool:
    old_normalized = re.sub(r"\s+", " ", old_source.lower()).strip()
    new_normalized = re.sub(r"\s+", " ", new_source.lower()).strip()
    return bool(old_normalized) and old_normalized == new_normalized

def canonical_vector(vector: Any) -> str:
    normalized = normalize_cvss_vector(vector)
    if normalized.startswith("CVSS:"):
        return normalized.split("/", 1)[1] if "/" in normalized else ""
    return normalized

def _roundup_v31(value: float) -> float:
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (integer // 10000 + 1) / 10.0

def _roundup_v30(value: float) -> float:
    import math

    return math.ceil(value * 10) / 10.0

_V3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V3_AC = {"L": 0.77, "H": 0.44}
_V3_UI = {"N": 0.85, "R": 0.62}
_V3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_V3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}

_V2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_V2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_V2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_V2_CIA = {"N": 0.0, "P": 0.275, "C": 0.660}

def base_score(version: str, vector: str) -> float | None:
    m = vector_components(vector)
    try:
        if version in ("3.0", "3.1"):
            iss = 1 - (1 - _V3_CIA[m["C"]]) * (1 - _V3_CIA[m["I"]]) * (1 - _V3_CIA[m["A"]])
            changed = m["S"] == "C"
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
            pr = (_V3_PR_C if changed else _V3_PR_U)[m["PR"]]
            exploitability = 8.22 * _V3_AV[m["AV"]] * _V3_AC[m["AC"]] * pr * _V3_UI[m["UI"]]
            if impact <= 0:
                return 0.0
            roundup = _roundup_v31 if version == "3.1" else _roundup_v30
            total = 1.08 * (impact + exploitability) if changed else impact + exploitability
            return roundup(min(total, 10.0))
        if version == "2.0":
            impact = 10.41 * (1 - (1 - _V2_CIA[m["C"]]) * (1 - _V2_CIA[m["I"]]) * (1 - _V2_CIA[m["A"]]))
            exploitability = 20 * _V2_AV[m["AV"]] * _V2_AC[m["AC"]] * _V2_AU[m["Au"]]
            f_impact = 0.0 if impact == 0 else 1.176
            return round((0.6 * impact + 0.4 * exploitability - 1.5) * f_impact + 1e-9, 1)
    except KeyError:
        return None
    if version == "4.0":

        from src.normalize.cvss40 import try_base_score_v40

        return try_base_score_v40(vector)
    return None

_V2_V3_TEMPORAL = {"E", "RL", "RC"}
_V3_ENV = {"CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
_V2_ENV = {"CDP", "TD", "CR", "IR", "AR"}

def classify_changed_components(version: str, components: list[str]) -> dict[str, Any]:
    groups: dict[str, list[str]] = {"base": [], "threat": [], "environmental": [], "supplemental": [], "unknown": []}
    if version == "4.0":
        from src.normalize.cvss40 import metric_group

        for key in components:
            groups[metric_group(key)].append(key)
    else:
        env = _V2_ENV if version == "2.0" else _V3_ENV
        for key in components:
            if key in _V2_V3_TEMPORAL:
                groups["threat"].append(key)
            elif key in env:
                groups["environmental"].append(key)
            else:
                groups["base"].append(key)
    return {
        "changed_base_components": groups["base"],
        "changed_threat_components": groups["threat"],
        "changed_environmental_components": groups["environmental"],
        "changed_supplemental_components": groups["supplemental"],
        "base_components_changed": bool(groups["base"]),
        "threat_only_change": bool(components) and bool(groups["threat"]) and not groups["base"]
        and not groups["environmental"] and not groups["supplemental"] and not groups["unknown"],
    }

def base_severity(version: str, score: float | None) -> str | None:
    if score is None:
        return None
    if version == "2.0":
        return "LOW" if score < 4.0 else "MEDIUM" if score < 7.0 else "HIGH"
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
