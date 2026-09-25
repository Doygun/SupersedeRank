from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src import paths
from src.normalize.cvss import base_score, base_severity, canonical_vector
from src.normalize.cvss40 import severity_v40, try_bt_score_v40

METRIC_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))

NOT_AVAILABLE = "NOT_AVAILABLE_IN_HISTORY"

def build_reported_index(cve_dir: Path = paths.NVD_CVE_DIR) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    index: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for path in sorted(Path(cve_dir).glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        for item in payload["vulnerabilities"]:
            cve = item["cve"]
            for key, version in METRIC_KEYS:
                for entry in cve.get("metrics", {}).get(key, []):
                    data = entry.get("cvssData", {})
                    vec = data.get("vectorString")
                    if not vec or data.get("baseScore") is None:
                        continue
                    index[(cve["id"], str(entry.get("source")), version, canonical_vector(vec))] = {
                        "reported_score": float(data["baseScore"]),
                        "reported_severity": data.get("baseSeverity") or entry.get("baseSeverity"),
                        "vector_string": vec,
                    }
    return index

def classify_reported(version: str, vector: str, base: float | None, reported: float | None,
                      reported_severity: str | None) -> tuple[str, bool]:
    if reported is None:
        return NOT_AVAILABLE, False
    if version == "4.0":
        from src.normalize.cvss40 import base_score_v40, bt_score_v40

        try:

            if base_score_v40(vector, "decimal") == reported and base_score_v40(vector, "js") != reported:
                return "ROUNDING_BOUNDARY_EQUIVALENT", True
        except Exception:
            pass
    if base is not None and base == reported:
        return "CVSS-B", True
    if version == "4.0":
        try:
            bt = bt_score_v40(vector, "decimal")
            if bt == reported and severity_v40(bt) == reported_severity:
                return "CVSS-BT", True
        except Exception:
            pass
    return "UNRESOLVED", False

def score_fields(version: str, vector_raw: str, vector: str, index: dict | None,
                 cve_id: str, source_identifier_raw: str) -> dict[str, Any]:
    b = base_score(version, vector)
    fields: dict[str, Any] = {
        "base_score": b,
        "base_severity": base_severity(version, b),
        "score_type": "CVSS-B",
        "threat_metric_present": False,
        "threat_metric_value": None,
        "bt_score": None,
        "bt_severity": None,
        "bt_score_available": False,
        "reported_score": None,
        "reported_score_type": NOT_AVAILABLE,
        "reported_score_matches": False,
    }
    if version == "4.0":
        from src.normalize.cvss40 import Cvss40ParseError, threat_metric

        try:
            e_value = threat_metric(vector_raw if vector_raw.startswith("CVSS:") else vector)
        except Cvss40ParseError:
            e_value = None
        if e_value is not None:
            fields["threat_metric_present"] = True
            fields["threat_metric_value"] = e_value
            bt = try_bt_score_v40(vector_raw if vector_raw.startswith("CVSS:") else vector)
            fields["bt_score"] = bt
            fields["bt_severity"] = severity_v40(bt)
            fields["bt_score_available"] = bt is not None
    if index:
        hit = index.get((cve_id, source_identifier_raw, version, canonical_vector(vector)))
        if hit:
            fields["reported_score"] = hit["reported_score"]
            kind, ok = classify_reported(version, hit["vector_string"], b, hit["reported_score"], hit["reported_severity"])
            fields["reported_score_type"] = kind
            fields["reported_score_matches"] = ok
    return fields
