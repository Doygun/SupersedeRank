from __future__ import annotations

import argparse
import bisect
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from src import paths
from src.evidence.build_evidence import base_vector, evidence_text, load_config as load_query_config

RETRIEVAL_CONFIG = paths.CONFIG_DIR / "retrieval.yaml"

def load_retrieval_config(path: Path = RETRIEVAL_CONFIG) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))

def corpus_row(e: dict[str, Any], qcfg: dict[str, Any], assignment: dict[str, str]) -> dict[str, Any]:
    row = {
        "evidence_id": e["evidence_id"], "cve_id": e["cve_id"], "source_identifier_raw": e["source_identifier_raw"],
        "source_key": e["source_key"], "cvss_version": e["cvss_version"], "full_vector": e["vector_raw"],
        "base_vector": base_vector(e["cvss_version"], e["vector"]), "base_score": e["base_score"],
        "base_severity": e["base_severity"], "score_type": e["score_type"],
        "threat_metric_present": e["threat_metric_present"], "threat_metric_value": e["threat_metric_value"],
        "bt_score": e["bt_score"], "bt_severity": e["bt_severity"], "reported_score": e["reported_score"],
        "reported_score_type": e["reported_score_type"], "valid_from": e["valid_from"], "valid_until": e["valid_until"],
        "valid_from_censored": e["valid_from_censored"], "observed_from": e["observed_from"],
        "timeline_status": e["timeline_status"], "activation_event_id": e["activation_event_id"],
        "termination_event_id": e["termination_event_id"],
        "replacement_event_id": e["termination_event_id"] if e["replacement_type"] else None,
        "replacement_type": e["replacement_type"], "replaces_evidence_id": e["replaces_evidence_id"],
        "replaced_by_evidence_id": e["superseded_by_evidence_id"], "chain_id": e["chain_id"],
        "chain_ambiguous": e["chain_ambiguous"], "split": assignment.get(e["cve_id"], "corpus_only"),
        "source_file": e["source_file"],
    }
    row["evidence_text"] = evidence_text(row, qcfg)
    return row

def eligibility(row: dict[str, Any], rules: dict[str, Any], forbidden: re.Pattern) -> str | None:
    if rules["require_cve_id"] and not row["cve_id"]:
        return "MISSING_CVE_ID"
    if rules["require_source_key"] and not row["source_key"]:
        return "MISSING_SOURCE_KEY"
    if rules["require_cvss_version"] and row["cvss_version"] in (None, "", "[UNKNOWN]"):
        return "MISSING_CVSS_VERSION"
    if rules["require_parseable_base_vector"] and (not row["base_vector"] or "*" in row["base_vector"] or "AV:" not in row["base_vector"]):
        return "BASE_VECTOR_NOT_PARSEABLE"
    if rules["require_observed_from"] and not row["observed_from"]:
        return "MISSING_OBSERVED_FROM"
    if rules["require_source_file"] and not row["source_file"]:
        return "MISSING_PROVENANCE"
    if rules["exclude_ambiguous_chains"] and row["chain_ambiguous"]:
        return "AMBIGUOUS_CHAIN"
    if not row["evidence_text"]:
        return "TEXT_NOT_GENERATED"
    if rules["forbid_label_words_in_text"] and forbidden.search(row["evidence_text"]):
        return "TEXT_CONTAINS_LABEL_WORD"

    if (row["replaced_by_evidence_id"] or "\x00") in row["evidence_text"]:
        return "TEXT_CONTAINS_FUTURE_INFO"
    return None

def build(cfg: dict[str, Any], qcfg: dict[str, Any]) -> tuple[list[dict], list[dict], dict[str, Any]]:
    rules = cfg["corpus"]["eligibility"]
    forbidden = re.compile("|".join(re.escape(w) for w in qcfg["evidence"]["forbidden_words_in_text"]), re.IGNORECASE)
    assignment = json.loads((paths.PROCESSED_DATA_DIR / "splits" / "temporal_split.json").read_text(encoding="utf-8"))
    accepted: list[dict] = []
    excluded: list[dict] = []
    total = 0
    text_ok = 0
    with (paths.PROJECT_ROOT / cfg["corpus"]["source"]).open(encoding="utf-8") as handle:
        for line in handle:
            e = json.loads(line)
            total += 1
            row = corpus_row(e, qcfg, assignment)
            if row["evidence_text"]:
                text_ok += 1
            reason = eligibility(row, rules, forbidden)
            if reason:
                excluded.append({"evidence_id": row["evidence_id"], "cve_id": row["cve_id"], "reason": reason,
                                 "cvss_version": row["cvss_version"], "base_vector": row["base_vector"]})
            else:
                accepted.append(row)
    accepted.sort(key=lambda r: (r["cve_id"], r["chain_id"], r["evidence_id"]))

    main_ids = set()
    ev_main = paths.PROCESSED_DATA_DIR / "evidence" / "evidence.jsonl"
    if ev_main.exists():
        main_ids = {json.loads(l)["evidence_id"] for l in ev_main.open(encoding="utf-8")}
    accepted_ids = {r["evidence_id"] for r in accepted}
    texts = Counter(r["evidence_text"] for r in accepted)
    same_value = Counter((r["cve_id"], r["source_key"], r["cvss_version"], r["base_vector"]) for r in accepted)
    overlaps = 0
    by_chain: defaultdict[str, list] = defaultdict(list)
    for r in accepted:
        by_chain[r["chain_id"]].append(r)
    for rows in by_chain.values():
        rows.sort(key=lambda r: r["observed_from"])
        for a, b in zip(rows, rows[1:]):
            if a["valid_until"] is None or b["observed_from"] < a["valid_until"]:
                overlaps += 1
    lengths = sorted(len(r["evidence_text"]) for r in accepted)
    observed_sorted = sorted(r["observed_from"] for r in accepted)
    visible: dict[str, float | None] = {}
    qdir = paths.PROCESSED_DATA_DIR / "queries"
    for s in ("train", "dev", "test"):
        p = qdir / f"{s}_queries.jsonl"
        if p.exists():
            times = [json.loads(l)["query_time"] for l in p.open(encoding="utf-8") if '"POST_REPLACEMENT_MAIN"' in l]
            visible[s] = round(sum(bisect.bisect_right(observed_sorted, t) for t in times) / len(times), 1) if times else None
    profile = {
        "potential_intervals": total,
        "text_generated": text_ok,
        "accepted": len(accepted),
        "excluded": len(excluded),
        "excluded_by_reason": dict(Counter(x["reason"] for x in excluded)),
        "unique_cves": len({r["cve_id"] for r in accepted}),
        "unique_source_keys": len({r["source_key"] for r in accepted}),
        "by_version": dict(Counter(r["cvss_version"] for r in accepted)),
        "base_score_available_ratio": round(sum(1 for r in accepted if r["base_score"] is not None) / len(accepted), 6),
        "left_censored": sum(1 for r in accepted if r["valid_from_censored"]),
        "ambiguous_chain_intervals_excluded": sum(1 for x in excluded if x["reason"] == "AMBIGUOUS_CHAIN"),
        "duplicate_evidence_text": sum(c - 1 for c in texts.values() if c > 1),
        "duplicate_cve_source_version_vector": sum(c - 1 for c in same_value.values() if c > 1),
        "overlapping_intervals_same_chain": overlaps,
        "text_length": {"mean": round(statistics.mean(lengths), 1), "median": statistics.median(lengths), "min": lengths[0], "max": lengths[-1]},
        "mean_visible_corpus_at_query_times": visible,
        "coverage_vs_main_evidence": {
            "main_evidence": len(main_ids),
            "main_in_full_corpus": len(main_ids & accepted_ids),
            "main_missing_from_full_corpus": sorted(main_ids - accepted_ids)[:20],
            "full_corpus_only": len(accepted_ids - main_ids),
        },
        "by_split_of_cve": dict(Counter(r["split"] for r in accepted)),
    }
    return accepted, excluded, profile

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args(argv)
    cfg = load_retrieval_config()
    qcfg = load_query_config()
    accepted, excluded, profile = build(cfg, qcfg)
    out = paths.PROJECT_ROOT / cfg["corpus"]["output"]
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for r in accepted:
            handle.write(json.dumps(r, ensure_ascii=False) + "\n")
    with (out.parent / "excluded_intervals.jsonl").open("w", encoding="utf-8") as handle:
        for x in excluded:
            handle.write(json.dumps(x, ensure_ascii=False) + "\n")
    paths.DATA_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    (paths.DATA_PROFILE_DIR / "corpus_profile.json").write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(profile, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
