from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from src import paths
from src.normalize.cvss import vector_components

CONFIG = paths.CONFIG_DIR / "queries.yaml"
BASE_ORDER = {
    "2.0": ["AV", "AC", "Au", "C", "I", "A"],
    "3.0": ["AV", "AC", "PR", "UI", "S", "C", "I", "A"],
    "3.1": ["AV", "AC", "PR", "UI", "S", "C", "I", "A"],
    "4.0": ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"],
}

def load_config(path: Path = CONFIG) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))

def base_vector(version: str, vector: str) -> str:
    comps = vector_components(vector)
    order = BASE_ORDER.get(version, [])
    return "/".join(f"{k}:{comps[k]}" for k in order if k in comps)

def severity_word(sev: str | None) -> str:
    return (sev or "unknown").capitalize()

def evidence_text(row: dict[str, Any], cfg: dict[str, Any]) -> str:
    fields = {
        "date": (row["valid_from"] or "")[:10],
        "source": row["source_key"],
        "cve": row["cve_id"],
        "version": row["cvss_version"],
        "base_vector": row["base_vector"],
        "score": row["base_score"],
        "severity": severity_word(row["base_severity"]),
    }
    ecfg = cfg["evidence"]
    if row["valid_from_censored"]:
        template = ecfg["text_template_censored"]
    elif row["base_score"] is None:
        template = ecfg["text_template_no_score"]
    else:
        template = ecfg["text_template_active"]
    return template.format(**fields)

def build(evidence_path: Path, split_dir: Path, cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    assignment = json.loads((split_dir / "temporal_split.json").read_text(encoding="utf-8"))
    eligible: dict[str, dict[str, Any]] = {}
    for name in ("train", "dev", "test", "future_event"):
        for line in (split_dir / "base_query" / f"{name}.jsonl").open(encoding="utf-8"):
            ev = json.loads(line)
            ev["split"] = name
            eligible[ev["old_evidence_id"]] = ev
    main_cves = {ev["cve_id"] for ev in eligible.values()}
    old_ids = set(eligible)
    new_ids = {ev["new_evidence_id"] for ev in eligible.values()}

    corpus: list[dict[str, Any]] = []
    with Path(evidence_path).open(encoding="utf-8") as handle:
        for line in handle:
            e = json.loads(line)
            if e["cve_id"] not in main_cves:
                continue
            role = "replaced_old" if e["evidence_id"] in old_ids else "replacing_new" if e["evidence_id"] in new_ids else "chain_context"
            row = {
                "evidence_id": e["evidence_id"],
                "cve_id": e["cve_id"],
                "source_identifier_raw": e["source_identifier_raw"],
                "source_key": e["source_key"],
                "cvss_version": e["cvss_version"],
                "full_vector": e["vector_raw"],
                "base_vector": base_vector(e["cvss_version"], e["vector"]),
                "base_score": e["base_score"],
                "base_severity": e["base_severity"],
                "score_type": e["score_type"],
                "threat_metric_present": e["threat_metric_present"],
                "threat_metric_value": e["threat_metric_value"],
                "bt_score": e["bt_score"],
                "bt_severity": e["bt_severity"],
                "reported_score": e["reported_score"],
                "reported_score_type": e["reported_score_type"],
                "valid_from": e["valid_from"],
                "valid_until": e["valid_until"],
                "valid_from_censored": e["valid_from_censored"],
                "observed_from": e["observed_from"],
                "timeline_status": e["timeline_status"],
                "activation_event_id": e["activation_event_id"],
                "termination_event_id": e["termination_event_id"],
                "replacement_event_id": e["termination_event_id"] if e["replacement_type"] else None,
                "replacement_type": e["replacement_type"],
                "replaces_evidence_id": e["replaces_evidence_id"],
                "replaced_by_evidence_id": e["superseded_by_evidence_id"],
                "chain_id": e["chain_id"],
                "chain_ambiguous": e["chain_ambiguous"],
                "evidence_role": role,
                "split": assignment.get(e["cve_id"], "corpus_only"),
                "source_file": e["source_file"],
            }
            row["evidence_text"] = evidence_text(row, cfg)
            corpus.append(row)
    corpus.sort(key=lambda r: (r["cve_id"], r["chain_id"], r["evidence_id"]))

    forbidden = re.compile("|".join(re.escape(w) for w in cfg["evidence"]["forbidden_words_in_text"]), re.IGNORECASE)
    profile = {
        "corpus_scope": cfg["evidence"]["corpus_scope"],
        "total_evidence": len(corpus),
        "cves": len(main_cves),
        "by_role": dict(Counter(r["evidence_role"] for r in corpus)),
        "by_split": dict(Counter(r["split"] for r in corpus)),
        "left_censored": sum(1 for r in corpus if r["valid_from_censored"]),
        "by_version": dict(Counter(r["cvss_version"] for r in corpus)),
        "by_source_key_top": dict(Counter(r["source_key"] for r in corpus).most_common(10)),
        "base_score_missing": sum(1 for r in corpus if r["base_score"] is None),
        "threat_metric_present": sum(1 for r in corpus if r["threat_metric_present"]),
        "reported_score_type": dict(Counter(r["reported_score_type"] for r in corpus)),
        "text_forbidden_word_hits": sum(1 for r in corpus if forbidden.search(r["evidence_text"])),
        "text_length_chars": {"min": min(len(r["evidence_text"]) for r in corpus), "max": max(len(r["evidence_text"]) for r in corpus)},
        "eligible_events": len(eligible),
    }
    return corpus, profile

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence", type=Path, default=paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl")
    parser.add_argument("--split-dir", type=Path, default=paths.PROCESSED_DATA_DIR / "splits")
    parser.add_argument("--out", type=Path, default=paths.PROCESSED_DATA_DIR / "evidence" / "evidence.jsonl")
    parser.add_argument("--profile-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    args = parser.parse_args(argv)
    cfg = load_config()
    corpus, profile = build(args.evidence, args.split_dir, cfg)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for row in corpus:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    args.profile_dir.mkdir(parents=True, exist_ok=True)
    (args.profile_dir / "evidence_profile.json").write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(profile, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
