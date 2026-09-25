from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src import paths
from src.evidence.build_evidence import load_config
from src.label import query_time_labels as L
from src.timeline.config import load_timeline_config

SPLITS = ("train", "dev", "test", "future_event")

def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s)

def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat()

def query_time_post(event_time: str, new_end: str | None, window_end: str, rule: dict[str, Any]) -> tuple[str | None, str | None]:
    start = _dt(event_time)
    end = _dt(min(new_end, window_end)) if new_end else _dt(window_end)
    remaining = (end - start).total_seconds()
    if remaining < rule["min_interval_seconds"]:
        return None, "NEW_INTERVAL_TOO_SHORT"
    offset = min(rule["offset_days"] * 86400.0, remaining * rule["max_fraction_of_interval"])
    return _iso(start + timedelta(seconds=offset)), None

def query_time_pre(event_time: str, old_observed_from: str, window_start: str, rule: dict[str, Any]) -> tuple[str | None, str | None]:
    end = _dt(event_time)
    start = _dt(max(old_observed_from, window_start))
    span = (end - start).total_seconds()
    if span < rule["min_interval_seconds"]:
        return None, "OLD_INTERVAL_TOO_SHORT"
    offset = min(rule["offset_days"] * 86400.0, span * rule["max_fraction_of_interval"])
    return _iso(end - timedelta(seconds=offset)), None

def build(evidence_path: Path, split_dir: Path, cfg: dict[str, Any]) -> tuple[dict[str, list[dict]], list[dict], dict[str, Any]]:
    tcfg = load_timeline_config()
    qcfg = cfg["queries"]
    evidence = [json.loads(l) for l in Path(evidence_path).open(encoding="utf-8")]
    by_id = {e["evidence_id"]: e for e in evidence}
    by_cve: defaultdict[str, list[dict]] = defaultdict(list)
    for e in evidence:
        by_cve[e["cve_id"]].append(e)
    observed_sorted = sorted(e["observed_from"] for e in evidence)

    events: list[tuple[str, dict]] = []
    for name in SPLITS:
        for line in (split_dir / "base_query" / f"{name}.jsonl").open(encoding="utf-8"):
            events.append((name, json.loads(line)))
    events.sort(key=lambda x: (x[1]["termination_event_id"], x[1]["old_evidence_id"]))

    rng = random.Random(int(qcfg["seed"]))
    template_ids = sorted(qcfg["templates"])
    assigned_templates = {ev["termination_event_id"] + "|" + ev["old_evidence_id"]: rng.choice(template_ids) for _, ev in events}

    roles = []
    if qcfg["post_replacement"]["enabled"]:
        roles.append(("post", qcfg["post_replacement"]))
    if qcfg["pre_replacement_control"]["enabled"]:
        roles.append(("pre", qcfg["pre_replacement_control"]))

    out: dict[str, list[dict]] = {s: [] for s in SPLITS}
    excluded: list[dict] = []

    for split, ev in events:
        old, new = by_id.get(ev["old_evidence_id"]), by_id.get(ev["new_evidence_id"])
        key = ev["termination_event_id"] + "|" + ev["old_evidence_id"]
        template_id = assigned_templates[key]
        if old is None or new is None:
            excluded.append({"event_id": ev["termination_event_id"], "split": split, "role": "ANY", "reason": "EVIDENCE_NOT_IN_CORPUS"})
            continue
        for kind, rule in roles:
            if kind == "post":
                t, why = query_time_post(new["valid_from"], new["valid_until"], tcfg.window_end, rule)
            else:
                t, why = query_time_pre(old["valid_until"], old["observed_from"], tcfg.window_start, rule)
            if t is None:
                excluded.append({"event_id": ev["termination_event_id"], "split": split, "role": rule["role"], "reason": why})
                continue
            if not (tcfg.window_start <= t <= tcfg.window_end):
                excluded.append({"event_id": ev["termination_event_id"], "split": split, "role": rule["role"], "reason": "QUERY_TIME_OUTSIDE_WINDOW"})
                continue
            q = L.Query(cve_id=ev["cve_id"], source_key=ev["source_key"], cvss_version=ev["cvss_version"], query_time=t)
            same_cve = by_cve[ev["cve_id"]]
            visible = [e for e in same_cve if e["observed_from"] <= t]
            labels = {e["evidence_id"]: L.label(e, q) for e in visible}
            relations = {e["evidence_id"]: L.source_relation(e, q) for e in visible}
            current = [i for i, lbl in labels.items() if lbl == L.CURRENT]
            outdated = [i for i, lbl in labels.items() if lbl == L.OUTDATED]
            other_current = [i for i, rel in relations.items() if rel == L.OTHER_SOURCE_CURRENT]
            if not current:
                excluded.append({"event_id": ev["termination_event_id"], "split": split, "role": rule["role"], "reason": "NO_CURRENT_TARGET"})
                continue
            if kind == "post" and qcfg["requirements"]["main_requires_outdated_same_chain"] and not outdated:
                excluded.append({"event_id": ev["termination_event_id"], "split": split, "role": rule["role"], "reason": "NO_OUTDATED_SAME_CHAIN"})
                continue
            current = sorted(current)
            target = by_id[current[0]]
            if target["base_score"] is None or target["base_severity"] is None:

                excluded.append({"event_id": ev["termination_event_id"], "split": split, "role": rule["role"], "reason": "TARGET_SCORE_UNAVAILABLE"})
                continue
            template = qcfg["templates"][template_id]
            query_text = template.format(query_date=t[:10], version=ev["cvss_version"], source=ev["source_key"], cve=ev["cve_id"])
            qid = hashlib.sha1(f"{split}|{ev['termination_event_id']}|{ev['old_evidence_id']}|{rule['role']}|{template_id}".encode()).hexdigest()[:16]
            out[split].append({
                "query_id": f"q_{qid}",
                "cve_id": ev["cve_id"],
                "source_key": ev["source_key"],
                "cvss_version": ev["cvss_version"],
                "query_time": t,
                "query_family": qcfg["query_family"],
                "query_role": rule["role"],
                "query_template_id": template_id,
                "query_text": query_text,
                "answer_base_vector": target["base_vector"],
                "answer_base_score": target["base_score"],
                "answer_base_severity": target["base_severity"],
                "answer_evidence_id": target["evidence_id"],
                "current_evidence_ids": current,
                "outdated_evidence_ids": sorted(outdated),
                "other_source_current_evidence_ids": sorted(other_current),
                "visible_evidence_ids": sorted(e["evidence_id"] for e in visible),
                "visible_corpus_count": bisect.bisect_right(observed_sorted, t),
                "valid_from_censored": bool(target["valid_from_censored"]),
                "split": split,
                "source_event_id": ev["termination_event_id"],
                "replaced_old_evidence_id": ev["old_evidence_id"],
                "replacing_new_evidence_id": ev["new_evidence_id"],
                "multiple_current_targets": len(current) > 1,
            })

    all_q = [q for s in SPLITS for q in out[s]]
    manifest = {
        "query_family": qcfg["query_family"],
        "seed": qcfg["seed"],
        "template_assignment": qcfg["template_assignment"],
        "query_time_rules": {"post_replacement": qcfg["post_replacement"], "pre_replacement_control": qcfg["pre_replacement_control"]},
        "config_sha256": hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest(),
        "observation_window": {"start": tcfg.window_start, "end": tcfg.window_end},
        "eligible_events": len(events),
        "counts": {s: len(out[s]) for s in SPLITS},
        "counts_by_role": {s: dict(Counter(q["query_role"] for q in out[s])) for s in SPLITS},
        "counts_by_template": dict(Counter(q["query_template_id"] for q in all_q)),
        "main_queries_total": sum(1 for q in all_q if q["query_role"] == "POST_REPLACEMENT_MAIN" and q["split"] != "future_event"),
        "control_queries_total": sum(1 for q in all_q if q["query_role"] == "PRE_REPLACEMENT_CONTROL" and q["split"] != "future_event"),
        "excluded": len(excluded),
        "excluded_by_reason": dict(Counter(x["reason"] for x in excluded)),
        "test_usage_policy": "test/future_event queries are never used for model, template, threshold, feature or query-time offset selection",
    }
    return out, excluded, manifest

def profile(out: dict[str, list[dict]], by_id_scores: dict[str, dict]) -> dict[str, Any]:
    all_q = [q for s in SPLITS for q in out[s]]
    main = [q for q in all_q if q["query_role"] == "POST_REPLACEMENT_MAIN"]
    return {
        "total_queries": len(all_q),
        "by_split": {s: len(out[s]) for s in SPLITS},
        "by_role": dict(Counter(q["query_role"] for q in all_q)),
        "by_template": dict(Counter(q["query_template_id"] for q in all_q)),
        "main_by_split": dict(Counter(q["split"] for q in main)),
        "multiple_current_targets": sum(1 for q in all_q if q["multiple_current_targets"]),
        "queries_with_other_source_current": sum(1 for q in all_q if q["other_source_current_evidence_ids"]),
        "mean_visible_same_cve_evidence": round(sum(len(q["visible_evidence_ids"]) for q in all_q) / len(all_q), 3) if all_q else None,
        "mean_visible_corpus_count": round(sum(q["visible_corpus_count"] for q in all_q) / len(all_q), 1) if all_q else None,
        "mean_outdated_same_chain_main": round(sum(len(q["outdated_evidence_ids"]) for q in main) / len(main), 3) if main else None,
        "by_source_key_top": dict(Counter(q["source_key"] for q in all_q).most_common(10)),
        "by_version": dict(Counter(q["cvss_version"] for q in all_q)),
        "answer_severity": dict(Counter(str(q["answer_base_severity"]) for q in all_q)),
        "answer_score_histogram": dict(sorted(Counter(str(int(q["answer_base_score"])) if q["answer_base_score"] is not None else "none" for q in all_q).items())),
        "censored_target": dict(Counter(q["valid_from_censored"] for q in all_q)),
    }

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence", type=Path, default=paths.PROCESSED_DATA_DIR / "evidence" / "evidence.jsonl")
    parser.add_argument("--split-dir", type=Path, default=paths.PROCESSED_DATA_DIR / "splits")
    parser.add_argument("--out-dir", type=Path, default=paths.PROCESSED_DATA_DIR / "queries")
    parser.add_argument("--profile-dir", type=Path, default=paths.DATA_PROFILE_DIR)
    args = parser.parse_args(argv)
    cfg = load_config()
    out, excluded, manifest = build(args.evidence, args.split_dir, cfg)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for s in SPLITS:
        with (args.out_dir / f"{s}_queries.jsonl").open("w", encoding="utf-8") as handle:
            for q in out[s]:
                handle.write(json.dumps(q, ensure_ascii=False) + "\n")
    with (args.out_dir / "excluded_queries.jsonl").open("w", encoding="utf-8") as handle:
        for x in excluded:
            handle.write(json.dumps(x, ensure_ascii=False) + "\n")
    (args.out_dir / "query_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    prof = profile(out, {})
    args.profile_dir.mkdir(parents=True, exist_ok=True)
    (args.profile_dir / "query_profile.json").write_text(json.dumps(prof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": manifest, "profile": prof}, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
