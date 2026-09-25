from __future__ import annotations

import json
import sys
from collections import Counter
from typing import Any

from src import paths
from src.rerank.common import load_pool, load_rerank_config, query_lookup

OUT = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_learned"
POS, NEG = "TARGET_CURRENT", "TARGET_OUTDATED"

def is_temporal_example(candidate_class: str) -> bool:
    return candidate_class in (POS, NEG)

def profile_split(rows: list[dict], queries: dict[str, dict], rule_lists: dict[str, dict] | None, cve_split: dict[str, str], split: str) -> dict[str, Any]:
    n_pos = n_neg = 0
    per_q_pos, per_q_neg = [], []
    ev_count: Counter = Counter()
    ev_label: dict[str, set] = {}
    cves_of_examples: set[str] = set()
    rule_signal = Counter()
    other_classes = Counter()
    for r in rows:
        q = queries[r["query_id"]]
        p = n = 0
        flags = {c["evidence_id"]: c["suppressed"] for c in rule_lists[r["query_id"]]["candidates"]} if rule_lists else {}
        for c in r["candidates"]:
            if not is_temporal_example(c["class"]):
                other_classes[c["class"]] += 1
                continue
            ev_count[c["evidence_id"]] += 1
            ev_label.setdefault(c["evidence_id"], set()).add(c["class"])
            cves_of_examples.add(q["cve_id"])
            if c["class"] == POS:
                p += 1
            else:
                n += 1
            if rule_lists:
                rule_signal[(c["class"], flags[c["evidence_id"]])] += 1
        n_pos += p; n_neg += n
        per_q_pos.append(p); per_q_neg.append(n)
    repeats = Counter(ev_count.values())
    label_conflicts = sum(1 for s in ev_label.values() if len(s) > 1)
    foreign = Counter(cve_split.get(c, "?") for c in cves_of_examples)
    return {"queries": len(rows), "current_examples": n_pos, "outdated_examples": n_neg, "class_ratio_outdated_to_current": round(n_neg / n_pos, 4) if n_pos else None,
            "current_per_query": {"mean": round(sum(per_q_pos) / len(rows), 4), "min": min(per_q_pos), "max": max(per_q_pos), "dist": dict(Counter(per_q_pos))},
            "outdated_per_query": {"mean": round(sum(per_q_neg) / len(rows), 4), "min": min(per_q_neg), "max": max(per_q_neg), "dist": dict(Counter(per_q_neg))},
            "unique_evidence": len(ev_count), "evidence_repeat_distribution_queries_per_evidence": dict(sorted(repeats.items())),
            "evidence_with_both_labels_across_queries": label_conflicts,
            "example_cves": len(cves_of_examples), "example_cve_split_membership": dict(foreign),
            "non_example_candidate_classes": dict(other_classes),
            "rule_signal_on_examples": {f"{cls}|suppressed={sup}": v for (cls, sup), v in sorted(rule_signal.items())} if rule_lists else None}

def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cfg = load_rerank_config()
    pool = load_pool(paths.PROJECT_ROOT / cfg["candidate_pool"]["source"], ("train", "dev"))
    queries = query_lookup(("train", "dev"), "POST_REPLACEMENT_MAIN")
    cve_split = json.loads((paths.PROCESSED_DATA_DIR / "splits" / "temporal_split.json").read_text(encoding="utf-8"))
    rule_dir = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_rule" / "full"
    out: dict[str, Any] = {"definition": "temporal example = target-chain candidate with class TARGET_CURRENT (positive) or TARGET_OUTDATED (negative) in the accepted BM25 top-50 pool",
                           "not_examples": ["OTHER_CVE", "OTHER_SOURCE_CURRENT", "OTHER_SOURCE_INACTIVE", "other cvss_version", "unlabeled chain context"],
                           "test_and_future_event": "never opened in this profile"}
    for split in ("train", "dev"):
        rl = None
        p = rule_dir / f"{split}_inferred_top50.jsonl"
        if p.exists():
            rl = {json.loads(l)["query_id"]: json.loads(l) for l in p.open(encoding="utf-8")}
        out[split] = profile_split(pool[split], queries, rl, cve_split, split)
    train_cves = {queries[r["query_id"]]["cve_id"] for r in pool["train"]}
    dev_cves = {queries[r["query_id"]]["cve_id"] for r in pool["dev"]}
    out["cve_level_disjointness"] = {"train_dev_cve_overlap": len(train_cves & dev_cves), "train_example_cves_labelled_other_split": {k: v for k, v in out["train"]["example_cve_split_membership"].items() if k != "train"},
                                     "train_dev_evidence_overlap": 0}
    tr_ev = set(); dv_ev = set()
    for r in pool["train"]:
        tr_ev |= {c["evidence_id"] for c in r["candidates"] if is_temporal_example(c["class"])}
    for r in pool["dev"]:
        dv_ev |= {c["evidence_id"] for c in r["candidates"] if is_temporal_example(c["class"])}
    out["cve_level_disjointness"]["train_dev_evidence_overlap"] = len(tr_ev & dv_ev)
    (OUT / "train_label_profile.json").write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({s: {k: out[s][k] for k in ("queries", "current_examples", "outdated_examples", "class_ratio_outdated_to_current", "unique_evidence",
                                                "evidence_repeat_distribution_queries_per_evidence", "evidence_with_both_labels_across_queries", "rule_signal_on_examples")} for s in ("train", "dev")}
                     | {"disjoint": out["cve_level_disjointness"], "train_per_query": (out["train"]["current_per_query"]["dist"], out["train"]["outdated_per_query"]["dist"])}, indent=1))
    return 0

if __name__ == "__main__":
    sys.exit(main())
