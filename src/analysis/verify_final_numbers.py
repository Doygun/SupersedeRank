from __future__ import annotations

import json
import re
import sys
from typing import Any

import yaml

from src import paths
from src.eval import metrics as M
from src.retrieval.bm25_runner import summarize

OUT = paths.PROJECT_ROOT / "results" / "experiments" / "statistical_analysis"
METRICS = ("recall@10", "recall@50", "mrr@10", "ndcg@10", "ndcg@10_graded", "stale@10", "outdated_count@10_mean", "first_outdated_rank_mean", "outdated_suppression@10",
           "current_preservation@10", "current_at1_and_no_stale@10", "top1_current_rate", "top1_outdated_rate", "other_source_current_in_top10", "ranking_failure_rate")
SOURCES = {
    "bm25": ("results/experiments/bm25_full/bm25_report.json", ["main", "bm25", "all"], None),
    "bm25_recency": ("results/experiments/reranking_baselines/baseline_comparison.json", ["main", "bm25_recency", "all"], None),
    "cross_encoder": ("results/experiments/reranking_baselines/baseline_comparison.json", ["main", "cross_encoder", "all"], None),
    "rule_corpus": ("results/experiments/chronorank_rule/full_report.json", ["main", "rule_inferred", "all"], ["main", "rule_inferred", "stale_suppression"]),
    "rule_target": ("results/experiments/chronorank_rule_target/rule_target_report.json", ["main", "rule_target", "all"], ["main", "rule_target", "stale_suppression"]),
    "rule_direct_upper_bound": ("results/experiments/chronorank_rule/full_report.json", ["main", "rule_direct_upper_bound", "all"], ["main", "rule_direct_upper_bound", "stale_suppression"]),
    "oracle_temporal": ("results/experiments/chronorank_rule/full_report.json", ["main", "oracle_temporal", "all"], ["main", "oracle_temporal", "stale_suppression"]),
}

def dig(d: dict, path: list[str]) -> dict:
    for k in path:
        d = d[k]
    return d

def recompute(rows: list[dict], m: str) -> dict[str, Any]:
    s = summarize(rows, m)
    s.update({k: v for k, v in M.summarize_stale_suppression([r[m] for r in rows]).items() if k != "queries"})
    return s

def md_table_values(path: str, method_col_name: str) -> dict[str, str]:
    text = (paths.PROJECT_ROOT / path).read_text(encoding="utf-8")
    out = {}
    for block in re.split(r"\n\s*\n", text):
        lines = [l for l in block.splitlines() if l.startswith("|")]
        if len(lines) < 3 or "Metrik" not in lines[0]:
            continue
        header = [h.strip() for h in lines[0].strip("|").split("|")]
        if method_col_name not in header:
            continue
        j = header.index(method_col_name)
        for l in lines[2:]:
            cells = [c.strip() for c in l.strip("|").split("|")]
            if len(cells) > j:
                out[cells[0]] = cells[j]
        return out
    return out

def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cfg = yaml.safe_load((paths.PROJECT_ROOT / "config" / "statistics.yaml").read_text(encoding="utf-8"))
    per = json.loads((paths.PROJECT_ROOT / cfg["population"]["source"]).read_text(encoding="utf-8"))
    main_rows = [p for p in per if p["split"] in ("train", "dev", "test")]
    test_rows = [p for p in per if p["split"] == "test"]
    report: dict[str, Any] = {"main_queries": len(main_rows), "test_queries": len(test_rows), "test_cves": len({p["cve_id"] for p in test_rows}), "methods": {}, "mismatches": []}
    for m, (file, all_path, ss_path) in SOURCES.items():
        src = json.loads((paths.PROJECT_ROOT / file).read_text(encoding="utf-8"))
        src_all = dig(src, all_path)
        src_ss = dig(src, ss_path) if ss_path else {}
        rec = recompute(main_rows, m)
        entry = {"source_file": file, "main": {}, "test": recompute(test_rows, m)}
        for k in METRICS:
            v_pq = rec.get(k)
            v_src = src_all.get(k, src_ss.get(k))
            entry["main"][k] = {"per_query": v_pq, "source_json": v_src, "match": (v_src is None) or (v_pq is not None and abs(float(v_pq) - float(v_src)) < 1e-9)}
            if v_src is not None and not entry["main"][k]["match"]:
                report["mismatches"].append({"method": m, "metric": k, "per_query": v_pq, "source_json": v_src, "file": file})
            if v_src is None:
                entry["main"][k]["note"] = "metric not present in the source report (computed here from per-query)"
        report["methods"][m] = entry

    md = md_table_values("results/experiments/chronorank_rule_target/rule_target_report.md", "**ChronoRank-Rule-Target**")
    md_checks = {}
    for label, key in (("MRR@10", "mrr@10"), ("NDCG@10 (dereceli)", "ndcg@10_graded"), ("StaleEvidenceRate@10", "stale@10"), ("CurrentAt1AndNoStaleAt10", "current_at1_and_no_stale@10"),
                       ("OutdatedSuppression@10", "outdated_suppression@10"), ("CurrentPreservation@10", "current_preservation@10")):
        js = report["methods"]["rule_target"]["main"][key]["per_query"]
        md_checks[label] = {"markdown": md.get(label), "json": js, "match": md.get(label) is not None and abs(float(md[label]) - float(js)) < 1e-9}
    report["markdown_vs_json_rule_target"] = md_checks
    report["all_match"] = not report["mismatches"] and all(v["match"] for v in md_checks.values())
    (OUT / "final_numbers_verification.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"all_match": report["all_match"], "mismatches": report["mismatches"], "markdown": md_checks,
                      "test": {m: {k: report["methods"][m]["test"][k] for k in ("mrr@10", "ndcg@10_graded", "stale@10", "current_at1_and_no_stale@10")} for m in SOURCES}}, indent=1))
    return 0 if report["all_match"] else 1

if __name__ == "__main__":
    sys.exit(main())
