from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from src import paths
from src.eval import metrics as M
from src.retrieval.bm25_runner import summarize

R = paths.PROJECT_ROOT / "results"
TEX_NAMES = {"bm25": "BM25", "bm25_recency": "BM25+Recency", "cross_encoder": "Cross-encoder", "recency_only": "Recency-only",
             "rule_target": "ChronoRank-Rule-Target", "rule_corpus": "ChronoRank-Rule-Corpus",
             "rule_direct_upper_bound": "Direct-Link Policy (diagnostic)", "oracle_temporal": "Temporal-clean oracle (oracle upper bound)"}
GROUPS = [("Retrieval and semantic baselines", ["bm25", "bm25_recency", "cross_encoder"]), ("ChronoRank", ["rule_target", "rule_corpus"]),
          ("Diagnostic policy", ["rule_direct_upper_bound"]), ("Oracle upper bound", ["oracle_temporal"])]
COLS = [("mrr@10", "MRR@10"), ("ndcg@10", "NDCG@10"), ("ndcg@10_graded", "gNDCG@10"), ("stale@10", "Stale@10"), ("outdated_suppression@10", "OutSupp@10"),
        ("current_preservation@10", "CurPres@10"), ("current_at1_and_no_stale@10", "Cur@1$\\wedge$NoStale@10"), ("top1_current_rate", "Top-1 CUR")]

def load(path: str) -> Any:
    return json.loads((paths.PROJECT_ROOT / path).read_text(encoding="utf-8"))

def f(x: Any, d: int = 3) -> str:
    return "--" if x is None else f"{x:.{d}f}"

def agg(rows: list[dict], m: str) -> dict[str, Any]:
    s = summarize(rows, m)
    s.update({k: v for k, v in M.summarize_stale_suppression([r[m] for r in rows]).items() if k != "queries"})
    return s

def table(caption: str, label: str, header: list[str], body: list[str], width: str = "", stretch: str = "") -> str:
    cols = "l" + "r" * (len(header) - 1)

    lines = [r"\begin{table}", r"\centering", (r"\renewcommand{\arraystretch}{" + stretch + "}") if stretch else "", r"\caption{" + caption + "}", r"\label{" + label + "}",
             r"\resizebox{" + width + r"\linewidth}{!}{%", r"\begin{tabular}{" + cols + "}", r"\toprule",
             " & ".join(header) + r" \\", r"\midrule", *body, r"\bottomrule", r"\end{tabular}}", r"\end{table}"]
    return "\n".join(l for l in lines if l) + "\n"

def cell(est: float, ci: list[float]) -> str:
    return r"\begin{tabular}[c]{@{}c@{}}" + f(est) + r"\\{\scriptsize[" + f(ci[0]) + ", " + f(ci[1]) + r"]}\end{tabular}"

def grouped_body(rows: list[dict], cols: list[tuple[str, str]], groups=GROUPS) -> list[str]:
    body = []
    for gname, methods in groups:
        body.append(r"\multicolumn{" + str(len(cols) + 1) + r"}{l}{" + gname + r"} \\")
        for m in methods:
            a = agg(rows, m)
            body.append(TEX_NAMES[m] + " & " + " & ".join(f(a.get(k)) for k, _ in cols) + r" \\")
    return body

def main() -> int:
    cfg = yaml.safe_load((paths.PROJECT_ROOT / "config" / "statistics.yaml").read_text(encoding="utf-8"))
    out_dir = paths.PROJECT_ROOT / cfg["tables"]["output_dir"]; out_dir.mkdir(parents=True, exist_ok=True)
    per = load(cfg["population"]["source"])
    main_rows = [p for p in per if p["split"] in ("train", "dev", "test")]
    test_rows = [p for p in per if p["split"] == "test"]

    (out_dir / "main_results.tex").write_text(table("Reranking results on the main queries.", "tab:main_results",
                                                    ["Method"] + [h for _, h in COLS], grouped_body(main_rows, COLS), stretch="1.45"), encoding="utf-8")

    boot = load("results/experiments/statistical_analysis/bootstrap_results.json")
    tcols = [("current_at1_and_no_stale@10", "Cur@1$\\wedge$NoStale@10"), ("stale@10", "Stale@10"), ("ndcg@10_graded", "gNDCG@10"), ("mrr@10", "MRR@10"), ("outdated_suppression@10", "OutSupp@10"), ("current_preservation@10", "CurPres@10")]
    body = []
    for gname, methods in GROUPS:
        body.append(r"\multicolumn{" + str(len(tcols) + 1) + r"}{l}{" + gname + r"} \\")
        for m in methods:
            r = boot["results"][m]
            body.append(TEX_NAMES[m] + " & " + " & ".join(cell(r[k]["estimate"], r[k]["ci95"]) for k, _ in tcols) + r" \\[2pt]")
    (out_dir / "test_results.tex").write_text(table("Future-entity test results.", "tab:test_results", ["Method"] + [h for _, h in tcols], body), encoding="utf-8")

    pc = load("results/experiments/statistical_analysis/paired_comparisons.json")
    metric_names = dict(tcols)
    metric_names.update({"ndcg@10": "NDCG@10"})
    body, full = [], []
    for other, per_k in pc["comparisons"].items():
        for k in cfg["metrics"]["primary"] + [m for m in cfg["metrics"]["secondary"] if m in per_k]:
            c = per_k[k]; h = c.get("holm")
            p = c["p_two_sided_bootstrap"]; p = p if isinstance(p, str) else f"{p:.4f}"
            cells = (f"{f(c['mean_diff_ref_minus_other'], 4)} & [{f(c['ci95'][0], 4)}, {f(c['ci95'][1], 4)}] & {p} & "
                     f"{f(h['p_holm'], 4) if h else '--'} & {c['wins_ref']}/{c['losses_ref']}/{c['ties']}" + r" \\")
            full.append(f"vs {TEX_NAMES[other]} & {metric_names.get(k, k)} & {c['family']} & " + cells)
            if k in cfg["metrics"]["primary"]:
                body.append(f"vs {TEX_NAMES[other]} & {metric_names.get(k, k)} & " + cells)
    (out_dir / "statistical_significance.tex").write_text(table("Paired method differences on the test split.", "tab:significance", ["Comparison", "Metric", "$\\Delta$", "95\\% CI", "$p$", "Holm $p$", "W/L/T"], body), encoding="utf-8")
    (out_dir / "statistical_significance_full.tex").write_text(table("Paired method differences for all reported metrics.", "tab:significance_full", ["Comparison", "Metric", "Family", "$\\Delta$", "95\\% CI", "$p$", "Holm $p$", "W/L/T"], full, width="0.84"), encoding="utf-8")

    sc = load("results/experiments/chronorank_rule_target/rule_scope_comparison.json")
    s, cap = sc["suppression"], sc["capacity_limitation_queries"]
    rows = [("Suppressed candidates (total)", s["corpus"]["total"], s["target"]["total"]), ("\\quad target chain", s["corpus"]["target_chain"], s["target"]["target_chain"]),
            ("\\quad outside the target chain", s["corpus"]["non_target"], s["target"]["non_target"]), ("Suppressed per query", s["corpus"]["per_query"], s["target"]["per_query"]),
            ("Queries with $<10$ preserved candidates", cap["corpus"], cap["target"]), ("CURRENT lost", sc["current_loss"]["corpus"], sc["current_loss"]["target"]),
            ("OTHER\\_SOURCE\\_CURRENT lost", sc["other_source_current_loss"]["corpus"], sc["other_source_current_loss"]["target"]),
            ("Graded relevance lost from top-10", sc["graded_relevance_lost_from_top10"]["corpus"], sc["graded_relevance_lost_from_top10"]["target"])]
    for k, lab in (("current_at1_and_no_stale@10", "Cur@1$\\wedge$NoStale@10"), ("stale@10", "Stale@10"), ("outdated_suppression@10", "OutSupp@10"), ("ndcg@10_graded", "gNDCG@10"), ("mrr@10", "MRR@10")):
        rows.append((lab, sc["main_metrics"]["rule_corpus"][k], sc["main_metrics"]["rule_target"][k]))
    body = [f"{lab} & {v1 if isinstance(v1, int) else f(v1)} & {v2 if isinstance(v2, int) else f(v2)}" + r" \\" for lab, v1, v2 in rows]
    body.append(r"\midrule")
    for lab, key in (("Identical rankings", "same_list"), ("Target better", "target_better_joint_or_stale"), ("Corpus better", "corpus_better_joint_or_stale"), ("Equal on joint/stale", "equal_joint_and_stale")):
        body.append(lab + r" (queries) & \multicolumn{2}{c}{" + str(sc[key]) + r"} \\")
    (out_dir / "rule_scope_comparison.tex").write_text(table("Comparison of suppression scopes.", "tab:rule_scope",
                                                             ["", TEX_NAMES["rule_corpus"], TEX_NAMES["rule_target"]], body), encoding="utf-8")

    off = load("results/experiments/offset_sensitivity/offset_sensitivity_pool_fixed.json"); sm = load("results/experiments/offset_sensitivity/offset_sensitivity_smoke_reretrieval.json")
    body = []
    for k, c in off["cohorts"].items():
        m = c["methods"]; r = sm["cohorts"][k]["reretrieval"]
        body.append(f"{k} & {c['eligible_queries']} & {f(m['bm25']['top1_current_rate'])} & {f(m['bm25_recency']['top1_current_rate'])} & {f(m['bm25_recency']['mrr@10'])} & {f(m['bm25_recency']['stale@10'])} & "
                    f"{f(m['bm25_recency_tau180']['top1_current_rate'])} & {f(m['bm25_recency_tau365']['top1_current_rate'])} & {sm['cohorts'][k]['eligible_queries']} & {f(r['bm25_recency']['top1_current_rate'])}" + r" \\")
    (out_dir / "robustness_offset.tex").write_text(table("Query-time offset sensitivity.", "tab:robustness_offset", ["Offset", "$n$", "BM25 Top-1", "Rec. Top-1", "Rec. MRR", "Rec. Stale", "$\\tau$180 Top-1", "$\\tau$365 Top-1", "$n$ (re-retr.)", "Rec. Top-1 (re-retr.)"], body), encoding="utf-8")

    ls = load("results/experiments/chronorank_learned/smoke_report.json")
    lcols = [("mrr@10", "MRR@10"), ("ndcg@10_graded", "gNDCG@10"), ("stale@10", "Stale@10"), ("outdated_suppression@10", "OutSupp@10"), ("current_preservation@10", "CurPres@10"), ("current_at1_and_no_stale@10", "Cur@1$\\wedge$NoStale@10")]
    body = []
    for m, name in (("rule_inferred", TEX_NAMES["rule_corpus"]), ("learned_full", "Learned-Full (LR)"), ("learned_no_rule_signal", "Learned-NoRuleSignal (LR)")):
        a, ss = ls[m]["all"], ls[m]["stale_suppression"]
        body.append(name + " & " + " & ".join(f(a.get(k, ss.get(k))) for k, _ in lcols) + r" \\")
    ag = ls["rule_agreement"]; cl = ls["classification_selected"]["learned_full"]
    body.append(r"\multicolumn{7}{l}{Decisions on the query's chain identical to " + TEX_NAMES["rule_target"] + ": " + f"{ag['same_target_chain_decisions']}/{ag['queries']}; train/dev accuracy {cl['train']['accuracy']:.3f}/{cl['dev']['accuracy']:.3f}; C={ls['selection']['learned_full']['selected_C']}" + r"} \\")
    (out_dir / "learned_diagnostic.tex").write_text(table("Diagnostic results of the learned model.", "tab:learned_diagnostic",
                                                          ["Method"] + [h for _, h in lcols], body), encoding="utf-8")

    from src.retrieval.bm25_runner import evaluate, load_main_queries
    tq = {q["query_id"]: q for q in load_main_queries(["test"], "POST_REPLACEMENT_MAIN")["test"]}
    bm25_lists = {r["query_id"]: r["candidates"] for r in (json.loads(l) for l in (R / "experiments" / "bm25_full" / "test_top50.jsonl").open(encoding="utf-8"))}
    rec_rows = []
    for r in (json.loads(l) for l in (R / "experiments" / "recency" / "test_recency_only_top50.jsonl").open(encoding="utf-8")):
        e = evaluate(r["candidates"], tq[r["query_id"]]); e.update(M.stale_suppression(r["candidates"], bm25_lists[r["query_id"]]))
        rec_rows.append({"recency_only": e})
    fig = []
    for m in ("bm25", "recency_only", "bm25_recency", "cross_encoder", "rule_corpus", "rule_target"):
        a = agg(rec_rows if m == "recency_only" else test_rows, m)
        fig.append({"method": m, "label": TEX_NAMES[m], "current_preservation@10": a["current_preservation@10"], "top1_current_rate": a["top1_current_rate"],
                    "outdated_suppression@10": a["outdated_suppression@10"], "one_minus_stale@10": round(1 - a["stale@10"], 4), "current_at1_and_no_stale@10": a["current_at1_and_no_stale@10"], "split": "test", "queries": len(test_rows)})
    with (out_dir / "figure_results_data.csv").open("w", newline="", encoding="utf-8") as h:
        w = csv.DictWriter(h, fieldnames=list(fig[0].keys())); w.writeheader(); w.writerows(fig)
    (out_dir / "figure_results_data.json").write_text(json.dumps({"axes": {"x": ["current_preservation@10", "top1_current_rate"], "y": ["outdated_suppression@10", "one_minus_stale@10"]},
                                                                  "ideal_region": "CURRENT preserved (x -> 1) and OUTDATED suppressed (y -> 1)", "points": fig}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("yazildi:", sorted(p.name for p in out_dir.iterdir()))
    return 0

if __name__ == "__main__":
    sys.exit(main())
