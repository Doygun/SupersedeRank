from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from typing import Any

from src import paths
from src.eval import metrics as M
from src.rerank import rule_inferred as RI
from src.retrieval.bm25_runner import summarize

OUT = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_rule"
SPLITS = ("train", "dev", "test")
CATS = ("TARGET_CHAIN_OUTDATED", "OTHER_CVE_INFERRED_SUPERSEDED", "SAME_CVE_OTHER_SOURCE_INFERRED_SUPERSEDED",
        "SAME_CVE_OTHER_VERSION_INFERRED_SUPERSEDED", "UNLABELED_CHAIN_CONTEXT", "OTHER")
METHODS = ("bm25", "recency_only", "bm25_recency", "cross_encoder", "rule_inferred", "rule_direct_upper_bound", "oracle_temporal")

def category(c: dict, v: dict, q: dict) -> str:
    if c["class"] == "TARGET_OUTDATED":
        return "TARGET_CHAIN_OUTDATED"
    if v["cve_id"] != q["cve_id"]:
        return "OTHER_CVE_INFERRED_SUPERSEDED"
    if v["source_key"] != q["source_key"]:
        return "SAME_CVE_OTHER_SOURCE_INFERRED_SUPERSEDED"
    if str(v["cvss_version"]) != str(q["cvss_version"]):
        return "SAME_CVE_OTHER_VERSION_INFERRED_SUPERSEDED"
    if c["class"] not in ("TARGET_CURRENT", "TARGET_OUTDATED"):
        return "UNLABELED_CHAIN_CONTEXT"
    return "OTHER"

def graded(c: dict) -> int:
    return 2 if c["class"] == "TARGET_CURRENT" else 1 if c["class"] == "OTHER_SOURCE_CURRENT" else 0

def main() -> int:
    index, _ = RI.build_index(paths.PROCESSED_DATA_DIR / "cvss_evidence.jsonl", paths.PROCESSED_DATA_DIR / "evidence" / "evidence.jsonl",
                              paths.PROCESSED_DATA_DIR / "sensitivity" / "cross_event_replacements.jsonl")
    per_query = {p["query_id"]: p for p in json.loads((OUT / "per_query.json").read_text(encoding="utf-8"))}
    stats: dict[str, dict[str, Any]] = {k: {"occurrences": 0, "evidence": set(), "cves": set(), "suppressed_from_bm25_top10": 0, "same_cve": 0, "other_cve": 0,
                                           "left_censored": 0, "graded_relevance_mass": 0, "graded_relevance_lost_from_top10": 0, "by_split": Counter()} for k in CATS}
    total, lost_top10_mass, preserved_mass_top10 = 0, 0, 0
    queries_with_other_cve_suppression = 0
    for s in SPLITS:
        for line in (OUT / "full" / f"{s}_inferred_top50.jsonl").open(encoding="utf-8"):
            r = json.loads(line)
            q = per_query[r["query_id"]]
            any_other = False
            for c in r["candidates"]:
                if c["rank"] <= 10:
                    preserved_mass_top10 += graded(c)
                if not c["suppressed"]:
                    continue
                total += 1
                v = index.view[c["evidence_id"]]
                k = category(c, v, q)
                st = stats[k]
                st["occurrences"] += 1; st["evidence"].add(c["evidence_id"]); st["cves"].add(v["cve_id"]); st["by_split"][s] += 1
                st["suppressed_from_bm25_top10"] += c["bm25_rank"] <= 10
                st["same_cve"] += v["cve_id"] == q["cve_id"]; st["other_cve"] += v["cve_id"] != q["cve_id"]
                st["left_censored"] += v["valid_from_censored"]
                g = graded(c)
                st["graded_relevance_mass"] += g
                if c["bm25_rank"] <= 10 and c["rank"] > 10:
                    st["graded_relevance_lost_from_top10"] += g
                    lost_top10_mass += g
                any_other |= k == "OTHER_CVE_INFERRED_SUPERSEDED"
            queries_with_other_cve_suppression += any_other
    cat_out = {}
    for k, st in stats.items():
        n = st["occurrences"]
        cat_out[k] = {"occurrences": n, "share_of_all_suppressed": round(n / total, 4) if total else 0.0, "unique_evidence": len(st["evidence"]), "unique_cves": len(st["cves"]),
                      "suppressed_while_in_bm25_top10": st["suppressed_from_bm25_top10"], "same_cve_share": round(st["same_cve"] / n, 4) if n else None,
                      "other_cve_share": round(st["other_cve"] / n, 4) if n else None, "left_censored": st["left_censored"],
                      "left_censored_share": round(st["left_censored"] / n, 4) if n else None, "graded_relevance_mass_suppressed": st["graded_relevance_mass"],
                      "graded_relevance_lost_from_top10": st["graded_relevance_lost_from_top10"], "by_split": dict(st["by_split"])}
    audit = {"suppressed_total": total, "queries": len([p for p in per_query.values() if p["split"] != "future_event"]),
             "queries_with_other_cve_suppression": queries_with_other_cve_suppression, "categories": cat_out,
             "graded_relevance": {"lost_from_top10_total": lost_top10_mass, "preserved_in_rule_top10_total": preserved_mass_top10,
                                  "note": "relevance 2 = target CURRENT, 1 = other-source CURRENT, 0 otherwise; suppressed candidates carry 0 by the gates"},
             "answer": "RULE-INFERRED also moves other CVEs' own-chain superseded evidence (category OTHER_CVE_INFERRED_SUPERSEDED) to the second block; "
                       "see the category shares. Target CURRENT and OTHER_SOURCE_CURRENT are never suppressed (gates)."}

    test = [p for p in per_query.values() if p["split"] == "test"]
    groups = {"A_preserved_ge10": [p for p in test if p["preserved_ge10"]], "B_preserved_lt10": [p for p in test if not p["preserved_ge10"]]}
    test_out = {}
    for g, rows in groups.items():
        entry: dict[str, Any] = {"queries": len(rows), "n_preserved_min": min((p["n_preserved"] for p in rows), default=None), "n_preserved_max": max((p["n_preserved"] for p in rows), default=None),
                                 "source_groups": dict(Counter(p["source_key"] for p in rows).most_common(6)), "methods": {}}
        for m in METHODS:
            s = summarize(rows, m)
            s.update({k: v for k, v in M.summarize_stale_suppression([p[m] for p in rows]).items() if k != "queries"})
            entry["methods"][m] = {k: s[k] for k in ("recall@50", "mrr@10", "ndcg@10", "ndcg@10_graded", "stale@10", "top1_current_rate", "top1_outdated_rate",
                                                     "outdated_count@10_mean", "first_outdated_rank_mean", "outdated_suppression@10", "current_preservation@10", "current_at1_and_no_stale@10")}
        test_out[g] = entry
    forced_b = sum(p["rule_inferred"]["outdated_count@10"] for p in groups["B_preserved_lt10"])
    test_out["remaining_stale_test"] = {"outdated_in_top10_group_B": forced_b, "outdated_in_top10_group_A": sum(p["rule_inferred"]["outdated_count@10"] for p in groups["A_preserved_ge10"]),
                                        "joint_test_overall": M.mean(1.0 if p["rule_inferred"]["current_at1_and_no_stale@10"] else 0.0 for p in test)}
    out = {"suppression_audit": audit, "test_split_by_preserved_candidates": test_out}
    (OUT / "suppression_audit.json").write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    L = ["# RULE-INFERRED Bastırılan Aday Denetimi ve Test A/B Ayrıştırması — 2026-09-16", "",
         f"## 1. Bastırılan adaylar ({total} aday gösterimi, {audit['queries']} ana sorgu)",
         "| Kategori | Gösterim | Pay | Benzersiz kanıt | Benzersiz CVE | BM25 top-10'dayken bastırılan | Aynı CVE payı | Farklı CVE payı | Sol sansürlü (pay) | Dereceli relevance kütlesi | Top-10'dan kaybedilen relevance |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
    for k, v in cat_out.items():
        L.append(f"| {k} | {v['occurrences']} | {v['share_of_all_suppressed']} | {v['unique_evidence']} | {v['unique_cves']} | {v['suppressed_while_in_bm25_top10']} | {v['same_cve_share']} | {v['other_cve_share']} | "
                 f"{v['left_censored']} ({v['left_censored_share']}) | {v['graded_relevance_mass_suppressed']} | {v['graded_relevance_lost_from_top10']} |")
    L += ["", f"- Başka CVE'nin kendi zincirinde geçersiz kılınmış kanıtını bastıran sorgu sayısı: {queries_with_other_cve_suppression} / {audit['queries']}.",
          f"- Top-10'dan kaybedilen toplam dereceli relevance: {lost_top10_mass} (CURRENT ve OTHER_SOURCE_CURRENT hiç bastırılmadığından 0 beklenir). Rule top-10'unda korunan relevance kütlesi: {preserved_mass_top10}.",
          f"- Cevap: {audit['answer']}", "",
          "## 2. Test kümesi: A (≥10 korunmuş aday) ve B (<10 korunmuş aday)"]
    for g, e in ((k, test_out[k]) for k in ("A_preserved_ge10", "B_preserved_lt10")):
        L += [f"### {g}: n={e['queries']}, korunmuş aday {e['n_preserved_min']}–{e['n_preserved_max']}; kaynaklar {e['source_groups']}",
              "| Yöntem | Recall@50 | MRR@10 | NDCG@10 | NDCG@10 dereceli | Stale@10 | ilk sıra CURRENT | ilk sıra OUTDATED | OutdatedCount@10 | FirstOutdatedRank | OutdatedSuppression@10 | CurrentPreservation@10 | CurrentAt1AndNoStaleAt10 |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for m, s in e["methods"].items():
            L.append(f"| {m} | " + " | ".join(str(s[k]) for k in ("recall@50", "mrr@10", "ndcg@10", "ndcg@10_graded", "stale@10", "top1_current_rate", "top1_outdated_rate", "outdated_count@10_mean",
                                                                  "first_outdated_rank_mean", "outdated_suppression@10", "current_preservation@10", "current_at1_and_no_stale@10")) + " |")
        L.append("")
    L.append(f"- Test'te top-10'da kalan OUTDATED: A grubunda {test_out['remaining_stale_test']['outdated_in_top10_group_A']}, B grubunda {test_out['remaining_stale_test']['outdated_in_top10_group_B']}; "
             f"test geneli CurrentAt1AndNoStaleAt10 {test_out['remaining_stale_test']['joint_test_overall']}.")
    (OUT / "suppression_audit.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(json.dumps({"total": total, "categories": {k: (v["occurrences"], v["unique_evidence"], v["unique_cves"], v["suppressed_while_in_bm25_top10"], v["graded_relevance_lost_from_top10"]) for k, v in cat_out.items()},
                      "queries_with_other_cve_suppression": queries_with_other_cve_suppression, "lost_mass": lost_top10_mass,
                      "test_groups": {g: (e["queries"], e["methods"]["rule_inferred"]["stale@10"], e["methods"]["rule_inferred"]["current_at1_and_no_stale@10"], e["methods"]["bm25"]["stale@10"]) for g, e in test_out.items() if g.startswith(("A", "B"))}}, indent=1))
    return 0

if __name__ == "__main__":
    sys.exit(main())
