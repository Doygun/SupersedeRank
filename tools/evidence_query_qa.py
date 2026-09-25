from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import paths
from src.label import query_time_labels as L

SPLITS = ("train", "dev", "test", "future_event")
OUT_JSON = paths.PROJECT_ROOT / "results" / "quality_assurance" / "evidence_query_qa.json"
OUT_MD = paths.PROJECT_ROOT / "results" / "quality_assurance" / "evidence_query_qa_report.md"

def rows(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.open(encoding="utf-8")]

def main() -> int:
    cfg = yaml.safe_load((paths.CONFIG_DIR / "queries.yaml").read_text(encoding="utf-8"))
    ev = rows(paths.PROCESSED_DATA_DIR / "evidence" / "evidence.jsonl")
    by_id = {e["evidence_id"]: e for e in ev}
    qdir = paths.PROCESSED_DATA_DIR / "queries"
    queries = {s: rows(qdir / f"{s}_queries.jsonl") for s in SPLITS}
    excluded = rows(qdir / "excluded_queries.jsonl")
    manifest = json.loads((qdir / "query_manifest.json").read_text(encoding="utf-8"))
    all_q = [q for s in SPLITS for q in queries[s]]
    main = [q for q in all_q if q["query_role"] == "POST_REPLACEMENT_MAIN"]
    ctrl = [q for q in all_q if q["query_role"] == "PRE_REPLACEMENT_CONTROL"]
    forbidden = re.compile("|".join(re.escape(w) for w in cfg["evidence"]["forbidden_words_in_text"]), re.IGNORECASE)

    checks = {
        "evidence_ids_unique": len(by_id) == len(ev),
        "query_ids_unique": len({q["query_id"] for q in all_q}) == len(all_q),
        "each_query_one_split": all(q["split"] == s for s in SPLITS for q in queries[s]),
        "target_same_chain": all(by_id[q["answer_evidence_id"]]["cve_id"] == q["cve_id"] and by_id[q["answer_evidence_id"]]["source_key"] == q["source_key"]
                                 and by_id[q["answer_evidence_id"]]["cvss_version"] == q["cvss_version"] for q in all_q),
        "main_has_current": all(q["current_evidence_ids"] for q in main),
        "main_has_outdated_same_chain": all(q["outdated_evidence_ids"] for q in main),
        "no_future_evidence_visible": all(by_id[i]["observed_from"] <= q["query_time"] for q in all_q for i in q["visible_evidence_ids"]),
        "test_cves_not_in_train_dev": not ({q["cve_id"] for q in queries["test"]} & {q["cve_id"] for q in queries["train"] + queries["dev"]}),
        "future_event_not_in_test": not ({q["query_id"] for q in queries["future_event"]} & {q["query_id"] for q in queries["test"]}),
        "text_no_label_words": all(not forbidden.search(e["evidence_text"]) for e in ev),
        "text_no_replaced_by_leak": all((e["replaced_by_evidence_id"] or "zzz") not in e["evidence_text"] for e in ev),
        "censored_use_censored_template": all(e["evidence_text"].startswith("At the beginning of the observation window") == bool(e["valid_from_censored"]) for e in ev),
        "uncensored_start_is_activation": all((e["valid_from"] is not None and e["activation_event_id"] is not None) for e in ev if not e["valid_from_censored"]),
        "query_times_in_window": all(manifest["observation_window"]["start"] <= q["query_time"] <= manifest["observation_window"]["end"] for q in all_q),
        "answer_consistent_with_evidence": all(by_id[q["answer_evidence_id"]]["base_vector"] == q["answer_base_vector"] and by_id[q["answer_evidence_id"]]["base_score"] == q["answer_base_score"] for q in all_q),
        "answers_are_cvssb_not_bt": all(q["answer_base_score"] == by_id[q["answer_evidence_id"]]["base_score"] and (by_id[q["answer_evidence_id"]]["bt_score"] is None or q["answer_base_score"] != by_id[q["answer_evidence_id"]]["bt_score"] or by_id[q["answer_evidence_id"]]["bt_score"] == by_id[q["answer_evidence_id"]]["base_score"]) for q in all_q),
        "manifest_counts_match_files": all(manifest["counts"][s] == len(queries[s]) for s in SPLITS),
        "no_multiple_current_targets": not any(q["multiple_current_targets"] for q in all_q),
    }

    spill = 0
    for q in main:
        new = by_id[q["replacing_new_evidence_id"]]
        if new["valid_until"] is not None and not (q["query_time"] < new["valid_until"]):
            spill += 1
    checks["no_query_time_spill_into_next_replacement"] = spill == 0

    summary = {
        "evidence": {
            "total": len(ev),
            "replaced_old": sum(1 for e in ev if e["evidence_role"] == "replaced_old"),
            "replacing_new": sum(1 for e in ev if e["evidence_role"] == "replacing_new"),
            "chain_context": sum(1 for e in ev if e["evidence_role"] == "chain_context"),
            "left_censored": sum(1 for e in ev if e["valid_from_censored"]),
            "by_split": dict(Counter(e["split"] for e in ev)),
        },
        "queries": {
            "total": len(all_q),
            "main_post_replacement": len(main),
            "control_pre_replacement": len(ctrl),
            "by_split": {s: len(queries[s]) for s in SPLITS},
            "main_by_split": dict(Counter(q["split"] for q in main)),
            "by_template": dict(Counter(q["query_template_id"] for q in all_q)),
            "excluded": len(excluded),
            "excluded_by_reason": dict(Counter(x["reason"] for x in excluded)),
            "multiple_current_targets": sum(1 for q in all_q if q["multiple_current_targets"]),
            "with_other_source_current": sum(1 for q in all_q if q["other_source_current_evidence_ids"]),
            "mean_visible_same_cve": round(sum(len(q["visible_evidence_ids"]) for q in all_q) / len(all_q), 3),
            "mean_visible_corpus": round(sum(q["visible_corpus_count"] for q in all_q) / len(all_q), 1),
            "by_source_key_top": dict(Counter(q["source_key"] for q in all_q).most_common(10)),
            "by_version": dict(Counter(q["cvss_version"] for q in all_q)),
            "answer_severity": dict(Counter(str(q["answer_base_severity"]) for q in all_q)),
            "answer_score_bins": dict(sorted(Counter(str(int(q["answer_base_score"])) for q in all_q).items(), key=lambda kv: int(kv[0]))),
            "censored_vs_uncensored": dict(Counter("censored" if q["valid_from_censored"] else "uncensored" for q in all_q)),
        },
        "checks": checks,
        "all_checks_pass": all(checks.values()),
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tr = lambda n: f"{n:,}".replace(",", ".")
    e, q = summary["evidence"], summary["queries"]
    lines = [
        "# Evidence ve Sorgu Üretimi — Kalite Güvence Raporu", "",
        "Kaynak: `data/processed/evidence/evidence.jsonl`, `data/processed/queries/*.jsonl`, `query_manifest.json`.",
        "Şemalar: ``, ``. Kapsam: .", "",
        "## Evidence", "| Sayım | Değer |", "|---|---|",
        f"| Toplam evidence | {tr(e['total'])} |", f"| Eski (replaced_old) | {tr(e['replaced_old'])} |",
        f"| Yeni (replacing_new) | {tr(e['replacing_new'])} |", f"| Zincir bağlamı | {tr(e['chain_context'])} |",
        f"| Sol sansürlü | {tr(e['left_censored'])} |", f"| Split (train/dev/test) | {e['by_split']} |", "",
        "## Sorgular", "| Sayım | Değer |", "|---|---|",
        f"| Toplam sorgu | {tr(q['total'])} |", f"| Replacement sonrası ana | {tr(q['main_post_replacement'])} |",
        f"| Replacement öncesi kontrol | {tr(q['control_pre_replacement'])} |", f"| Split başına (toplam) | {q['by_split']} |",
        f"| Ana sorgu split başına | {q['main_by_split']} |", f"| Şablon dağılımı | {q['by_template']} |",
        f"| Dışlanan sorgu | {q['excluded']} ({q['excluded_by_reason']}) |",
        f"| Birden fazla CURRENT hedef | {q['multiple_current_targets']} |",
        f"| OTHER_SOURCE_CURRENT aday içerebilecek sorgu | {tr(q['with_other_source_current'])} |",
        f"| Sorgu başına ortalama görünür aynı-CVE kanıt / corpus | {q['mean_visible_same_cve']} / {q['mean_visible_corpus']} |",
        f"| Kaynak dağılımı (ilk 10) | {q['by_source_key_top']} |", f"| CVSS sürümü | {q['by_version']} |",
        f"| Cevap önem derecesi | {q['answer_severity']} |", f"| Cevap puanı (tam sayı kutuları) | {q['answer_score_bins']} |",
        f"| Sansürlü / sansürsüz hedef | {q['censored_vs_uncensored']} |", "",
        "## Otomatik kontroller", "| Kontrol | Sonuç |", "|---|---|",
    ] + [f"| {k} | {'✅' if v else '❌'} |" for k, v in checks.items()] + ["", f"**Tümü geçti:** {'evet' if summary['all_checks_pass'] else 'HAYIR'}", ""]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"all_checks_pass": summary["all_checks_pass"], "failed": [k for k, v in checks.items() if not v]}, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
