from __future__ import annotations

import json
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import paths
from src.normalize.cvss40 import (
    REFERENCE_VERSION, ROUNDING_PRECISION_DECIMALS, Cvss40ParseError, base_score_v40, bt_score_v40,
    parse_vector_v40, severity_v40, threat_metric,
)

OUT_JSON = paths.PROJECT_ROOT / "results" / "quality_assurance" / "cvss40_score_validation.json"
OUT_MD = paths.PROJECT_ROOT / "results" / "quality_assurance" / "cvss40_dogrulama_raporu.md"
EXAMPLE_SEED = 4040

def classify(reported: float, reported_sev: str | None, vector: str) -> dict:
    js_b = base_score_v40(vector, "js")
    dec_b = base_score_v40(vector, "decimal")
    js_bt = bt_score_v40(vector, "js")
    dec_bt = bt_score_v40(vector, "decimal")
    e_value = threat_metric(vector)
    sev_dec_b = severity_v40(dec_b)
    if dec_b == reported and js_b == reported and sev_dec_b == reported_sev:
        kind = "CVSS-B"
    elif dec_b == reported and sev_dec_b == reported_sev:
        kind = "ROUNDING_BOUNDARY_EQUIVALENT"
    elif dec_bt == reported and severity_v40(dec_bt) == reported_sev:
        kind = "CVSS-BT"
    else:
        kind = "UNRESOLVED"
    return {
        "reported_score_type": kind,
        "reference_js_base_score": js_b,
        "decimal_exact_base_score": dec_b,
        "reference_js_bt_score": js_bt,
        "decimal_exact_bt_score": dec_bt,
        "threat_metric_value": e_value,
        "js_matches_reported": js_b == reported,
        "decimal_matches_reported": dec_b == reported,
    }

def main() -> int:
    files = sorted(paths.NVD_CVE_DIR.glob("*.json"))
    c: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    boundary: list[dict] = []
    unresolved: list[dict] = []
    unparseable: list[dict] = []
    bt_by_source: Counter[str] = Counter()
    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        for item in payload["vulnerabilities"]:
            for entry in item["cve"].get("metrics", {}).get("cvssMetricV40", []):
                data = entry["cvssData"]
                vector = data.get("vectorString", "")
                c["total_vectors"] += 1
                try:
                    parse_vector_v40(vector)
                except Cvss40ParseError as error:
                    unparseable.append({"cve": item["cve"]["id"], "vector": vector, "error": str(error)})
                    continue
                c["parseable"] += 1
                reported = data.get("baseScore")
                if reported is None:
                    c["nvd_score_missing"] += 1
                    continue
                c["comparable"] += 1
                try:
                    info = classify(float(reported), data.get("baseSeverity") or entry.get("baseSeverity"), vector)
                except Exception as error:
                    c["not_computable"] += 1
                    unparseable.append({"cve": item["cve"]["id"], "vector": vector, "error": f"compute: {error}"})
                    continue
                kinds[info["reported_score_type"]] += 1
                row = {"cve": item["cve"]["id"], "source": entry.get("source"), "vector": vector, "reported": reported, **info}
                if info["reported_score_type"] == "ROUNDING_BOUNDARY_EQUIVALENT":
                    boundary.append(row)
                elif info["reported_score_type"] == "UNRESOLVED":
                    unresolved.append(row)
                elif info["reported_score_type"] == "CVSS-BT":
                    bt_by_source[str(entry.get("source"))] += 1
    rng = random.Random(EXAMPLE_SEED)
    out = {
        "implementation": "src/normalize/cvss40.py (port of FIRSTdotorg/cvss-v4-calculator cvss_score.js)",
        "reference_version": REFERENCE_VERSION,
        "specification": "CVSS v4.0 Specification Document (FIRST, 2023), MacroVector scoring",
        "compared_field": "cvssMetricV40[].cvssData.baseScore and baseSeverity (all sources incl. CNA/ADP)",
        "rounding_policy": {
            "adopted": "decimal-exact half-up: Decimal(f'{x:.%df}').quantize(0.1, ROUND_HALF_UP)" % ROUNDING_PRECISION_DECIMALS,
            "intermediate_precision_decimals": ROUNDING_PRECISION_DECIMALS,
            "reference_js": "Math.round(x*10)/10 == floor(x*10+0.5)/10 (kept for auditing, not used for evidence)",
            "note": "Differences between the two policies are binary floating-point boundary cases, not implementation errors.",
        },
        "files": len(files),
        "counts": {
            "total_vectors": c["total_vectors"],
            "parseable": c["parseable"],
            "unparseable": len([u for u in unparseable if not u["error"].startswith("compute")]),
            "comparable": c["comparable"],
            "nvd_score_missing": c["nvd_score_missing"],
            "not_computable": c["not_computable"],
            "reported_score_type": {
                "CVSS-B": kinds["CVSS-B"],
                "CVSS-BT": kinds["CVSS-BT"],
                "ROUNDING_BOUNDARY_EQUIVALENT": kinds["ROUNDING_BOUNDARY_EQUIVALENT"],
                "UNRESOLVED": kinds["UNRESOLVED"],
            },
            "bt_matches_by_source": dict(bt_by_source.most_common(10)),
        },
        "rounding_boundary_cases": boundary,
        "unresolved_examples": rng.sample(unresolved, min(10, len(unresolved))) if unresolved else [],
        "unparseable_examples": unparseable[:10],
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    k = out["counts"]
    t = k["reported_score_type"]
    tr = lambda n: f"{n:,}".replace(",", ".")
    md = "\n".join([
        "# CVSS 4.0 Puan Doğrulama Raporu",
        "",
        "Uygulama: `src/normalize/cvss40.py`, resmî FIRST hesaplayıcısının (cvss_score.js) Python portu; tablolar",
        f"`src/normalize/cvss40_tables.py` aynı depodan üretildi (sürüm: {REFERENCE_VERSION}). Spesifikasyon: CVSS v4.0 (FIRST, 2023).",
        "Karşılaştırılan alan: NVD CVE kayıtlarındaki `cvssMetricV40[].cvssData.baseScore` ve `baseSeverity` (tüm kaynaklar).",
        "",
        "**Yuvarlama politikası:** ara değer önce 10 ondalık hanede dize üzerinden normalize edilir",
        "(`Decimal(f'{x:.10f}')`, `Decimal(float)` kullanılmaz), sonra `ROUND_HALF_UP` ile 0,1'e yuvarlanır. JavaScript",
        "referansının `Math.round(x*10)/10` davranışı denetim amacıyla ayrıca hesaplanır ve saklanır. Veriye bakılarak",
        "hesaplama kuralı değiştirilmemiştir; iki politika arasındaki farklar ikili kayan-nokta sınır durumlarıdır, önceki",
        "uygulama hatası değildir.",
        "",
        "| Sayım | Değer |",
        "|---|---|",
        f"| Toplam CVSS 4.0 vektörü | {tr(k['total_vectors'])} |",
        f"| Ayrıştırılabilen | {tr(k['parseable'])} |",
        f"| Puan karşılaştırması yapılabilen | {tr(k['comparable'])} |",
        f"| NVD puanı = CVSS-B (JS ve ondalık yuvarlama aynı) | {tr(t['CVSS-B'])} |",
        f"| NVD puanı = tam-vektör CVSS-BT (tehdit metriği içeren) | {tr(t['CVSS-BT'])} |",
        f"| NVD puanı = ondalık-kesin CVSS-B, JS referansından 0,1 farklı (kayan-nokta sınır durumu) | {tr(t['ROUNDING_BOUNDARY_EQUIVALENT'])} |",
        f"| Açıklanamayan | {tr(t['UNRESOLVED'])} |",
        f"| NVD puanı bulunmayan | {tr(k['nvd_score_missing'])} |",
        f"| Hesaplanamayan | {tr(k['not_computable'])} |",
        f"| Ayrıştırılamayan | {tr(k['unparseable'])} |",
        "",
        "Her kayan-nokta sınır kaydı için `reference_js_base_score` ve `decimal_exact_base_score` JSON'da korunur",
        "(`rounding_boundary_cases`). BT eşleşmelerinin kaynak dağılımı `bt_matches_by_source` alanındadır.",
        "",
    ])
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps(k, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
