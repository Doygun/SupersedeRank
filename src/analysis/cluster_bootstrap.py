from __future__ import annotations

import hashlib
import json
import sys
import time
from typing import Any

import numpy as np
import yaml

from src import paths
from src.eval import metrics as M

OUT = paths.PROJECT_ROOT / "results" / "experiments" / "statistical_analysis"

def load_config() -> dict[str, Any]:
    return yaml.safe_load((paths.PROJECT_ROOT / "config" / "statistics.yaml").read_text(encoding="utf-8"))

def metric_value(row: dict, m: str, k: str) -> float | None:
    v = row[m].get(k)
    if v is None:
        return None
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    return float(v)

def cluster_arrays(rows: list[dict], methods: list[str], metrics: list[str], unit: str) -> tuple[list[str], dict[str, dict[str, tuple[np.ndarray, np.ndarray]]]]:
    clusters = sorted({r[unit] for r in rows})
    idx = {c: i for i, c in enumerate(clusters)}
    arrays: dict[str, dict[str, tuple[np.ndarray, np.ndarray]]] = {}
    for m in methods:
        arrays[m] = {}
        for k in metrics:
            s = np.zeros(len(clusters)); n = np.zeros(len(clusters))
            for r in rows:
                v = metric_value(r, m, k)
                if v is not None:
                    s[idx[r[unit]]] += v; n[idx[r[unit]]] += 1
            arrays[m][k] = (s, n)
    return clusters, arrays

def bootstrap_means(arrays: dict[str, dict[str, tuple[np.ndarray, np.ndarray]]], draws: np.ndarray) -> dict[str, dict[str, np.ndarray]]:
    out: dict[str, dict[str, np.ndarray]] = {}
    for m, per_metric in arrays.items():
        out[m] = {}
        for k, (s, n) in per_metric.items():
            ss = s[draws].sum(axis=1); nn = n[draws].sum(axis=1)
            with np.errstate(invalid="ignore", divide="ignore"):
                out[m][k] = np.where(nn > 0, ss / nn, np.nan)
    return out

def point_estimate(arrays: dict, m: str, k: str) -> float:
    s, n = arrays[m][k]
    return float(s.sum() / n.sum()) if n.sum() else float("nan")

def holm(pvals: dict[str, float], alpha: float) -> dict[str, dict[str, Any]]:
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items); out = {}; running = 0.0
    for i, (name, p) in enumerate(items):
        adj = min(1.0, (m - i) * p); running = max(running, adj)
        out[name] = {"p_raw": p, "p_holm": running, "reject_at_alpha": running <= alpha}
    return out

def main() -> int:
    t0 = time.perf_counter()
    cfg = load_config()
    pop, bcfg, mcfg, ccfg = cfg["population"], cfg["bootstrap"], cfg["metrics"], cfg["comparisons"]
    per = json.loads((paths.PROJECT_ROOT / pop["source"]).read_text(encoding="utf-8"))
    rows = [p for p in per if p["split"] == pop["split"]]
    assert all(p["split"] not in pop["exclude_splits"] for p in rows)
    methods = cfg["methods"]["main"] + cfg["methods"]["scope_analysis"] + cfg["methods"]["upper_bounds"]
    metrics = list(mcfg["ci_metrics"])
    clusters, arrays = cluster_arrays(rows, methods, metrics, bcfg["unit"])
    rng = np.random.default_rng(int(bcfg["seed"]))
    B, n = int(bcfg["replicates"]), len(clusters)
    draws = rng.integers(0, n, size=(B, n))
    boot = bootstrap_means(arrays, draws)
    lo, hi = 100 * (1 - bcfg["ci_level"]) / 2, 100 * (1 + bcfg["ci_level"]) / 2
    results = {m: {k: {"estimate": round(point_estimate(arrays, m, k), 4), "ci95": [round(float(np.nanpercentile(boot[m][k], lo)), 4), round(float(np.nanpercentile(boot[m][k], hi)), 4)],
                       "queries_defined": int(arrays[m][k][1].sum())} for k in metrics} for m in methods}

    ref = ccfg["reference"]; lower_better = set(mcfg["lower_is_better"])
    comparisons: dict[str, dict[str, Any]] = {}
    pvals_primary: dict[str, float] = {}
    for other in ccfg["against"]:
        comparisons[other] = {}
        for k in metrics:
            d = boot[ref][k] - boot[other][k]
            d = d[~np.isnan(d)]
            est = point_estimate(arrays, ref, k) - point_estimate(arrays, other, k)
            p_le, p_ge = float((d <= 0).mean()), float((d >= 0).mean())
            p_two = min(1.0, max(1.0 / B, 2 * min(p_le, p_ge)))
            wins = losses = ties = 0
            for r in rows:
                a, b = metric_value(r, ref, k), metric_value(r, other, k)
                if a is None or b is None:
                    continue
                if lower_better and k in lower_better:
                    a, b = -a, -b
                wins += a > b + 1e-12; losses += b > a + 1e-12; ties += abs(a - b) <= 1e-12
            comparisons[other][k] = {"mean_diff_ref_minus_other": round(est, 4), "ci95": [round(float(np.percentile(d, lo)), 4), round(float(np.percentile(d, hi)), 4)],
                                     "p_diff_gt_0": round(float((d > 0).mean()), 4), "p_two_sided_bootstrap": round(p_two, 4) if p_two > 1.0 / B else f"<{1.0 / B:g}",
                                     "favours_reference": (est < 0) if k in lower_better else (est > 0), "wins_ref": wins, "losses_ref": losses, "ties": ties,
                                     "family": "primary" if k in mcfg["primary"] else "secondary"}
            if k in mcfg["primary"]:
                pvals_primary[f"{other}|{k}"] = p_two
    holm_out = holm(pvals_primary, float(ccfg["alpha"]))
    for name, h in holm_out.items():
        other, k = name.split("|")
        comparisons[other][k]["holm"] = h

    per_main = [p for p in per if p["split"] in ("train", "dev", "test")]
    cap = {}
    thr = int(cfg["capacity_analysis"]["threshold"])
    for scope, rws in (("test", rows), ("all_main", per_main)):
        cap[scope] = {}
        for g, sel in (("preserved_ge10", lambda p: p["n_preserved_corpus"] >= thr), ("preserved_lt10", lambda p: p["n_preserved_corpus"] < thr)):
            sub = [p for p in rws if sel(p)]
            cap[scope][g] = {"queries": len(sub), "cves": len({p["cve_id"] for p in sub}), "methods": {}}
            for m in methods:
                cap[scope][g]["methods"][m] = {"mrr@10": M.mean(p[m]["mrr@10"] for p in sub), "stale@10": M.mean(p[m]["stale@10"] for p in sub),
                                               "current_at1_and_no_stale@10": M.mean(1.0 if p[m]["current_at1_and_no_stale@10"] else 0.0 for p in sub),
                                               "outdated_suppression@10": M.mean(p[m]["outdated_suppression@10"] for p in sub if p[m]["outdated_suppression@10"] is not None)}
    manifest = {"config_hash": hashlib.sha256((paths.PROJECT_ROOT / "config" / "statistics.yaml").read_bytes()).hexdigest(),
                "population": {"split": pop["split"], "queries": len(rows), "clusters_cve": n, "source": pop["source"]},
                "bootstrap": {"unit": bcfg["unit"], "replicates": B, "seed": int(bcfg["seed"]), "ci_method": bcfg["ci_method"], "ci_level": bcfg["ci_level"], "shared_replicates": True,
                              "draws_sha256": hashlib.sha256(draws.tobytes()).hexdigest(), "p_value": bcfg["p_value"], "estimator": "ratio of summed defined values to defined counts over sampled clusters"},
                "methods": methods, "metrics": metrics, "primary_metrics": mcfg["primary"], "secondary_metrics": mcfg["secondary"], "comparisons": {"reference": ref, "against": ccfg["against"]},
                "holm_family": ccfg["primary_family"], "alpha": ccfg["alpha"], "undefined_policy": mcfg["undefined_policy"], "seconds": round(time.perf_counter() - t0, 1)}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "bootstrap_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "bootstrap_results.json").write_text(json.dumps({"split": pop["split"], "queries": len(rows), "clusters": n, "results": results}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "paired_comparisons.json").write_text(json.dumps({"reference": ref, "comparisons": comparisons, "holm_primary_family": holm_out}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "capacity_analysis.json").write_text(json.dumps({"reference_policy": cfg["capacity_analysis"]["reference_policy"], "threshold": thr, "groups": cap}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    names = cfg["methods"]["names"]
    L = [f"# Test Kümesi İstatistiksel Analizi — CVE-düzeyi cluster bootstrap ({B} tekrar, seed {bcfg['seed']}, percentile %95 GA) — 2026-09-16", "",
         f"Popülasyon: {len(rows)} test sorgusu / {n} CVE (eğitimde görülmemiş). Aynı CVE çekilişleri bütün yöntemler ve farklar için ortak. Tanımsız metrikler ({mcfg['undefined_policy']}).", "",
         "## Yöntem başına %95 güven aralıkları (test)", "| Yöntem | " + " | ".join(metrics) + " |", "|---|" + "---|" * len(metrics)]
    for m in methods:
        L.append(f"| {names[m]} | " + " | ".join(f"{results[m][k]['estimate']} [{results[m][k]['ci95'][0]}, {results[m][k]['ci95'][1]}]" for k in metrics) + " |")
    L += ["", f"## Eşleştirilmiş farklar: {names[ref]} − diğer (test; birincil aile Holm ile düzeltildi: {ccfg['primary_family']})",
          "| Karşılaştırma | Metrik | Aile | Fark | %95 GA | P(fark>0) | p (iki taraflı) | Holm p | Ret? | Kazanan / kaybeden / eşit |", "|---|---|---|---|---|---|---|---|---|---|"]
    for other, per_k in comparisons.items():
        for k, c in per_k.items():
            h = c.get("holm", {})
            L.append(f"| vs {names[other]} | {k} | {c['family']} | {c['mean_diff_ref_minus_other']} | [{c['ci95'][0]}, {c['ci95'][1]}] | {c['p_diff_gt_0']} | {c['p_two_sided_bootstrap']} | "
                     f"{h.get('p_holm', '–')} | {h.get('reject_at_alpha', '–')} | {c['wins_ref']} / {c['losses_ref']} / {c['ties']} |")
    L += ["", "## Kapasite analizi (Rule-Corpus'a göre korunmuş aday ≥10 / <10)"]
    for scope, groups in cap.items():
        for g, e in groups.items():
            L.append(f"- **{scope} / {g}** (n={e['queries']}, CVE {e['cves']}): " + "; ".join(f"{names[m]} MRR {v['mrr@10']} Stale {v['stale@10']} joint {v['current_at1_and_no_stale@10']} Supp {v['outdated_suppression@10']}" for m, v in e["methods"].items()))
    (OUT / "bootstrap_report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(json.dumps({"seconds": manifest["seconds"], "results_primary": {m: {k: results[m][k] for k in mcfg["primary"]} for m in methods},
                      "primary_comparisons": {o: {k: {kk: comparisons[o][k][kk] for kk in ("mean_diff_ref_minus_other", "ci95", "p_two_sided_bootstrap", "wins_ref", "losses_ref", "ties")} | {"holm": comparisons[o][k].get("holm")} for k in mcfg["primary"]} for o in ccfg["against"]}}, indent=1, default=str))
    return 0

if __name__ == "__main__":
    sys.exit(main())
