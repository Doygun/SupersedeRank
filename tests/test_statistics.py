from __future__ import annotations

import json
import re

import numpy as np
import pytest
import yaml

from src import paths
from src.analysis import cluster_bootstrap as CB

CFG = yaml.safe_load((paths.PROJECT_ROOT / "config" / "statistics.yaml").read_text(encoding="utf-8"))
SA = paths.PROJECT_ROOT / "results" / "experiments" / "statistical_analysis"
TAB = paths.PROJECT_ROOT / "results" / "paper_tables"

def _rows():

    return [{"query_id": "q1", "cve_id": "CVE-A", "split": "test", "m0": {"x": 0.0, "u": None}, "m1": {"x": 1.0, "u": 1.0}},
            {"query_id": "q2", "cve_id": "CVE-A", "split": "test", "m0": {"x": 0.0, "u": 0.0}, "m1": {"x": 1.0, "u": None}},
            {"query_id": "q3", "cve_id": "CVE-B", "split": "test", "m0": {"x": 1.0, "u": 1.0}, "m1": {"x": 1.0, "u": 1.0}},
            {"query_id": "q4", "cve_id": "CVE-C", "split": "test", "m0": {"x": 0.5, "u": 0.0}, "m1": {"x": 0.5, "u": 0.0}}]

@pytest.mark.unit
def test_bootstrap_unit_is_cve_and_queries_travel_together():
    clusters, arrays = CB.cluster_arrays(_rows(), ["m0", "m1"], ["x", "u"], "cve_id")
    assert clusters == ["CVE-A", "CVE-B", "CVE-C"]
    s, n = arrays["m1"]["x"]; assert n.tolist() == [2.0, 1.0, 1.0] and s.tolist() == [2.0, 1.0, 0.5]
    su, nu = arrays["m1"]["u"]; assert nu.tolist() == [1.0, 1.0, 1.0]
    draws = np.array([[0, 0, 0], [1, 2, 2]])
    means = CB.bootstrap_means(arrays, draws)
    assert means["m1"]["x"].tolist() == [1.0, pytest.approx(2.0 / 3)] and means["m0"]["x"].tolist() == [0.0, pytest.approx(2.0 / 3)]
    assert CB.point_estimate(arrays, "m1", "x") == pytest.approx(3.5 / 4)

@pytest.mark.unit
def test_same_seed_same_draws_and_shared_replicates():
    a = np.random.default_rng(int(CFG["bootstrap"]["seed"])).integers(0, 1356, size=(50, 1356))
    b = np.random.default_rng(int(CFG["bootstrap"]["seed"])).integers(0, 1356, size=(50, 1356))
    assert np.array_equal(a, b) and CFG["bootstrap"]["shared_replicates"] is True and CFG["bootstrap"]["replicates"] >= 10000

@pytest.mark.unit
def test_holm_and_config_scope():
    h = CB.holm({"a": 0.001, "b": 0.02, "c": 0.04}, 0.05)
    assert h["a"]["p_holm"] == pytest.approx(0.003) and h["b"]["p_holm"] == pytest.approx(0.04) and h["c"]["p_holm"] == pytest.approx(0.04)
    assert h["a"]["reject_at_alpha"] and h["b"]["reject_at_alpha"] and h["c"]["reject_at_alpha"]
    assert CFG["population"]["split"] == "test" and set(CFG["population"]["exclude_splits"]) == {"train", "dev", "future_event"}
    assert CFG["methods"]["main"] == ["bm25", "bm25_recency", "cross_encoder", "rule_target"] and CFG["methods"]["scope_analysis"] == ["rule_corpus"]
    assert set(CFG["methods"]["upper_bounds"]) == {"rule_direct_upper_bound", "oracle_temporal"}
    assert all("learned" in m for m in CFG["methods"]["diagnostic_only"]) and "hybrid" not in json.dumps(CFG["methods"]).lower()
    assert CFG["comparisons"]["reference"] == "rule_target"

@pytest.mark.full_data
def test_bootstrap_artifacts_and_tables():
    if not (SA / "bootstrap_results.json").exists():
        pytest.skip("istatistik çıktısı yok")
    man = json.loads((SA / "bootstrap_manifest.json").read_text(encoding="utf-8"))
    res = json.loads((SA / "bootstrap_results.json").read_text(encoding="utf-8"))
    pc = json.loads((SA / "paired_comparisons.json").read_text(encoding="utf-8"))
    assert man["population"]["split"] == "test" and man["population"]["queries"] == 1506 and man["population"]["clusters_cve"] == 1356
    assert man["bootstrap"]["unit"] == "cve_id" and man["bootstrap"]["replicates"] == 10000 and man["bootstrap"]["shared_replicates"]
    for m, r in res["results"].items():
        assert "learned" not in m and "hybrid" not in m
        for k, v in r.items():
            lo, hi = v["ci95"]; assert lo <= hi and 0.0 <= lo <= 1.0 and 0.0 <= hi <= 1.0 and 0.0 <= v["estimate"] <= 1.0
            assert lo - 1e-9 <= v["estimate"] <= hi + 1e-9
    assert pc["reference"] == "rule_target" and set(pc["comparisons"]) == {"bm25", "bm25_recency", "cross_encoder", "rule_corpus"}
    assert len(pc["holm_primary_family"]) == 12

    per = json.loads((paths.PROJECT_ROOT / CFG["population"]["source"]).read_text(encoding="utf-8"))
    assert sum(1 for p in per if p["split"] == "future_event") == 19 and sum(1 for p in per if p["split"] == "test") == 1506

    draws = np.random.default_rng(int(CFG["bootstrap"]["seed"])).integers(0, 1356, size=(10000, 1356))
    import hashlib
    assert hashlib.sha256(draws.tobytes()).hexdigest() == man["bootstrap"]["draws_sha256"]

    main_tex = (TAB / "main_results.tex").read_text(encoding="utf-8"); test_tex = (TAB / "test_results.tex").read_text(encoding="utf-8")
    for tex in (main_tex, test_tex):
        assert "Learned" not in tex and "Hybrid" not in tex and "dagger" not in tex and "Policy (upper bound)" not in tex
        assert "Direct-Link Policy (diagnostic)" in tex and "Diagnostic policy" in tex and "Oracle upper bound" in tex and "Temporal-clean oracle (oracle upper bound)" in tex
    est = res["results"]["rule_target"]["current_at1_and_no_stale@10"]
    assert f"{est['estimate']:.3f}" + r"\\{\scriptsize[" + f"{est['ci95'][0]:.3f}, {est['ci95'][1]:.3f}]" + "}" in test_tex
    rt = json.loads((paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_rule_target" / "rule_target_report.json").read_text(encoding="utf-8"))
    row = next(l for l in main_tex.splitlines() if "ChronoRank-Rule-Target" in l)
    assert f"{rt['main']['rule_target']['all']['mrr@10']:.3f}" in row and f"{rt['main']['rule_target']['stale_suppression']['current_at1_and_no_stale@10']:.3f}" in row
    fig = json.loads((TAB / "figure_results_data.json").read_text(encoding="utf-8"))
    assert {p["method"] for p in fig["points"]} == {"bm25", "recency_only", "bm25_recency", "cross_encoder", "rule_corpus", "rule_target"}
    assert all(0.0 <= p["current_preservation@10"] <= 1.0 and 0.0 <= p["one_minus_stale@10"] <= 1.0 for p in fig["points"])
    learned = (TAB / "learned_diagnostic.tex").read_text(encoding="utf-8")
    assert "Diagnostic results of the learned model." in learned and "ChronoRank-Rule-Corpus &" in learned
