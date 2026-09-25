from __future__ import annotations

import json
import re

import pytest

from src import paths
from src.eval import metrics as M
from src.evidence import build_corpus as BC
from src.evidence.build_evidence import load_config as load_query_config
from src.label import query_time_labels as L
from src.retrieval import bm25_smoke as S

QCFG = load_query_config()
RCFG = BC.load_retrieval_config()
FORBIDDEN = re.compile("|".join(re.escape(w) for w in QCFG["evidence"]["forbidden_words_in_text"]), re.IGNORECASE)

def _row(**kw):
    base = dict(evidence_id="CVE-1|3.1|NVD|1", cve_id="CVE-1", source_key="NVD", cvss_version="3.1",
                base_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", observed_from="2024-03-01T00:00:00+00:00",
                source_file="data/raw/x.json", chain_ambiguous=False, evidence_text="As of 2024-03-01, NVD assessed CVE-1 ...",
                replaced_by_evidence_id=None, valid_until=None)
    base.update(kw)
    return base

@pytest.mark.unit
def test_corpus_eligibility_rules():
    rules = RCFG["corpus"]["eligibility"]
    assert BC.eligibility(_row(), rules, FORBIDDEN) is None
    assert BC.eligibility(_row(chain_ambiguous=True), rules, FORBIDDEN) == "AMBIGUOUS_CHAIN"
    assert BC.eligibility(_row(base_vector="AV:*/AC:*"), rules, FORBIDDEN) == "BASE_VECTOR_NOT_PARSEABLE"
    assert BC.eligibility(_row(base_vector=""), rules, FORBIDDEN) == "BASE_VECTOR_NOT_PARSEABLE"
    assert BC.eligibility(_row(evidence_text="This superseded assessment ..."), rules, FORBIDDEN) == "TEXT_CONTAINS_LABEL_WORD"
    assert BC.eligibility(_row(replaced_by_evidence_id="CVE-1|3.1|NVD|2", evidence_text="see CVE-1|3.1|NVD|2"), rules, FORBIDDEN) == "TEXT_CONTAINS_FUTURE_INFO"
    assert BC.eligibility(_row(source_file=None), rules, FORBIDDEN) == "MISSING_PROVENANCE"

    assert BC.eligibility(_row(valid_until="2024-03-01T10:00:00+00:00"), rules, FORBIDDEN) is None

@pytest.mark.unit
def test_tokenizer_keeps_ids_metrics_and_versions():
    toks = S.tokenize("As of 2024-03-01, NVD assessed CVE-2024-1234 under CVSS 3.1 with Base metric vector AV:N/AC:L, a CVSS-B score of 9.8")
    assert "cve-2024-1234" in toks and "3.1" in toks and "av:n" in toks and "ac:l" in toks and "9.8" in toks and "cvss-b" in toks
    assert S.tokenize("cna@vuldb.com") == ["cna@vuldb.com"]
    assert S.query_tokens({"cve_id": "CVE-1", "source_key": "NVD", "cvss_version": "4.0", "query_text": "What?"})[:3] == ["cve-1", "nvd", "4.0"]

@pytest.mark.unit
def test_metrics():
    assert M.ndcg_at_k([1, 0, 0], [1], 10) == 1.0
    assert 0 < M.ndcg_at_k([0, 1, 0], [1], 10) < 1.0
    assert M.mrr_at_k([0, 0, 1], 10) == pytest.approx(1 / 3) and M.mrr_at_k([0] * 10 + [1], 10) == 0.0
    assert M.recall_at_k(["a"], ["a"], 10) == 1.0 and M.recall_at_k([], ["a"], 10) == 0.0
    assert M.stale_rate_at_k([L.OUTDATED, L.CURRENT, L.NOT_TARGET_CHAIN] + [L.NOT_TARGET_CHAIN] * 7, 10) == 0.1
    assert M.stale_rate_at_k([L.NOT_TARGET_CHAIN] * 10, 10) == 0.0

@pytest.mark.unit
def test_candidate_classes_and_oracle_order():
    q = L.Query(cve_id="CVE-1", source_key="NVD", cvss_version="3.1", query_time="2024-06-01T00:00:00+00:00")
    cur = dict(evidence_id="a", cve_id="CVE-1", source_key="NVD", cvss_version="3.1", observed_from="2024-05-01T00:00:00+00:00",
               valid_until=None, replacement_type=None, chain_ambiguous=False, valid_from_censored=False)
    old = dict(cur, evidence_id="b", observed_from="2024-01-01T00:00:00+00:00", valid_until="2024-05-01T00:00:00+00:00", replacement_type="STRICT_SAME_CHANGE")
    other = dict(cur, evidence_id="c", source_key="cna@x")
    far = dict(cur, evidence_id="d", cve_id="CVE-2")
    classes = [S.classify_candidate(d, q)[2] for d in (far, old, other, cur)]
    assert classes == ["OTHER", "TARGET_OUTDATED", "OTHER_SOURCE_CURRENT", "TARGET_CURRENT"]
    ranked = [{"rank": i + 1, "evidence_id": d["evidence_id"], "score": 0, "label": S.classify_candidate(d, q)[0],
               "relation": S.classify_candidate(d, q)[1], "class": S.classify_candidate(d, q)[2]} for i, d in enumerate((far, old, other, cur))]
    cf = S.oracle_rerank(ranked, "current_first")
    tmp = S.oracle_rerank(ranked, "temporal")
    assert [c["evidence_id"] for c in cf] == ["a", "c", "b", "d"]
    assert [c["evidence_id"] for c in tmp] == ["a", "c", "d", "b"]
    qrow = {"current_evidence_ids": ["a"], "other_source_current_evidence_ids": ["c"]}
    assert S.evaluate(cf, qrow)["mrr@10"] == 1.0 and S.evaluate(ranked, qrow)["mrr@10"] == 0.25
    assert S.evaluate(ranked, qrow)["stale@10"] == 0.1 and S.evaluate(cf, qrow)["stale@10"] == 0.1 and S.evaluate(tmp, qrow)["stale@10"] == 0.1

    ranked11 = ranked + [dict(ranked[0], rank=5 + i, evidence_id=f"x{i}") for i in range(7)]
    assert S.evaluate(S.oracle_rerank(ranked11, "temporal"), qrow)["stale@10"] == 0.0
    assert S.evaluate(S.oracle_rerank(ranked11, "current_first"), qrow)["stale@10"] == 0.1

@pytest.mark.full_data
def test_full_corpus_profile_and_smoke_artifacts():
    prof_path = paths.DATA_PROFILE_DIR / "corpus_profile.json"
    rep_path = paths.PROJECT_ROOT / RCFG["smoke_test"]["output_dir"] / "smoke_report.json"
    if not prof_path.exists() or not rep_path.exists():
        pytest.skip("Corpus/smoke çıktıları yok")
    prof = json.loads(prof_path.read_text(encoding="utf-8"))
    assert prof["potential_intervals"] == 265_965 and prof["accepted"] + prof["excluded"] == prof["potential_intervals"]
    assert prof["overlapping_intervals_same_chain"] == 0

    assert prof["duplicate_evidence_text"] < 100
    assert prof["coverage_vs_main_evidence"]["main_in_full_corpus"] >= 9_000
    rep = json.loads(rep_path.read_text(encoding="utf-8"))
    assert rep["queries_total"] == 300 and rep["corpus_docs"] == prof["accepted"]
    sampled = json.loads((rep_path.parent / "sampled_queries.json").read_text(encoding="utf-8"))
    assert all(len(v) == 100 for v in sampled.values()) and "future_event" not in sampled

    for split in ("train", "dev", "test"):
        for line in (rep_path.parent / f"{split}_top50.jsonl").open(encoding="utf-8"):
            row = json.loads(line)
            assert len(row["candidates"]) <= 50
            assert all(c["class"] in S.ORACLES["current_first"] for c in row["candidates"])
    for m in ("ndcg@10", "mrr@10"):
        assert rep["oracle_current_first"]["all"][m] >= rep["bm25"]["all"][m]
    assert rep["oracle_temporal"]["all"]["stale@10"] <= rep["bm25"]["all"]["stale@10"]

@pytest.mark.unit
def test_tie_break_is_deterministic_and_time_blind():
    from src.retrieval.bm25_runner import tie_key
    a = tie_key(1, "q1", "CVE-1|3.1|NVD|1"); b = tie_key(1, "q1", "CVE-1|3.1|NVD|2")
    assert a == tie_key(1, "q1", "CVE-1|3.1|NVD|1") and a != b and len(a) == 64

    firsts = sum(1 for i in range(200) if tie_key(7, f"q{i}", f"CVE-{i}|3.1|NVD|1") < tie_key(7, f"q{i}", f"CVE-{i}|3.1|NVD|2"))
    assert 60 < firsts < 140
