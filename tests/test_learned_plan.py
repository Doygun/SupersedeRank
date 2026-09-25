from __future__ import annotations

import json

import pytest
import yaml

from src import paths
from src.analysis.learned_profile import is_temporal_example

CFG = yaml.safe_load((paths.PROJECT_ROOT / "config" / "learned.yaml").read_text(encoding="utf-8"))

@pytest.mark.unit
def test_only_target_chain_current_outdated_are_examples():
    assert is_temporal_example("TARGET_CURRENT") and is_temporal_example("TARGET_OUTDATED")
    for cls in ("OTHER", "OTHER_SOURCE_CURRENT", "OTHER_SOURCE_INACTIVE", "NOT_LABELABLE", "UNLABELED_CHAIN_CONTEXT"):
        assert not is_temporal_example(cls)

@pytest.mark.unit
def test_plan_constants_are_fixed_and_forbidden_fields_listed():
    assert CFG["model"]["family"] == "logistic_regression" and CFG["model"]["C_candidates"] == [0.1, 1.0, 10.0] and CFG["model"]["penalty"] == "l2"
    assert CFG["combination"]["alpha_candidates"] == [0.1, 0.3, 0.5, 1.0] and CFG["combination"]["primary"] == "block_ordering_by_p_current"
    assert CFG["examples"]["train_split"] == "train" and CFG["examples"]["selection_split"] == "dev" and CFG["examples"]["resampling"] == "none"
    forbidden = " ".join(CFG["features"]["forbidden"])
    for f in ("valid_until", "replaced_by_evidence_id", "superseded_by_evidence_id", "replacement_type", "timeline_status", "termination_event_id", "future-event"):
        assert f in forbidden
    allowed = CFG["features"]["semantic"] + CFG["features"]["temporal"] + CFG["features"]["structural"]
    assert not any(f in allowed for f in ("valid_until", "replaced_by_evidence_id", "superseded_by_evidence_id", "replacement_type", "timeline_status"))
    assert "newer_different_base_vector_exists" in CFG["features"]["temporal"] and CFG["model"]["conditions"] == ["learned_full", "learned_no_rule_signal"]

@pytest.mark.full_data
def test_train_label_profile_integrity():
    path = paths.PROJECT_ROOT / "results" / "experiments" / "chronorank_learned" / "train_label_profile.json"
    if not path.exists():
        pytest.skip("profil yok")
    p = json.loads(path.read_text(encoding="utf-8"))
    assert p["train"]["queries"] == 1719 and p["train"]["current_examples"] == 1719 and p["dev"]["queries"] == 312
    assert p["cve_level_disjointness"]["train_dev_cve_overlap"] == 0 and p["cve_level_disjointness"]["train_dev_evidence_overlap"] == 0
    assert "test" not in p and "future_event" not in p
    assert p["train"]["rule_signal_on_examples"]["TARGET_CURRENT|suppressed=False"] == 1719
