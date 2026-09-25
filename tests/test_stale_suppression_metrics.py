from __future__ import annotations

import pytest

from src.eval import metrics as M

def _c(rank, cls, eid=None):
    return {"rank": rank, "evidence_id": eid or f"e{rank}", "class": cls, "score": 0.0}

def _pool(classes):
    return [_c(i, c) for i, c in enumerate(classes, start=1)]

@pytest.mark.unit
def test_outdated_count_and_first_rank():
    base = _pool(["TARGET_OUTDATED", "TARGET_CURRENT", "OTHER", "TARGET_OUTDATED"] + ["OTHER"] * 46)
    assert M.outdated_count_at_k(base, 10) == 2 and M.first_outdated_rank(base) == 1
    moved = base[1:2] + base[2:3] + base[4:] + base[0:1] + base[3:4]
    assert M.outdated_count_at_k(moved, 10) == 0 and M.first_outdated_rank(moved) == 49
    assert M.first_outdated_rank(_pool(["OTHER"] * 50)) == 51
    assert M.first_outdated_rank(_pool(["TARGET_CURRENT", "TARGET_OUTDATED"]), pool_size=2) == 2

@pytest.mark.unit
def test_suppression_and_preservation():
    base = _pool(["TARGET_OUTDATED", "TARGET_CURRENT", "TARGET_OUTDATED"] + ["OTHER"] * 47)
    same = list(base)
    assert M.outdated_suppression_at_k(same, base) == 0.0 and M.current_preservation_at_k(same, base) == 1.0
    half = [base[1], base[0]] + base[3:] + [base[2]]
    assert M.outdated_suppression_at_k(half, base) == pytest.approx(0.5)
    lost = base[3:] + [base[1], base[0], base[2]]
    assert M.outdated_suppression_at_k(lost, base) == 1.0 and M.current_preservation_at_k(lost, base) == 0.0
    no_out = _pool(["TARGET_CURRENT"] + ["OTHER"] * 49)
    assert M.outdated_suppression_at_k(no_out, no_out) is None
    no_cur = _pool(["TARGET_OUTDATED"] + ["OTHER"] * 9 + ["TARGET_CURRENT"] + ["OTHER"] * 39)
    assert M.current_preservation_at_k(no_cur, no_cur) is None
    assert M.outdated_count_at_k(_pool(["OTHER_SOURCE_CURRENT"] * 10), 10) == 0

@pytest.mark.unit
def test_joint_success_and_summary():
    base = _pool(["TARGET_OUTDATED", "TARGET_CURRENT"] + ["OTHER"] * 48)
    assert not M.current_at_1_and_no_stale_at_k(base)
    cur_first = [base[1], base[0]] + base[2:]
    assert not M.current_at_1_and_no_stale_at_k(cur_first)
    clean = [base[1]] + base[2:] + [base[0]]
    assert M.current_at_1_and_no_stale_at_k(clean)
    rows = [M.stale_suppression(x, base) for x in (base, cur_first, clean)]
    s = M.summarize_stale_suppression(rows)
    assert s["queries"] == 3 and s["current_at1_and_no_stale@10"] == pytest.approx(1 / 3, abs=1e-4)
    assert s["outdated_suppression@10"] == pytest.approx(1 / 3, abs=1e-4) and s["current_preservation@10"] == 1.0
    assert s["first_outdated_beyond_top10_rate"] == pytest.approx(1 / 3, abs=1e-4) and s["outdated_count@10_mean"] == pytest.approx(2 / 3, abs=1e-4)
