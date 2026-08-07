"""Test the Better Half re-gating audit."""

from __future__ import annotations

from solver.better_half_regate_audit import run


def test_half_only_audits_produce_no_better_half_match() -> None:
    """Re-gating the four Half-only audits against both targets yields no match."""
    result = run()
    assert result["status"] == "NO_MATCH_IN_REGATED_FAMILY"
    assert result["summary"]["better_half_matches"] == 0
    assert result["summary"]["half_matches"] == 0
    assert result["summary"]["audits_regated"] == 4
    assert result["controls"]["negative_control_scalar_1_rejected"] is True
    assert result["controls"]["targets_self_check_passed"] is True
    # Each audit must have been gated with its original scalar count
    names = {a["name"] for a in result["per_audit"]}
    assert names == {
        "solver.prime_reinsertion_audit",
        "solver.frontier_experiment",
        "solver.trail1_splice_experiment",
        "solver.trail1_permutation_experiment",
    }
