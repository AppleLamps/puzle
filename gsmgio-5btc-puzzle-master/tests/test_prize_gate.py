"""Test the shared cross-repository prize gate."""

from __future__ import annotations

from solver import prize_gate, targets


def test_shared_gate_uses_canonical_targets() -> None:
    """Inside this package the constants come from solver.targets, not a copy."""
    assert prize_gate.HALF_ADDRESS is targets.HALF_ADDRESS
    assert prize_gate.BETTER_ADDRESS is targets.BETTER_ADDRESS
    assert prize_gate.HALF_H160 == targets.HALF_H160
    assert prize_gate.BETTER_H160 == targets.BETTER_H160


def test_planted_controls_fire() -> None:
    """Every encoding, both target slots, both serializations."""
    assert prize_gate.selftest(verbose=False)


def test_non_targets_never_match() -> None:
    for record in targets.NON_TARGETS.values():
        assert prize_gate.gate_scalar(int(record["scalar"], 16)) is None
