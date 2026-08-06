"""Pin the creator's own acceptance criterion against the post-3.2 chain.

2021-03-14: "Breaking salphation should be giving the feeling of the phase's
name."  Read plainly that is a legibility requirement, and it is the standard
the phase-3.2 break meets.  These tests pin the measurement so that the chain's
lack of authentication cannot quietly be forgotten again.
"""

from __future__ import annotations

from solver.salvation_coherence_audit import _is_legible, part_a


def test_phase32_break_is_legible_and_the_chain_is_not() -> None:
    audit = part_a()

    reference = audit["true_positive_reference"]
    assert reference["legible"]
    assert reference["opening_bytes"].startswith("I've been waiting for you.")

    for name, record in audit["chained_unlocks"].items():
        assert not record["legible"], f"{name} unexpectedly legible: {record}"
        assert record["entropy_bits_per_byte"] > 6.0, name


def test_chance_padding_rate_is_high_enough_to_explain_the_chain() -> None:
    """A rate near 0.4% makes padding hits worthless as evidence."""
    audit = part_a()
    for name, null in audit["null_padding_rates"].items():
        assert 0.001 < null["padding_rate"] < 0.02, (name, null)
        assert null["legible_hits"] == 0, (name, null)


def test_legibility_gate_accepts_english_and_rejects_random() -> None:
    assert _is_legible(b"I've been waiting for you. You have many questions.")
    assert not _is_legible(bytes(range(256)) * 2)
