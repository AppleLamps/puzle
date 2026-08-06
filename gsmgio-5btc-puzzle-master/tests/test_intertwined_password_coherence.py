"""v50: the "seven intertwined passwords" family stays a bounded negative.

The Architect plaintext demands "seven intertwined passwords"; the only
authenticated password in the puzzle is a sha256 hex digest.  These tests pin a
bounded slice of that family so the negative -- and its chance-level padding
rate -- cannot silently drift into a claimed break.
"""

from __future__ import annotations

from solver.intertwined_password_coherence_audit import (
    _braid,
    _is_legible,
    _zip_shortest,
    run,
)


def test_intertwine_helpers_are_round_robin() -> None:
    assert _braid(("abc", "de")) == "adbec"
    assert _zip_shortest(("abc", "de")) == "adbe"


def test_bounded_slice_finds_no_break_and_padding_is_chance() -> None:
    result = run(limit=400)
    assert result["status"] == "NO_LEGIBLE_BREAK_AND_NO_PRIZE_MATCH"
    totals = result["totals"]
    assert totals["legible_hits"] == 0
    assert totals["prize_gate_hits"] == 0
    # Any clean unpad in this slice is noise: rate must sit near the chance line.
    assert totals["padding_rate"] < 0.02, totals


def test_legibility_gate_matches_v49() -> None:
    assert _is_legible(b"take the private key you have earned it")
    assert not _is_legible(bytes(range(256)))
