"""Reproduce and gate the community ``YOUWON`` / index-21 alignment.

Background.  Subtracting the Phase 3.2 VIC plaintext from the 91-character
SalPhaseIon ``dbbi`` stream, letter by letter modulo 26, yields a string that
contains ``YOUWON`` starting at zero-based index 21.  The finding is old --
``RB`` reported it in 2022 and ``Sycorax`` rediscovered it in April 2024 -- but
it lived in the Telegram transcript only.  On 2026-07-13 ``Vasilis Dragon``
published a fully specified transcript with SHA-256 checkpoints for every
intermediate, which is what makes it auditable.

This module does four things:

1. Re-derives every intermediate from repository artifacts, not from pasted
   literals, and records whether the five published checkpoints reproduce.
2. Records the structural facts: the index, the 21/49/21 split, and the two
   "rails" that also select index 21.
3. Measures how surprising the alignment actually is, because two of the three
   signals are not independent of each other.
4. Pushes a bounded, code-preregistered candidate family through
   :mod:`solver.targets`, with a planted positive control on the same path.

Run ``python -m solver.youwon_index21_audit``.
"""

from __future__ import annotations

import hashlib
import json
import random
import re

from . import targets
from .extract import ROOT
from .salphaseion_raw import extract_raw, sha256_hex
from .secp256k1_verify import N


RESULT_PATH = ROOT / "youwon_index21_audit.json"
PHASE32_PATH = ROOT / "phase32_classical.json"

# The five checkpoints published on 2026-07-13.  They are recorded as reported
# values and compared, never trusted.
REPORTED = {
    "s91": "71fe46259e270c113529dfaded4b59c59a9dffd826a7202ab07fc498b6a2c5ca",
    "m91": "2fbfbef7442558f17ecc866a0b89ed491c41abc042df4d41452835adff09e9d3",
    "difference": "f17857308a886531637b33c9ddb92952206c286519412278ba9f836ffc69336e",
    "borrow_rail": "ccf4c906024ce25a4cad66f2a78deecc216a39a791d5c1402f30374ee749ac0e",
    "vic_rail": "2d3b44885d39ccc2471ef0e67bab18ce8f087d816ea4cbb07cf21be77d5baee3",
}

# Steps 3 and 4 of the same post continue past the alignment: a self-keyed bifid
# of S570 is said to yield ``BTCSEED||P1||z``, whose digraph rail reverses to
# ``KMODEST``; the DEL from step 2 then removes the ``K``, whose bifid-square
# coordinates (2,5) read as ``BE`` under A1Z26, giving ``YOU WON - BE MODEST``.
#
# This module does *not* re-derive those two steps.  Step 4 is disclaimed by its
# own author ("im reading those coords because i already know what the answer
# should be, so call it a convention not a forced step"), and step 3 needs a
# bifid convention that the post does not pin down.  What is checked here is
# that the reported terminal strings hash to the reported values, and that the
# terminal strings themselves fail the prize gates.
REPORTED_TERMINAL = {
    "kmodest": "7782502c6a6ad8b6b33f3d517b0ee217a15fef516e4e4d0f2f921ffa66c33974",
    "YOUWONBEMODEST": "e8f325105e899ed8505fc60dcf2d8c24cda35e0ff4a998688b9924b4d1161ecd",
}

# Top row of the Phase 3.2 straddling checkerboard.  Those eight letters take a
# one-digit codeword; every other letter takes two.  This is the only input to
# the VIC rail, so that rail is a function of the VIC plaintext alone.
VIC_TOP_ROW = "FUBCDORA"

CONTROL_SCALAR = 0x00000000000000000000000000000000000000000000000000000000000C0DE5

MONTE_CARLO_TRIALS = 20000
MONTE_CARLO_SEED = 20260805


def _difference(left: str, right: str) -> str:
    return "".join(chr((ord(a) - ord(b)) % 26 + ord("A")) for a, b in zip(left, right))


def _borrow_rail(left: str, right: str) -> str:
    """One bit per position: did the subtraction underflow?"""
    return "".join("1" if ord(a) < ord(b) else "0" for a, b in zip(left, right))


def _vic_rail(text: str) -> str:
    """One bit per position: does this letter need a two-digit VIC codeword?"""
    return "".join("0" if character in VIC_TOP_ROW else "1" for character in text)


def _runs(bits: str) -> list[list[int]]:
    """``[start, length]`` for every maximal run of ones, longest first.

    Lists rather than tuples so the in-memory result and the JSON round trip
    compare equal.
    """
    found = [[match.start(), len(match.group())] for match in re.finditer("1+", bits)]
    return sorted(found, key=lambda item: (-item[1], item[0]))


def _sources() -> tuple[str, str]:
    s91 = extract_raw().s91.upper()
    phase32 = json.loads(PHASE32_PATH.read_text(encoding="utf-8"))
    m91 = phase32["vic"]["plaintext"].upper()
    if len(s91) != 91 or len(m91) != 91:
        raise ValueError("both operands must be exactly 91 characters")
    if not s91.isalpha() or not m91.isalpha():
        raise ValueError("both operands must be pure letters")
    return s91, m91


def _candidate_words(state: dict[str, str]) -> dict[str, bytes]:
    """The bounded 32-byte family this audit falsifies.

    Every member is a SHA-256 of a string that the alignment itself produces,
    under three letter cases, plus the two byte-level rewrites the surrounding
    material suggests: the DEL mask (the borrow rail reads 127) and a byte
    reversal (several stages in this puzzle are little-endian).
    """
    words: dict[str, bytes] = {}
    for label, text in state.items():
        for case_name, cased in (
            ("upper", text.upper()),
            ("lower", text.lower()),
            ("asis", text),
        ):
            digest = hashlib.sha256(cased.encode("ascii")).digest()
            for variant, value in (
                ("sha256", digest),
                ("sha256^0x7f", bytes(byte ^ 0x7F for byte in digest)),
                ("sha256-reversed", digest[::-1]),
            ):
                words[f"{label}/{case_name}/{variant}"] = value
    return words


def _integer_candidates(difference: str, borrow: str, vic: str) -> dict[str, int]:
    base26 = 0
    for character in difference:
        base26 = base26 * 26 + (ord(character) - ord("A"))
    return {
        "difference-base26": base26,
        "difference-base26^127": base26 ^ 127,
        "borrow-rail-bits": int(borrow, 2),
        "vic-rail-bits": int(vic, 2),
        "rails-xor": int(borrow, 2) ^ int(vic, 2),
    }


def _monte_carlo(s91: str, m91: str) -> dict[str, object]:
    """How often do the two rails agree by chance?

    The borrow rail is *not* independent of the difference string: with
    ``a = (s - m) mod 26`` the subtraction underflows exactly when
    ``m + a >= 26``, so a run of high-alphabet difference letters forces a run
    of borrows.  ``YOUWON`` is such a run.  Only the VIC rail is independent --
    it never looks at ``s91`` at all -- so the coincidence worth measuring is
    the VIC rail's longest run landing on the same index as the borrow rail's.
    """
    generator = random.Random(MONTE_CARLO_SEED)
    letters = list(m91)
    agreements = 0
    for _ in range(MONTE_CARLO_TRIALS):
        generator.shuffle(letters)
        shuffled = "".join(letters)
        borrow_runs = _runs(_borrow_rail(s91, shuffled))
        vic_runs = _runs(_vic_rail(shuffled))
        if borrow_runs and vic_runs and borrow_runs[0][0] == vic_runs[0][0]:
            agreements += 1
    return {
        "trials": MONTE_CARLO_TRIALS,
        "seed": MONTE_CARLO_SEED,
        "null_model": "uniform random permutations of the VIC plaintext letters",
        "statistic": "longest run of the borrow rail and of the VIC rail start at the same index",
        "agreements": agreements,
        "rate": agreements / MONTE_CARLO_TRIALS,
    }


def _forced_borrows(difference: str, m91: str, start: int, length: int) -> bool:
    """True when the observed borrow bits over a span are algebraically forced."""
    for offset in range(start, start + length):
        value = ord(m91[offset]) - ord("A") + ord(difference[offset]) - ord("A")
        if value < 26:
            return False
    return True


def run() -> dict[str, object]:
    s91, m91 = _sources()
    difference = _difference(s91, m91)
    borrow = _borrow_rail(s91, m91)
    vic = _vic_rail(m91)

    computed = {
        "s91": sha256_hex(s91.lower().encode("ascii")),
        "m91": sha256_hex(m91.lower().encode("ascii")),
        "difference": sha256_hex(difference.encode("ascii")),
        "borrow_rail": sha256_hex(borrow.encode("ascii")),
        "vic_rail": sha256_hex(vic.encode("ascii")),
    }
    reproduced = {name: computed[name] == value for name, value in REPORTED.items()}
    terminal_reproduced = {
        text: sha256_hex(text.encode("ascii")) == digest
        for text, digest in REPORTED_TERMINAL.items()
    }

    index = difference.find("YOUWON")
    if index < 0:
        raise AssertionError("YOUWON is absent from the difference; the operands are wrong")
    borrow_runs = _runs(borrow)
    vic_runs = _runs(vic)
    long_borrow_runs = [run_ for run_ in borrow_runs if run_[1] >= 7]

    # The reported split is symmetric: YOUWON starts at 21 and the mirrored cut
    # at 91 - 21 = 70 leaves 21 / 49 / 21.
    tail = len(difference) - index
    structure = {
        "youwon_index_zero_based": index,
        "split": [index, tail - index, index] if index >= 0 else None,
        "difference": difference,
        "borrow_rail": borrow,
        "vic_rail": vic,
        "borrow_runs_at_least_7": long_borrow_runs,
        "borrow_span_value": int(borrow[index : index + 7], 2) if index >= 0 else None,
        "vic_longest_run": vic_runs[0] if vic_runs else None,
        "middle_block": difference[index:tail] if index >= 0 else None,
    }

    interpretation = {
        "borrow_span_is_del": structure["borrow_span_value"] == 127,
        "borrow_run_is_forced_by_youwon": _forced_borrows(difference, m91, index, 6)
        if index >= 0
        else None,
        "vic_rail_ignores_s91": True,
        "note": (
            "Two of the three signals are dependent. The borrow rail underflows exactly "
            "when m + a >= 26, so the high-alphabet letters of YOUWON force borrows at "
            "those positions; the seventh bit is the only free one. The VIC rail is the "
            "single independent selector, because it is a function of the VIC plaintext "
            "alone."
        ),
    }

    state = {
        "difference": difference,
        "difference-head": difference[:index],
        "difference-youwon": "YOUWON",
        "difference-middle": structure["middle_block"] or "",
        "difference-middle-after-youwon": difference[index + 6 : tail],
        "difference-tail": difference[tail:],
        "difference-from-youwon": difference[index:],
        "rows-MMJIOLS": "MMJIOLS",
        "cols-JPJSROH": "JPJSROH",
        "rows-cols": "MMJIOLSJPJSROH",
        "borrow-rail": borrow,
        "vic-rail": vic,
        "s91": s91,
        "m91": m91,
        "s91||m91": s91 + m91,
        "m91||s91": m91 + s91,
        "difference||127": difference + "127",
        "127||difference": "127" + difference,
        "difference||DEL": difference + "DEL",
        # Reported terminal of steps 3 and 4, gated but not re-derived.
        "terminal-KMODEST": "KMODEST",
        "terminal-MODEST": "MODEST",
        "terminal-BEMODEST": "BEMODEST",
        "terminal-YOUWONBEMODEST": "YOUWONBEMODEST",
        "terminal-YOUWONBEMODEST-spaced": "YOU WON BE MODEST",
        "terminal-YOUWON||middle": "YOUWON" + (structure["middle_block"] or "")[6:],
    }

    words = _candidate_words(state)
    integers = _integer_candidates(difference, borrow, vic)

    matches: list[dict[str, object]] = []
    seen: set[int] = set()
    for label, value in words.items():
        scalar = int.from_bytes(value, "big") % N
        if not scalar or scalar in seen:
            continue
        seen.add(scalar)
        hit = targets.gate_scalar(scalar)
        if hit is not None:
            matches.append({"candidate": label, "gate": hit})
    for label, value in integers.items():
        scalar = value % N
        if not scalar or scalar in seen:
            continue
        seen.add(scalar)
        hit = targets.gate_scalar(scalar)
        if hit is not None:
            matches.append({"candidate": label, "gate": hit})

    # Positive control: the production gate must accept a planted target and
    # must still reject that same scalar against the real targets.
    control_x, control_y = targets._public_point(CONTROL_SCALAR)
    control = {
        "scalar": f"{CONTROL_SCALAR:064x}",
        "accepted_against_planted_target": targets.gate_point(
            control_x,
            control_y,
            half_public=targets.serializations(control_x, control_y)["uncompressed"],
        )
        is not None,
        "rejected_against_real_targets": targets.gate_scalar(CONTROL_SCALAR) is None,
    }
    if not control["accepted_against_planted_target"] or not control["rejected_against_real_targets"]:
        raise AssertionError("positive control failed; the gate is not exercising the target path")

    result: dict[str, object] = {
        "schema": "youwon-index21-audit-v1",
        "status": "MATCH" if matches else "NO_PRIZE_MATCH",
        "provenance": {
            "s91": "solver.salphaseion_raw.extract_raw().s91",
            "m91": "phase32_classical.json /vic/plaintext",
            "vic_top_row": VIC_TOP_ROW,
            "reported_by": "Vasilis Dragon, project Telegram, 2026-07-13; first sighting RB 2022, Sycorax 2024-04",
        },
        "checkpoints": {"reported": REPORTED, "computed": computed, "reproduced": reproduced},
        "reported_terminal": {
            "steps": "3 and 4 of the same post, gated here but not re-derived",
            "hashes_match_reported_strings": terminal_reproduced,
            "author_disclaimer": "step 4 is 'a convention not a forced step'",
        },
        "structure": structure,
        "interpretation": interpretation,
        "significance": _monte_carlo(s91, m91),
        "candidate_family": {
            "string_sources": sorted(state),
            "cases": ["upper", "lower", "asis"],
            "byte_variants": ["sha256", "sha256^0x7f", "sha256-reversed"],
            "integer_readings": sorted(integers),
            "unique_scalars": len(seen),
        },
        "control": control,
        "matches": matches,
        "scope_note": (
            "This falsifies only the bounded family listed above. It does not falsify the "
            "alignment itself, which remains an unexplained structural observation, and it "
            "cannot reach any construction that needs an operand this audit never builds."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":  # pragma: no cover
    print(json.dumps(run(), indent=2))
