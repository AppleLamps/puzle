"""Seal v72: chess/poster second door before chain1.

The creator confirmed the rabbit-nest second door is unfound (2026-03-03)
and may precede chain1 entirely.  v62 tested eye-index spiral bit edits;
second_door_frontier tested broad morphology families but not this bounded
chess + poster bundle as **pre-chain1** unlock material.

This manifest freezes authenticated chess phase-2 artefacts (FEN, ahimsa
move ``Rc6+``, chess-hint alphabet sentence), bunny-nest impure-cell bits,
eye-modified URL variants, and poster diagonal-half bit streams — gated as
passwords/scalars against chain1, env48, and raw48 under legibility.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "second_door_chess_poster_preregistered.json"
SEAL_PATH = ROOT / "second_door_chess_poster_preregistered.sha256"
RESULT_PATH = ROOT / "second_door_chess_poster_audit.json"

# Authenticated phase-2 part 7 (README / SOLUTION.md).
CHESS_FEN = "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
CHESS_MOVE = "Rc6+"

CHESS_MATERIALS = (
    "fen_literal",
    "fen_lower",
    "fen_no_spaces",
    "move_rc6_plus",
    "move_rc6",
    "fen_then_move",
    "chess_hint_letters_lower",
)

POSTER_MATERIALS = (
    "eye_flip_bit_163_url",
    "eye_swap_bits_163_173_url",
    "eye_force_bit_163_one_url",
    "eye_force_bit_163_zero_url",
    "eye_xor_bits_163_173_url",
    "bunny_impure7_bits_packed",
    "main_diagonal_lower_bits98",
    "anti_diagonal_lower_bits98",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
AES_TARGETS = ("chain1", "env48", "raw48_evp_iv", "raw48_continuation_iv")
SCALAR_DERIVATIONS = ("sha256", "double_sha256")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_materials() -> int:
    return len(CHESS_MATERIALS) + len(POSTER_MATERIALS)


def expected_aes_trials() -> int:
    return expected_materials() * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(AES_TARGETS)


def expected_scalar_gates() -> int:
    return expected_materials() * len(SCALAR_DERIVATIONS)


def build_manifest() -> dict[str, object]:
    return {
        "schema": "second-door-chess-poster-v72",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v72_second_door_chess_poster",
        "date": "2026-08-07",
        "hypothesis": (
            "The unfound poster/chess second door yields unlock material "
            "(FEN, ahimsa move, bunny nest, eye URL edit) that opens chain1 "
            "or the split envelopes before the community chain-1 password "
            "family applies."
        ),
        "chess_fen": CHESS_FEN,
        "chess_move": CHESS_MOVE,
        "chess_materials": list(CHESS_MATERIALS),
        "poster_materials": list(POSTER_MATERIALS),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "aes_targets": list(AES_TARGETS),
        "scalar_derivations": list(SCALAR_DERIVATIONS),
        "expected_counts": {
            "materials": expected_materials(),
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible plaintext under the v58/v51 gate; scalars via "
            "solver.targets.gate_scalar_bytes."
        ),
        "scope_note": (
            "Pre-chain1 chess/poster bundle only. Does not replay "
            "second_door_frontier_derivations.json broad families or "
            "v62 eye edits beyond the five frozen URL serializations."
        ),
        "control_scalar_hex": CONTROL_SCALAR_HEX,
        "targets": {
            "half_uncompressed_pubkey": HALF_PUBLIC_UNCOMPRESSED.hex(),
            "better_half_hash160": BETTER_H160.hex(),
        },
    }


def seal() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")


if __name__ == "__main__":
    seal()
    print(f"sealed {MANIFEST_PATH.name} ({expected_materials()} materials)")
