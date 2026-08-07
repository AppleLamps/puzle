"""Seal v75: second-door poster operands composed with 479/484 anchors.

v72 gated poster/chess materials as **direct passwords**.  This manifest tests
**composition**: each second-door poster operand paired with a 479/484-class
anchor under four fixed rules (xor, add mod 256, sha256-concat, interleave).

Poster operands: eye URL edit, bunny nest, 91-cell triangle splits (the §12
observation), rot180 mask.  Anchor operands: 479, 484, yellow9 primes,
Architect ``[479:512]``.  Outputs gated as scalars and legibility-gated AES
passwords on chain1, env48, raw48.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "second_door_composition_preregistered.json"
SEAL_PATH = ROOT / "second_door_composition_preregistered.sha256"
RESULT_PATH = ROOT / "second_door_composition_audit.json"

POSTER_OPERANDS = (
    "eye_flip_url_packed",
    "eye_force_one_url_packed",
    "bunny_impure7_packed",
    "lower_triangle91_bits_packed",
    "upper_triangle91_bits_packed",
    "rot180_mask98_packed",
)

ANCHOR_OPERANDS = (
    "anchor479_decimal",
    "anchor484_decimal",
    "yellow9_primes_decimal",
    "architect_privatekey_window33",
)

COMPOSITIONS = (
    "xor_poster_anchor",
    "add_mod256_poster_anchor",
    "sha256_concat_poster_anchor",
    "interleave_poster_anchor",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
AES_TARGETS = ("chain1", "env48", "raw48_evp_iv", "raw48_continuation_iv")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_compositions() -> int:
    return len(POSTER_OPERANDS) * len(ANCHOR_OPERANDS) * len(COMPOSITIONS)


def expected_aes_trials() -> int:
    return expected_compositions() * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(AES_TARGETS)


def expected_scalar_gates() -> int:
    return expected_compositions() * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "second-door-composition-v75",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v75_second_door_composition",
        "date": "2026-08-07",
        "hypothesis": (
            "The unfound poster second door composes with 479/484 anchors to "
            "yield a scalar or legible chain1/env48/raw48 unlock — not a raw "
            "password string."
        ),
        "poster_operands": list(POSTER_OPERANDS),
        "anchor_operands": list(ANCHOR_OPERANDS),
        "compositions": list(COMPOSITIONS),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "aes_targets": list(AES_TARGETS),
        "expected_counts": {
            "compositions": expected_compositions(),
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible plaintext under the v58/v51 gate; scalars via "
            "solver.targets.gate_scalar_bytes on sha256/double_sha256."
        ),
        "scope_note": (
            "Composition-only second-door family. Distinct from v72 direct "
            "passwords and second_door_frontier broad derivations."
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
    print(f"sealed {MANIFEST_PATH.name} ({expected_compositions()} compositions)")
