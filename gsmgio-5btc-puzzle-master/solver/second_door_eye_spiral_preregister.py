"""Seal v62: second-door eye-cell spiral bit operations.

The off-white cell at grid (7,4) is the poster's only anomaly; its spiral index
is 163 and its rot180 partner at (6,9) is black at index 173.  Prior audits
measured structure (§14b) and resistor/zeroing families (v53) but never gated
**bit operations at the eye index** on the authenticated 196-bit spiral body.

This manifest freezes six deterministic edits to the spiral bitstream, two
serializations each, scalar gates, and legibility-gated AES trials against
chain1 and env48 only.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "second_door_eye_spiral_preregistered.json"
SEAL_PATH = ROOT / "second_door_eye_spiral_preregistered.sha256"
RESULT_PATH = ROOT / "second_door_eye_spiral_audit.json"

EYE_SPIRAL_INDEX = 163
PARTNER_SPIRAL_INDEX = 173

BIT_EDITS = (
    "baseline_body196",
    "flip_bit_163",
    "swap_bits_163_173",
    "force_bit_163_one",
    "force_bit_163_zero",
    "xor_bits_163_173_into_163",
)

SERIALIZATIONS = ("packed_first_192", "sha256_of_packed192")
PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
ENVELOPES = ("chain1", "env48")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_scalar_gates() -> int:
    return len(BIT_EDITS) * len(SERIALIZATIONS) * 2


def expected_aes_trials() -> int:
    return (
        len(BIT_EDITS)
        * len(SERIALIZATIONS)
        * len(PASSWORD_FORMS)
        * len(KDF_DIGESTS)
        * len(ENVELOPES)
    )


def build_manifest() -> dict[str, object]:
    return {
        "schema": "second-door-eye-spiral-v62",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v62_second_door_eye_spiral",
        "date": "2026-08-07",
        "hypothesis": (
            "The second door is unlocked by a deterministic edit to the spiral "
            "bitstream at the off-white eye cell (spiral index 163)."
        ),
        "eye_spiral_index": EYE_SPIRAL_INDEX,
        "partner_spiral_index": PARTNER_SPIRAL_INDEX,
        "bit_edits": list(BIT_EDITS),
        "serializations": list(SERIALIZATIONS),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "envelopes": list(ENVELOPES),
        "expected_counts": {
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible AES plaintext or solver.targets scalar gate; padding alone "
            "never accepted."
        ),
        "scope_note": (
            "Closes only these six eye-index bit edits and two serializations "
            "against chain1/env48. Does not reopen Cosmic/Chain4 or widen to "
            "free spiral read orders."
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
    print(f"sealed {MANIFEST_PATH.name}")
