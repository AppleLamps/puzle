"""Seal v59: seven pipeline structural outputs composed for yin-yang step 4.

The creator's 2023-02-23 image lists seven ordered phrases; yin-yang is step 4
and remains unreached.  Prior audits tested each operand alone or widened AES
menus.  This manifest freezes **two composition rules** over seven **structural
outputs** (one per pipeline step), not phrase-string concatenation:

1. ``fold_xor`` — left-to-right XOR with cyclic extension to equal length.
2. ``fold_sha256_chain`` — ``h0 = sha256(op1)``; ``h_i = sha256(h_{i-1} || op_i)``.

Each composed material is gated as a scalar and as an AES password against env48
and raw48 under the legibility gate.  Padding is never acceptance.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "yinyang_seven_operand_composition_preregistered.json"
SEAL_PATH = ROOT / "yinyang_seven_operand_composition_preregistered.sha256"
RESULT_PATH = ROOT / "yinyang_seven_operand_composition_audit.json"

COMPOSITIONS = ("fold_xor", "fold_sha256_chain")
PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
AES_TARGETS = ("env48", "raw48_evp_iv", "raw48_continuation_iv")

# One structural output per creator pipeline step, in order.
STEP_OPERAND_IDS = (
    "step1_yellowblueprimes_blue_zero5_decimal",
    "step2_matrixsumlist_row_mod10",
    "step3_lastwords_decoded",
    "step4_yinyang_rot180_mask_packed",
    "step5_wewontgiveaway_architect_479_33",
    "step6_infrontofyoureyes_middle49",
    "step7_giveaway_yellow9_decimal",
)

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_aes_trials() -> int:
    return len(COMPOSITIONS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(AES_TARGETS)


def expected_scalar_gates() -> int:
    return len(COMPOSITIONS) * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "yinyang-seven-operand-composition-v59",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v59_yinyang_seven_operand_composition",
        "date": "2026-08-07",
        "hypothesis": (
            "Yin-yang step 4 is a fixed composition of seven structural pipeline "
            "outputs in creator order — not phrase concatenation and not a free "
            "cipher menu."
        ),
        "step_operands": list(STEP_OPERAND_IDS),
        "compositions": list(COMPOSITIONS),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "aes_targets": list(AES_TARGETS),
        "expected_counts": {
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible plaintext under the v58/v51 gate; scalars via "
            "solver.targets.gate_scalar_bytes on sha256/double_sha256 of each "
            "composed material."
        ),
        "scope_note": (
            "Closes only fold_xor and fold_sha256_chain over the seven listed "
            "structural operands. Does not widen encodings or add classical "
            "ciphers; does not claim step-to-operand mapping is authenticated."
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
    print(f"sealed {MANIFEST_PATH.name} -> {SEAL_PATH.name}")
