"""Seal v70: extended 479→yinyang seven-operand compositions incl. chain1.

v59 closed ``fold_xor`` and ``fold_sha256_chain`` over seven structural pipeline
outputs against env48/raw48 only.  This manifest extends composition with four
rules that v59 never tried, and adds **chain1** as an AES target — the
legibility-gated unlock the record says is still open.

New composition rules (same seven v59 step operands, creator order):

1. ``fold_add_mod256`` — byte-wise sum mod 256 with cyclic extension.
2. ``fold_interleave_bytes`` — round-robin byte interleave across operands.
3. ``fold_sha256_concat`` — ``sha256(op1 || … || op7)`` (single digest, not chain).
4. ``yinyang_mirror_xor`` — XOR first three operands with last three; step 4
   (rot180 mask) is the centre operand appended verbatim.

Each composed material is gated as scalar and as AES password on chain1, env48,
and raw48 (both IV modes).  Padding is never acceptance.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "yinyang_composition_extended_preregistered.json"
SEAL_PATH = ROOT / "yinyang_composition_extended_preregistered.sha256"
RESULT_PATH = ROOT / "yinyang_composition_extended_audit.json"

# v59 operands plus four new rules.
STEP_OPERAND_IDS = (
    "step1_yellowblueprimes_blue_zero5_decimal",
    "step2_matrixsumlist_row_mod10",
    "step3_lastwords_decoded",
    "step4_yinyang_rot180_mask_packed",
    "step5_wewontgiveaway_architect_479_33",
    "step6_infrontofyoureyes_middle49",
    "step7_giveaway_yellow9_decimal",
)

COMPOSITIONS = (
    "fold_add_mod256",
    "fold_interleave_bytes",
    "fold_sha256_concat",
    "yinyang_mirror_xor",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
AES_TARGETS = ("chain1", "env48", "raw48_evp_iv", "raw48_continuation_iv")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_aes_trials() -> int:
    return len(COMPOSITIONS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(AES_TARGETS)


def expected_scalar_gates() -> int:
    return len(COMPOSITIONS) * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "yinyang-composition-extended-v70",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v70_yinyang_composition_extended",
        "date": "2026-08-07",
        "hypothesis": (
            "479→yinyang step 4 is one of four extended composition rules over "
            "seven structural operands, and the composed material opens chain1 "
            "or the split envelopes with legible plaintext."
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
            "solver.targets.gate_scalar_bytes on sha256/double_sha256."
        ),
        "scope_note": (
            "Extends v59 with four composition rules and adds chain1 as a "
            "target. Does not change step-to-operand mapping or reopen v59 "
            "fold_xor / fold_sha256_chain results."
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
