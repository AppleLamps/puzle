"""Seal v58: SalPhaseIon split envelopes keyed by pipeline operands, not phrases.

The archived page places env48 before the unique ``enter`` marker and raw48
after it.  v49–v52 and v22 swept phrase text, sha256-format phrases, personal
recognition strings, and resistor sum lists — but always either concatenating
phrase *names* or using one operand class against both halves.

This manifest freezes a structural reading: **pre-enter material opens env48;
post-enter / continuation material opens raw48**.  Operands are computed
outputs (fields, decodes, prime lists, rot180 streams, Architect windows,
difference blocks) — never an ordered concatenation of the seven phrase strings.

Legibility gate per ATTEMPT_LOG §14d; padding is never acceptance.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "pipeline_operand_split_envelope_preregistered.json"
SEAL_PATH = ROOT / "pipeline_operand_split_envelope_preregistered.sha256"
RESULT_PATH = ROOT / "pipeline_operand_split_envelope_audit.json"

ENV48_SHA256 = "f35efe2236bf60310e7b645ad297b70c6fd1670e5717d7601f5319e69d489b1b"
RAW48_SHA256 = "bab0c6d922a323c893f071b3b70885d00ae885914dbd70568dd6a032bc05ed70"

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
RAW48_IV_MODES = ("evp_iv", "continuation_iv")

# Pre-enter page operands → env48 only.
ENV48_OPERAND_IDS = (
    "E01_s91_letters",
    "E02_s91_digits_a1_i9",
    "E03_s570_letters",
    "E04_lastwords_decoded",
    "E05_thispassword_decoded",
    "E06_resistor_row_eye9_raw",
    "E07_resistor_col_eye9_raw",
    "E08_resistor_row_eye0_raw",
    "E09_resistor_col_eye0_raw",
    "E10_resistor_row_eye9_mod10",
    "E11_resistor_col_eye9_mod10",
    "E12_resistor_row_eye0_mod10",
    "E13_resistor_col_eye0_mod10",
    "E14_prime_blue_zero5_decimal",
    "E15_prime_yellow9_decimal",
    "E16_prime_all24_two_digit",
)

# Post-enter / continuation operands → raw48 only.
RAW48_OPERAND_IDS = (
    "R01_architect_479_120",
    "R02_architect_479_60",
    "R03_vic_digits_149",
    "R04_vic_funds_message",
    "R05_rot180_mask_packed",
    "R06_rot180_yin_bits_packed",
    "R07_difference_middle49",
    "R08_difference_full91",
)

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_aes_trials() -> int:
    env = len(ENV48_OPERAND_IDS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS)
    raw = (
        len(RAW48_OPERAND_IDS)
        * len(PASSWORD_FORMS)
        * len(KDF_DIGESTS)
        * len(RAW48_IV_MODES)
    )
    return env + raw


def expected_scalar_gates() -> int:
    return (len(ENV48_OPERAND_IDS) + len(RAW48_OPERAND_IDS)) * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "pipeline-operand-split-envelope-v58",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v58_pipeline_operand_split",
        "date": "2026-08-07",
        "hypothesis": (
            "env48 and raw48 are two locks keyed by different SalPhaseIon-page "
            "operands: material before the enter marker for env48, continuation "
            "material after it for raw48 — structural outputs only, never "
            "seven-phrase concatenation."
        ),
        "targets": {
            "env48_sha256": ENV48_SHA256,
            "raw48_sha256": RAW48_SHA256,
            "half_uncompressed_pubkey": HALF_PUBLIC_UNCOMPRESSED.hex(),
            "better_half_hash160": BETTER_H160.hex(),
        },
        "env48_operands": list(ENV48_OPERAND_IDS),
        "raw48_operands": list(RAW48_OPERAND_IDS),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "raw48_iv_modes": list(RAW48_IV_MODES),
        "expected_counts": {
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible plaintext: printable_ratio>=0.85 and entropy<=5.9, or an "
            "English run of >=6 letters; padding logged never accepted. Scalars "
            "via solver.targets.gate_scalar_bytes on sha256/double_sha256 of "
            "each operand preimage."
        ),
        "scope_note": (
            "Closes only this page-order operand assignment against env48/raw48. "
            "Does not concat phrase text, does not reopen Cosmic/Chain4/base-38, "
            "and does not claim the enter-marker split is creator-authenticated."
        ),
        "control_scalar_hex": CONTROL_SCALAR_HEX,
    }


def seal() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")


if __name__ == "__main__":
    seal()
    print(f"sealed {MANIFEST_PATH.name} -> {SEAL_PATH.name}")
