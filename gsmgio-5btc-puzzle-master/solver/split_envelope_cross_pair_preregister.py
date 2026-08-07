"""Seal v65: cross-half and paired split-envelope operands.

v58 assigned pre-enter operands to env48 and post-enter operands to raw48
only.  This manifest tests:

**Part A — cross-half assignment:** each env48-class operand as a raw48
password (both IV modes) and each raw48-class operand as an env48 password.

**Part B — eight frozen pipeline pairs:** concatenation ``env_op || raw_op``
and ``raw_op || env_op`` as chain1 passwords (structural bytes only).

Legibility gate throughout; padding never accepted.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .pipeline_operand_split_envelope_preregister import (
    ENV48_OPERAND_IDS,
    KDF_DIGESTS,
    PASSWORD_FORMS,
    RAW48_IV_MODES,
    RAW48_OPERAND_IDS,
)
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "split_envelope_cross_pair_preregistered.json"
SEAL_PATH = ROOT / "split_envelope_cross_pair_preregistered.sha256"
RESULT_PATH = ROOT / "split_envelope_cross_pair_audit.json"

FROZEN_PAIRS = (
    ("E04_lastwords_decoded", "R01_architect_479_120"),
    ("E01_s91_letters", "R07_difference_middle49"),
    ("E14_prime_blue_zero5_decimal", "R05_rot180_mask_packed"),
    ("E10_resistor_row_eye9_mod10", "R03_vic_digits_149"),
    ("E04_lastwords_decoded", "R04_vic_funds_message"),
    ("E16_prime_all24_two_digit", "R06_rot180_yin_bits_packed"),
    ("E03_s570_letters", "R02_architect_479_60"),
    ("E05_thispassword_decoded", "R08_difference_full91"),
)

CONCAT_ORDERS = ("env_then_raw", "raw_then_env")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_cross_aes() -> int:
    env_on_raw = len(ENV48_OPERAND_IDS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(RAW48_IV_MODES)
    raw_on_env = len(RAW48_OPERAND_IDS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS)
    return env_on_raw + raw_on_env


def expected_pair_aes() -> int:
    return len(FROZEN_PAIRS) * len(CONCAT_ORDERS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS)


def expected_scalar_gates() -> int:
    return (len(FROZEN_PAIRS) * len(CONCAT_ORDERS) + len(ENV48_OPERAND_IDS) + len(RAW48_OPERAND_IDS)) * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "split-envelope-cross-pair-v65",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v65_split_envelope_cross_pair",
        "date": "2026-08-07",
        "env48_operands": list(ENV48_OPERAND_IDS),
        "raw48_operands": list(RAW48_OPERAND_IDS),
        "frozen_pairs": [list(pair) for pair in FROZEN_PAIRS],
        "concat_orders": list(CONCAT_ORDERS),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "raw48_iv_modes": list(RAW48_IV_MODES),
        "expected_counts": {
            "cross_aes_trials": expected_cross_aes(),
            "pair_chain1_aes_trials": expected_pair_aes(),
            "scalar_gates": expected_scalar_gates(),
        },
        "scope_note": (
            "Closes cross-half operand assignment and eight frozen env/raw "
            "concat pairs against split envelopes and chain1. Not phrase text."
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
