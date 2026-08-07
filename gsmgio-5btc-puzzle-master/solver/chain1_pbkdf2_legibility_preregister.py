"""Seal v69: chain-1 under PBKDF2, sequential phrase layers, and 479 anchors.

v67 closed the openssl *cipher* catalogue but explicitly left PBKDF2 open:
``openssl enc -pbkdf2`` writes the same ``Salted__`` header with a different
KDF.  Community transcript also records the creator layering envelopes.

This manifest freezes three families against **chain1 only**, all under the
legibility gate:

1. **PBKDF2-HMAC-SHA256** at 1,000 and 10,000 iterations (OpenSSL defaults
   near 10k) for eighteen authenticated passwords.
2. **Sequential seven-phrase layered decrypt**: apply each 2023-02-23 phrase in
   creator order; if a layer yields another ``Salted__`` envelope, continue.
3. **479-anchor password strings** derived from the fitted yin-yang milestone
   (484/479 balance, ``TAKETHE`` / ``PRIVATEKEY`` anchors).

Padding is never acceptance.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "chain1_pbkdf2_legibility_preregistered.json"
SEAL_PATH = ROOT / "chain1_pbkdf2_legibility_preregistered.sha256"
RESULT_PATH = ROOT / "chain1_pbkdf2_legibility_audit.json"

PBKDF2_ITERATIONS = (1000, 10000)
PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")

PBKDF2_PASSWORD_IDS = (
    "P01_canonical_5token_concat",
    "P02_phase32_password",
    "P03_phrases_all7_concat",
    "P04_phrases_first4_concat",
    "P05_phrase_yinyang",
    "P06_sha_first_hint",
    "P07_sha_answer_too",
    "P08_salvation",
    "P09_hashthetext",
    "P10_architect_479_33",
    "P11_architect_takethe_privatekey",
    "P12_yellow479blue484",
    "P13_479479",
    "P14_theflowerblossoms",
    "P15_enter",
    "P16_token_thispassword",
    "P17_phrase_xor7_digest",
    "P18_tokens7_hashthetext_sha_answer",
)

ANCHOR_PASSWORD_IDS = (
    "A01_479",
    "A02_484",
    "A03_479479",
    "A04_484479",
    "A05_yellow479blue484",
    "A06_architect_takethe_privatekey",
    "A07_architect_479_33",
)

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_pbkdf2_trials() -> int:
    return len(PBKDF2_PASSWORD_IDS) * len(PASSWORD_FORMS) * len(PBKDF2_ITERATIONS)


def expected_anchor_trials() -> int:
    return len(ANCHOR_PASSWORD_IDS) * len(PASSWORD_FORMS) * 2  # md5 evp + sha256 evp


def expected_sequential_paths() -> int:
    return len(PASSWORD_FORMS) * 2  # md5 + sha256 EVP, full seven-phrase chain each


def build_manifest() -> dict[str, object]:
    return {
        "schema": "chain1-pbkdf2-legibility-v69",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v69_chain1_pbkdf2_legibility",
        "date": "2026-08-07",
        "hypothesis": (
            "Chain-1 opens legibly under PBKDF2 KDF, sequential seven-phrase "
            "layering, or 479/yin-yang anchor passwords."
        ),
        "pbkdf2_iterations": list(PBKDF2_ITERATIONS),
        "pbkdf2_password_ids": list(PBKDF2_PASSWORD_IDS),
        "anchor_password_ids": list(ANCHOR_PASSWORD_IDS),
        "sequential_phrases": 7,
        "password_forms": list(PASSWORD_FORMS),
        "envelope": "chain1",
        "expected_counts": {
            "pbkdf2_trials": expected_pbkdf2_trials(),
            "anchor_evp_trials": expected_anchor_trials(),
            "sequential_paths": expected_sequential_paths(),
        },
        "acceptance": (
            "Legible plaintext: printable_ratio>=0.85 and entropy<=5.9, or an "
            "English run of >=6 letters; padding logged, never accepted."
        ),
        "scope_note": (
            "Closes PBKDF2-HMAC-SHA256 at 1k/10k iterations, sequential "
            "seven-phrase layered decrypt, and seven 479-anchor strings on "
            "chain1 only. Does not reopen EVP MD5/SHA-256 families closed in "
            "v49-v68 or non-PBKDF2 ciphers closed in v67."
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
