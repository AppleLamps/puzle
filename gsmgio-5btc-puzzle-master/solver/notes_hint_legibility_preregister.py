"""Seal v61: 2026-07-16 NOTES callback under legibility gate.

The creator's only self-declared hint (2026-07-12 ``NOTE: that is a hint``) was
extended on 2026-07-16 with ``Lately, I'm working with many **NOTES**.`` and
``Give yourself yourself and yourself will be given yourself.``  v52 tested a
bounded recognition set of publicly creator-associated strings; it did **not**
test a NOTES-specific operand family tied to the July-16 callback.

This manifest freezes a small, tier-1-adjacent phrase set (creator Telegram
only, no identity fishing) against env48, raw48, and chain1 under legibility.
Padding is never acceptance.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .pipeline_operand_split_envelope_preregister import (
    ENV48_SHA256,
    KDF_DIGESTS,
    PASSWORD_FORMS,
    RAW48_SHA256,
)
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "notes_hint_legibility_preregistered.json"
SEAL_PATH = ROOT / "notes_hint_legibility_preregistered.sha256"
RESULT_PATH = ROOT / "notes_hint_legibility_audit.json"

# Creator-sourced strings from the 2026-07-12 / 2026-07-16 thread only.
PHRASES = (
    "NOTE",
    "NOTES",
    "note",
    "notes",
    "many NOTES",
    "many notes",
    "Give yourself yourself and yourself will be given yourself.",
    "Give yourself yourself and yourself will be given yourself",
    "yourself will be given yourself",
    "close friends",
    "My close friends have the best chance of solving it",
)

ENVELOPES = ("env48", "raw48", "chain1")
RAW48_IV_MODES = ("evp_iv", "continuation_iv")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_aes_trials() -> int:
    env_chain = len(PHRASES) * len(PASSWORD_FORMS) * len(KDF_DIGESTS)
    env48_chain1 = env_chain * 2  # env48 + chain1
    raw48 = len(PHRASES) * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(RAW48_IV_MODES)
    return env48_chain1 + raw48


def expected_scalar_gates() -> int:
    return len(PHRASES) * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "notes-hint-legibility-v61",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v61_notes_hint_legibility",
        "date": "2026-08-07",
        "hypothesis": (
            "The 2026-07-16 NOTES callback names a small creator phrase family "
            "that opens env48, raw48, or chain1 with legible plaintext."
        ),
        "phrases": list(PHRASES),
        "envelopes": list(ENVELOPES),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "raw48_iv_modes": list(RAW48_IV_MODES),
        "expected_counts": {
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible plaintext: printable_ratio>=0.85 and entropy<=5.9, or an "
            "English run of >=6 letters; padding logged, never accepted."
        ),
        "scope_note": (
            "Closes only this eleven-phrase NOTES/NOTE/self-giveaway set against "
            "env48/raw48/chain1. Not open-ended identity research; distinct from "
            "v52's 55-string recognition catalogue."
        ),
        "pinned_targets": {
            "env48_sha256": ENV48_SHA256,
            "raw48_sha256": RAW48_SHA256,
        },
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
