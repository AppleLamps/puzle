"""Seal v60: chain-1 envelope keyed by pipeline structural operands.

v58 closed page-order assignment for env48/raw48 only.  v49–v51 swept phrase
text and sha256-format *names* against chain1/chain2/cosmic, but the
**96-byte chain-1 envelope** — the first place the chain leaves legibility —
was never tested under the same **structural operand** set v58 uses (resistor
lists, prime serializations, rot180 packed streams, Architect windows, ``D``
blocks), without phrase concatenation.

This manifest applies the full v58 operand catalogue to **chain1** and
**chain2** only, under the legibility gate.  Cosmic/Chain4/base-38 are out of
scope.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .pipeline_operand_split_envelope_preregister import (
    ENV48_OPERAND_IDS,
    ENV48_SHA256,
    KDF_DIGESTS,
    PASSWORD_FORMS,
    RAW48_OPERAND_IDS,
    RAW48_SHA256,
    build_manifest as split_manifest,
)
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "chain1_structural_operand_legibility_preregistered.json"
SEAL_PATH = ROOT / "chain1_structural_operand_legibility_preregistered.sha256"
RESULT_PATH = ROOT / "chain1_structural_operand_legibility_audit.json"

OPERAND_IDS = tuple(ENV48_OPERAND_IDS) + tuple(RAW48_OPERAND_IDS)
ENVELOPES = ("chain1", "chain2")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_aes_trials() -> int:
    return len(OPERAND_IDS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(ENVELOPES)


def expected_scalar_gates() -> int:
    return len(OPERAND_IDS) * 2


def build_manifest() -> dict[str, object]:
    base = split_manifest()
    return {
        "schema": "chain1-structural-operand-legibility-v60",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v60_chain1_structural_operand_legibility",
        "date": "2026-08-07",
        "extends_v58": {
            "manifest_schema": base["schema"],
            "env48_sha256": ENV48_SHA256,
            "raw48_sha256": RAW48_SHA256,
        },
        "hypothesis": (
            "The 96-byte chain-1 envelope opens with a structural pipeline "
            "operand (field, prime list, rot180 stream, Architect window, or "
            "difference block) under the authenticated sha256-hex password "
            "format — not a seven-phrase concatenation."
        ),
        "operands": list(OPERAND_IDS),
        "envelopes": list(ENVELOPES),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "expected_counts": {
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": base["acceptance"],
        "scope_note": (
            "Closes structural-operand AES/scalar search against chain1 and "
            "chain2 only. Does not concat phrase text, does not reopen Cosmic/"
            "Chain4/base-38, and does not claim any operand is the creator's "
            "intended chain-1 password."
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
