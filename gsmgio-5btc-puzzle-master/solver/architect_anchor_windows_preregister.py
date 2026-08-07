"""Seal v63: Architect anchor windows only (479 continuation).

Open-frontier item 1 asks for the operation after Architect offset 479.
Prior audits hashed windows with free conventions (725-record bounded search,
10k continuation family).  This manifest extracts **only** the byte spans
between authenticated named anchors in the Beaufort plaintext — no numeric
offsets beyond anchor boundaries:

* ``TAKETHE`` (472) through ``RETURN`` (1010)
* ``PRIVATEKEY`` (479) through ``RETURN``
* ``RETURN`` (1010) through ``REINSERTING`` (1089)
* ``SOURCECODES`` (1021) through ``REINSERTING``
* ``REINSERTING`` (1089) first 120 / 60 characters
* full ``TAKETHE``..``REINSERTING`` span

Fixed serializations and password forms; legibility gate on AES; scalars via
``solver.targets`` only.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "architect_anchor_windows_preregistered.json"
SEAL_PATH = ROOT / "architect_anchor_windows_preregistered.sha256"
RESULT_PATH = ROOT / "architect_anchor_windows_audit.json"

# Verified against committed Beaufort plaintext (2026-08-07).
ANCHORS = {
    "TAKETHE": 472,
    "PRIVATEKEY_FIRST": 479,
    "RETURN": 1010,
    "SOURCECODES": 1021,
    "REINSERTING": 1089,
    "PRIVATEKEY_SECOND": 1238,
}

WINDOWS = (
    "W01_take_through_return",
    "W02_privatekey_through_return",
    "W03_privatekey_120",
    "W04_privatekey_60",
    "W05_return_through_reinsert",
    "W06_sourcecodes_through_reinsert",
    "W07_reinsert_120",
    "W08_reinsert_60",
    "W09_take_through_reinsert",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
AES_ENVELOPES = ("chain1", "env48")
RAW48_IV_MODES = ("evp_iv", "continuation_iv")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_aes_trials() -> int:
    chain_env = len(WINDOWS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(AES_ENVELOPES)
    raw48 = len(WINDOWS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(RAW48_IV_MODES)
    return chain_env + raw48


def expected_scalar_gates() -> int:
    return len(WINDOWS) * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "architect-anchor-windows-v63",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v63_architect_anchor_windows",
        "date": "2026-08-07",
        "anchors": ANCHORS,
        "windows": list(WINDOWS),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "aes_envelopes": list(AES_ENVELOPES),
        "raw48_iv_modes": list(RAW48_IV_MODES),
        "expected_counts": {
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible AES plaintext or solver.targets scalar; padding never "
            "accepted."
        ),
        "scope_note": (
            "Closes only anchor-bounded Architect windows with fixed lengths "
            "where named. No free numeric offsets, no Cosmic/Chain4/base-38."
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
