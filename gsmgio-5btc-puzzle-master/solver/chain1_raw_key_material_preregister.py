"""Seal v73: chain1 96-byte blob as encoded key material, not OpenSSL AES.

v67 closed alternate **ciphers** within the ``Salted__`` framing.  The split
envelope K4 family gated raw48 windows as scalars only.  This manifest treats
the full glued chain1 envelope (env48 + raw48 = 96 bytes) as **raw key
material** without password decryption: sliding 32-byte windows, half XOR/add,
header-stripped slices, env48 salt/ciphertext fields, and base58check scans.

No AES password attempts.  Acceptance is only ``solver.targets.gate_scalar_bytes``.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "chain1_raw_key_material_preregistered.json"
SEAL_PATH = ROOT / "chain1_raw_key_material_preregistered.sha256"
RESULT_PATH = ROOT / "chain1_raw_key_material_audit.json"

BLOB_SCOPES = (
    "chain1_glued_96",
    "env48_half",
    "raw48_half",
)

DERIVATIONS = (
    "raw32_window",
    "sha256_window",
    "double_sha256_window",
)

COMBINE_RULES = (
    "xor_halves",
    "add_mod256_halves",
    "xor_env_ct_raw48",
    "xor_env_salt_raw48",
)

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def _window_count(length: int) -> int:
    return max(0, length - 32 + 1)


def expected_scalar_gates() -> int:
    lengths = {"chain1_glued_96": 96, "env48_half": 48, "raw48_half": 48}
    windows = sum(_window_count(lengths[scope]) for scope in BLOB_SCOPES) * len(DERIVATIONS)
    whole_prefix = len(BLOB_SCOPES) * len(DERIVATIONS)
    combines = len(COMBINE_RULES) * len(DERIVATIONS)
    return windows + whole_prefix + combines


def build_manifest() -> dict[str, object]:
    return {
        "schema": "chain1-raw-key-material-v73",
        "status": "SEALED_BEFORE_SCALAR_EVALUATION",
        "id": "v73_chain1_raw_key_material",
        "date": "2026-08-07",
        "hypothesis": (
            "The 96-byte chain1 blob (48-byte Salted__ envelope + 48-byte "
            "headerless half) is encoded private-key material rather than "
            "an OpenSSL password envelope."
        ),
        "blob_scopes": list(BLOB_SCOPES),
        "combine_rules": list(COMBINE_RULES),
        "derivations": list(DERIVATIONS),
        "window_counts": {
            scope: _window_count(length)
            for scope, length in (
                ("chain1_glued_96", 96),
                ("env48_half", 48),
                ("raw48_half", 48),
            )
        },
        "expected_counts": {
            "scalar_gates": expected_scalar_gates(),
            "base58check_scopes": ["whole-blob-per-scope", "32-byte-windows"],
        },
        "acceptance": "solver.targets.gate_scalar_bytes only; no AES.",
        "scope_note": (
            "Non-AES interpretation of chain1 bytes. Distinct from v67 cipher "
            "catalogue and split-envelope K4 (raw48 only). Does not decrypt "
            "with community passwords or parse the known 79-byte triplet."
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
    print(f"sealed {MANIFEST_PATH.name} ({expected_scalar_gates()} scalar gates)")
