"""Seal v64: rot180 49-pair interleave with middle49 / prime list.

Yin-yang step 4 remains unreached.  v47 closed rot180 streams alone; v59
closed fold_xor/sha256_chain over seven operands.  This manifest tests **one
interleave family** suggested by the exact 49/98 rot180 split and the 49-letter
``YOUWON`` middle block ``D[21:70]``:

1. ``mod26_add_mask49`` — ``middle49[i] + mask[i] (mod 26)``
2. ``mod26_add_yin_first49`` — ``middle49[i] + yin_first_of_pair[i] (mod 26)``
3. ``ascii_mask_then_middle`` — 49 mask bits as ``0/1`` + middle49 letters
4. ``prime24_interleave_mask`` — blue-zero5 decimal digits interleaved with
   first 48 mask bits (cycled)

Outputs gated as scalars and AES passwords (chain1/env48) under legibility.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "yinyang_interleave_49_preregistered.json"
SEAL_PATH = ROOT / "yinyang_interleave_49_preregistered.sha256"
RESULT_PATH = ROOT / "yinyang_interleave_49_audit.json"

COMPOSITIONS = (
    "mod26_add_mask49",
    "mod26_add_yin_first49",
    "ascii_mask_then_middle",
    "prime24_interleave_mask",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
ENVELOPES = ("chain1", "env48")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_aes_trials() -> int:
    return len(COMPOSITIONS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(ENVELOPES)


def expected_scalar_gates() -> int:
    return len(COMPOSITIONS) * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "yinyang-interleave-49-v64",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v64_yinyang_interleave_49",
        "date": "2026-08-07",
        "compositions": list(COMPOSITIONS),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "envelopes": list(ENVELOPES),
        "expected_counts": {
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "scope_note": (
            "Closes only these four 49-wide interleaves of rot180 material "
            "with middle49/primes. No free cipher menu."
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
