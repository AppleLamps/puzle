"""Seal v76: Architect 479 continuation as named literal operations.

Open-frontier item 1: the operation after ``PRIVATEKEY…`` at offset 479.
v63 extracted anchor windows as passwords; v71 tested index selection.  This
manifest applies **named operations** the authenticated text supports, each on
a fixed operand span — no free numeric offsets:

* ``hash_the_text`` — sha256 of each anchor window
* ``reinsert_yellow9`` / ``reinsert_blue_zero5`` — prime-list digit overlay
* ``select_rot180_suffix`` — mask-gated chars from Architect ``[479:577]``
* ``xor_middle49`` — privatekey 60-byte window XOR middle49
* ``beaufort_hope`` — Beaufort on return..reinsert with HOPE quote
* ``mod26_add_s91`` / ``mod26_add_middle49`` — letterwise mod-26 add
* ``concat_enter_lastwords`` — window + literal enter + decoded lastwords
* ``sha256_chain_hashthetext`` — sha256(HASHTHETEXT || sha256(window))
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "architect_479_continuation_ops_preregistered.json"
SEAL_PATH = ROOT / "architect_479_continuation_ops_preregistered.sha256"
RESULT_PATH = ROOT / "architect_479_continuation_ops_audit.json"

OPERATIONS = (
    "hash_the_text_W01",
    "hash_the_text_W02",
    "hash_the_text_W03",
    "hash_the_text_W04",
    "hash_the_text_W05",
    "hash_the_text_W06",
    "hash_the_text_W07",
    "hash_the_text_W08",
    "hash_the_text_W09",
    "reinsert_yellow9_W02",
    "reinsert_blue_zero5_W06",
    "select_rot180_suffix98",
    "xor_middle49_W04",
    "beaufort_hope_W05",
    "mod26_add_s91_W02",
    "mod26_add_middle49_W04",
    "concat_enter_lastwords_W02",
    "sha256_chain_hashthetext_W01",
    "sha256_chain_hashthetext_W06",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
AES_TARGETS = ("chain1", "env48", "raw48_evp_iv", "raw48_continuation_iv")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_materials() -> int:
    return len(OPERATIONS)


def expected_aes_trials() -> int:
    return expected_materials() * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(AES_TARGETS)


def expected_scalar_gates() -> int:
    return expected_materials() * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "architect-479-continuation-ops-v76",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v76_architect_479_continuation_ops",
        "date": "2026-08-07",
        "hypothesis": (
            "The intended operation after Architect offset 479 is one of "
            "nineteen literal named transforms on anchor-bounded spans and "
            "authenticated operands."
        ),
        "operations": list(OPERATIONS),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "aes_targets": list(AES_TARGETS),
        "expected_counts": {
            "materials": expected_materials(),
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible plaintext under the v58/v51 gate; scalars via "
            "solver.targets.gate_scalar_bytes on sha256/double_sha256."
        ),
        "scope_note": (
            "Literal named operations only; no free offsets. Distinct from "
            "v63 windows-as-passwords and v71 index selection."
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
    print(f"sealed {MANIFEST_PATH.name} ({expected_materials()} operations)")
