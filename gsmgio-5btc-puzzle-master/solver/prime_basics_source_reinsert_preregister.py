"""Seal v55: reinsert yellowblueprimes lists into Architect source codes.

Conversation reading of the Architect instruction, in its own order:

1. return to the source codes — the authenticated 1,539-byte Architect layers
   (raw symbol record, published transliteration, Beaufort A–Z plaintext);
2. temporary dissemination of the code you hopefully carry —
   ``THEMATRIXHASYOU`` or the phase-3.2 OpenSSL passphrase;
3. reinserting the prime basics — the yellow/blue prime lists already produced
   by ``yellowblueprimes`` on the poster markers (including the 5→0 balance).

This is deliberately not a re-run of:

* ``architect_source_prime_reinsertion_audit.json`` — primes as *indices* into
  the source, with prime-ops before dissemination;
* ``yinyang_prime_dual_audit.json`` — the same lists hashed alone, never
  spliced back into a source layer;
* ``prime_reinsertion_audit.json`` — poster colours into S91 at prime slots.

Acceptance is only :mod:`solver.targets`. Padding and English fragments are
never acceptance. Cosmic / Chain 4 / base-38 are out of scope.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED
from .yinyang_prime_dual_preregister import MARKERS, _primes, prime_lists


MANIFEST_PATH = ROOT / "prime_basics_source_reinsert_preregistered.json"
SEAL_PATH = ROOT / "prime_basics_source_reinsert_preregistered.sha256"
RESULT_PATH = ROOT / "prime_basics_source_reinsert_audit.json"

SCHEMA = "prime-basics-source-reinsert-v55"

RAW_SHA256 = "bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b"
TRANSLITERATION_SHA256 = "6d66e0e0e2dfdb812d5ecee2be6f54c1f3b8c84b0d74580686cf2053d76a200e"
PLAINTEXT_SHA256 = "56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241"

PHASE32_PASSWORD = b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
BEAUFORT_KEY = b"THEMATRIXHASYOU"

LAYERS = ("raw", "transliteration", "plaintext")
DISSEMINATIONS = (
    "identity",
    "xor-beaufort-key-ascii",
    "xor-beaufort-key-digest",
    "xor-phase32-password",
)
# The dual lists the conversation treats as "prime basics we already have."
PAYLOAD_LISTS = (
    "yellow9",
    "blue15",
    "blue15_zero5",
    "blue14_drop5",
    "yin_yang_pair",
    "yang_yin_pair",
    "sums_pair",
    "all24_zero5",
)
SERIALIZATIONS = ("raw_value_bytes", "ascii_decimal_concat", "mod26_A0_ascii")
# Named anchors from the authenticated Architect plaintext.
INSERT_MODES = (
    "overwrite@479",   # PRIVATEKEY
    "overwrite@1021",  # SOURCECODES
    "overwrite@1103",  # PRIMEBASICS
    "xor@479",
    "xor@1103",
    "append",
)
EXTRACTORS = ("sha256", "first-32", "last-32", "window-479-32")

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_candidate_count() -> int:
    return (
        len(LAYERS)
        * len(DISSEMINATIONS)
        * len(PAYLOAD_LISTS)
        * len(SERIALIZATIONS)
        * len(INSERT_MODES)
        * len(EXTRACTORS)
    )


def build_manifest() -> dict[str, object]:
    lists = prime_lists()
    missing = [name for name in PAYLOAD_LISTS if name not in lists]
    if missing:
        raise ValueError(f"payload lists missing from prime_lists(): {missing}")
    return {
        "schema": SCHEMA,
        "status": "SEALED_BEFORE_SCALAR_EVALUATION",
        "hypothesis": (
            "After returning to the Architect source-code layers, temporarily "
            "disseminate the carried Beaufort/phase-3.2 code, then reinsert the "
            "yellowblueprimes dual lists (the prime basics already in hand) at "
            "the named PRIVATEKEY / SOURCECODES / PRIMEBASICS anchors."
        ),
        "instruction_order": [
            "return to the source codes",
            "temporary dissemination of the code you hopefully carry",
            "reinserting the prime basics",
        ],
        "distinct_from": {
            "architect_source_prime_reinsertion_audit.json": (
                "uses consecutive primes as indices; applies prime-ops before "
                "dissemination; does not splice yellow/blue list values"
            ),
            "yinyang_prime_dual_audit.json": (
                "hashes the same lists alone; never writes them back into a "
                "source layer"
            ),
            "prime_reinsertion_audit.json": (
                "inserts poster colour values into S91 at prime positions"
            ),
        },
        "frozen_inputs": {
            "poster_marker_colors": MARKERS,
            "consecutive_primes_2_89": _primes(24),
            "blue_sum": 484,
            "yellow_sum": 479,
            "imbalance": 5,
            "source_layers": {
                "raw_sha256": RAW_SHA256,
                "transliteration_sha256": TRANSLITERATION_SHA256,
                "plaintext_sha256": PLAINTEXT_SHA256,
                "length": 1539,
            },
            "carried_codes": {
                "beaufort_key_utf8": BEAUFORT_KEY.decode("ascii"),
                "phase32_password_utf8": PHASE32_PASSWORD.decode("ascii"),
            },
            "named_anchors_0based": {
                "PRIVATEKEY": 479,
                "SOURCECODES": 1021,
                "PRIMEBASICS": 1103,
            },
        },
        "payload_lists": {
            name: {
                "length": len(lists[name]),
                "sum": sum(lists[name]),
                "sha256": sha256_hex(",".join(map(str, lists[name])).encode("ascii")),
            }
            for name in PAYLOAD_LISTS
        },
        "expansion": {
            "layers": list(LAYERS),
            "disseminations": list(DISSEMINATIONS),
            "payload_lists": list(PAYLOAD_LISTS),
            "serializations": list(SERIALIZATIONS),
            "insert_modes": list(INSERT_MODES),
            "extractors": list(EXTRACTORS),
            "expected_candidate_records": expected_candidate_count(),
        },
        "acceptance": {
            "only_gate": "solver.targets.gate_scalar_bytes",
            "half": {"exact_public_key": HALF_PUBLIC_UNCOMPRESSED.hex()},
            "better_half": {"hash160": BETTER_H160.hex()},
            "explicitly_not_acceptance": [
                "valid PKCS#7 padding",
                "readable English fragments",
                "a sum that works out to 479",
            ],
            "planted_control_scalar": CONTROL_SCALAR_HEX,
        },
        "scope_note": (
            "Closes only this ordered reading: disseminate carried code over an "
            "Architect source layer, then splice/XOR/append the sealed "
            "yellowblueprimes list serializations at the named anchors. Does "
            "not address Bitcoin Core source, HTML page source, or free cipher "
            "selection after reinsertion."
        ),
        "out_of_scope": [
            "Cosmic Duality, Chain 4, base-38",
            "prime assignments other than consecutive 2..89 on the pinned markers",
            "zeroing rules other than the balancing blue 5",
            "23/16/7 cipher-menu selection after reinsertion",
        ],
    }


def seal() -> str:
    encoded = (json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    SEAL_PATH.write_text(digest + "\n", encoding="ascii")
    return digest


if __name__ == "__main__":
    print(seal())
