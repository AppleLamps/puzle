"""Seal v68: non-round-robin weaves of the seven passwords.

The Architect plaintext — tier 1, it decrypts from a creator ciphertext — tells
the finisher to select from "SEVEN INTERTWINED PASSWORDS".  v50 read
"intertwined" as round-robin: braid one character at a time across the parts,
or zip to the shortest, over every ordering.  Both are the same weave function
under permutation, and both were falsified.

"Intertwined" does not have to mean round-robin.  This manifest freezes fifteen
weave functions that are *not* reachable by permuting a round-robin braid:
padded column reads that keep a fill character, chunked interleaves, nested
pairwise braids, per-part reversal, letterwise modular stacking, grid
transposition, running Caesar composition, and head/tail alternation.

Applied to the seven 2023-02-23 phrases and to the seven SalPhaseIon tokens,
against chain1 and chain2, under a legibility gate.  Padding is never
acceptance.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "nonroundrobin_weave_preregistered.json"
SEAL_PATH = ROOT / "nonroundrobin_weave_preregistered.sha256"
RESULT_PATH = ROOT / "nonroundrobin_weave_audit.json"

CREATOR_PHRASES = (
    "yellowblueprimes",
    "matrixsumlist",
    "lastwordsbeforearchichoice",
    "yinyang",
    "wewontgiveawaythepassword",
    "itsinfrontofyoureyesbutyourenotseeingit",
    "verylaststepisatruegiveawaypromised",
)

# The seven SalPhaseIon tokens with the two placeholder markers replaced by
# their authenticated readings.
SALPHASEION_TOKENS = (
    "matrixsumlist",
    "enter",
    "lastwordsbeforearchichoice",
    "thispassword",
    "matrixsumlist",
    "shabefourfirsthintisyourlastcommand",
    "shabefanstoo",
)

PART_SETS = ("phrases", "tokens")

WEAVE_IDS = (
    "W01_column_weave_padded",
    "W02_chunk2_weave",
    "W03_chunk3_weave",
    "W04_chunk4_weave",
    "W05_proportional_weave",
    "W06_nested_pairwise_braid",
    "W07_reverse_each_concat",
    "W08_reverse_each_braid",
    "W09_mod26_add_stack",
    "W10_mod26_sub_stack",
    "W11_xor_ascii_stack_hex",
    "W12_transpose_grid_7col",
    "W13_caesar_chain",
    "W14_length_sorted_concat",
    "W15_head_tail_alternate",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
ENVELOPES = ("chain1", "chain2")
FILL_CHARACTER = "."
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_aes_trials() -> int:
    return (
        len(WEAVE_IDS)
        * len(PART_SETS)
        * len(PASSWORD_FORMS)
        * len(KDF_DIGESTS)
        * len(ENVELOPES)
    )


def expected_scalar_gates() -> int:
    return len(WEAVE_IDS) * len(PART_SETS) * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "nonroundrobin-weave-v68",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v68_nonroundrobin_weave",
        "date": "2026-08-07",
        "hypothesis": (
            "'Seven intertwined passwords' names a weave that is not a "
            "round-robin braid, and one of these fifteen weaves opens chain1 "
            "or chain2 with legible plaintext."
        ),
        "why_new": (
            "v50 falsified round-robin braid and zip over every ordering. Each "
            "weave frozen here is a different function, not a reordering: it "
            "keeps fill characters, moves multi-character chunks, nests, "
            "reverses parts, stacks letters modularly, transposes a grid, "
            "composes Caesar shifts, or alternates head and tail."
        ),
        "part_sets": {
            "phrases": list(CREATOR_PHRASES),
            "tokens": list(SALPHASEION_TOKENS),
        },
        "weave_ids": list(WEAVE_IDS),
        "fill_character": FILL_CHARACTER,
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "envelopes": list(ENVELOPES),
        "expected_counts": {
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible plaintext (printable_ratio>=0.85 and entropy<=5.9, or an "
            "English run of >=6 letters) or a 32-byte window gating to a prize "
            "target; padding logged, never accepted."
        ),
        "scope_note": (
            "Closes fifteen non-round-robin weave functions on two seven-part "
            "sets against chain1 and chain2 under EVP MD5 and SHA-256. It does "
            "not re-enumerate orderings (v50 did that for round-robin), and it "
            "does not test Cosmic, Chain 4, or weaves of stage answers."
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
