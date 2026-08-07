"""Seal v71: 479/484/rot180 mask as *index selectors* into Architect or S570.

v59/v70 **composed** bytes from seven structural operands.  s570_fold and
creator_pipeline use matrix sums as indices into Architect[479].  v46 used
prime lists as **key material**, not indices.

This manifest freezes **selection** — walk an index stream (479/484 anchors,
yellow/blue prime lists, rot180 mask gating) into one of four authenticated
corpora (Architect A–Z, S570 faed, S91, difference ``D``) and concatenate
the extracted characters.  No byte folding, XOR, or interleave composition.

Each selected string is gated as scalar (sha256 / double_sha256) and as an
AES password on chain1, env48, and raw48 (both IV modes).  Padding is never
acceptance.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "yinyang_479_index_selector_preregistered.json"
SEAL_PATH = ROOT / "yinyang_479_index_selector_preregistered.sha256"
RESULT_PATH = ROOT / "yinyang_479_index_selector_audit.json"

YINYANG_OFFSET = 479
BLUE_OFFSET = 484

INDEX_BASES = (
    "absolute_0based",
    "from_479_0based",
    "from_479_1based",
    "cumulative_from_479_0based",
)

INDEX_STREAMS = (
    "yellow9_primes",
    "blue15_zero5",
    "all24_primes",
    "anchor479484_alternate",
)

CORPORA = (
    "architect_az",
    "s570_faed_ascii",
    "s91_ascii",
    "difference_d_ascii",
)

SELECTION_RULES = (
    "linear_index",
    "mask_gated_linear",
    "mask_dual_corpus_arch479_s570484",
    "mask_dual_corpus_arch484_s570479",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
AES_TARGETS = ("chain1", "env48", "raw48_evp_iv", "raw48_continuation_iv")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_families() -> int:
    linear_rules = ("linear_index", "mask_gated_linear")
    dual_rules = (
        "mask_dual_corpus_arch479_s570484",
        "mask_dual_corpus_arch484_s570479",
    )
    linear = len(linear_rules) * len(INDEX_STREAMS) * len(INDEX_BASES) * len(CORPORA)
    dual = len(dual_rules) * len(INDEX_STREAMS) * len(INDEX_BASES)
    return linear + dual


def expected_aes_trials() -> int:
    return expected_families() * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(AES_TARGETS)


def expected_scalar_gates() -> int:
    return expected_families() * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "yinyang-479-index-selector-v71",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v71_yinyang_479_index_selector",
        "date": "2026-08-07",
        "hypothesis": (
            "479→yinyang step 4 is an index operation: 479/484 anchors, "
            "yellow/blue prime lists, and the rot180 inversion mask select "
            "characters from Architect or S570 (or S91 / D), not a byte "
            "composition over structural operands."
        ),
        "anchors": {"yinyang": YINYANG_OFFSET, "blue": BLUE_OFFSET},
        "index_bases": list(INDEX_BASES),
        "index_streams": list(INDEX_STREAMS),
        "corpora": list(CORPORA),
        "selection_rules": list(SELECTION_RULES),
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "aes_targets": list(AES_TARGETS),
        "expected_counts": {
            "families": expected_families(),
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible plaintext under the v58/v51 gate; scalars via "
            "solver.targets.gate_scalar_bytes on sha256/double_sha256 of "
            "the selected character string."
        ),
        "scope_note": (
            "Selection-only family over four corpora and four index bases. "
            "Distinct from v59/v70 byte composition, s570_fold_architect "
            "matrix-sum indices, creator_pipeline poster sums, and v46 prime "
            "lists as key material. Does not reopen Cosmic/Chain4."
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
    print(f"sealed {MANIFEST_PATH.name} ({expected_families()} families)")
