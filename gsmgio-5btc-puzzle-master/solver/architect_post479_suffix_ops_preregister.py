"""Seal v78: post-479 continuation operations not covered by v76.

v76 closed hash/reinsert/select/Beaufort/mod26/enter/HASHTHETEXT on **anchor
windows**.  This manifest tests operations the continuation text names on the
**post-479 suffix** itself:

* ``HUNDREDFOURTY`` — exact 140-character slice from offset 479
* ``TAKETHISTOHEART`` / ``WISEMANABOVE`` — named sub-spans
* **Return to source codes** — raw/transliteration record xor/Beaufort on suffix
* **Dual PRIVATEKEY** — xor first and second ``PRIVATEKEY`` regions (479, 1238)
* **matrixsumlist** — resistor row sums as indices into the 140-char suffix
* **Fresco quote** — wise-man 23-word quote Beaufort/mod26 on suffix
* **Dissemination** — repeat/concat suffix
* **Seven tokens** — SalPhaseIon token-digest xor fold on suffix
* **VIC digits** — checkerboard digit overlay on suffix

No free numeric offsets beyond named anchors at 479, 511, 535, 562, 1021, 1238.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "architect_post479_suffix_ops_preregistered.json"
SEAL_PATH = ROOT / "architect_post479_suffix_ops_preregistered.sha256"
RESULT_PATH = ROOT / "architect_post479_suffix_ops_audit.json"

OPERATIONS = (
    "suffix140_hundredforty",
    "suffix_takeheart_wiseman",
    "suffix_479_to_hundredforty_word",
    "matrixsumlist_row_index_suffix140",
    "matrixsumlist_local_suffix140",
    "raw_source_xor_suffix140",
    "transliteration_xor_suffix140",
    "dual_privatekey_xor_32",
    "beaufort_fresco_suffix140",
    "mod26_fresco_add_suffix140",
    "disseminate_concat_suffix140_x2",
    "return_sourcecodes_beaufort_suffix140",
    "sha256_suffix140_then_sourcecodes",
    "seven_token_xor_fold_suffix140",
    "vic_digits_mod10_suffix140",
    "prime_reinsert_yellow9_suffix140",
    "takeheart_center32",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
AES_TARGETS = ("chain1", "env48", "raw48_evp_iv", "raw48_continuation_iv")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"

FRESCO_QUOTE = (
    "The future is fluid. Each act, each decision, and each development creates "
    "new possibilities and eliminates others. The future is ours to direct."
)


def expected_materials() -> int:
    return len(OPERATIONS)


def expected_aes_trials() -> int:
    return expected_materials() * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(AES_TARGETS)


def expected_scalar_gates() -> int:
    return expected_materials() * 2


def build_manifest() -> dict[str, object]:
    return {
        "schema": "architect-post479-suffix-ops-v78",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v78_architect_post479_suffix_ops",
        "date": "2026-08-07",
        "hypothesis": (
            "The operation after Architect ``PRIVATEKEY…`` is one of seventeen "
            "literal suffix operations named by HUNDREDFOURTY, source codes, "
            "wise-man quote, matrixsumlist, or dual-PRIVATEKEY — not covered "
            "by v76 anchor-window transforms."
        ),
        "named_anchors_from_479": {
            "PRIVATEKEY": 479,
            "TAKETHISTOHEART": 511,
            "WISEMANABOVE": 535,
            "HUNDREDFOURTY": 562,
            "PRIVATEKEY_SECOND": 1238,
            "SOURCECODES": 1021,
        },
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
            "Post-479 suffix family only. Distinct from v76 anchor-window "
            "operations and architect_479_semantic_pipeline Fresco/F73D92 route."
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
