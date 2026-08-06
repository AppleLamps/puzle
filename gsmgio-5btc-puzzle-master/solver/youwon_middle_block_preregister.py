"""Seal the v44 candidate family over the ``YOUWON`` difference blocks.

``docs/ATTEMPT_LOG.md`` §12 item 5 and the Telegram review both name "the
49-character middle block that ``YOUWON`` opens" as undigested.  That block
lives in the *difference* string ``D = S91 - VIC (mod 26)``, which is where
``YOUWON`` appears at zero-based index 21.

The existing v42 audit is labelled "S91 49-Char Middle Block" but slices the
raw base-9 SalPhaseIon field ``S91[21:70]`` (``ihbeggege...``), not
``D[21:70]`` (``YOUWONXCPKWGBNAX...``).  Those are different operands, so the
named block has not in fact been gated.  This manifest freezes the family
before evaluation.

Sources, all derived from committed artifacts:

* ``difference_full``      -- all 91 letters of ``D``
* ``head21`` / ``tail21``  -- the two flanks of the 21/49/21 split
* ``middle49``             -- the named block, ``D[21:70]``
* ``middle_after_youwon43``-- the block with its opening ``YOUWON`` removed
* ``head_plus_tail42``     -- the flanks concatenated in source order
* ``flanks_sum21`` / ``flanks_diff21`` -- the flanks combined letterwise
  modulo 26, the only two-operand combination the 21/49/21 symmetry suggests

Each source is expanded over two orientations, two letter cases, and eight
fixed byte derivations.  Nothing here scores plaintext, and AES padding is
never acceptance: the only acceptance gate is :mod:`solver.targets`.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import extract_raw, sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "youwon_middle_block_preregistered.json"
SEAL_PATH = ROOT / "youwon_middle_block_preregistered.sha256"
RESULT_PATH = ROOT / "youwon_middle_block_audit.json"
PHASE32_PATH = ROOT / "phase32_classical.json"

ORIENTATIONS = ("forward", "reversed")
CASES = ("upper", "lower")
DERIVATIONS = (
    "sha256",
    "double_sha256",
    "sha256^0x7f",
    "sha256_reversed",
    "base26_A0_bigendian",
    "base26_A1_bigendian",
    "sha256_of_A0_bytes",
    "sha256_of_A1_bytes",
)
AES_DIGESTS = ("md5", "sha256")
AES_PASSWORD_FORMS = ("literal", "sha256_lowercase_hex")

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def difference_state() -> dict[str, str]:
    """Re-derive ``D`` and the blocks the 21/49/21 split defines."""
    s91 = extract_raw().s91.upper()
    m91 = json.loads(PHASE32_PATH.read_text(encoding="utf-8"))["vic"]["plaintext"].upper()
    if len(s91) != 91 or len(m91) != 91 or not s91.isalpha() or not m91.isalpha():
        raise ValueError("both operands must be 91 pure letters")
    difference = "".join(chr((ord(a) - ord(b)) % 26 + ord("A")) for a, b in zip(s91, m91))
    index = difference.find("YOUWON")
    if index != 21:
        raise ValueError(f"YOUWON is not at index 21 (found {index}); upstream drift")
    head, middle, tail = difference[:21], difference[21:70], difference[70:]
    if (len(head), len(middle), len(tail)) != (21, 49, 21):
        raise ValueError("the 21/49/21 split did not reproduce")
    letterwise = lambda op: "".join(  # noqa: E731 - table-like definition
        chr(op(ord(a) - 65, ord(b) - 65) % 26 + 65) for a, b in zip(head, tail)
    )
    return {
        "difference_full": difference,
        "head21": head,
        "middle49": middle,
        "tail21": tail,
        "middle_after_youwon43": middle[6:],
        "head_plus_tail42": head + tail,
        "flanks_sum21": letterwise(lambda x, y: x + y),
        "flanks_diff21": letterwise(lambda x, y: x - y),
    }


def build_manifest() -> dict[str, object]:
    state = difference_state()
    return {
        "schema": "youwon-middle-block-preregistration-v44",
        "status": "SEALED_BEFORE_SCALAR_OR_AES_EVALUATION",
        "hypothesis": (
            "The 49-letter block that YOUWON opens inside D = S91 - VIC (mod 26), "
            "and the two 21-letter flanks the split leaves, carry the intended "
            "continuation of the alignment."
        ),
        "supersedes_note": (
            "v42 (v42_s91_middle_block.json) is labelled as this block but slices "
            "the raw base-9 field S91[21:70], not D[21:70]. The named operand is "
            "untested before this manifest."
        ),
        "sources": {name: {"length": len(text), "sha256": sha256_hex(text.encode("ascii"))} for name, text in state.items()},
        "expansion": {
            "orientations": list(ORIENTATIONS),
            "cases": list(CASES),
            "derivations": list(DERIVATIONS),
            "logical_scalar_candidates": len(state) * len(ORIENTATIONS) * len(CASES) * len(DERIVATIONS),
        },
        "aes_family": {
            "target": "the authenticated SalPhaseIon short envelope",
            "password_sources": sorted(state),
            "password_forms": list(AES_PASSWORD_FORMS),
            "kdf_digests": list(AES_DIGESTS),
            "logical_trials": len(state) * len(CASES) * len(AES_PASSWORD_FORMS) * len(AES_DIGESTS),
        },
        "acceptance": {
            "only_gate": "solver.targets.gate_scalar_bytes",
            "half": {"exact_public_key": HALF_PUBLIC_UNCOMPRESSED.hex()},
            "better_half": {"hash160": BETTER_H160.hex()},
            "explicitly_not_acceptance": [
                "valid PKCS#7 padding",
                "readable English fragments",
                "vanity address prefixes",
            ],
            "planted_control_scalar": CONTROL_SCALAR_HEX,
        },
        "out_of_scope": [
            "any cipher whose key is a free parameter",
            "re-enumerating the v42 raw-S91 slice",
            "the KMODEST / BE MODEST continuation, already gated in youwon_index21_audit.json",
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
