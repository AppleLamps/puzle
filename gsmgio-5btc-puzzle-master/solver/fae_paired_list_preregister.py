"""Seal the v45 candidate family pairing the 9x63 sum list with the F63 field.

``docs/ATTEMPT_LOG.md`` §13 closes the direct serialisations of the ``fae`` +
9x63 sum lists as a bounded negative and leaves one residual explicitly OPEN:

    test a preregistered operation combining the 63 generated sums with the
    immediately following F63 raw digits

That is what this manifest freezes.  The two operands are the same
authenticated objects the sealed v-F-A-E audit used:

* ``sums``  -- the 63-element lists obtained from ``S570[3:]`` (567 = 9 x 63)
  under the one-based and zero-based ``a..i`` mappings, read as source-order
  9x63 column sums and as source-order 63x9 row sums.
* ``F63``   -- the immediately following 63-symbol raw field, read with the
  established SalPhaseIon digit mapping ``a=1..i=9, o=0``.  This is the field
  that decodes to ``lastwordsbeforearchichoice``.

Both lists have exactly 63 entries, which is what makes an elementwise pairing
the low-free-parameter reading rather than another chosen layout.  Eight fixed
elementwise operations are sealed, plus the two order-preserving interleaves,
and each resulting list is expanded over the same nine serialisations the
v-F-A-E audit already used, so this family is a strict extension of a sealed
negative rather than a new grammar.

The only acceptance gate is :mod:`solver.targets`.  Padding is never
acceptance.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import extract_raw, sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "fae_paired_list_preregistered.json"
SEAL_PATH = ROOT / "fae_paired_list_preregistered.sha256"
RESULT_PATH = ROOT / "fae_paired_list_audit.json"

SUM_MAPPINGS = ("one_based", "zero_based")
SUM_LAYOUTS = ("9x63_column_sums", "63x9_row_sums")
PAIR_OPERATIONS = (
    "sum_plus_digit",
    "sum_minus_digit",
    "digit_minus_sum",
    "sum_xor_digit",
    "sum_times_digit",
    "sum_plus_digit_mod9",
    "sum_plus_digit_mod10",
    "sum_plus_digit_mod26",
    "interleave_sum_first",
    "interleave_digit_first",
)
SERIALIZATIONS = (
    "raw_sum_bytes",
    "ascii_decimal_concat",
    "ascii_two_digit_concat",
    "ascii_csv",
    "ascii_space",
    "mod10_ascii",
    "mod9_zero_ascii",
    "mod9_zero_to9_ascii",
    "mod26_A0_ascii",
)
AES_DIGESTS = ("md5", "sha256")
AES_PASSWORD_FORMS = ("literal", "sha256_lowercase_hex")

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"

DIGIT_MAP = {**{chr(97 + index): index + 1 for index in range(9)}, "o": 0}


def operands() -> dict[str, object]:
    """Re-derive the sum lists and the following 63-digit field."""
    raw = extract_raw()
    if not raw.s570.startswith("fae"):
        raise ValueError("S570 no longer starts with fae")
    remainder = raw.s570[3:]
    if len(remainder) != 567 or len(set(raw.s570)) != 9:
        raise ValueError("the 567 = 9 x 63 structural observation changed")
    if len(raw.lastwords_numeric) != 63:
        raise ValueError("the following raw field is no longer 63 symbols")

    sums: dict[str, list[int]] = {}
    for mapping_name in SUM_MAPPINGS:
        offset = 1 if mapping_name == "one_based" else 0
        mapping = {chr(97 + index): index + offset for index in range(9)}
        values = [mapping[character] for character in remainder]
        grid = [values[row * 63 : (row + 1) * 63] for row in range(9)]
        sums[f"{mapping_name}/9x63_column_sums"] = [sum(row[column] for row in grid) for column in range(63)]
        sums[f"{mapping_name}/63x9_row_sums"] = [sum(values[index * 9 : (index + 1) * 9]) for index in range(63)]

    digits = [DIGIT_MAP[character] for character in raw.lastwords_numeric]
    return {"sums": sums, "digits": digits, "f63_text": raw.lastwords_numeric}


def build_manifest() -> dict[str, object]:
    derived = operands()
    sums: dict[str, list[int]] = derived["sums"]  # type: ignore[assignment]
    digits: list[int] = derived["digits"]  # type: ignore[assignment]
    return {
        "schema": "fae-paired-list-preregistration-v45",
        "status": "SEALED_BEFORE_SCALAR_OR_AES_EVALUATION",
        "hypothesis": (
            "The 63 sums generated from the fae-headed 9x63 matrix are meant to be "
            "combined elementwise with the immediately following 63-symbol field, "
            "not serialised on their own."
        ),
        "residual_of": {
            "manifest": "fae_9x63_preregistered.json",
            "result": "fae_9x63_audit.json",
            "open_item": "ATTEMPT_LOG.md section 13, OPEN row",
        },
        "operands": {
            "sum_lists": {name: {"length": len(values), "sha256": sha256_hex(",".join(map(str, values)).encode("ascii"))} for name, values in sorted(sums.items())},
            "f63": {
                "length": len(digits),
                "text": derived["f63_text"],
                "digit_mapping": "a=1..i=9, o=0",
                "sha256": sha256_hex(",".join(map(str, digits)).encode("ascii")),
                "decodes_to": "lastwordsbeforearchichoice",
            },
        },
        "expansion": {
            "sum_mappings": list(SUM_MAPPINGS),
            "sum_layouts": list(SUM_LAYOUTS),
            "pair_operations": list(PAIR_OPERATIONS),
            "serializations": list(SERIALIZATIONS),
            "logical_records": len(sums) * len(PAIR_OPERATIONS) * len(SERIALIZATIONS),
        },
        "aes_family": {
            "target": "the authenticated SalPhaseIon short envelope",
            "password_forms": list(AES_PASSWORD_FORMS),
            "kdf_digests": list(AES_DIGESTS),
        },
        "acceptance": {
            "only_gate": "solver.targets.gate_scalar_bytes",
            "half": {"exact_public_key": HALF_PUBLIC_UNCOMPRESSED.hex()},
            "better_half": {"hash160": BETTER_H160.hex()},
            "explicitly_not_acceptance": [
                "valid PKCS#7 padding",
                "readable English fragments",
                "a high elementwise agreement score between the two lists",
            ],
            "planted_control_scalar": CONTROL_SCALAR_HEX,
        },
        "out_of_scope": [
            "re-running the direct serialisations already sealed in fae_9x63_preregistered.json",
            "any mapping of S570 onto an F-A-E Sonata transcription, which needs an external score",
            "layouts of S570 other than the sealed source-order 9x63 and 63x9 readings",
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
