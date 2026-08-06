"""Seal the v48 test of ``matrixsumlist`` as an instruction over the S-fields.

``CLAUDE.md`` records an unresolved tension.  ``matrixsumlist`` is an
authenticated SalPhaseIon *literal* -- the 104-symbol ``a``/``b`` block decodes
to it exactly -- and it is also phrase 2 of the creator's ordered seven-phrase
pipeline, which reads like an *instruction*.  If it is an instruction, the
obvious objects for it to operate on are the two undecoded base-9 fields that
sit beside it, ``S91`` and ``S570``.

This manifest freezes three things, in increasing strength.

**1. The dimensional census.**  An instruction "make a matrix, sum it, list the
sums" is only meaningful if the resulting list has somewhere to go.  Enumerate
every rectangular factorisation of 91, 570 and 567 (the remainder after the
``fae`` header), take row and column sums, and record which sum lists have a
length matching another authenticated field.  This is a closed question with a
small answer, and it bounds the whole "bridge two fields" reading.

**2. The self-labelling test.**  ``S91 = 7 x 13`` and ``matrixsumlist`` is
exactly 13 letters, so a 7x13 matrix has one column per letter of its own name.
If the 13 column sums spelled ``MATRIXSUMLIST`` the instruction reading would be
self-authenticating.

**3. A bounded scalar and AES family.**  Every sum list from every forced
factorisation, under two ``a..i`` mappings and both axes, over the nine
serialisations the sealed F-A-E audit used, plus the three whole-field totals.

Statistical honesty: any field-to-field agreement is scored against a Monte
Carlo null built by shuffling the source field, because a partial agreement
between two base-9 streams is expected at roughly one in nine or one in ten per
position.  Agreement is **never** an acceptance criterion; the only gate is
:mod:`solver.targets`.

Scope note for the existing artifact: ``matrixsumlist_audit.json`` states in its
own scope note that it falsifies "only the fully enumerated exploratory family
above", and it is computed over the S91 field.  v48 covers S570 and S567
systematically and adds the census and the self-labelling test.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import extract_raw, sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "matrixsumlist_instruction_preregistered.json"
SEAL_PATH = ROOT / "matrixsumlist_instruction_preregistered.sha256"
RESULT_PATH = ROOT / "matrixsumlist_instruction_audit.json"

MAPPINGS = ("one_based", "zero_based")
AXES = ("rowsums", "colsums")
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
DERIVATIONS = ("sha256", "double_sha256", "sha256^0x7f", "sha256_reversed")
AES_DIGESTS = ("md5", "sha256")
AES_PASSWORD_FORMS = ("literal", "sha256_lowercase_hex")

SELF_LABEL = "MATRIXSUMLIST"
SELF_LABEL_REDUCTIONS = ("mod26_A0", "mod26_A1", "mod26_negated")

MONTE_CARLO_TRIALS = 20000
MONTE_CARLO_SEED = 20260806

# a=1..i=9 with o=0, the mapping the authenticated decimal fields already use.
DIGIT_MAP = {**{chr(97 + index): index + 1 for index in range(9)}, "o": 0}


def factorisations(total: int) -> list[tuple[int, int]]:
    """Every rectangle with both sides above one, so no degenerate layouts."""
    return [(rows, total // rows) for rows in range(2, total) if total % rows == 0 and total // rows > 1]


def source_fields() -> dict[str, str]:
    raw = extract_raw()
    if len(raw.s91) != 91 or len(raw.s570) != 570:
        raise ValueError("S91/S570 lengths drifted")
    if not raw.s570.startswith("fae"):
        raise ValueError("S570 no longer starts with fae")
    return {"s91": raw.s91, "s570": raw.s570, "s570_after_fae": raw.s570[3:]}


def comparison_targets() -> dict[str, list[int]]:
    raw = extract_raw()
    return {
        "lastwords63": [DIGIT_MAP[character] for character in raw.lastwords_numeric],
        "password29": [DIGIT_MAP[character] for character in raw.password_numeric],
        "s91": [DIGIT_MAP[character] for character in raw.s91],
    }


def sum_lists() -> dict[str, list[int]]:
    """Every forced matrix-sum list, keyed by its full provenance."""
    lists: dict[str, list[int]] = {}
    for field_name, text in sorted(source_fields().items()):
        for mapping in MAPPINGS:
            offset = 1 if mapping == "one_based" else 0
            values = [ord(character) - 97 + offset for character in text]
            for rows, columns in factorisations(len(values)):
                grid = [values[index * columns : (index + 1) * columns] for index in range(rows)]
                lists[f"{field_name}/{mapping}/{rows}x{columns}/rowsums"] = [sum(row) for row in grid]
                lists[f"{field_name}/{mapping}/{rows}x{columns}/colsums"] = [
                    sum(row[column] for row in grid) for column in range(columns)
                ]
            lists[f"{field_name}/{mapping}/whole_field_total"] = [sum(values)]
    return lists


def census() -> list[dict[str, object]]:
    """Which forced sum lists could even address another authenticated field."""
    targets = comparison_targets()
    found = []
    for name, values in sorted(sum_lists().items()):
        for target_name, target in sorted(targets.items()):
            if len(values) == len(target):
                found.append({"sum_list": name, "matches_length_of": target_name, "length": len(target)})
    return found


def build_manifest() -> dict[str, object]:
    lists = sum_lists()
    fields = source_fields()
    return {
        "schema": "matrixsumlist-instruction-preregistration-v48",
        "status": "SEALED_BEFORE_SCALAR_OR_AES_EVALUATION",
        "hypothesis": (
            "matrixsumlist is an instruction as well as a literal, and its object is "
            "S91 or S570: build the matrix, sum it, and the resulting list is the "
            "next operand."
        ),
        "tension_being_tested": (
            "matrixsumlist is an authenticated SalPhaseIon literal and simultaneously "
            "phrase 2 of the creator's ordered pipeline. CLAUDE.md records that this "
            "is unresolved."
        ),
        "frozen_inputs": {
            name: {"length": len(text), "sha256": sha256_hex(text.encode("ascii")), "alphabet": "".join(sorted(set(text)))}
            for name, text in sorted(fields.items())
        },
        "dimensional_census": census(),
        "self_labelling_test": {
            "claim": "S91 as 7x13 has one column per letter of its own 13-letter name",
            "expected_string": SELF_LABEL,
            "reductions": list(SELF_LABEL_REDUCTIONS),
        },
        "expansion": {
            "mappings": list(MAPPINGS),
            "axes": list(AXES),
            "serializations": list(SERIALIZATIONS),
            "derivations": list(DERIVATIONS),
            "sum_lists": len(lists),
            "logical_scalar_candidates": len(lists) * len(SERIALIZATIONS) * len(DERIVATIONS),
        },
        "aes_family": {
            "target": "the authenticated SalPhaseIon short envelope",
            "password_forms": list(AES_PASSWORD_FORMS),
            "kdf_digests": list(AES_DIGESTS),
        },
        "statistics": {
            "null_model": "uniform random permutations of the source field",
            "trials": MONTE_CARLO_TRIALS,
            "seed": MONTE_CARLO_SEED,
            "purpose": "context for any field-to-field agreement; agreement is never acceptance",
        },
        "acceptance": {
            "only_gate": "solver.targets.gate_scalar_bytes",
            "half": {"exact_public_key": HALF_PUBLIC_UNCOMPRESSED.hex()},
            "better_half": {"hash160": BETTER_H160.hex()},
            "explicitly_not_acceptance": [
                "valid PKCS#7 padding",
                "readable English fragments",
                "a high elementwise agreement between a sum list and another field",
            ],
        },
        "out_of_scope": [
            "non-rectangular or overlapping matrix layouts",
            "any cipher whose key is a free parameter",
            "Cosmic, Chain 4 and base-38 operands",
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
