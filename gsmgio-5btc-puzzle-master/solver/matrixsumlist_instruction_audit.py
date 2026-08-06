"""Evaluate the sealed v48 ``matrixsumlist``-as-instruction family.

Verifies the seal, re-derives the fields, fails on drift, runs a planted
positive control through the production gate, then executes the three sealed
tests: the dimensional census, the self-labelling test, and the bounded scalar
and AES family.  Field agreements are scored against a Monte Carlo null and are
never acceptance.

Run ``python -m solver.matrixsumlist_instruction_audit``.
"""

from __future__ import annotations

import hashlib
import json
import random

from . import targets
from .matrixsumlist_instruction_preregister import (
    AES_DIGESTS,
    AES_PASSWORD_FORMS,
    DERIVATIONS,
    MANIFEST_PATH,
    MONTE_CARLO_SEED,
    MONTE_CARLO_TRIALS,
    RESULT_PATH,
    SEAL_PATH,
    SELF_LABEL,
    SELF_LABEL_REDUCTIONS,
    SERIALIZATIONS,
    build_manifest,
    census,
    comparison_targets,
    source_fields,
    sum_lists,
)
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion_raw import extract_raw

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def _serialize(values: list[int], name: str) -> bytes:
    if name == "raw_sum_bytes":
        return bytes(value % 256 for value in values)
    if name == "ascii_decimal_concat":
        return "".join(str(value) for value in values).encode("ascii")
    if name == "ascii_two_digit_concat":
        return "".join(f"{value % 100:02d}" for value in values).encode("ascii")
    if name == "ascii_csv":
        return ",".join(str(value) for value in values).encode("ascii")
    if name == "ascii_space":
        return " ".join(str(value) for value in values).encode("ascii")
    if name == "mod10_ascii":
        return "".join(str(value % 10) for value in values).encode("ascii")
    if name == "mod9_zero_ascii":
        return "".join(str(value % 9) for value in values).encode("ascii")
    if name == "mod9_zero_to9_ascii":
        return "".join(str(value % 9 or 9) for value in values).encode("ascii")
    if name == "mod26_A0_ascii":
        return "".join(chr(65 + value % 26) for value in values).encode("ascii")
    raise ValueError(f"unsealed serialization: {name}")


def _derive(value: bytes, name: str) -> bytes:
    digest = hashlib.sha256(value).digest()
    if name == "sha256":
        return digest
    if name == "double_sha256":
        return hashlib.sha256(digest).digest()
    if name == "sha256^0x7f":
        return bytes(byte ^ 0x7F for byte in digest)
    if name == "sha256_reversed":
        return digest[::-1]
    raise ValueError(f"unsealed derivation: {name}")


def _reduce_to_letters(values: list[int], reduction: str) -> str:
    if reduction == "mod26_A0":
        return "".join(chr(65 + value % 26) for value in values)
    if reduction == "mod26_A1":
        return "".join(chr(65 + (value - 1) % 26) for value in values)
    if reduction == "mod26_negated":
        return "".join(chr(65 + (-value) % 26) for value in values)
    raise ValueError(f"unsealed reduction: {reduction}")


def _self_labelling() -> dict[str, object]:
    """Does S91 as 7x13 spell its own 13-letter name in its column sums?"""
    text = source_fields()["s91"]
    records = []
    for mapping, offset in (("one_based", 1), ("zero_based", 0)):
        values = [ord(character) - 97 + offset for character in text]
        grid = [values[index * 13 : (index + 1) * 13] for index in range(7)]
        column_sums = [sum(row[column] for row in grid) for column in range(13)]
        for reduction in SELF_LABEL_REDUCTIONS:
            candidate = _reduce_to_letters(column_sums, reduction)
            records.append(
                {
                    "mapping": mapping,
                    "reduction": reduction,
                    "column_sums": column_sums,
                    "string": candidate,
                    "positions_matching_name": sum(a == b for a, b in zip(candidate, SELF_LABEL)),
                    "exact": candidate == SELF_LABEL,
                }
            )
    return {
        "expected": SELF_LABEL,
        "records": records,
        "any_exact": any(record["exact"] for record in records),
        "best_positions_of_13": max(record["positions_matching_name"] for record in records),
    }


def _agreement_with_nulls() -> list[dict[str, object]]:
    """Score each dimensionally legal comparison against a shuffled-source null."""
    fields = source_fields()
    comparisons = comparison_targets()
    reductions = {
        "mod10": lambda value: value % 10,
        "mod9": lambda value: value % 9,
        "mod9_1to9": lambda value: value % 9 or 9,
        "mod26": lambda value: value % 26,
    }
    results = []
    for entry in census():
        provenance: str = entry["sum_list"]  # type: ignore[assignment]
        field_name, mapping, layout, axis = provenance.split("/")
        target = comparisons[entry["matches_length_of"]]  # type: ignore[index]
        rows, columns = (int(part) for part in layout.split("x"))
        offset = 1 if mapping == "one_based" else 0
        base = [ord(character) - 97 + offset for character in fields[field_name]]

        def sums_of(values: list[int]) -> list[int]:
            grid = [values[index * columns : (index + 1) * columns] for index in range(rows)]
            if axis == "rowsums":
                return [sum(row) for row in grid]
            return [sum(row[column] for row in grid) for column in range(columns)]

        actual = sums_of(base)
        for reduction_name, reduce in reductions.items():
            observed = sum(reduce(a) == b for a, b in zip(actual, target))
            generator = random.Random(MONTE_CARLO_SEED)
            shuffled = list(base)
            at_least = 0
            for _ in range(MONTE_CARLO_TRIALS):
                generator.shuffle(shuffled)
                trial = sum(reduce(a) == b for a, b in zip(sums_of(shuffled), target))
                if trial >= observed:
                    at_least += 1
            results.append(
                {
                    "sum_list": provenance,
                    "target": entry["matches_length_of"],
                    "reduction": reduction_name,
                    "observed_agreement": observed,
                    "of": len(target),
                    "null_trials": MONTE_CARLO_TRIALS,
                    "null_at_least_as_extreme": at_least,
                    "p_value": at_least / MONTE_CARLO_TRIALS,
                }
            )
    return results


def _printable_ratio(value: bytes) -> float:
    return sum(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in value) / max(1, len(value))


def _control() -> dict[str, object]:
    scalar = int(CONTROL_SCALAR_HEX, 16)
    x, y = targets._public_point(scalar)
    planted = targets.gate_point(
        x,
        y,
        half_public=targets.serializations(x, y)["uncompressed"],
        half_h160=targets.HALF_H160,
        better_h160=targets.BETTER_H160,
    )
    return {
        "scalar": CONTROL_SCALAR_HEX,
        "accepted_against_planted_target": planted is not None,
        "rejected_against_real_targets": targets.gate_scalar(scalar) is None,
    }


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    actual_seal = hashlib.sha256(encoded).hexdigest()
    if actual_seal != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if manifest["status"] != "SEALED_BEFORE_SCALAR_OR_AES_EVALUATION":
        raise ValueError("manifest is not marked sealed")
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("re-derived manifest differs from the sealed manifest")

    control = _control()
    if not (control["accepted_against_planted_target"] and control["rejected_against_real_targets"]):
        raise ValueError("the gate failed its own control; results would be meaningless")

    lists = sum_lists()
    raw = extract_raw()

    matches: list[dict[str, object]] = []
    seen: set[bytes] = set()

    def gate(value: bytes, provenance: str) -> None:
        if len(value) != 32 or value in seen:
            return
        seen.add(value)
        hit = targets.gate_scalar_bytes(value)
        if hit:
            matches.append({"provenance": provenance, "scalar_hex": value.hex(), "gate": hit})

    serialized: list[tuple[str, bytes]] = []
    for name, values in sorted(lists.items()):
        for serialization in SERIALIZATIONS:
            serialized.append((f"{name}/{serialization}", _serialize(values, serialization)))

    for provenance, value in serialized:
        for derivation in DERIVATIONS:
            gate(_derive(value, derivation), f"{provenance}/{derivation}")

    aes_tests = 0
    valid_padding: list[dict[str, object]] = []
    structured: list[dict[str, object]] = []
    passwords: dict[bytes, list[str]] = {}
    for provenance, value in serialized:
        digest = hashlib.sha256(value).digest()
        for form in AES_PASSWORD_FORMS:
            password = value if form == "literal" else digest.hex().encode("ascii")
            passwords.setdefault(password, []).append(f"{provenance}/{form}")

    for password, provenances in passwords.items():
        for kdf in AES_DIGESTS:
            aes_tests += 1
            try:
                decrypted = decrypt_salted_aes256_cbc(raw.short_envelope, password, digest=kdf)
            except ValueError:
                continue
            record = {
                "provenances": provenances[:3],
                "provenance_count": len(provenances),
                "kdf_digest": kdf,
                "plaintext_hex": decrypted.plaintext.hex(),
                "printable_ratio": _printable_ratio(decrypted.plaintext),
                "padding_length": decrypted.padding_length,
            }
            valid_padding.append(record)
            lowered = decrypted.plaintext.lower()
            if record["printable_ratio"] >= 0.85 or any(
                token in lowered for token in (b"private", b"bitcoin", b"matrix", b"key", b"gsmg")
            ):
                structured.append(record)
            for offset in range(max(0, len(decrypted.plaintext) - 31)):
                gate(decrypted.plaintext[offset : offset + 32], f"AES-window/{provenances[0]}/{kdf}/offset-{offset}")

    census_records = census()
    self_labelling = _self_labelling()
    agreements = _agreement_with_nulls()

    result = {
        "schema": "matrixsumlist-instruction-audit-v48",
        "status": "MATCH" if matches else "NO_PRIZE_MATCH_IN_PREREGISTERED_FAMILY",
        "preregistration_sha256": actual_seal,
        "dimensional_census": {
            "sum_lists_enumerated": len(lists),
            "that_can_address_another_field": len(census_records),
            "records": census_records,
            "finding": (
                "Across every rectangular factorisation of 91, 570 and 567, only the "
                "9x63 and 63x9 readings of S570-after-fae produce a sum list whose "
                "length matches another authenticated field, and all four point at "
                "the same 63-symbol lastwords field. Nothing addresses the 29-symbol "
                "password field or S91."
            ),
        },
        "self_labelling_test": self_labelling,
        "field_agreements_against_null": agreements,
        "whole_field_totals": {
            "s91_one_based": sum(ord(character) - 96 for character in source_fields()["s91"]),
            "s570_one_based": sum(ord(character) - 96 for character in source_fields()["s570"]),
            "note": "422 reproduces the historical S91 matrix-sum total recorded in tmp/kenorb-analysis.md",
        },
        "serialized_records": len(serialized),
        "unique_scalar_tests": len(seen),
        "unique_passwords": len(passwords),
        "aes_tests": aes_tests,
        "valid_padding_count": len(valid_padding),
        "structured_plaintexts": structured,
        "control": control,
        "matches": matches,
        "scope_note": (
            "Falsifies only the sealed v48 family: every forced rectangular sum list "
            "of S91, S570 and S570-after-fae under two mappings and both axes, over "
            "nine serialisations and four derivations, plus the listed short-envelope "
            "AES trials. It does not refute matrixsumlist as a literal, and it cannot "
            "refute an instruction reading whose object is some artifact other than "
            "these three fields."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    outcome = run()
    printable = {
        key: value
        for key, value in outcome.items()
        if key not in ("field_agreements_against_null", "self_labelling_test")
    }
    print(json.dumps(printable, indent=2))
    print("\nself-labelling best:", outcome["self_labelling_test"]["best_positions_of_13"], "of 13")
    for record in outcome["field_agreements_against_null"]:
        print(
            f"  {record['observed_agreement']:3d}/{record['of']}  p={record['p_value']:.4f}  "
            f"{record['sum_list']} [{record['reduction']}]"
        )
