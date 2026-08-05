"""Exact-gated audit of a bounded ``matrixsumlist`` interpretation family.

The SalPhaseIon word ``matrixsumlist`` and its 91-symbol field are authentic.
The transformations below are explicitly *exploratory*: they enumerate a
finite, reproducible interpretation of matrix/sum/list rather than claiming a
creator-authored grammar.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import itertools
import json

from .extract import ROOT
from .prime_reinsertion_audit import (
    TARGET_ADDRESS,
    TARGET_X,
    TARGET_Y,
    _image_records,
    _prefix,
    _primes,
    _target_match,
)
from .secp256k1_verify import N


RESULT_PATH = ROOT / "matrixsumlist_audit.json"


def _transforms(matrix: list[list[int]]):
    def rotate(value: list[list[int]]) -> list[list[int]]:
        return [list(row) for row in zip(*value[::-1])]

    seen: set[tuple[tuple[int, ...], ...]] = set()
    current = matrix
    for rotation in range(4):
        for reflected, value in ((False, current), (True, [row[::-1] for row in current])):
            key = tuple(tuple(row) for row in value)
            if key not in seen:
                seen.add(key)
                suffix = "_mirror" if reflected else ""
                yield f"rot{rotation * 90}{suffix}", value
        current = rotate(current)


def _digital_root(value: int) -> int:
    return 1 + (value - 1) % 9


def _lists91(vector: list[int]):
    pairs = list(itertools.combinations(range(14), 2))
    yield "pairs", [vector[left] + vector[right] for left, right in pairs]
    yield "pairs_reverse", [vector[left] + vector[right] for left, right in reversed(pairs)]

    for descending in (False, True):
        lengths = range(14, 1, -1) if descending else range(2, 15)
        for reverse_starts in (False, True):
            output: list[int] = []
            for length in lengths:
                starts = list(range(15 - length))
                if reverse_starts:
                    starts.reverse()
                output.extend(sum(vector[start : start + length]) for start in starts)
            label = f"intervals_{'desc' if descending else 'asc'}"
            if reverse_starts:
                label += "_reverse_starts"
            yield label, output


def _triangle_orders(values: list[int]):
    rows: list[list[int]] = []
    offset = 0
    for width in range(1, 14):
        rows.append(values[offset : offset + width])
        offset += width
    if offset != 91:
        raise ValueError("triangle input is not 91 elements")
    yield "identity", values
    yield "reverse", values[::-1]
    yield "reverse_each_row", [value for row in rows for value in row[::-1]]
    yield "reverse_rows", [value for row in rows[::-1] for value in row]
    yield "columns", [rows[row][column] for column in range(13) for row in range(column, 13)]
    yield "columns_reverse", [
        rows[row][column]
        for column in range(12, -1, -1)
        for row in range(12, column - 1, -1)
    ]


def _base9_outputs(digits: list[int]):
    values = [digit - 1 for digit in digits]
    if any(not 0 <= value < 9 for value in values):
        raise ValueError("base-9 digit outside 1..9")
    number = 0
    for value in values:
        number = number * 9 + value
    raw = number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
    yield "integer-minimal", raw
    for width in range(2, 9):
        if len(values) % width or 9**width > 256:
            continue
        yield f"chunks-{width}", bytes(
            sum(values[offset + index] * 9 ** (width - 1 - index) for index in range(width))
            for offset in range(0, len(values), width)
        )


def run() -> dict[str, object]:
    prefix = _prefix()
    target = [ord(symbol) - ord("a") + 1 for symbol in prefix]
    matrix, _, colors, _, _ = _image_records()
    primes = _primes(91)
    color_bits = [int(value == 15) for value in colors]

    structural_hypotheses = 0
    exact_key_matches: list[str] = []
    maximum_key_equalities = 0
    output_records = 0
    output_kinds: Counter[str] = Counter()
    raw_lengths: Counter[int] = Counter()
    unique_raw: set[bytes] = set()
    raw_32_records = 0
    scalar_records = 0
    scalar_sources: dict[int, str] = {}
    zero_scalar_records = 0

    def submit(value: bytes, provenance: str) -> None:
        nonlocal scalar_records, zero_scalar_records
        scalar_records += 1
        scalar = int.from_bytes(value, "big") % N
        if scalar == 0:
            zero_scalar_records += 1
            return
        scalar_sources.setdefault(scalar, provenance)

    for transform_name, transformed in _transforms(matrix):
        vectors = {
            "row_ones": [sum(row) for row in transformed],
            "row_binary": [int("".join(str(value) for value in row), 2) for row in transformed],
            "row_transitions": [sum(left != right for left, right in zip(row, row[1:])) for row in transformed],
        }
        for vector_name, vector in vectors.items():
            for list_name, generated in _lists91(vector):
                mappings = (
                    ("digital_root", [_digital_root(value) for value in generated]),
                    ("mod9_zero_to9", [value % 9 or 9 for value in generated]),
                )
                for mapping_name, key in mappings:
                    for order_name, ordered_key in _triangle_orders(key):
                        key_provenance = f"{transform_name}/{vector_name}/{list_name}/{mapping_name}/{order_name}"
                        equalities = sum(left == right for left, right in zip(target, ordered_key))
                        maximum_key_equalities = max(maximum_key_equalities, equalities)
                        if equalities == 91:
                            exact_key_matches.append(key_provenance)
                        for operation, decoded in (
                            ("prefix-key", [_digital_root(left - right) for left, right in zip(target, ordered_key)]),
                            ("key-prefix", [_digital_root(right - left) for left, right in zip(target, ordered_key)]),
                            ("prefix+key", [_digital_root(left + right) for left, right in zip(target, ordered_key)]),
                        ):
                            structural_hypotheses += 1
                            selected = [decoded[position - 1] for position in primes]
                            projections = (
                                ("full91", decoded),
                                ("primes", selected),
                                ("prime_blue", [digit for digit, bit in zip(selected, color_bits) if bit]),
                                ("prime_yellow", [digit for digit, bit in zip(selected, color_bits) if not bit]),
                                ("prime_color_shift", [_digital_root(digit + bit) for digit, bit in zip(selected, color_bits)]),
                            )
                            for projection, digits in projections:
                                digit_ascii = "".join(str(digit) for digit in digits).encode("ascii")
                                projection_provenance = f"{key_provenance}/{operation}/{projection}"
                                # The digit string is itself an explicit serialization.
                                submit(hashlib.sha256(digit_ascii).digest(), f"SHA256(digits:{projection_provenance})")
                                for decode_name, raw in _base9_outputs(digits):
                                    output_records += 1
                                    output_kinds[f"{projection}/{decode_name}"] += 1
                                    raw_lengths[len(raw)] += 1
                                    unique_raw.add(raw)
                                    raw_provenance = f"{projection_provenance}/{decode_name}"
                                    if len(raw) == 32:
                                        raw_32_records += 1
                                        submit(raw, raw_provenance)
                                    submit(hashlib.sha256(raw).digest(), f"SHA256(raw:{raw_provenance})")

    if structural_hypotheses != 5184 or output_records != 36288:
        raise ValueError(f"search cardinality changed: {structural_hypotheses=}, {output_records=}")

    matches: list[dict[str, str]] = []
    for scalar, provenance in scalar_sources.items():
        if _target_match(scalar):
            matches.append({
                "derivation": provenance,
                "private_hex": f"{scalar:064x}",
                "address": TARGET_ADDRESS,
            })

    result: dict[str, object] = {
        "status": "MATCH" if matches else "NO_MATCH_IN_ENUMERATED_FAMILY",
        "authenticated_inputs": {
            "prefix_length": len(prefix),
            "prefix_sha256": hashlib.sha256(prefix.encode("ascii")).hexdigest(),
            "decoded_instruction": "matrixsumlist",
            "prime_positions": primes,
            "color_bits_row_major": color_bits,
        },
        "evidence_boundary": "Only the S91 field and decoded word matrixsumlist are authenticated. Every transform/list/order/operation below is an explicitly enumerated exploratory interpretation, not a creator-documented rule.",
        "family": {
            "grid_transforms": 8,
            "row_vectors": ["row_ones", "row_binary", "row_transitions"],
            "list_constructions": ["pairs", "pairs_reverse", "intervals_asc", "intervals_asc_reverse_starts", "intervals_desc", "intervals_desc_reverse_starts"],
            "digit_mappings": ["digital_root", "mod9_zero_to9"],
            "triangle_orders": ["identity", "reverse", "reverse_each_row", "reverse_rows", "columns", "columns_reverse"],
            "operations": ["prefix-key", "key-prefix", "prefix+key"],
            "projections": ["full91", "primes", "prime_blue", "prime_yellow", "prime_color_shift"],
            "base9_decodings": ["minimal big-endian integer", "two-digit chunks when length is even"],
        },
        "structural_hypotheses": structural_hypotheses,
        "exact_generated_key_matches": exact_key_matches,
        "maximum_generated_key_equalities_of_91": maximum_key_equalities,
        "base9_output_records": output_records,
        "output_records_by_kind": dict(sorted(output_kinds.items())),
        "raw_length_histogram": {str(length): count for length, count in sorted(raw_lengths.items())},
        "unique_raw_outputs": len(unique_raw),
        "raw_32_byte_records": raw_32_records,
        "scalar_serializations": ["raw output when exactly 32 bytes", "SHA256(base-9 decoded raw bytes)", "SHA256(ASCII digits 1..9)"],
        "scalar_candidate_records": scalar_records,
        "zero_scalar_records": zero_scalar_records,
        "unique_nonzero_scalars": len(scalar_sources),
        "target": {"x": f"{TARGET_X:064x}", "y": f"{TARGET_Y:064x}", "address": TARGET_ADDRESS},
        "matches": matches,
        "scope_note": "This falsifies only the fully enumerated exploratory family above. It does not show that every possible meaning of matrixsumlist is wrong.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
