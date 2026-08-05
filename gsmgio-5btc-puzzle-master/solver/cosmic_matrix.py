"""Test the 103x103 bit-matrix interpretation without assuming shift 7."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ShiftCandidate:
    shift: int
    minimum: int
    maximum: int
    secondary: bytes


@dataclass(frozen=True)
class CosmicMatrixResult:
    bits: tuple[int, ...]
    matrix_bits: tuple[int, ...]
    trailing_bits: tuple[int, ...]
    row_sums: tuple[int, ...]
    column_sums: tuple[int, ...]
    total_ones: int
    weighted_rows: int
    weighted_columns: int
    range_candidates: tuple[ShiftCandidate, ...]
    exact_range_candidates: tuple[ShiftCandidate, ...]
    selected: ShiftCandidate
    digits: tuple[int, ...]
    base38_bytes: bytes
    half: bytes
    better_half: bytes
    trail1: bytes


def _bits_msb(data: bytes) -> tuple[int, ...]:
    return tuple((byte >> bit) & 1 for byte in data for bit in range(7, -1, -1))


def base_digits_to_bytes(digits: tuple[int, ...], base: int) -> bytes:
    if base < 2 or any(not 0 <= digit < base for digit in digits):
        raise ValueError("digit is invalid for requested base")
    value = 0
    for digit in digits:
        value = value * base + digit
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def analyze(cosmic: bytes) -> CosmicMatrixResult:
    if len(cosmic) != 1327:
        raise ValueError("103x103 interpretation requires the 1327-byte artifact")
    bits = _bits_msb(cosmic)
    matrix_bits = bits[: 103 * 103]
    trailing_bits = bits[103 * 103 :]
    rows = tuple(sum(matrix_bits[row * 103 : (row + 1) * 103]) for row in range(103))
    columns = tuple(sum(matrix_bits[row * 103 + col] for row in range(103)) for col in range(103))
    candidates = []
    exact = []
    for shift in range(103):
        secondary = bytes(rows[i] + columns[(i + shift) % 103] for i in range(103))
        candidate = ShiftCandidate(shift, min(secondary), max(secondary), secondary)
        if candidate.minimum >= 80 and candidate.maximum <= 117:
            candidates.append(candidate)
        if candidate.minimum == 80 and candidate.maximum == 117:
            exact.append(candidate)
    if len(exact) != 1:
        raise ValueError(f"expected a unique exact 80..117 range, found {len(exact)}")
    selected = exact[0]
    digits = tuple(value - 80 for value in selected.secondary)
    decoded = base_digits_to_bytes(digits, 38)
    if len(decoded) != 68:
        raise ValueError("base-38 output is not 68 bytes")
    return CosmicMatrixResult(
        bits=bits,
        matrix_bits=matrix_bits,
        trailing_bits=trailing_bits,
        row_sums=rows,
        column_sums=columns,
        total_ones=sum(rows),
        weighted_rows=sum((i + 1) * value for i, value in enumerate(rows)),
        weighted_columns=sum((i + 1) * value for i, value in enumerate(columns)),
        range_candidates=tuple(candidates),
        exact_range_candidates=tuple(exact),
        selected=selected,
        digits=digits,
        base38_bytes=decoded,
        half=decoded[:32],
        better_half=decoded[32:64],
        trail1=decoded[64:68],
    )

