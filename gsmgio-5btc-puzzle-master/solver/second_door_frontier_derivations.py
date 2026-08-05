"""Second-door frontier derivations for the first rabbit image.

This audit intentionally starts from the creator-sourced "yellowblueprimes"
head and the first image.  It avoids re-running the prior marker-only
yellow/blue audit and instead tests the newer leads:

* sub-cell rabbit nest morphology;
* all-196-cell resistor streams with prime-index zeroing;
* the off-white cell as a third channel;
* yellow/blue resistor digits inserted into the known URL at prime slots;
* 14x14 matrix sums/products/determinants;
* left/right/top/bottom and diagonal "half" splits.

Every byte candidate is expanded through the same gates:

* URL/path-like material and sha256 slug material are recorded;
* AES-256-CBC OpenSSL passwords are tried against Cosmic and the 80-byte
  SalPhaseIon ciphertext envelope;
* scalar candidates are checked against both prize P2PKH targets.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
import string
from pathlib import Path
from typing import Iterable

from PIL import Image

try:  # coincurve is much faster, but keep the script runnable without it.
    from coincurve import PrivateKey as CoincurvePrivateKey
except ImportError:  # pragma: no cover - exercised only in lean environments
    CoincurvePrivateKey = None

from .chains import reconstruct
from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion import derive_tokens
from .salphaseion_blind_eval import _formats, _readable
from .secp256k1_verify import N, base58check, hash160, public_key


RESULT_PATH = ROOT / "second_door_frontier_derivations.json"
IMAGE = Path("/workspace/follow_the_white_rabbit.png")
FALLBACK_IMAGE = ROOT / "puzzle.png"

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)
OFF_WHITE = (254, 254, 254)

URL = b"gsmg.io/theseedisplanted"
URL_PATH = b"theseedisplanted"
GENESIS = 0xF73D92
HALF_ADDR = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER_ADDR = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
HALF_H160 = bytes.fromhex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")
BETTER_H160 = bytes.fromhex("4bc468447fe1b048ad030a2f9a125478eabc4ed6")
HALF_PUB_UNCOMPRESSED = bytes.fromhex(
    "04"
    "f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)
PRIZES = {
    "Half": {"address": HALF_ADDR, "hash160": HALF_H160},
    "Better_Half": {"address": BETTER_ADDR, "hash160": BETTER_H160},
}

IMPURE_RABBIT_CELLS = ((6, 6), (6, 7), (7, 6), (7, 7), (7, 8), (7, 9), (8, 6))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def primes(limit: int) -> set[int]:
    return {
        value
        for value in range(2, limit + 1)
        if all(value % divisor for divisor in range(2, math.isqrt(value) + 1))
    }


def spiral_positions(size: int) -> list[tuple[int, int]]:
    order: list[tuple[int, int]] = []
    top = left = 0
    bottom = right = size - 1
    while top <= bottom and left <= right:
        for row in range(top, bottom + 1):
            order.append((row, left))
        left += 1
        for col in range(left, right + 1):
            order.append((bottom, col))
        bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                order.append((row, right))
            right -= 1
        if top <= bottom:
            for col in range(right, left - 1, -1):
                order.append((top, col))
            top += 1
    return order


def int_to_minimal_bytes(value: int) -> bytes:
    value = abs(value)
    if value == 0:
        return b"\0"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def bits_to_bytes(bits: str) -> bytes:
    padded = bits + "0" * ((8 - len(bits) % 8) % 8)
    return bytes(int(padded[index : index + 8], 2) for index in range(0, len(padded), 8))


def digits_to_base_bytes(digits: str, base: int) -> bytes | None:
    if not digits or any(int(ch) >= base for ch in digits):
        return None
    return int_to_minimal_bytes(int(digits, base))


def chunk_bytes(digits: str, width: int, base: int = 10) -> bytes | None:
    out = bytearray()
    for index in range(0, len(digits), width):
        chunk = digits[index : index + width]
        if len(chunk) != width:
            continue
        if any(int(ch) >= base for ch in chunk):
            return None
        value = int(chunk, base)
        if value > 255:
            return None
        out.append(value)
    return bytes(out) if out else None


KEYPAD = {
    "2": "ABC",
    "3": "DEF",
    "4": "GHI",
    "5": "JKL",
    "6": "MNO",
    "7": "PQRS",
    "8": "TUV",
    "9": "WXYZ",
}


def keypad_first_letters(digits: str) -> bytes:
    text = []
    for digit in digits:
        if digit in KEYPAD:
            text.append(KEYPAD[digit][0])
        elif digit == "0":
            text.append(" ")
        elif digit == "1":
            text.append(".")
    return "".join(text).strip().encode("ascii")


def keypad_multitap_runs(digits: str) -> bytes:
    text = []
    for match in re.finditer(r"([2-9])\1*", digits):
        digit = match.group(1)
        letters = KEYPAD[digit]
        text.append(letters[(len(match.group(0)) - 1) % len(letters)])
    return "".join(text).encode("ascii")


def bareiss_determinant(matrix: list[list[int]]) -> int:
    work = [row[:] for row in matrix]
    size = len(work)
    sign = 1
    previous = 1
    for pivot_index in range(size - 1):
        if work[pivot_index][pivot_index] == 0:
            swap = next(
                (row for row in range(pivot_index + 1, size) if work[row][pivot_index] != 0),
                None,
            )
            if swap is None:
                return 0
            work[pivot_index], work[swap] = work[swap], work[pivot_index]
            sign *= -1
        pivot = work[pivot_index][pivot_index]
        for row in range(pivot_index + 1, size):
            for col in range(pivot_index + 1, size):
                work[row][col] = (
                    work[row][col] * pivot - work[row][pivot_index] * work[pivot_index][col]
                ) // previous
        previous = pivot
        for row in range(pivot_index + 1, size):
            work[row][pivot_index] = 0
    return sign * work[-1][-1]


@dataclass
class ImageGrids:
    path: Path
    image: Image.Image
    cell_size: int
    majority: list[list[tuple[int, int, int]]]
    center: list[list[tuple[int, int, int]]]
    counters: list[list[Counter[tuple[int, int, int]]]]


def load_image_grids() -> ImageGrids:
    path = IMAGE if IMAGE.exists() else FALLBACK_IMAGE
    image = Image.open(path).convert("RGB")
    cell_size = image.width // 14 if image.width == image.height else min(image.width, image.height) // 14
    majority: list[list[tuple[int, int, int]]] = []
    center: list[list[tuple[int, int, int]]] = []
    counters: list[list[Counter[tuple[int, int, int]]]] = []
    for row in range(14):
        majority_row = []
        center_row = []
        counter_row = []
        for col in range(14):
            counter = Counter(
                image.getpixel((x, y))
                for y in range(row * cell_size, (row + 1) * cell_size)
                for x in range(col * cell_size, (col + 1) * cell_size)
            )
            counter_row.append(counter)
            majority_row.append(counter.most_common(1)[0][0])
            center_row.append(image.getpixel((col * cell_size + cell_size // 2, row * cell_size + cell_size // 2)))
        counters.append(counter_row)
        majority.append(majority_row)
        center.append(center_row)
    return ImageGrids(path, image, cell_size, majority, center, counters)


@dataclass
class MaterialBank:
    labels: dict[bytes, set[str]] = field(default_factory=lambda: defaultdict(set))
    family_raw_candidates: Counter[str] = field(default_factory=Counter)
    family_unique: dict[str, set[bytes]] = field(default_factory=lambda: defaultdict(set))

    def add(self, family: str, label: str, value: bytes | str | int | None) -> None:
        if value is None:
            return
        if isinstance(value, int):
            value = str(value).encode("ascii")
        elif isinstance(value, str):
            value = value.encode("ascii")
        if not value:
            return
        self.family_raw_candidates[family] += 1
        self.family_unique[family].add(value)
        self.labels[value].add(f"{family}/{label}")

    def add_int_forms(self, family: str, label: str, value: int) -> None:
        self.add(family, f"{label}/decimal", str(value))
        self.add(family, f"{label}/hex", f"{value:x}" if value >= 0 else f"-{abs(value):x}")
        self.add(family, f"{label}/abs-bytes", int_to_minimal_bytes(value))
        self.add(family, f"{label}/mod-n-32be", (value % N).to_bytes(32, "big"))


def marker_resistor_stream(grid: list[list[tuple[int, int, int]]]) -> str:
    markers = [grid[row][col] for row, col in spiral_positions(14) if grid[row][col] in {BLUE, YELLOW}]
    if len(markers) != 24:
        raise ValueError(f"expected 24 yellow/blue markers, found {len(markers)}")
    bits = "".join("1" if colour == BLUE else "0" for colour in markers)
    if int(bits, 2) != GENESIS:
        raise ValueError(f"marker stream drifted: {int(bits, 2):06X}")
    return "".join("6" if colour == BLUE else "4" for colour in markers)


def add_digit_interpretations(bank: MaterialBank, family: str, label: str, digits: str) -> None:
    bank.add(family, f"{label}/digits-ascii", digits)
    without_zero = digits.replace("0", "")
    if without_zero and without_zero != digits:
        bank.add(family, f"{label}/digits-omit-zero", without_zero)
    bank.add(family, f"{label}/decimal-int-bytes", int_to_minimal_bytes(int(digits, 10)))
    base7 = digits_to_base_bytes(digits, 7)
    if base7 is not None:
        bank.add(family, f"{label}/base7-int-bytes", base7)
    for width in (2, 3):
        packed = chunk_bytes(digits, width, 10)
        if packed is not None:
            bank.add(family, f"{label}/decimal-chunk{width}-bytes", packed)
        packed7 = chunk_bytes(digits, width, 7)
        if packed7 is not None:
            bank.add(family, f"{label}/base7-chunk{width}-bytes", packed7)
    bank.add(family, f"{label}/phone-first-letters", keypad_first_letters(digits))
    bank.add(family, f"{label}/phone-multitap-runs", keypad_multitap_runs(digits))


def transform_prime_digits(digits: str, limit: int = 196) -> dict[str, str]:
    prime_set = primes(limit)
    return {
        "plain": digits,
        "prime-to-zero": "".join("0" if index in prime_set else ch for index, ch in enumerate(digits, 1)),
        "prime-omit": "".join(ch for index, ch in enumerate(digits, 1) if index not in prime_set),
        "nonprime-to-zero": "".join(ch if index in prime_set else "0" for index, ch in enumerate(digits, 1)),
        "prime-only": "".join(ch for index, ch in enumerate(digits, 1) if index in prime_set),
    }


def add_all_196_resistor_streams(bank: MaterialBank, grids: ImageGrids) -> dict[str, object]:
    family = "all_196_resistor_prime_zero"
    orders = {
        "spiral": spiral_positions(14),
        "spiral-reversed": list(reversed(spiral_positions(14))),
        "row-major": [(row, col) for row in range(14) for col in range(14)],
    }
    colour_maps = {
        "bw09-off9": {BLACK: "0", WHITE: "9", BLUE: "6", YELLOW: "4", OFF_WHITE: "9"},
        "bw09-off0": {BLACK: "0", WHITE: "9", BLUE: "6", YELLOW: "4", OFF_WHITE: "0"},
        "b1w0-off0": {BLACK: "1", WHITE: "0", BLUE: "6", YELLOW: "4", OFF_WHITE: "0"},
        "b0w1-off0": {BLACK: "0", WHITE: "1", BLUE: "6", YELLOW: "4", OFF_WHITE: "0"},
        "markers-only-off0": {BLACK: "0", WHITE: "0", BLUE: "6", YELLOW: "4", OFF_WHITE: "0"},
        "offwhite-third2": {BLACK: "1", WHITE: "0", BLUE: "6", YELLOW: "4", OFF_WHITE: "2"},
    }
    grids_by_name = {"majority": grids.majority, "center": grids.center}
    examples = {}
    for grid_name, grid in grids_by_name.items():
        for map_name, colour_map in colour_maps.items():
            for order_name, order in orders.items():
                digits = "".join(colour_map[grid[row][col]] for row, col in order)
                base_label = f"{grid_name}/{map_name}/{order_name}"
                examples.setdefault(base_label, digits[:64])
                for transform_name, transformed in transform_prime_digits(digits).items():
                    add_digit_interpretations(bank, family, f"{base_label}/{transform_name}", transformed)
    return {
        "colour_maps": sorted(colour_maps),
        "orders": sorted(orders),
        "grid_sources": sorted(grids_by_name),
        "prime_index_limit": 196,
        "sample_prefixes": dict(list(examples.items())[:8]),
    }


def cell_micro_bits(grids: ImageGrids, row: int, col: int) -> list[list[int]]:
    block = grids.cell_size // 5
    bits: list[list[int]] = []
    for sub_row in range(5):
        row_bits = []
        for sub_col in range(5):
            black = 0
            for y in range(row * grids.cell_size + sub_row * block, row * grids.cell_size + (sub_row + 1) * block):
                for x in range(col * grids.cell_size + sub_col * block, col * grids.cell_size + (sub_col + 1) * block):
                    if grids.image.getpixel((x, y)) == BLACK:
                        black += 1
            row_bits.append(1 if black >= (block * block + 1) // 2 else 0)
        bits.append(row_bits)
    return bits


def matrix_to_bitstring(matrix: list[list[int]], order: str = "row") -> str:
    if order == "row":
        return "".join(str(bit) for row in matrix for bit in row)
    if order == "col":
        return "".join(str(matrix[row][col]) for col in range(len(matrix[0])) for row in range(len(matrix)))
    raise ValueError(order)


def rotate_matrix(matrix: list[list[int]]) -> list[list[int]]:
    return [list(row) for row in zip(*matrix[::-1])]


def mirror_matrix(matrix: list[list[int]]) -> list[list[int]]:
    return [list(reversed(row)) for row in matrix]


def trim_matrix(matrix: list[list[int]]) -> list[list[int]]:
    rows = [index for index, row in enumerate(matrix) if any(row)]
    cols = [index for index in range(len(matrix[0])) if any(row[index] for row in matrix)]
    if not rows or not cols:
        return [[]]
    return [row[min(cols) : max(cols) + 1] for row in matrix[min(rows) : max(rows) + 1]]


def connected_components(matrix: list[list[int]]) -> list[int]:
    if not matrix or not matrix[0]:
        return []
    height = len(matrix)
    width = len(matrix[0])
    seen: set[tuple[int, int]] = set()
    sizes = []
    for row in range(height):
        for col in range(width):
            if not matrix[row][col] or (row, col) in seen:
                continue
            queue = deque([(row, col)])
            seen.add((row, col))
            size = 0
            while queue:
                current_row, current_col = queue.popleft()
                size += 1
                for next_row, next_col in (
                    (current_row - 1, current_col),
                    (current_row + 1, current_col),
                    (current_row, current_col - 1),
                    (current_row, current_col + 1),
                ):
                    if (
                        0 <= next_row < height
                        and 0 <= next_col < width
                        and matrix[next_row][next_col]
                        and (next_row, next_col) not in seen
                    ):
                        seen.add((next_row, next_col))
                        queue.append((next_row, next_col))
            sizes.append(size)
    return sorted(sizes, reverse=True)


def run_lengths(bits: str) -> str:
    if not bits:
        return ""
    lengths = []
    current = bits[0]
    count = 0
    for bit in bits:
        if bit == current:
            count += 1
        else:
            lengths.append(str(count))
            current = bit
            count = 1
    lengths.append(str(count))
    return ",".join(lengths)


def add_bit_matrix_material(bank: MaterialBank, family: str, label: str, matrix: list[list[int]]) -> None:
    for variant_name, variant in (
        ("raw", matrix),
        ("trimmed", trim_matrix(matrix)),
        ("mirror", mirror_matrix(matrix)),
        ("rot90", rotate_matrix(matrix)),
        ("rot90-mirror", mirror_matrix(rotate_matrix(matrix))),
    ):
        if not variant or not variant[0]:
            continue
        row_bits = matrix_to_bitstring(variant, "row")
        col_bits = matrix_to_bitstring(variant, "col")
        bank.add(family, f"{label}/{variant_name}/row-bits-ascii", row_bits)
        bank.add(family, f"{label}/{variant_name}/row-bits-bytes", bits_to_bytes(row_bits))
        bank.add(family, f"{label}/{variant_name}/col-bits-bytes", bits_to_bytes(col_bits))
        bank.add(family, f"{label}/{variant_name}/row-run-lengths", run_lengths(row_bits))
        bank.add(family, f"{label}/{variant_name}/col-run-lengths", run_lengths(col_bits))
        row_sums = [sum(row) for row in variant]
        col_sums = [sum(variant[row][col] for row in range(len(variant))) for col in range(len(variant[0]))]
        bank.add(family, f"{label}/{variant_name}/rowsums", ",".join(map(str, row_sums)))
        bank.add(family, f"{label}/{variant_name}/colsums", ",".join(map(str, col_sums)))


def add_rabbit_nest_family(bank: MaterialBank, grids: ImageGrids) -> dict[str, object]:
    family = "subcell_rabbit_nest_qr_barcode_morphology"
    counts = [grids.counters[row][col][BLACK] for row, col in IMPURE_RABBIT_CELLS]
    count_units = [count // 25 for count in counts]
    bank.add(family, "black-counts-decimal-csv", ",".join(map(str, counts)))
    bank.add(family, "black-counts-concat", "".join(map(str, counts)))
    bank.add(family, "black-counts-div25-digits", "".join(map(str, count_units)))
    bank.add(family, "black-counts-div25-csv", ",".join(map(str, count_units)))
    bank.add(family, "black-counts-div25-bytes", bytes(count_units))

    per_cell_bits = []
    ascii_cells = []
    for row, col in IMPURE_RABBIT_CELLS:
        matrix = cell_micro_bits(grids, row, col)
        per_cell_bits.append(matrix_to_bitstring(matrix))
        ascii_cells.append(["".join("#" if bit else "." for bit in line) for line in matrix])
        add_bit_matrix_material(bank, family, f"cell-{row}-{col}-5x5", matrix)
    all_cell_bits = "".join(per_cell_bits)
    bank.add(family, "seven-5x5-cells/row-bits-ascii", all_cell_bits)
    bank.add(family, "seven-5x5-cells/row-bits-bytes", bits_to_bytes(all_cell_bits))

    min_row = min(row for row, _ in IMPURE_RABBIT_CELLS)
    max_row = max(row for row, _ in IMPURE_RABBIT_CELLS)
    min_col = min(col for _, col in IMPURE_RABBIT_CELLS)
    max_col = max(col for _, col in IMPURE_RABBIT_CELLS)
    impure_only = [[0 for _ in range((max_col - min_col + 1) * 5)] for _ in range((max_row - min_row + 1) * 5)]
    bbox_full = [[0 for _ in range((max_col - min_col + 1) * 5)] for _ in range((max_row - min_row + 1) * 5)]
    impure_set = set(IMPURE_RABBIT_CELLS)
    for row in range(min_row, max_row + 1):
        for col in range(min_col, max_col + 1):
            matrix = cell_micro_bits(grids, row, col)
            for sub_row in range(5):
                for sub_col in range(5):
                    target_row = (row - min_row) * 5 + sub_row
                    target_col = (col - min_col) * 5 + sub_col
                    bbox_full[target_row][target_col] = matrix[sub_row][sub_col]
                    if (row, col) in impure_set:
                        impure_only[target_row][target_col] = matrix[sub_row][sub_col]
    add_bit_matrix_material(bank, family, "impure-only-bbox-15x20", impure_only)
    add_bit_matrix_material(bank, family, "full-bbox-15x20", bbox_full)

    components_impure = connected_components(impure_only)
    components_full = connected_components(bbox_full)
    bank.add(family, "impure-only-components", ",".join(map(str, components_impure)))
    bank.add(family, "full-bbox-components", ",".join(map(str, components_full)))
    qr_sizes = {21 + 4 * version for version in range(40)}
    qr_like = len(impure_only) in qr_sizes and len(impure_only[0]) == len(impure_only)
    return {
        "impure_cells_zero_based": [list(cell) for cell in IMPURE_RABBIT_CELLS],
        "black_counts": counts,
        "black_counts_div25": count_units,
        "micro_block": "5x5 per 25x25 cell, thresholded by black majority in each 5x5 pixel block",
        "impure_bbox_shape": [len(impure_only), len(impure_only[0])],
        "full_bbox_shape": [len(bbox_full), len(bbox_full[0])],
        "qr_symbol_size_match": qr_like,
        "impure_component_sizes": components_impure,
        "full_component_sizes": components_full,
        "ascii_cells": ascii_cells,
    }


def insert_before_prime_positions(base: bytes, inserts: str) -> bytes:
    prime_set = primes(len(base))
    out = bytearray()
    insert_index = 0
    for position, byte in enumerate(base, 1):
        if position in prime_set and insert_index < len(inserts):
            out.extend(inserts[insert_index].encode("ascii"))
            insert_index += 1
        out.append(byte)
    if insert_index < len(inserts):
        out.extend(inserts[insert_index:].encode("ascii"))
    return bytes(out)


def insert_after_prime_positions(base: bytes, inserts: str) -> bytes:
    prime_set = primes(len(base))
    out = bytearray()
    insert_index = 0
    for position, byte in enumerate(base, 1):
        out.append(byte)
        if position in prime_set and insert_index < len(inserts):
            out.extend(inserts[insert_index].encode("ascii"))
            insert_index += 1
    if insert_index < len(inserts):
        out.extend(inserts[insert_index:].encode("ascii"))
    return bytes(out)


def replace_prime_positions(base: bytes, inserts: str) -> bytes:
    prime_set = primes(len(base))
    out = bytearray()
    insert_index = 0
    for position, byte in enumerate(base, 1):
        if position in prime_set and insert_index < len(inserts):
            out.extend(inserts[insert_index].encode("ascii"))
            insert_index += 1
        else:
            out.append(byte)
    return bytes(out)


def add_url_prime_insert_family(bank: MaterialBank, grids: ImageGrids) -> dict[str, object]:
    family = "url_prime_insert_yellow_blue_hashthetext"
    resistor = marker_resistor_stream(grids.majority)
    bases = {"full-url": URL, "path-only": URL_PATH}
    generated = {}
    for base_name, base in bases.items():
        for style_name, value in (
            ("insert-before-prime-slots", insert_before_prime_positions(base, resistor)),
            ("insert-after-prime-slots", insert_after_prime_positions(base, resistor)),
            ("replace-prime-slots", replace_prime_positions(base, resistor)),
            ("append-resistor", base + resistor.encode("ascii")),
            ("prepend-resistor", resistor.encode("ascii") + base),
        ):
            label = f"{base_name}/{style_name}"
            generated[label] = value.decode("ascii", "replace")
            bank.add(family, label, value)
            digest = sha256(value)
            bank.add(family, f"{label}/HASHTHETEXT-sha256-digest", digest)
            bank.add(family, f"{label}/HASHTHETEXT-sha256-lowerhex-path", digest.hex())
            bank.add(family, f"{label}/literal-HASHTHETEXT-plus-text-sha256", sha256(b"HASHTHETEXT" + value))
            bank.add(family, f"{label}/yellowblueprimes-plus-text-sha256", sha256(b"yellowblueprimes" + value))
    return {
        "marker_resistor_digits": resistor,
        "prime_slots_full_url": sorted(primes(len(URL))),
        "prime_slots_path_only": sorted(primes(len(URL_PATH))),
        "generated_text": generated,
    }


def add_offwhite_family(bank: MaterialBank, grids: ImageGrids) -> dict[str, object]:
    family = "offwhite_third_channel_mask"
    off_cells = [
        (row, col)
        for row in range(14)
        for col in range(14)
        if grids.majority[row][col] == OFF_WHITE or grids.center[row][col] == OFF_WHITE
    ]
    order = spiral_positions(14)
    index_by_cell = {cell: index for index, cell in enumerate(order)}
    for row, col in off_cells:
        spiral_index_zero = index_by_cell[(row, col)]
        bank.add(family, f"coord-{row}-{col}-zero-based", f"{row},{col}")
        bank.add(family, f"coord-{row + 1}-{col + 1}-one-based", f"{row + 1},{col + 1}")
        bank.add(family, "spiral-index-zero-based", str(spiral_index_zero))
        bank.add(family, "spiral-index-one-based", str(spiral_index_zero + 1))
        byte_index = spiral_index_zero // 8
        bit_index = spiral_index_zero % 8
        if byte_index < len(URL):
            bank.add(family, "url-zero-offwhite-byte", URL[:byte_index] + b"0" + URL[byte_index + 1 :])
            bank.add(family, "url-nul-offwhite-byte", URL[:byte_index] + b"\0" + URL[byte_index + 1 :])
            bank.add(family, "url-omit-offwhite-byte", URL[:byte_index] + URL[byte_index + 1 :])
            bank.add(family, "url-split-at-offwhite-byte", URL[:byte_index] + b"|" + URL[byte_index:])
            bank.add(family, "url-insert-46-at-offwhite-byte", URL[:byte_index] + b"46" + URL[byte_index:])
        bank.add(family, "offwhite-byte-bit", f"{byte_index},{bit_index}")

    mask_bits = "".join("1" if (row, col) in off_cells else "0" for row, col in order)
    bank.add(family, "spiral-offwhite-mask-bits", mask_bits)
    bank.add(family, "spiral-offwhite-mask-bytes", bits_to_bytes(mask_bits))
    ternary = []
    for row, col in order:
        colour = grids.majority[row][col]
        if colour == OFF_WHITE:
            ternary.append("2")
        elif colour in {BLACK, BLUE}:
            ternary.append("1")
        else:
            ternary.append("0")
    ternary_text = "".join(ternary)
    bank.add(family, "spiral-ternary-offwhite2-ascii", ternary_text)
    bank.add(family, "spiral-ternary-offwhite2-base3-bytes", digits_to_base_bytes(ternary_text, 3))
    return {
        "offwhite_cells_zero_based": [list(cell) for cell in off_cells],
        "offwhite_cells_one_based": [[row + 1, col + 1] for row, col in off_cells],
        "spiral_indices_zero_based": [index_by_cell[cell] for cell in off_cells],
        "spiral_indices_one_based": [index_by_cell[cell] + 1 for cell in off_cells],
        "url_byte_indices": [index_by_cell[cell] // 8 for cell in off_cells],
    }


def matrix_from_grid(grid: list[list[tuple[int, int, int]]], colour_map: dict[tuple[int, int, int], int]) -> list[list[int]]:
    return [[colour_map[grid[row][col]] for col in range(14)] for row in range(14)]


def add_matrix_family(bank: MaterialBank, grids: ImageGrids) -> dict[str, object]:
    family = "matrix_14x14_resistor_sum_product_det"
    maps = {
        "bw09-off9": {BLACK: 0, WHITE: 9, BLUE: 6, YELLOW: 4, OFF_WHITE: 9},
        "bw09-off0": {BLACK: 0, WHITE: 9, BLUE: 6, YELLOW: 4, OFF_WHITE: 0},
        "b1w0-off2": {BLACK: 1, WHITE: 0, BLUE: 6, YELLOW: 4, OFF_WHITE: 2},
        "markers-only": {BLACK: 0, WHITE: 0, BLUE: 6, YELLOW: 4, OFF_WHITE: 0},
    }
    summaries = {}
    for grid_name, grid in {"majority": grids.majority, "center": grids.center}.items():
        for map_name, colour_map in maps.items():
            matrix = matrix_from_grid(grid, colour_map)
            row_sums = [sum(row) for row in matrix]
            col_sums = [sum(matrix[row][col] for row in range(14)) for col in range(14)]
            total = sum(row_sums)
            trace = sum(matrix[index][index] for index in range(14))
            anti_trace = sum(matrix[index][13 - index] for index in range(14))
            nonzero_product = 1
            for value in (value for row in matrix for value in row if value):
                nonzero_product *= value
            determinant = bareiss_determinant(matrix)
            label = f"{grid_name}/{map_name}"
            bank.add(family, f"{label}/rowsums-concat", "".join(map(str, row_sums)))
            bank.add(family, f"{label}/colsums-concat", "".join(map(str, col_sums)))
            bank.add(family, f"{label}/rowsums-csv", ",".join(map(str, row_sums)))
            bank.add(family, f"{label}/colsums-csv", ",".join(map(str, col_sums)))
            bank.add(family, f"{label}/rowcol-sums-csv", ",".join(map(str, row_sums + col_sums)))
            bank.add_int_forms(family, f"{label}/total", total)
            bank.add_int_forms(family, f"{label}/trace", trace)
            bank.add_int_forms(family, f"{label}/anti-trace", anti_trace)
            bank.add_int_forms(family, f"{label}/nonzero-product", nonzero_product)
            bank.add_int_forms(family, f"{label}/determinant", determinant)
            summaries[label] = {
                "total": total,
                "trace": trace,
                "anti_trace": anti_trace,
                "determinant": determinant,
                "nonzero_product_decimal_digits": len(str(nonzero_product)),
                "row_sums": row_sums,
                "col_sums": col_sums,
            }
    return {"maps": sorted(maps), "summaries": summaries}


def filtered_stream(
    grid: list[list[tuple[int, int, int]]],
    colour_map: dict[tuple[int, int, int], str],
    cells: Iterable[tuple[int, int]],
) -> str:
    return "".join(colour_map[grid[row][col]] for row, col in cells)


def add_half_family(bank: MaterialBank, grids: ImageGrids) -> dict[str, object]:
    family = "half_image_grid_splits"
    colour_maps = {
        "bw09-off0": {BLACK: "0", WHITE: "9", BLUE: "6", YELLOW: "4", OFF_WHITE: "0"},
        "b1w0-off2": {BLACK: "1", WHITE: "0", BLUE: "6", YELLOW: "4", OFF_WHITE: "2"},
        "markers-only": {BLACK: "0", WHITE: "0", BLUE: "6", YELLOW: "4", OFF_WHITE: "0"},
    }
    all_cells = [(row, col) for row in range(14) for col in range(14)]
    spiral = spiral_positions(14)
    split_sets = {
        "left": [(row, col) for row, col in all_cells if col < 7],
        "right": [(row, col) for row, col in all_cells if col >= 7],
        "top": [(row, col) for row, col in all_cells if row < 7],
        "bottom": [(row, col) for row, col in all_cells if row >= 7],
        "main-diagonal-lower": [(row, col) for row, col in all_cells if row >= col],
        "main-diagonal-upper": [(row, col) for row, col in all_cells if row < col],
        "anti-diagonal-lower": [(row, col) for row, col in all_cells if row + col >= 13],
        "anti-diagonal-upper": [(row, col) for row, col in all_cells if row + col < 13],
        "checker-even": [(row, col) for row, col in all_cells if (row + col) % 2 == 0],
        "checker-odd": [(row, col) for row, col in all_cells if (row + col) % 2 == 1],
    }
    ordered_split_sets = {
        **{f"row-major/{name}": cells for name, cells in split_sets.items()},
        **{f"spiral/{name}": [cell for cell in spiral if cell in set(cells)] for name, cells in split_sets.items()},
    }
    summaries = {}
    for grid_name, grid in {"majority": grids.majority, "center": grids.center}.items():
        for map_name, colour_map in colour_maps.items():
            streams = {
                split_name: filtered_stream(grid, colour_map, cells)
                for split_name, cells in ordered_split_sets.items()
            }
            for split_name, stream in streams.items():
                add_digit_interpretations(bank, family, f"{grid_name}/{map_name}/{split_name}", stream)
            pairs = (
                ("left", "right"),
                ("top", "bottom"),
                ("main-diagonal-lower", "main-diagonal-upper"),
                ("anti-diagonal-lower", "anti-diagonal-upper"),
                ("checker-even", "checker-odd"),
            )
            for left, right in pairs:
                left_stream = streams[f"row-major/{left}"]
                right_stream = streams[f"row-major/{right}"]
                add_digit_interpretations(
                    bank,
                    family,
                    f"{grid_name}/{map_name}/row-major/{left}-then-{right}",
                    left_stream + right_stream,
                )
                add_digit_interpretations(
                    bank,
                    family,
                    f"{grid_name}/{map_name}/row-major/{right}-then-{left}",
                    right_stream + left_stream,
                )
                bank.add(
                    family,
                    f"{grid_name}/{map_name}/row-major/{left}-sum|{right}-sum",
                    f"{sum(map(int, left_stream))}|{sum(map(int, right_stream))}",
                )
            summaries[f"{grid_name}/{map_name}"] = {
                "left_sum": sum(map(int, streams["row-major/left"])),
                "right_sum": sum(map(int, streams["row-major/right"])),
                "top_sum": sum(map(int, streams["row-major/top"])),
                "bottom_sum": sum(map(int, streams["row-major/bottom"])),
            }
    return {"split_sets": sorted(split_sets), "maps": sorted(colour_maps), "summaries": summaries}


def public_keys_for_scalar(scalar: bytes) -> dict[str, bytes]:
    if CoincurvePrivateKey is not None:
        private = CoincurvePrivateKey(scalar)
        return {
            "uncompressed": private.public_key.format(compressed=False),
            "compressed": private.public_key.format(compressed=True),
        }
    return {
        "uncompressed": public_key(scalar, compressed=False),
        "compressed": public_key(scalar, compressed=True),
    }


def p2pkh_from_public(public: bytes) -> str:
    return base58check(b"\0" + hash160(public))


@dataclass
class ScalarGate:
    seen_scalars: set[bytes] = field(default_factory=set)
    scalar_tests: int = 0
    variant_count: int = 0
    matches: list[dict[str, object]] = field(default_factory=list)

    def add_material(self, labels: set[str], material: bytes, *, windows: bool = True) -> None:
        for variant_label, candidate in self.scalar_variants(material, windows=windows):
            self.variant_count += 1
            scalar_int = int.from_bytes(candidate, "big") % N
            if scalar_int == 0:
                continue
            scalar = scalar_int.to_bytes(32, "big")
            if scalar in self.seen_scalars:
                continue
            self.seen_scalars.add(scalar)
            self.scalar_tests += 1
            self.test_scalar(labels, variant_label, scalar)

    def scalar_variants(self, material: bytes, *, windows: bool) -> Iterable[tuple[str, bytes]]:
        yield "sha256", sha256(material)
        yield "double-sha256", sha256(sha256(material))
        if len(material) < 32:
            yield "left-zero-pad", material.rjust(32, b"\0")
            yield "right-zero-pad", material.ljust(32, b"\0")
        elif len(material) == 32:
            yield "raw32", material
            yield "raw32-reversed", material[::-1]
        else:
            yield "first32", material[:32]
            yield "last32", material[-32:]
            if windows and len(material) <= 512:
                for offset in range(len(material) - 31):
                    window = material[offset : offset + 32]
                    yield f"win[{offset}:{offset + 32}]", window
                    yield f"win[{offset}:{offset + 32}]/rev", window[::-1]
        if material and all(48 <= byte <= 57 for byte in material):
            yield "decimal-int-mod-n", (int(material.decode("ascii")) % N).to_bytes(32, "big")
        compact = material.strip()
        if len(compact) >= 2 and len(compact) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f]+", compact):
            try:
                decoded = bytes.fromhex(compact.decode("ascii"))
            except ValueError:
                decoded = b""
            if decoded:
                yield "hex-decoded-sha256", sha256(decoded)
                if len(decoded) == 32:
                    yield "hex-decoded-raw32", decoded

    def test_scalar(self, labels: set[str], variant_label: str, scalar: bytes) -> None:
        pubs = public_keys_for_scalar(scalar)
        for serialization, pub in pubs.items():
            public_h160 = hash160(pub)
            address = p2pkh_from_public(pub)
            for prize_name, prize in PRIZES.items():
                exact_pubkey = prize_name == "Half" and serialization == "uncompressed" and pub == HALF_PUB_UNCOMPRESSED
                if address == prize["address"] and public_h160 == prize["hash160"]:
                    self.matches.append(
                        {
                            "prize": prize_name,
                            "address": address,
                            "serialization": serialization,
                            "scalar_hex": scalar.hex(),
                            "variant": variant_label,
                            "labels": sorted(labels),
                            "half_uncompressed_pubkey_exact": exact_pubkey,
                        }
                    )


def password_variants(material: bytes) -> Iterable[tuple[str, bytes]]:
    yield "raw", material
    yield "sha256-digest", sha256(material)
    digest = sha256_hex(material).encode("ascii")
    yield "sha256-lowerhex", digest
    yield "sha256-upperhex", digest.upper()
    yield "double-sha256-digest", sha256(sha256(material))
    compact = material.strip()
    if len(compact) >= 2 and len(compact) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f]+", compact):
        try:
            yield "hex-decoded", bytes.fromhex(compact.decode("ascii"))
        except ValueError:
            pass


def printable_sample(data: bytes, limit: int = 96) -> str:
    return "".join(chr(value) if chr(value) in string.printable and value not in (11, 12) else "." for value in data[:limit])


def evaluate_aes(bank: MaterialBank) -> dict[str, object]:
    extracted = extract_all()
    salphaseion = derive_tokens()
    chains = reconstruct(extracted, salphaseion)
    known_cosmic_sha = sha256_hex(chains.cosmic_decryption.plaintext)
    canonical_chain1_password = "".join(salphaseion.tokens[:5]).encode("ascii")
    canonical_chain1 = decrypt_salted_aes256_cbc(extracted.chain1_envelope, canonical_chain1_password)
    known_short_sha = sha256_hex(canonical_chain1.plaintext)
    blobs = {
        "cosmic-duality": extracted.cosmic_envelope,
        "salphaseion-short-80ct": extracted.chain1_envelope,
    }
    known_passwords = {
        ("cosmic-duality", salphaseion.xor_password),
        ("salphaseion-short-80ct", canonical_chain1_password),
    }
    attempts = 0
    padding_hits = []
    structured_hits = []
    seen: set[tuple[str, str, bytes]] = set()
    for material, labels in bank.labels.items():
        for password_label, password in password_variants(material):
            for digest in ("md5", "sha256"):
                for blob_name, envelope in blobs.items():
                    key = (blob_name, digest, password)
                    if key in seen:
                        continue
                    seen.add(key)
                    if (blob_name, password) in known_passwords:
                        continue
                    attempts += 1
                    try:
                        decrypted = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
                    except ValueError:
                        continue
                    plaintext = decrypted.plaintext
                    plaintext_sha = sha256_hex(plaintext)
                    readable, metrics = _readable(plaintext)
                    formats = _formats(plaintext)
                    record = {
                        "blob": blob_name,
                        "kdf_digest": digest,
                        "password_variant": password_label,
                        "password_sha256": sha256_hex(password),
                        "labels": sorted(labels),
                        "plaintext_length": len(plaintext),
                        "plaintext_sha256": plaintext_sha,
                        "padding_length": decrypted.padding_length,
                        "readable": readable,
                        "formats": formats,
                        "metrics": metrics,
                        "sample": printable_sample(plaintext),
                    }
                    padding_hits.append(record)
                    if (readable or formats) and plaintext_sha not in {known_cosmic_sha, known_short_sha}:
                        structured_hits.append(record)
    return {
        "attempts": attempts,
        "padding_hit_count": len(padding_hits),
        "padding_hits_sample": padding_hits[:50],
        "structured_hit_count": len(structured_hits),
        "structured_hits": structured_hits,
        "known_cosmic_plaintext_sha256": known_cosmic_sha,
        "known_salphaseion_short_plaintext_sha256": known_short_sha,
        "salphaseion_short_ciphertext_len": len(extracted.chain1_envelope) - 16,
    }


def collect_url_candidates(bank: MaterialBank) -> dict[str, object]:
    path_like = []
    sha_slugs = set()
    known = {URL.decode("ascii"), URL_PATH.decode("ascii"), "/theseedisplanted"}
    path_pattern = re.compile(rb"^[A-Za-z0-9][A-Za-z0-9._/-]{5,96}$")
    for material, labels in bank.labels.items():
        sha_slugs.add(sha256_hex(material))
        compact = material.strip()
        if path_pattern.fullmatch(compact):
            text = compact.decode("ascii", "ignore")
            if text not in known:
                path_like.append({"text": text, "labels": sorted(labels)[:8]})
        if len(compact) == 32 and all(chr(byte) in string.hexdigits for byte in compact):
            path_like.append({"text": compact.decode("ascii"), "labels": sorted(labels)[:8], "note": "32-hex"})
        if len(compact) == 64 and all(chr(byte) in string.hexdigits for byte in compact):
            path_like.append({"text": "/" + compact.decode("ascii").lower(), "labels": sorted(labels)[:8], "note": "64-hex slug"})
    return {
        "path_like_candidate_count": len(path_like),
        "path_like_candidates_sample": path_like[:80],
        "sha256_slug_count": len(sha_slugs),
        "sha256_slug_samples": sorted(sha_slugs)[:20],
        "note": "Slugs are generated local candidates; this script does not perform live gsmg.io HTTP probing.",
    }


def run() -> dict[str, object]:
    grids = load_image_grids()
    bank = MaterialBank()
    family_details = {
        "subcell_rabbit_nest_qr_barcode_morphology": add_rabbit_nest_family(bank, grids),
        "all_196_resistor_prime_zero": add_all_196_resistor_streams(bank, grids),
        "offwhite_third_channel_mask": add_offwhite_family(bank, grids),
        "url_prime_insert_yellow_blue_hashthetext": add_url_prime_insert_family(bank, grids),
        "matrix_14x14_resistor_sum_product_det": add_matrix_family(bank, grids),
        "half_image_grid_splits": add_half_family(bank, grids),
    }

    scalar_gate = ScalarGate()
    for material, labels in bank.labels.items():
        scalar_gate.add_material(labels, material, windows=True)

    aes = evaluate_aes(bank)
    urls = collect_url_candidates(bank)
    family_counts = {
        family: {
            "raw_candidates": bank.family_raw_candidates[family],
            "unique_materials": len(bank.family_unique[family]),
        }
        for family in sorted(bank.family_raw_candidates)
    }
    matches = {
        "prize_scalar_matches": scalar_gate.matches,
        "structured_aes_hits": aes["structured_hits"],
        "url_path_like_candidates": urls["path_like_candidates_sample"],
    }
    status = "MATCH" if scalar_gate.matches or aes["structured_hits"] else "NO_MATCH"
    result: dict[str, object] = {
        "schema": "second-door-frontier-derivations-v1",
        "status": status,
        "source": {
            "image": str(grids.path),
            "image_size": list(grids.image.size),
            "cell_size": grids.cell_size,
            "known_spiral_url": URL.decode("ascii"),
            "marker_hex": f"{GENESIS:06X}",
            "resistor_digits": {"yellow": 4, "blue": 6},
            "prizes": {
                "Half": {"address": HALF_ADDR, "known_uncompressed_pubkey": HALF_PUB_UNCOMPRESSED.hex()},
                "Better_Half": {"address": BETTER_ADDR, "known": "hash160 only"},
            },
            "new_evidence": {
                "cosmic_103_exact_80_117_random_hit_rate": "about 18%; treated as weak authentication",
                "april_2025_yin_yang": "creator said not found",
                "focus": "first image second door",
            },
        },
        "families_tested": [
            "sub-cell rabbit nest as QR/barcode/morphology",
            "all 196 cells under spiral with resistor digits and prime-index zeroing",
            "off-white 254,254,254 as third channel and spiral mask",
            "Yellow=4/Blue=6 inserted into URL prime slots then HASHTHETEXT sha256",
            "14x14 resistor matrices with sum/product/determinant key material",
            "left/right/top/bottom/diagonal/checker half-image splits",
        ],
        "family_counts": family_counts,
        "family_details": family_details,
        "unique_materials_total": len(bank.labels),
        "url_gate": urls,
        "aes_gate": {key: value for key, value in aes.items() if key != "structured_hits"},
        "scalar_gate": {
            "scalar_variant_count_before_dedup": scalar_gate.variant_count,
            "scalar_attempts_unique": scalar_gate.scalar_tests,
            "prize_matches": scalar_gate.matches,
            "targets_checked": {
                "Half": HALF_ADDR,
                "Better_Half": BETTER_ADDR,
                "serializations": ["uncompressed", "compressed"],
            },
        },
        "matches": matches,
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(
        json.dumps(
            {
                "status": output["status"],
                "result_path": str(RESULT_PATH),
                "unique_materials_total": output["unique_materials_total"],
                "scalar_attempts_unique": output["scalar_gate"]["scalar_attempts_unique"],
                "aes_attempts": output["aes_gate"]["attempts"],
                "structured_aes_hit_count": output["aes_gate"]["structured_hit_count"],
                "prize_matches": output["scalar_gate"]["prize_matches"],
                "url_path_like_candidate_count": output["url_gate"]["path_like_candidate_count"],
                "sha256_slug_count": output["url_gate"]["sha256_slug_count"],
            },
            indent=2,
            sort_keys=True,
        )
    )
