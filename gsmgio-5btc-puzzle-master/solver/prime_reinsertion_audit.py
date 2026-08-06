"""Audit the literal SalPhaseIon ``REINSERTING THE PRIME BASICS`` route.

This deliberately finite experiment reproduces the public 91-symbol prefix,
extracts the colored 14x14 grid cells from the original image, inserts the 24
color values at the one-indexed prime positions, and exact-gates every explicit
byte/SHA-256 interpretation against the prize public point.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import re

from cryptography.hazmat.primitives.asymmetric import ec
from PIL import Image

from .extract import README, ROOT
from .secp256k1_verify import N
from .targets import HALF_ADDRESS, HALF_X, HALF_Y


IMAGE = ROOT / "puzzle.png"
RESULT_PATH = ROOT / "prime_reinsertion_audit.json"
# Re-exported from solver.targets, which is the single source of truth.  Many
# audits import these three names from this module for historical reasons.
TARGET_X = HALF_X
TARGET_Y = HALF_Y
TARGET_ADDRESS = HALF_ADDRESS
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
NEAR_WHITE = (254, 254, 254)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _prefix() -> str:
    line = next(
        value
        for value in README.read_text(encoding="utf-8-sig").splitlines()
        if value.startswith("> d b b i b f")
    )
    highlighted_binary = re.search(r"\*\*((?:[ab]\s+)+[ab])\*\*", line)
    if highlighted_binary is None:
        raise ValueError("could not locate the first highlighted binary segment")
    prefix = "".join(re.findall(r"(?<![A-Za-z])[a-i](?![A-Za-z])", line[: highlighted_binary.start()]))
    if len(prefix) != 91 or set(prefix) - set("abcdefghi"):
        raise ValueError("the README did not yield the expected 91-symbol a-i prefix")
    return prefix


def _spiral(grid: list[list[int]]) -> list[int]:
    """Read from upper left, down first, counterclockwise toward the center."""
    top = left = 0
    bottom = len(grid) - 1
    right = len(grid[0]) - 1
    output: list[int] = []
    while left <= right and top <= bottom:
        for row in range(top, bottom + 1):
            output.append(grid[row][left])
        left += 1
        for column in range(left, right + 1):
            output.append(grid[bottom][column])
        bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                output.append(grid[row][right])
            right -= 1
        if top <= bottom:
            for column in range(right, left - 1, -1):
                output.append(grid[top][column])
            top += 1
    return output


def _image_records() -> tuple[list[list[int]], list[list[int]], list[int], dict[str, int], tuple[int, int]]:
    with Image.open(IMAGE) as source_image:
        dimensions = source_image.size
        image = source_image.convert("RGB")
    if image.width != 1048 or image.height < image.width:
        raise ValueError(f"unexpected puzzle image dimensions: {image.size}")
    pixels = [
        [
            image.getpixel((int((column + 0.5) * image.width / 14), int((row + 0.5) * image.width / 14)))
            for column in range(14)
        ]
        for row in range(14)
    ]
    counts = Counter(pixel for row in pixels for pixel in row)
    expected = Counter({BLACK: 87, WHITE: 84, NEAR_WHITE: 1, BLUE: 15, YELLOW: 9})
    if counts != expected:
        raise ValueError(f"grid-center RGB census changed: {dict(counts)}")
    binary = [[1 if pixel in (BLACK, BLUE) else 0 for pixel in row] for row in pixels]
    numbered = [
        [15 if pixel == BLUE else 9 if pixel == YELLOW else 1 if pixel == BLACK else 0 for pixel in row]
        for row in pixels
    ]
    colors = [15 if pixel == BLUE else 9 for row in pixels for pixel in row if pixel in (BLUE, YELLOW)]
    return binary, numbered, colors, {str(rgb): count for rgb, count in sorted(counts.items())}, dimensions


def _primes(limit: int) -> list[int]:
    return [value for value in range(2, limit + 1) if all(value % divisor for divisor in range(2, math.isqrt(value) + 1))]


def _streams(grid: list[list[int]]) -> dict[str, list[int]]:
    return {
        "rowsums": [sum(row) for row in grid],
        "colsums": [sum(grid[row][column] for row in range(14)) for column in range(14)],
        "flatten": [value for row in grid for value in row],
        "spiral": _spiral(grid),
    }


def _insert(source: list[int], colors: list[int], primes: set[int]) -> list[int]:
    source_iter = iter(source)
    color_iter = iter(colors)
    output = [next(color_iter) if position in primes else next(source_iter) for position in range(1, 92)]
    try:
        next(source_iter)
        raise ValueError("unused source values after reinsertion")
    except StopIteration:
        pass
    try:
        next(color_iter)
        raise ValueError("unused color values after reinsertion")
    except StopIteration:
        pass
    return output


def _target_match(candidate: int) -> bool:
    candidate %= N
    if candidate == 0:
        return False
    public = ec.derive_private_key(candidate, ec.SECP256K1()).public_key().public_numbers()
    return public.x == TARGET_X and public.y == TARGET_Y


def run() -> dict[str, object]:
    prefix = _prefix()
    binary, numbered, colors, rgb_counts, image_dimensions = _image_records()
    spiral_bits = _spiral(binary)
    spiral_ascii = bytes(
        int("".join(str(bit) for bit in spiral_bits[offset : offset + 8]), 2)
        for offset in range(0, 192, 8)
    )
    if spiral_ascii != b"gsmg.io/theseedisplanted" or spiral_bits[192:] != [0, 1, 0, 0]:
        raise ValueError("image extraction failed the published spiral positive control")

    primes = _primes(91)
    if len(primes) != 24 or len(colors) != 24:
        raise ValueError("prime/color cardinality mismatch")
    all_streams = {
        **{f"binary/{name}": values for name, values in _streams(binary).items()},
        **{f"numbered/{name}": values for name, values in _streams(numbered).items()},
    }
    eligible = {name: values for name, values in all_streams.items() if len(values) >= 67}
    prefix_values = [ord(symbol) - ord("a") + 1 for symbol in prefix]

    inserted_records: list[tuple[str, list[int]]] = []
    for stream_name, stream in eligible.items():
        for source_name, source in (("stream", stream[:67]), ("prefix", prefix_values[:67])):
            for color_name, color_values in (("normal", colors), ("reverse", list(reversed(colors)))):
                label = f"{stream_name}/{source_name}/colors-{color_name}"
                inserted_records.append((label, _insert(source, color_values, set(primes))))

    ordered_records = [
        (f"{label}/{order}", values if order == "forward" else list(reversed(values)))
        for label, values in inserted_records
        for order in ("forward", "reverse")
    ]
    offsets = (0, 1, 32, 64, 65, 96, 97)
    variants = (("raw", None), ("mod26", 26), ("mod36", 36), ("mod64", 64), ("mod95", 95), ("mod256", 256))
    decoded: list[tuple[str, bytes]] = []
    for label, values in ordered_records:
        for variant, modulus in variants:
            reduced = values if modulus is None else [value % modulus for value in values]
            for offset in offsets:
                decoded.append((f"{label}/{variant}/offset-{offset}", bytes((value + offset) % 256 for value in reduced)))

    scalar_inputs: list[tuple[str, bytes]] = []
    raw_32 = [(label, value) for label, value in decoded if len(value) == 32]
    scalar_inputs.extend(raw_32)
    scalar_inputs.extend((f"SHA256({label})", hashlib.sha256(value).digest()) for label, value in decoded)
    for label, values in ordered_records:
        decimal = "".join(str(value) for value in values).encode("ascii")
        scalar_inputs.append((f"SHA256(decimal-concat:{label})", hashlib.sha256(decimal).digest()))

    seen: set[int] = set()
    matches: list[dict[str, str]] = []
    for label, value in scalar_inputs:
        scalar = int.from_bytes(value, "big") % N
        if not scalar or scalar in seen:
            continue
        seen.add(scalar)
        if _target_match(scalar):
            matches.append({"derivation": label, "private_hex": f"{scalar:064x}", "address": TARGET_ADDRESS})

    printable = sorted(
        (
            (sum(32 <= byte < 127 for byte in value) / len(value), label, value)
            for label, value in decoded
        ),
        reverse=True,
    )[:5]
    result: dict[str, object] = {
        "status": "MATCH" if matches else "NO_MATCH_IN_ENUMERATED_FAMILY",
        "source": {
            "readme_sha256": _sha(README.read_bytes()),
            "image_sha256": _sha(IMAGE.read_bytes()),
            "prefix_length": len(prefix),
            "prefix": prefix,
            "prefix_sha256": _sha(prefix.encode("ascii")),
            "image_dimensions": list(image_dimensions),
            "grid_region": [0, 0, 1048, 1048],
            "sample_rule": "centers of the 14x14 cells in the image's 1048x1048 upper square",
            "rgb_counts": rgb_counts,
            "color_count": len(colors),
            "blue_count": colors.count(15),
            "yellow_count": colors.count(9),
            "color_values_row_major": colors,
            "spiral_ascii": spiral_ascii.decode("ascii"),
            "spiral_residual_bits": spiral_bits[192:],
        },
        "prime_positions": primes,
        "prime_count": len(primes),
        "stream_lengths": {name: len(values) for name, values in all_streams.items()},
        "eligible_streams": list(eligible),
        "source_streams": ["eligible grid stream first 67 values", "91-symbol prefix first 67 values"],
        "inserted_stream_records": len(inserted_records),
        "unique_inserted_streams": len({tuple(values) for _, values in inserted_records}),
        "ordered_stream_records": len(ordered_records),
        "unique_ordered_streams": len({tuple(values) for _, values in ordered_records}),
        "decoding_variants": [name for name, _ in variants],
        "byte_offsets": list(offsets),
        "decoded_byte_records": len(decoded),
        "unique_decoded_bytes": len({value for _, value in decoded}),
        "hex_decode_records": 0,
        "hex_decode_note": "Every reinserted record has odd length 91, so the documented paired-nibble decode is inapplicable.",
        "raw_32_byte_candidates": len(raw_32),
        "sha256_decoded_candidates": len(decoded),
        "sha256_decimal_concat_candidates": len(ordered_records),
        "scalar_candidate_records": len(scalar_inputs),
        "unique_nonzero_scalars": len(seen),
        "top_printable_diagnostics": [
            {"ratio": ratio, "derivation": label, "hex": value.hex(), "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in value)}
            for ratio, label, value in printable
        ],
        "target": {"x": f"{TARGET_X:064x}", "y": f"{TARGET_Y:064x}", "address": TARGET_ADDRESS},
        "matches": matches,
        "scope_note": "This exhausts only the explicitly enumerated row/column/flatten/spiral, prime-position, ordering, modular-byte, offset, and SHA-256 family. It is not a general impossibility result.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
