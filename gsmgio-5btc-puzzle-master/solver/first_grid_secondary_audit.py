"""Reproduce the first grid's colored-cell stream and QR-finder texture."""

from __future__ import annotations

from collections import Counter
import hashlib
import json

from PIL import Image

from .extract import ROOT
from .prime_reinsertion_audit import BLUE, YELLOW
from .salphaseion_preregister_v12 import _spiral_positions


IMAGE = ROOT / "puzzle.png"
RESULT = ROOT / "first_grid_secondary_audit.json"


def run() -> dict[str, object]:
    image = Image.open(IMAGE).convert("RGB")
    grid = [[image.getpixel((int((column + .5) * image.width / 14), int((row + .5) * image.width / 14)))
             for column in range(14)] for row in range(14)]

    def colored(order: list[tuple[int, int]]) -> tuple[str, str]:
        bits = "".join("1" if grid[row][column] == BLUE else "0"
                       for row, column in order if grid[row][column] in (BLUE, YELLOW))
        return bits, f"{int(bits, 2):06X}"

    row_order = [(row, column) for row in range(14) for column in range(14)]
    spiral_order = _spiral_positions(14)
    row_bits, row_hex = colored(row_order)
    spiral_bits, spiral_hex = colored(spiral_order)
    if len(row_bits) != 24 or len(spiral_bits) != 24 or spiral_hex != "F73D92":
        raise ValueError("colored-cell stream changed")

    # The three 7x7-module QR finder patterns occupy byte-identical 49x49
    # pixel crops.  Their visible gray 'merlons' therefore repeat a raster
    # template and cannot independently encode three payloads.
    finders = [image.crop(box).tobytes() for box in (
        (1, 1289, 50, 1338),
        (183, 1289, 232, 1338),
        (1, 1471, 50, 1520),
    )]
    finder_hashes = [hashlib.sha256(value).hexdigest() for value in finders]
    if len(set(finder_hashes)) != 1:
        raise ValueError("QR finder templates are no longer identical")

    qr = image.crop((1, 1289, 232, 1520))
    result = {
        "schema": "first-grid-secondary-audit-v1",
        "image_sha256": hashlib.sha256(IMAGE.read_bytes()).hexdigest(),
        "colored_cell_count": len(spiral_bits),
        "blue_count": spiral_bits.count("1"),
        "yellow_count": spiral_bits.count("0"),
        "row_major": {"bits": row_bits, "hex": row_hex},
        "authenticated_counterclockwise_spiral": {"bits": spiral_bits, "hex": spiral_hex},
        "colored_spiral_positions_one_based": list(range(8, 193, 8)),
        "url_ascii_lsb_bits": "".join(str(ord(character) & 1) for character in "gsmg.io/theseedisplanted"),
        "structural_interpretation": "The 24 colored cells are exactly spiral positions 8,16,...,192: the least-significant bit of each decoded URL byte.",
        "report_correction": "F73D92 is the exact spiral-ordered colored-cell/URL-LSB stream; BE2B9B is the unrelated row-major ordering.",
        "qr": {
            "bounds": [1, 1289, 232, 1520],
            "sha256": hashlib.sha256(qr.tobytes()).hexdigest(),
            "finder_crop_sha256": finder_hashes,
            "finder_crops_identical": True,
            "finder_texture_conclusion": "the repeated gray merlons contain no finder-to-finder entropy",
        },
        "sampled_grid_rgb_counts": {str(key): value for key, value in Counter(pixel for row in grid for pixel in row).items()},
    }
    RESULT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
