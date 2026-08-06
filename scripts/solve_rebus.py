#!/usr/bin/env python3
"""Extract the rebus tiles from the theseedisplanted page and pair them into words.

The page shows eight ~70x70 coloured tiles. Each tile holds up to two elements
stacked vertically: pictograms (a bank, a closed padlock, an open padlock) and
letter fragments. Blue and black tiles have their colour block flush against
their left edge with white padding on the right; red tiles are the mirror image.
That makes each line of the original image a [blue-or-black | red] pair cut
through the white gutter between the two blocks.

Reading the letters of a pair in normal order (top line left to right, then
bottom line left to right) yields one word per pair, and only one way of
pairing all eight tiles produces words for every pair.
"""

import itertools
import struct
from collections import Counter, defaultdict

from PIL import Image

from _paths import SOURCES

DIR = SOURCES / "GSMG Puzzle2_files"

# Letters visible in each tile, as (top line, bottom line). Pictograms and the
# +/- symbols carry no letters, so they appear as None.
TILES = {
    "black_banking - war": (None, "war"),
    "blue_ca": ("ca", None),
    "blue_dig_i": ("dig i", None),
    "blue_lock_lo": (None, "lo"),
    "red_crypto_gic": ("crypto", "gic"),
    "red_n_you": ("n you", None),
    "red_open_lock_n_ing": (None, "n ing"),
    "red_t": ("t", None),
}

# Non-letter content, for the record.
ART = {
    "black_banking - war": "bank pictogram ($ in a building)",
    "blue_dig_i": "plus sign",
    "blue_lock_lo": "closed padlock",
    "red_open_lock_n_ing": "open padlock",
    "red_t": "minus sign",
}

WORDS = {"canyou", "digit", "cryptologic", "warning", "cat", "lot", "logic"}


def block_geometry(name):
    """Return (width, colour block span, side the block is flush against)."""
    im = Image.open(DIR / f"{name}.png").convert("RGB")
    width, height = im.size
    pixels = im.load()
    fill = Counter(
        pixels[x, y] for y in range(height) for x in range(width)
    ).most_common(1)[0][0]
    xs = [x for x in range(width) if any(pixels[x, y] == fill for y in range(height))]
    left, right = min(xs), max(xs)
    side = "left" if left == 0 else "right" if right == width - 1 else "?"
    return width, (left, right), side, fill


def encoder_fingerprint(name):
    """Return (pixels-per-metre, PNG colour type, sRGB present) for a tile.

    Tiles saved in the same pass share these, so they group the tiles
    independently of anything visible in the picture.
    """
    data = (DIR / f"{name}.png").read_bytes()
    offset, phys, ctype, srgb = 8, None, None, False
    while offset < len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8].decode("latin1")
        body = data[offset + 8 : offset + 8 + length]
        if kind == "IHDR":
            ctype = body[9]
        elif kind == "pHYs":
            phys = struct.unpack(">IIB", body)[0]
        elif kind == "sRGB":
            srgb = True
        offset += 12 + length
    return phys, ctype, srgb


def read_pair(left, right):
    """Read a pair's letters in normal order: top line, then bottom line."""
    lines = (
        (TILES[left][0], TILES[right][0]),
        (TILES[left][1], TILES[right][1]),
    )
    return "".join(part for line in lines for part in line if part).replace(" ", "")


def main():
    lefts, rights = [], []
    print("tile inventory:")
    for name in sorted(TILES):
        width, span, side, fill = block_geometry(name)
        (lefts if side == "left" else rights).append(name)
        art = ART.get(name, "-")
        print(
            f"  {name:<22} w={width:<3} block={span[0]:>2}-{span[1]:<2} flush {side:<5}"
            f" rgb{fill}  art: {art:<32} letters: {TILES[name]}"
        )

    print(f"\nflush-left (blue/black) tiles: {lefts}")
    print(f"flush-right (red) tiles:       {rights}")

    matchings = []
    for order in itertools.permutations(rights):
        pairs = [(l, r, read_pair(l, r)) for l, r in zip(lefts, order)]
        if all(word in WORDS for _, _, word in pairs):
            matchings.append(pairs)

    print(f"\npairings where every pair spells a word: {len(matchings)}")
    for pairs in matchings:
        for left, right, word in pairs:
            print(f"  {left:<22} + {right:<22} = {word}")

    groups = defaultdict(list)
    for name in sorted(TILES):
        groups[encoder_fingerprint(name)].append(name)
    print("\nPNG encoder fingerprints (pixels-per-metre, colour type, sRGB):")
    for key, names in sorted(groups.items()):
        print(f"  {key} -> {names}")

    if len(matchings) == 1:
        found = {word for _, _, word in matchings[0]}
        print("\nwords: " + ", ".join(sorted(found)))
        print("message: cryptologic warning, can you dig it")
        print("password: cryptologicwarningcanyoudigit")


if __name__ == "__main__":
    main()
