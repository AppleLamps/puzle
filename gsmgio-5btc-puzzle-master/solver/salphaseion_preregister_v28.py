"""Seal the original-grid right-path / second-door construction.

The published first door starts at the upper-left cell and moves down in a
counterclockwise spiral.  The creator's later hint says the first image may
contain more than one door.  A community lead calls the missing route the
"right path".  Before inspecting its output, this manifest fixes the literal
sibling route: same upper-left origin, first move right, clockwise spiral.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json

from PIL import Image

from .extract import ROOT, extract_all
from .salphaseion_preregister_v27 import SEAL_PATH as V27_SEAL
from .salphaseion_raw import sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v28.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v28.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v28.json"
IMAGE_PATH = ROOT / "puzzle.png"

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
NEAR_WHITE = (254, 254, 254)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)


def _image_grid():
    with Image.open(IMAGE_PATH) as source:
        image = source.convert("RGB")
    grid = [[image.getpixel((int((column + 0.5) * image.width / 14), int((row + 0.5) * 1048 / 14))) for column in range(14)] for row in range(14)]
    expected = Counter({BLACK: 87, WHITE: 84, NEAR_WHITE: 1, BLUE: 15, YELLOW: 9})
    if Counter(pixel for row in grid for pixel in row) != expected:
        raise ValueError("original grid color census changed")
    bits = [[1 if pixel in (BLACK, BLUE) else 0 for pixel in row] for row in grid]
    return grid, bits


def _spiral_right(grid):
    top = left = 0
    bottom = len(grid) - 1
    right = len(grid[0]) - 1
    output = []
    while top <= bottom and left <= right:
        output.extend(grid[top][left : right + 1])
        top += 1
        for row in range(top, bottom + 1):
            output.append(grid[row][right])
        right -= 1
        if top <= bottom:
            output.extend(reversed(grid[bottom][left : right + 1]))
            bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                output.append(grid[row][left])
            left += 1
    return output


def _rotate(grid):
    return [list(row) for row in zip(*grid[::-1])]


def _routes(grid):
    current = grid
    output = {}
    for rotation in range(4):
        output[f"rotation-{rotation * 90}"] = _spiral_right(current)
        output[f"rotation-{rotation * 90}-mirror"] = _spiral_right([row[::-1] for row in current])
        current = _rotate(current)
    return output


def _bytes(bits):
    return bytes(int("".join(map(str, bits[offset : offset + 8])), 2) for offset in range(0, 192, 8))


def _forms(values):
    return {
        "decimal-concatenated": "".join(map(str, values)).encode("ascii"),
        "decimal-spaces": " ".join(map(str, values)).encode("ascii"),
        "decimal-commas": ",".join(map(str, values)).encode("ascii"),
        "compact-json": json.dumps(values, separators=(",", ":")).encode("ascii"),
        "raw-mod256": bytes(value % 256 for value in values),
    }


def build_manifest():
    color_grid, bit_grid = _image_grid()
    route_bits = _routes(bit_grid)
    primary = route_bits["rotation-0"]
    primary_bytes = _bytes(primary)
    preimages = defaultdict(set)

    def add(label, value):
        if value:
            preimages[value].add(f"original-grid-right-path/{label}")

    add("route-bytes", primary_bytes)
    add("route-bytes-hex-lower", primary_bytes.hex().encode("ascii"))
    add("route-bytes-hex-upper", primary_bytes.hex().upper().encode("ascii"))
    add("route-bits-196", "".join(map(str, primary)).encode("ascii"))
    add("route-residual-4-bits", "".join(map(str, primary[192:])).encode("ascii"))
    byte_values = list(primary_bytes)
    for name, value in _forms(byte_values).items():
        add(f"byte-list/{name}", value)
    for name, value in _forms([sum(byte_values)]).items():
        add(f"byte-list-total/{name}", value)
    popcounts = [sum(primary[offset : offset + 8]) for offset in range(0, 192, 8)]
    for name, value in _forms(popcounts).items():
        add(f"byte-popcount-list/{name}", value)

    # Traverse the same coordinates through the color grid and gather the
    # creator-authenticated color counts at colored cells: Blue=15, Yellow=9.
    color_routes = _routes(color_grid)
    gathered = [15 if pixel == BLUE else 9 for pixel in color_routes["rotation-0"] if pixel in (BLUE, YELLOW)]
    if len(gathered) != 24:
        raise ValueError("right route did not gather all colored cells")
    for name, value in _forms(gathered).items():
        add(f"colored-number-list/{name}", value)
    for name, value in _forms([sum(gathered)]).items():
        add(f"colored-number-total/{name}", value)

    candidates = []
    for preimage in sorted(preimages):
        for expansion, password in (("raw", preimage), ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")), ("sha256-raw-digest", hashlib.sha256(preimage).digest())):
            candidates.append({"candidate_id": f"v28c{len(candidates):04d}", "preimage_hex": preimage.hex(), "password_expansion": expansion, "password_hex": password.hex(), "password_sha256": sha256_hex(password), "provenance": sorted(preimages[preimage])})

    extracted = extract_all()
    blobs = {"salphaseion-short": extracted.chain1_envelope, "phase32-small": extracted.chain2_envelope, "cosmic-duality": extracted.cosmic_envelope}
    route_records = {name: {"bytes_sha256": sha256_hex(_bytes(bits)), "residual_bits": "".join(map(str, bits[192:]))} for name, bits in route_bits.items()}
    return {
        "schema": "salphaseion-source-only-preregistration-v28-original-grid-right-path", "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v27_manifest_sha256": V27_SEAL.read_text(encoding="ascii").strip(),
        "source": {"puzzle_png_sha256": sha256_hex(IMAGE_PATH.read_bytes()), "published_positive_control": "upper-left, down-first counterclockwise spiral -> gsmg.io/theseedisplanted", "primary_route": "upper-left, right-first clockwise spiral", "route_records_without_plaintext": route_records, "color_counts": {"blue": 15, "yellow": 9}},
        "blobs": {name: {"length": len(value), "sha256": sha256_hex(value), "salt_hex": value[8:16].hex(), "ciphertext_length": len(value) - 16} for name, value in blobs.items()},
        "declared_crypto": {"cipher": "AES-256-CBC", "password_to_key": "OpenSSL EVP_BytesToKey", "kdf_digests": ["md5", "sha256"], "padding": "strict PKCS#7", "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"]},
        "declared_acceptance": {"direct_route": "UTF-8 URL/path pattern or existing readable/exact-format rule", "aes": "existing v1 readable/exact-format rule", "padding_alone": False, "community_comment_is_lead_not_evidence": True, "forbidden_evidence": ["expected padding length", "Half/Better Half", "target point", "community plaintext hashes"]},
        "candidate_count": len(candidates), "candidates": candidates,
    }


def main():
    manifest = build_manifest(); encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded); SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"], "seal_sha256": sha256_hex(encoded)}, indent=2))


if __name__ == "__main__": main()
