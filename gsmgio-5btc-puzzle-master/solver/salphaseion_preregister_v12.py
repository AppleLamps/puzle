"""Seal the literal prime/color reinsertion into S91 before evaluation.

Three authenticated cardinalities meet exactly:

* S91 has positions 1..91;
* there are 24 primes not exceeding 91;
* the original puzzle image has 24 colored cells: Blue=15, Yellow=9.

The Architect plaintext says ``REINSERTING THE PRIME BASICS``.  A1Z26 turns
the two color counts into ``o`` and ``i``, completing the same ``a..i,o``
alphabet whose ``o=0`` decoding is demonstrated later on the page.  This round
replaces S91's prime positions with those color letters, preserving every
non-prime S91 symbol.  Row-major color order and the puzzle's authenticated
counterclockwise spiral are both fixed before any output is decoded.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import math

from PIL import Image

from .extract import ROOT, extract_all
from .salphaseion_preregister_v11 import SEAL_PATH as V11_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v12.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v12.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v12.json"
IMAGE_PATH = ROOT / "puzzle.png"

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
NEAR_WHITE = (254, 254, 254)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)


def _primes(limit: int) -> list[int]:
    return [value for value in range(2, limit + 1)
            if all(value % divisor for divisor in range(2, math.isqrt(value) + 1))]


def _spiral_positions(size: int) -> list[tuple[int, int]]:
    top = left = 0
    bottom = right = size - 1
    output: list[tuple[int, int]] = []
    while left <= right and top <= bottom:
        for row in range(top, bottom + 1):
            output.append((row, left))
        left += 1
        for column in range(left, right + 1):
            output.append((bottom, column))
        bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                output.append((row, right))
            right -= 1
        if top <= bottom:
            for column in range(right, left - 1, -1):
                output.append((top, column))
            top += 1
    return output


def _color_letters() -> tuple[dict[str, str], str]:
    with Image.open(IMAGE_PATH) as source:
        image = source.convert("RGB")
    grid = [
        [image.getpixel((int((column + 0.5) * image.width / 14),
                         int((row + 0.5) * image.width / 14)))
         for column in range(14)]
        for row in range(14)
    ]
    counts = Counter(pixel for row in grid for pixel in row)
    expected = Counter({BLACK: 87, WHITE: 84, NEAR_WHITE: 1, BLUE: 15, YELLOW: 9})
    if counts != expected:
        raise ValueError("authenticated image color census changed")

    def encode(pixel: tuple[int, int, int]) -> str | None:
        if pixel == BLUE:
            return chr(96 + counts[BLUE])  # 15 -> o
        if pixel == YELLOW:
            return chr(96 + counts[YELLOW])  # 9 -> i
        return None

    row_major = "".join(
        letter for row in grid for pixel in row if (letter := encode(pixel)) is not None
    )
    spiral = "".join(
        letter for row, column in _spiral_positions(14)
        if (letter := encode(grid[row][column])) is not None
    )
    if len(row_major) != 24 or len(spiral) != 24:
        raise ValueError("color route no longer has 24 symbols")
    return {"row-major": row_major, "counterclockwise-spiral": spiral}, sha256_hex(IMAGE_PATH.read_bytes())


def _reinsert(s91: str, colors: str) -> str:
    prime_positions = set(_primes(91))
    color_iter = iter(colors)
    output: list[str] = []
    for position, symbol in enumerate(s91, 1):
        output.append(next(color_iter) if position in prime_positions else symbol)
    try:
        next(color_iter)
        raise ValueError("unused color symbol")
    except StopIteration:
        pass
    return "".join(output)


def _decimal_to_hex_bytes(text: str) -> bytes:
    translate = {**{chr(97 + index): str(index + 1) for index in range(9)}, "o": "0"}
    decimal = "".join(translate[character] for character in text)
    hexadecimal = format(int(decimal), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    color_routes, image_sha256 = _color_letters()
    primes = _primes(91)
    if len(raw.s91) != 91 or len(primes) != 24:
        raise ValueError("S91/prime cardinality changed")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"prime-color-reinsertion/{label}")

    derived: list[dict[str, object]] = []
    for route_name, colors in color_routes.items():
        reinserted = _reinsert(raw.s91, colors)
        decoded = _decimal_to_hex_bytes(reinserted)
        forms = {
            "reinserted-symbols": reinserted.encode("ascii"),
            "decimal-to-hex-bytes": decoded,
            "decimal-digits": reinserted.translate(str.maketrans("abcdefghi o", "123456789 0")).encode("ascii"),
        }
        for form_name, value in forms.items():
            add(f"{route_name}/{form_name}", value)
        derived.append({
            "route": route_name,
            "color_letters": colors,
            "reinserted_sha256": sha256_hex(reinserted.encode("ascii")),
            "decoded_length": len(decoded),
            "decoded_sha256": sha256_hex(decoded),
        })

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v12c{len(candidates):03d}",
                "preimage_hex": preimage.hex(),
                "password_expansion": expansion,
                "password_hex": password.hex(),
                "password_sha256": sha256_hex(password),
                "provenance": sorted(preimages[preimage]),
            })

    blobs = {
        "salphaseion-short": extracted.chain1_envelope,
        "phase32-small": extracted.chain2_envelope,
        "cosmic-duality": extracted.cosmic_envelope,
    }
    return {
        "schema": "salphaseion-source-only-preregistration-v12-prime-color-reinsertion",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v11_manifest_sha256": V11_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "puzzle_image_sha256": image_sha256,
            "architect_instruction": "REINSERTING THE PRIME BASICS",
            "prime_positions_one_based": primes,
            "cardinality_rule": "24 primes <= 91 exactly match 24 colored cells",
            "color_rule": "Blue count 15 -> A1Z26 o; Yellow count 9 -> A1Z26 i",
            "color_orders": ["row-major", "authenticated counterclockwise spiral from upper left"],
            "numeric_rule": "page-established a=1..i=9,o=0 decimal integer -> base16 -> bytes",
            "derived_records": derived,
        },
        "blobs": {
            name: {
                "length": len(envelope),
                "sha256": sha256_hex(envelope),
                "salt_hex": envelope[8:16].hex(),
                "ciphertext_length": len(envelope) - 16,
            }
            for name, envelope in blobs.items()
        },
        "declared_crypto": {
            "cipher": "AES-256-CBC",
            "password_to_key": "OpenSSL EVP_BytesToKey",
            "kdf_digests": ["md5", "sha256"],
            "padding": "strict PKCS#7",
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
        },
        "declared_acceptance": {
            "inherits_v1_rules_verbatim": True,
            "padding_alone": False,
            "direct_decoded_bytes_are_evaluated_for_readable_or_exact_structure": True,
            "forbidden_evidence": [
                "expected padding length", "plus/minus grammar", "Half/Better Half",
                "target point or address", "known community plaintext hashes",
            ],
        },
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def main() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({
        "manifest": str(MANIFEST_PATH),
        "candidate_count": manifest["candidate_count"],
        "seal_sha256": sha256_hex(encoded),
    }, indent=2))


if __name__ == "__main__":
    main()
