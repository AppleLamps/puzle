"""Seal the color-count matrix grammar before AES evaluation.

The creator's color hint mechanically yields Blue=15 and Yellow=9.  S570 has
exactly 15 rows of 38 symbols, its alphabet has exactly nine symbols, and the
two following decoded fields have 38 letters.  Earlier rounds tested the
38-entry aligned sums but omitted the 15 row sums and subtraction operations.
This round closes that narrow gap without consulting any decrypted candidate.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json

from PIL import Image

from .extract import ROOT, extract_all
from .salphaseion_preregister_v7 import SEAL_PATH as V7_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v8.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v8.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v8.json"
IMAGE_PATH = ROOT / "puzzle.png"

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
NEAR_WHITE = (254, 254, 254)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)


def _color_counts() -> tuple[int, int, str]:
    image_bytes = IMAGE_PATH.read_bytes()
    with Image.open(IMAGE_PATH) as source:
        image = source.convert("RGB")
    if image.width != 1048 or image.height < image.width:
        raise ValueError("puzzle image dimensions changed")
    pixels = [
        image.getpixel((int((column + 0.5) * image.width / 14),
                        int((row + 0.5) * image.width / 14)))
        for row in range(14)
        for column in range(14)
    ]
    counts = Counter(pixels)
    expected = Counter({BLACK: 87, WHITE: 84, NEAR_WHITE: 1, BLUE: 15, YELLOW: 9})
    if counts != expected:
        raise ValueError("puzzle image color census changed")
    return counts[BLUE], counts[YELLOW], sha256_hex(image_bytes)


def _reshape(values: list[int], rows: int, columns: int) -> list[list[int]]:
    if rows * columns != len(values):
        raise ValueError("shape does not consume field")
    return [values[offset:offset + columns] for offset in range(0, len(values), columns)]


def _serializations(values: list[int]):
    decimal = [str(value) for value in values]
    yield "decimal-concatenated", "".join(decimal).encode("ascii")
    yield "decimal-spaces", " ".join(decimal).encode("ascii")
    yield "decimal-commas", ",".join(decimal).encode("ascii")
    yield "json-compact", ("[" + ",".join(decimal) + "]").encode("ascii")
    if all(0 <= value <= 255 for value in values):
        raw = bytes(values)
        yield "raw-bytes", raw
        yield "lowerhex", raw.hex().encode("ascii")
    yield "mod9-a0", "".join(chr(97 + value % 9) for value in values).encode("ascii")
    yield "mod9-i0", "".join("iabcdefgh"[value % 9] for value in values).encode("ascii")
    yield "mod26-a0", "".join(chr(97 + value % 26) for value in values).encode("ascii")
    yield "mod26-a1", "".join(chr(97 + (value - 1) % 26) for value in values).encode("ascii")


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    blue_count, yellow_count, image_sha256 = _color_counts()
    key13 = raw.matrix_marker
    key38 = raw.lastwords_marker + raw.password_marker
    if (blue_count, yellow_count) != (15, 9):
        raise ValueError("authenticated color counts changed")
    if len(raw.s570) != blue_count * len(key38):
        raise ValueError("S570 no longer matches Blue x adjacent-key length")
    if len(set(raw.s570)) != yellow_count or set(raw.s570) != set("abcdefghi"):
        raise ValueError("S570 alphabet no longer matches Yellow")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(label)

    specs = (
        ("S91", raw.s91, key13, ((7, 13), (13, 7))),
        ("S570", raw.s570, key38, ((15, 38), (38, 15))),
    )
    for field_name, text, key, shapes in specs:
        for mapping_name, values in (
            ("a0", [ord(character) - 97 for character in text]),
            ("a1", [ord(character) - 96 for character in text]),
        ):
            for rows, columns in shapes:
                grid = _reshape(values, rows, columns)
                vectors = {
                    "rows": [sum(row) for row in grid],
                    "columns": [sum(grid[row][column] for row in range(rows))
                                for column in range(columns)],
                }
                for vector_name, vector in vectors.items():
                    base = f"color-matrix/{field_name}/{mapping_name}/{rows}x{columns}/{vector_name}"
                    for serialization, encoded in _serializations(vector):
                        add(f"{base}/{serialization}", encoded)

                    # A sum list aligned to the adjacent label acts as a Caesar
                    # shift list.  Register all three arithmetic directions.
                    if len(vector) == len(key):
                        for key_origin, offset in (("a0", 0), ("a1", 1)):
                            key_values = [ord(character) - 97 + offset for character in key]
                            for operation, shifted in (
                                ("sum-plus-key", [left + right for left, right in zip(vector, key_values)]),
                                ("sum-minus-key", [left - right for left, right in zip(vector, key_values)]),
                                ("key-minus-sum", [right - left for left, right in zip(vector, key_values)]),
                            ):
                                encoded = "".join(chr(97 + value % 26) for value in shifted).encode("ascii")
                                add(f"{base}/{operation}/{key_origin}/mod26", encoded)

                    # A row sum selects a column from the adjacent label.  The
                    # modulo is fixed by the actual matrix width; both existing
                    # zero/one-based page conventions are registered.
                    if vector_name == "rows" and columns == len(key):
                        for convention, adjustment in (("zero-based", 0), ("one-based", -1)):
                            selected = "".join(key[(value + adjustment) % columns] for value in vector)
                            add(f"{base}/select-adjacent-key/{convention}", selected.encode("ascii"))

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v8c{len(candidates):04d}",
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
        "schema": "salphaseion-source-only-preregistration-v8-color-matrix",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v7_manifest_sha256": V7_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "puzzle_image_sha256": image_sha256,
            "blue_count": blue_count,
            "yellow_count": yellow_count,
            "dimension_rules": [
                "Blue=15 and len(S570)=570=15x38",
                "Yellow=9 and alphabet(S570)=abcdefghi has size 9",
                "len(lastwordsbeforearchichoice+thispassword)=38",
                "len(S91)=91=7x13 and len(matrixsumlist)=13",
            ],
            "candidate_rule": (
                "row/column sum lists, adjacent-label add/subtract operations, "
                "and row-sum selection of the adjacent column label"
            ),
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
