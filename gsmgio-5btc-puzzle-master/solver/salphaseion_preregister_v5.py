"""Seal matrix dimensions supplied by adjacent decoded text lengths.

S91 = 7x13 and the adjacent marker ``matrixsumlist`` has length 13.
S570 = 15x38 and the following decoded fields
``lastwordsbeforearchichoice`` + ``thispassword`` have length 26+12=38.
Only vectors aligned to those 13/38-character fields are admitted.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v4 import SEAL_PATH as V4_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v5.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v5.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v5.json"


def _reshape(values: list[int], rows: int, columns: int) -> list[list[int]]:
    if rows * columns != len(values):
        raise ValueError("shape does not consume field")
    return [values[offset:offset + columns] for offset in range(0, len(values), columns)]


def _aligned_sums(values: list[int], rows: int, columns: int, aligned_length: int) -> list[int]:
    grid = _reshape(values, rows, columns)
    row_sums = [sum(row) for row in grid]
    column_sums = [sum(grid[row][column] for row in range(rows)) for column in range(columns)]
    matches = [vector for vector in (row_sums, column_sums) if len(vector) == aligned_length]
    if len(matches) != 1:
        raise ValueError("shape does not yield one uniquely aligned sum vector")
    return matches[0]


def _stable_key_order(key: str) -> list[int]:
    return sorted(range(len(key)), key=lambda index: (key[index], index))


def _serializations(vector: list[int]):
    decimal = [str(value) for value in vector]
    yield "decimal-concatenated", "".join(decimal).encode("ascii")
    yield "decimal-spaces", " ".join(decimal).encode("ascii")
    yield "decimal-commas", ",".join(decimal).encode("ascii")
    yield "json-compact", ("[" + ",".join(decimal) + "]").encode("ascii")
    if all(0 <= value <= 255 for value in vector):
        raw = bytes(vector)
        yield "raw-bytes", raw
        yield "lowerhex", raw.hex().encode("ascii")
    yield "mod26-one-based", "".join(chr(97 + ((value - 1) % 26)) for value in vector).encode("ascii")
    yield "mod26-zero-based", "".join(chr(97 + (value % 26)) for value in vector).encode("ascii")


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    key13 = raw.matrix_marker
    key38 = raw.lastwords_marker + raw.password_marker
    if len(key13) != 13 or len(key38) != 38:
        raise ValueError("decoded adjacent-field lengths changed")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"adjacent-length-matrices/{label}")

    aligned: dict[tuple[str, str, str], list[int]] = {}
    specs = (
        ("S91", raw.s91, key13, ((7, 13), (13, 7))),
        ("S570", raw.s570, key38, ((15, 38), (38, 15))),
    )
    for field_name, text, key, shapes in specs:
        for mapping_name, values in (
            ("one-based", [ord(character) - 96 for character in text]),
            ("zero-based", [ord(character) - 97 for character in text]),
        ):
            for rows, columns in shapes:
                vector = _aligned_sums(values, rows, columns, len(key))
                shape = f"{rows}x{columns}"
                aligned[(field_name, mapping_name, shape)] = vector
                base = f"{field_name}/{mapping_name}/{shape}/aligned-sums"
                for serialization, value in _serializations(vector):
                    add(f"{base}/{serialization}", value)

                order = _stable_key_order(key)
                ordered = [vector[index] for index in order]
                for serialization, value in _serializations(ordered):
                    add(f"{base}/stable-key-order/{serialization}", value)

                for letter_mapping, offset in (("one-based", 1), ("zero-based", 0)):
                    key_values = [ord(character) - 97 + offset for character in key]
                    added = [
                        (value + key_value - (1 if letter_mapping == "one-based" else 0)) % 26
                        for value, key_value in zip(vector, key_values)
                    ]
                    letters = "".join(chr(97 + value) for value in added).encode("ascii")
                    add(f"{base}/sum-with-adjacent-key/{letter_mapping}", letters)

    for mapping_name in ("one-based", "zero-based"):
        for shape91 in ("7x13", "13x7"):
            for shape570 in ("15x38", "38x15"):
                combined = aligned[("S91", mapping_name, shape91)] + aligned[("S570", mapping_name, shape570)]
                base = f"combined-source-order/{mapping_name}/{shape91}+{shape570}"
                for serialization, value in _serializations(combined):
                    add(f"{base}/{serialization}", value)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v5c{len(candidates):04d}",
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
        "schema": "salphaseion-source-only-preregistration-v5",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v4_manifest_sha256": V4_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "dimension_rules": [
                "len(matrixsumlist)=13 and len(S91)=91=7x13",
                "len(lastwordsbeforearchichoice)+len(thispassword)=26+12=38 and len(S570)=570=15x38",
            ],
            "orientation_rule": "register both row-major orientations; retain only the sum vector whose length equals the adjacent decoded field",
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
