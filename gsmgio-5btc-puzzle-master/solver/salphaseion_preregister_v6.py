"""Seal the source-grounded Z9 matrix-sum construction.

The statistical controls reject treating S91/S570 as ordinary decimal
numerals.  This round therefore treats a..i as the nine elements of Z/9Z,
computes only the sum vectors aligned with the adjacent 13- and 38-character
fields, and preserves results as nine-symbol strings.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v5 import SEAL_PATH as V5_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v6.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v6.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v6.json"


def _reshape(values: list[int], rows: int, columns: int) -> list[list[int]]:
    if rows * columns != len(values):
        raise ValueError("shape does not consume field")
    return [values[offset:offset + columns] for offset in range(0, len(values), columns)]


def _aligned_sum_mod9(values: list[int], rows: int, columns: int, length: int) -> list[int]:
    grid = _reshape(values, rows, columns)
    row_sums = [sum(row) % 9 for row in grid]
    column_sums = [sum(grid[row][column] for row in range(rows)) % 9 for column in range(columns)]
    matches = [vector for vector in (row_sums, column_sums) if len(vector) == length]
    if len(matches) != 1:
        raise ValueError("shape does not yield a unique aligned vector")
    return matches[0]


def _stable_order(key: str) -> list[int]:
    return sorted(range(len(key)), key=lambda index: (key[index], index))


def _encode_symbols(values: list[int], convention: str) -> bytes:
    if convention == "zero-based-a0":
        alphabet = "abcdefghi"
    elif convention == "one-based-i0":
        alphabet = "iabcdefgh"
    else:
        raise ValueError("unknown Z9 symbol convention")
    return "".join(alphabet[value % 9] for value in values).encode("ascii")


def _key_values(key: str, convention: str) -> list[int]:
    if convention == "a0z25-mod9":
        return [(ord(character) - 97) % 9 for character in key]
    if convention == "a1z26-mod9":
        return [(ord(character) - 96) % 9 for character in key]
    raise ValueError("unknown key convention")


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    key13 = raw.matrix_marker
    key38 = raw.lastwords_marker + raw.password_marker
    if len(key13) != 13 or len(key38) != 38:
        raise ValueError("adjacent decoded field lengths changed")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, values: list[int]) -> None:
        for symbol_convention in ("zero-based-a0", "one-based-i0"):
            encoded = _encode_symbols(values, symbol_convention)
            preimages[encoded].add(f"z9-matrix-sum/{label}/{symbol_convention}")

    vectors: dict[tuple[str, str, str], list[int]] = {}
    specs = (
        ("S91", raw.s91, key13, ((7, 13), (13, 7))),
        ("S570", raw.s570, key38, ((15, 38), (38, 15))),
    )
    for field_name, text, key, shapes in specs:
        for input_convention, values in (
            ("a0", [(ord(character) - 97) % 9 for character in text]),
            ("a1-i0", [(ord(character) - 96) % 9 for character in text]),
        ):
            for rows, columns in shapes:
                shape = f"{rows}x{columns}"
                vector = _aligned_sum_mod9(values, rows, columns, len(key))
                vectors[(field_name, input_convention, shape)] = vector
                base = f"{field_name}/{input_convention}/{shape}/aligned"
                add(f"{base}/direct", vector)

                order = _stable_order(key)
                add(f"{base}/stable-adjacent-key-order", [vector[index] for index in order])

                for key_convention in ("a0z25-mod9", "a1z26-mod9"):
                    keyed = [
                        (value + key_value) % 9
                        for value, key_value in zip(vector, _key_values(key, key_convention))
                    ]
                    add(f"{base}/sum-with-adjacent-key/{key_convention}", keyed)

    # Concatenate corresponding list outputs in physical field order.  No
    # cross-product of unrelated transformations is admitted.
    for input_convention in ("a0", "a1-i0"):
        for shape91 in ("7x13", "13x7"):
            for shape570 in ("15x38", "38x15"):
                vector91 = vectors[("S91", input_convention, shape91)]
                vector570 = vectors[("S570", input_convention, shape570)]
                base = f"combined-source-order/{input_convention}/{shape91}+{shape570}"
                add(f"{base}/direct", vector91 + vector570)
                for key_convention in ("a0z25-mod9", "a1z26-mod9"):
                    keyed91 = [
                        (value + key_value) % 9
                        for value, key_value in zip(vector91, _key_values(key13, key_convention))
                    ]
                    keyed570 = [
                        (value + key_value) % 9
                        for value, key_value in zip(vector570, _key_values(key38, key_convention))
                    ]
                    add(f"{base}/sum-with-adjacent-keys/{key_convention}", keyed91 + keyed570)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v6c{len(candidates):04d}",
                "preimage_hex": preimage.hex(),
                "preimage_ascii": preimage.decode("ascii"),
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
        "schema": "salphaseion-source-only-preregistration-v6-z9",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v5_manifest_sha256": V5_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "classification": "structured nine-symbol data; not an ordinary uniform decimal numeral",
            "dimension_rules": [
                "len(S91)=91=7x13 and len(matrixsumlist)=13",
                "len(S570)=570=15x38 and len(lastwordsbeforearchichoice+thispassword)=38",
            ],
            "algebra": "row or column sums in Z/9Z, retaining only the vector aligned to the adjacent decoded field",
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
