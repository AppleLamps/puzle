"""Seal literal repeated-key matrix operations before AES evaluation.

The two unexplained source fields have exact adjacent widths:

* S91 = 7 x len("matrixsumlist")
* S570 = 15 x len("lastwordsbeforearchichoice" + "thispassword")

This round treats those adjacent strings as row-wise keys.  It registers the
finite operations that were missing from v1-v8: apply the key to every cell
before summing, use the key as a matrix-vector operand, and serialize a sum
list with Python's ordinary list representation.  Nothing in this module
examines a decryption result or target key/address.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v8 import SEAL_PATH as V8_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v9.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v9.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v9.json"


def _matrix(text: str, width: int, origin: int) -> list[list[int]]:
    if len(text) % width:
        raise ValueError("field does not fit its adjacent width")
    values = [ord(character) - 97 + origin for character in text]
    return [values[offset:offset + width] for offset in range(0, len(values), width)]


def _key_values(key: str, origin: int) -> list[int]:
    return [ord(character) - 97 + origin for character in key]


def _serializations(values: list[int]):
    decimal = [str(value) for value in values]
    yield "python-list", repr(values).encode("ascii")
    yield "json-compact", ("[" + ",".join(decimal) + "]").encode("ascii")
    yield "decimal-concatenated", "".join(decimal).encode("ascii")
    yield "decimal-spaces", " ".join(decimal).encode("ascii")
    yield "decimal-commas", ",".join(decimal).encode("ascii")
    if all(0 <= value <= 255 for value in values):
        raw = bytes(values)
        yield "raw-bytes", raw
        yield "lowerhex", raw.hex().encode("ascii")
    yield "mod9-a0", "".join(chr(97 + value % 9) for value in values).encode("ascii")
    yield "mod9-i0", "".join("iabcdefgh"[value % 9] for value in values).encode("ascii")
    yield "mod26-a0", "".join(chr(97 + value % 26) for value in values).encode("ascii")
    yield "mod26-a1", "".join(chr(97 + (value - 1) % 26) for value in values).encode("ascii")


def _symbol_encodings(values: list[int]):
    yield "a0", "".join(chr(97 + value % 9) for value in values).encode("ascii")
    yield "i0", "".join("iabcdefgh"[value % 9] for value in values).encode("ascii")


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    key13 = raw.matrix_marker
    key38 = raw.lastwords_marker + raw.password_marker
    specs = (
        ("S91", raw.s91, key13, 7),
        ("S570", raw.s570, key38, 15),
    )
    for _, text, key, rows in specs:
        if len(text) != rows * len(key):
            raise ValueError("authenticated adjacent dimension changed")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"repeated-adjacent-key/{label}")

    # Save corresponding results so the exact source-order concatenation can
    # be registered without a combinatorial cross-product.
    corresponding: dict[tuple[str, int, int, str, str], bytes] = {}

    for field_name, text, key, expected_rows in specs:
        width = len(key)
        for field_origin in (0, 1):
            grid = _matrix(text, width, field_origin)
            if len(grid) != expected_rows:
                raise ValueError("matrix row count changed")
            for key_origin in (0, 1):
                key_vector = _key_values(key, key_origin)

                # Literal row-wise application of the adjacent key in Z/9Z.
                for operation in ("field-plus-key", "field-minus-key", "key-minus-field"):
                    adjusted: list[list[int]] = []
                    for row in grid:
                        if operation == "field-plus-key":
                            adjusted.append([(left + right) % 9 for left, right in zip(row, key_vector)])
                        elif operation == "field-minus-key":
                            adjusted.append([(left - right) % 9 for left, right in zip(row, key_vector)])
                        else:
                            adjusted.append([(right - left) % 9 for left, right in zip(row, key_vector)])

                    flat = [value for row in adjusted for value in row]
                    base = (
                        f"{field_name}/field-origin-{field_origin}/key-origin-{key_origin}/"
                        f"{operation}"
                    )
                    for symbol_name, encoded in _symbol_encodings(flat):
                        label = f"{base}/full-field/{symbol_name}"
                        add(label, encoded)
                        corresponding[(field_name, field_origin, key_origin, operation,
                                       f"full-field/{symbol_name}")] = encoded

                    vectors = {
                        "row-sums": [sum(row) for row in adjusted],
                        "column-sums": [sum(row[column] for row in adjusted)
                                        for column in range(width)],
                    }
                    for vector_name, vector in vectors.items():
                        for serialization, encoded in _serializations(vector):
                            label = f"{base}/{vector_name}/{serialization}"
                            add(label, encoded)
                            corresponding[(field_name, field_origin, key_origin, operation,
                                           f"{vector_name}/{serialization}")] = encoded

                # The other direct meaning of a matrix and a same-width list:
                # multiply each row by the list and sum it (matrix-vector dot).
                dot = [sum(left * right for left, right in zip(row, key_vector)) for row in grid]
                base = (
                    f"{field_name}/field-origin-{field_origin}/key-origin-{key_origin}/"
                    "matrix-vector-dot"
                )
                for variant_name, vector in (("integer", dot), ("mod9", [value % 9 for value in dot])):
                    for serialization, encoded in _serializations(vector):
                        label = f"{base}/{variant_name}/{serialization}"
                        add(label, encoded)
                        corresponding[(field_name, field_origin, key_origin, "matrix-vector-dot",
                                       f"{variant_name}/{serialization}")] = encoded

    # Concatenate only like-for-like constructions in physical source order.
    keys = {
        (field_origin, key_origin, operation, representation)
        for field_name, field_origin, key_origin, operation, representation in corresponding
        if field_name == "S91"
    }
    for field_origin, key_origin, operation, representation in sorted(keys):
        left = corresponding.get(("S91", field_origin, key_origin, operation, representation))
        right = corresponding.get(("S570", field_origin, key_origin, operation, representation))
        if left is not None and right is not None:
            add(
                f"combined-source-order/field-origin-{field_origin}/key-origin-{key_origin}/"
                f"{operation}/{representation}",
                left + right,
            )

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v9c{len(candidates):05d}",
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
        "schema": "salphaseion-source-only-preregistration-v9-repeated-key-matrix",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v8_manifest_sha256": V8_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "dimension_rules": [
                "S91=7x13 and adjacent matrixsumlist has length 13",
                "S570=15x38 and adjacent lastwordsbeforearchichoice+thispassword has length 38",
            ],
            "candidate_rule": (
                "repeat the adjacent string as each matrix row; apply add/subtract in Z9 before "
                "row/column sums; or use the adjacent list as a matrix-vector operand; serialize "
                "sum lists including the ordinary Python list representation"
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
