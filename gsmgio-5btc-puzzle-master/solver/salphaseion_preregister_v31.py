"""Seal literal Z/9Z sums of the completed equal-shape matrices.

The first completed object is 15x13.  The following 15x38 object begins with
two further 15x13 blocks.  The page itself establishes a..i as 1..9 (with nine
represented by zero in base nine) and its appended marker is already binary.
This manifest fixes literal matrix addition only, then established numeric
serializations.  It deliberately excludes fitted subtraction.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v30 import SEAL_PATH as V30_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v31.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v31.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v31.json"


def _integer_bytes(number: int) -> bytes:
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def _base9(values: list[int]) -> bytes:
    number = 0
    for value in values:
        number = number * 9 + value
    return _integer_bytes(number)


def _decimal_to_hex(values: list[int]) -> bytes:
    hexadecimal = format(int("".join(map(str, values))), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def _routes(matrix: list[list[int]]) -> dict[str, list[int]]:
    height, width = len(matrix), len(matrix[0])
    return {
        "row-major": [value for row in matrix for value in row],
        "column-major": [matrix[row][column] for column in range(width) for row in range(height)],
        "row-sums-mod9": [sum(row) % 9 for row in matrix],
        "column-sums-mod9": [sum(matrix[row][column] for row in range(height)) % 9 for column in range(width)],
    }


def build_manifest():
    raw = extract_raw()
    extracted = extract_all()
    first_text = raw.s91 + raw.matrix_marker_bits
    first_values = [
        ((ord(symbol) - 96) % 9) if index < 91 else (ord(symbol) - 97)
        for index, symbol in enumerate(first_text)
    ]
    a = [first_values[offset : offset + 13] for offset in range(0, 195, 13)]
    b_values = [(ord(symbol) - 96) % 9 for symbol in raw.s570]
    rows38 = [b_values[offset : offset + 38] for offset in range(0, 570, 38)]
    b1 = [row[:13] for row in rows38]
    b2 = [row[13:26] for row in rows38]
    b3 = [row[26:] for row in rows38]
    if [len(a), len(b1), len(b2), len(b3)] != [15, 15, 15, 15]:
        raise ValueError("completed matrix heights changed")

    matrices = {"A": a, "B1": b1, "B2": b2, "B3": b3}
    for name, sources in {
        "A-plus-B1": (a, b1),
        "A-plus-B2": (a, b2),
        "B1-plus-B2": (b1, b2),
        "A-plus-B1-plus-B2": (a, b1, b2),
    }.items():
        matrices[name] = [
            [sum(matrix[row][column] for matrix in sources) % 9 for column in range(13)]
            for row in range(15)
        ]

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes):
        if value:
            preimages[value].add(f"literal-z9-matrix-sum/{label}")

    records = []
    for matrix_name, matrix in matrices.items():
        for route_name, values in _routes(matrix).items():
            for direction, routed in (("forward", values), ("reverse", values[::-1])):
                base = f"{matrix_name}/{route_name}/{direction}"
                add(f"{base}/digits", "".join(map(str, routed)).encode("ascii"))
                add(f"{base}/symbols-a0", bytes(97 + value for value in routed))
                add(f"{base}/raw-residue-bytes", bytes(routed))
                add(f"{base}/base9-whole", _base9(routed))
                add(f"{base}/decimal-to-hex", _decimal_to_hex(routed))
                records.append({"label": base, "base9_sha256": sha256_hex(_base9(routed))})

        # Preserve the 15-row structure when converting: each row is one
        # base-nine integer, serialized as its minimal big-endian byte string.
        row_bytes = b"".join(_base9(row) for row in matrix)
        add(f"{matrix_name}/base9-per-row", row_bytes)
        add(f"{matrix_name}/base9-per-row-reverse", row_bytes[::-1])

    candidates = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v31c{len(candidates):04d}",
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
        "schema": "salphaseion-source-only-preregistration-v31-literal-z9-matrix-sum",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v30_manifest_sha256": V30_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "layout": "A=15x13; B=15x38=B1(13)+B2(13)+B3(12)",
            "mapping": "S fields a..i -> 1..8,0; appended marker a,b -> 0,1",
            "operation": "literal elementwise addition modulo nine; no subtraction",
            "routes": ["row-major", "column-major", "row-sums-mod9", "column-sums-mod9", "base9-per-row"],
            "records_without_plaintext": records,
        },
        "blobs": {
            name: {"length": len(value), "sha256": sha256_hex(value), "salt_hex": value[8:16].hex(), "ciphertext_length": len(value) - 16}
            for name, value in blobs.items()
        },
        "declared_crypto": {
            "cipher": "AES-256-CBC", "password_to_key": "OpenSSL EVP_BytesToKey",
            "kdf_digests": ["md5", "sha256"], "padding": "strict PKCS#7",
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
        },
        "declared_acceptance": {
            "aes": "existing v1 readable/exact-format rule", "padding_alone": False,
            "forbidden_evidence": ["expected padding length", "fitted subtraction", "Half/Better Half", "target point", "community plaintext hashes"],
        },
        "candidate_count": len(candidates), "candidates": candidates,
    }


def main():
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"], "seal_sha256": sha256_hex(encoded)}, indent=2))


if __name__ == "__main__":
    main()
