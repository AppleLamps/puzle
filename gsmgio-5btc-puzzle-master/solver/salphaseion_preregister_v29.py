"""Seal sum-list-derived row/column transpositions on completed matrices.

The page supplies complete 15-row matrices and the literal instruction
``matrixsumlist``.  A standard numerical-sequence transposition interpretation
is to rank rows/columns by their sums and use that stable order as a route key.
This manifest fixes those finite permutations before any transformed bytes are
inspected or used for AES.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v28 import SEAL_PATH as V28_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v29.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v29.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v29.json"


def _matrix(text: str, width: int) -> list[list[str]]:
    rows = [list(text[offset : offset + width]) for offset in range(0, len(text), width)]
    if not rows or any(len(row) != width for row in rows):
        raise ValueError("incomplete matrix")
    return rows


def _stable_order(values, descending=False):
    return sorted(range(len(values)), key=lambda index: (values[index], index), reverse=descending)


def _key_order(key: str, descending=False):
    return sorted(range(len(key)), key=lambda index: (key[index], index), reverse=descending)


def _permute(matrix, row_order, column_order):
    return [[matrix[row][column] for column in column_order] for row in row_order]


def _route(matrix, mode):
    if mode == "row-major":
        return "".join(symbol for row in matrix for symbol in row)
    if mode == "column-major":
        return "".join(matrix[row][column] for column in range(len(matrix[0])) for row in range(len(matrix)))
    if mode == "row-serpentine":
        return "".join(symbol for index, row in enumerate(matrix) for symbol in (row if index % 2 == 0 else row[::-1]))
    if mode == "column-serpentine":
        output = []
        for column in range(len(matrix[0])):
            rows = range(len(matrix)) if column % 2 == 0 else range(len(matrix) - 1, -1, -1)
            output.extend(matrix[row][column] for row in rows)
        return "".join(output)
    raise ValueError("unknown route")


def _base9_bytes(symbols: str, convention: str) -> bytes:
    if convention == "a0":
        digits = [ord(symbol) - 97 for symbol in symbols]
    elif convention == "a1-i0":
        digits = [(ord(symbol) - 96) % 9 for symbol in symbols]
    else:
        raise ValueError("unknown base9 convention")
    number = 0
    for digit in digits:
        number = number * 9 + digit
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def _decimal_to_hex(symbols: str) -> bytes:
    digits = "".join(str(ord(symbol) - 96) for symbol in symbols)
    hexadecimal = format(int(digits), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def build_manifest():
    raw = extract_raw()
    extracted = extract_all()
    completed = raw.s91 + raw.matrix_marker_bits
    rows38 = _matrix(raw.s570, 38)
    texts = {
        "A-15x13": (completed, 13, raw.matrix_marker),
        "B-15x38": (raw.s570, 38, raw.lastwords_marker + raw.password_marker),
        "B1-15x13": ("".join("".join(row[:13]) for row in rows38), 13, raw.lastwords_marker[:13]),
        "B2-15x13": ("".join("".join(row[13:26]) for row in rows38), 13, raw.lastwords_marker[13:]),
        "B3-15x12": ("".join("".join(row[26:]) for row in rows38), 12, raw.password_marker),
    }
    if [len(value[0]) for value in texts.values()] != [195, 570, 195, 195, 180]:
        raise ValueError("completed matrix split changed")

    preimages = defaultdict(set)
    route_records = []

    def add(label, value):
        if value:
            preimages[value].add(f"sum-list-transposition/{label}")

    for mapping in ("a0", "a1-i0"):
        def numeric(symbol):
            return ord(symbol) - 97 if mapping == "a0" else (ord(symbol) - 96) % 9

        # Shared 15-row orders are independently motivated because all five
        # matrices have the same height.
        matrices = {name: _matrix(text, width) for name, (text, width, _) in texts.items()}
        row_sums = {name: [sum(numeric(symbol) for symbol in row) for row in matrix] for name, matrix in matrices.items()}
        shared_orders = {
            "source": list(range(15)),
            "A-sums-ascending": _stable_order(row_sums["A-15x13"]),
            "A-sums-descending": _stable_order(row_sums["A-15x13"], True),
            "B-sums-ascending": _stable_order(row_sums["B-15x38"]),
            "B-sums-descending": _stable_order(row_sums["B-15x38"], True),
        }
        for name, (text, width, key) in texts.items():
            matrix = matrices[name]
            columns = [[matrix[row][column] for row in range(15)] for column in range(width)]
            column_sums = [sum(numeric(symbol) for symbol in column) for column in columns]
            column_orders = {
                "source": list(range(width)),
                "sum-ascending": _stable_order(column_sums),
                "sum-descending": _stable_order(column_sums, True),
                "key-ascending": _key_order(key),
                "key-descending": _key_order(key, True),
            }
            for row_name, row_order in shared_orders.items():
                for column_name, column_order in column_orders.items():
                    permuted = _permute(matrix, row_order, column_order)
                    for route_name in ("row-major", "column-major", "row-serpentine", "column-serpentine"):
                        symbols = _route(permuted, route_name)
                        label = f"{mapping}/{name}/{row_name}/{column_name}/{route_name}"
                        add(f"{label}/symbols", symbols.encode("ascii"))
                        add(f"{label}/base9-bytes", _base9_bytes(symbols, mapping))
                        add(f"{label}/decimal-to-hex", _decimal_to_hex(symbols))
                        route_records.append({"label": label, "symbols_sha256": sha256_hex(symbols.encode("ascii")), "base9_sha256": sha256_hex(_base9_bytes(symbols, mapping))})

    candidates = []
    for preimage in sorted(preimages):
        for expansion, password in (("raw", preimage), ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")), ("sha256-raw-digest", hashlib.sha256(preimage).digest())):
            candidates.append({"candidate_id": f"v29c{len(candidates):06d}", "preimage_hex": preimage.hex(), "password_expansion": expansion, "password_hex": password.hex(), "password_sha256": sha256_hex(password), "provenance": sorted(preimages[preimage])})

    blobs = {"salphaseion-short": extracted.chain1_envelope, "phase32-small": extracted.chain2_envelope, "cosmic-duality": extracted.cosmic_envelope}
    return {
        "schema": "salphaseion-source-only-preregistration-v29-sum-list-transposition", "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v28_manifest_sha256": V28_SEAL.read_text(encoding="ascii").strip(),
        "source": {"capture_stability": capture_stability(), "textarea1_sha256": sha256_hex(raw.textarea1), "matrix_layout": "A=15x13; B=15x38=B1(13)+B2(13)+B3(12)", "permutations": "stable source, row-sum, column-sum, and adjacent-key orders only", "routes": ["row-major", "column-major", "row-serpentine", "column-serpentine"], "route_records_without_plaintext": route_records},
        "blobs": {name: {"length": len(value), "sha256": sha256_hex(value), "salt_hex": value[8:16].hex(), "ciphertext_length": len(value) - 16} for name, value in blobs.items()},
        "declared_crypto": {"cipher": "AES-256-CBC", "password_to_key": "OpenSSL EVP_BytesToKey", "kdf_digests": ["md5", "sha256"], "padding": "strict PKCS#7", "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"]},
        "declared_acceptance": {"direct_transform": "existing readable-text or exact-parser/checksum rule", "aes": "existing v1 readable/exact-format rule", "padding_alone": False, "forbidden_evidence": ["expected padding length", "Half/Better Half", "target point", "community plaintext hashes"]},
        "candidate_count": len(candidates), "candidates": candidates,
    }


def main():
    manifest = build_manifest(); encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded); SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"], "seal_sha256": sha256_hex(encoded)}, indent=2))


if __name__ == "__main__": main()
