"""Seal the source-ordered 13+13+12 block matrix-sum construction."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v24 import SEAL_PATH as V24_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v25.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v25.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v25.json"


def _columns(matrix: list[list[int]]) -> list[int]:
    return [sum(row[column] for row in matrix) for column in range(len(matrix[0]))]


def _rows(matrix: list[list[int]]) -> list[int]:
    return [sum(row) for row in matrix]


def _forms(values: list[int]) -> dict[str, bytes]:
    return {
        "raw-mod256": bytes(value % 256 for value in values),
        "decimal-concatenated": "".join(map(str, values)).encode("ascii"),
        "decimal-spaces": " ".join(map(str, values)).encode("ascii"),
        "decimal-commas": ",".join(map(str, values)).encode("ascii"),
        "compact-json": json.dumps(values, separators=(",", ":")).encode("ascii"),
        "mod9-symbols": bytes(97 + value % 9 for value in values),
        "mod26-a0": bytes(97 + value % 26 for value in values),
        "mod26-a1": bytes(97 + (value - 1) % 26 for value in values),
    }


def _combine(matrices: list[list[list[int]]], signs: tuple[int, ...], modulus: int | None) -> list[list[int]]:
    height = len(matrices[0])
    width = len(matrices[0][0])
    output: list[list[int]] = []
    for row in range(height):
        values: list[int] = []
        for column in range(width):
            value = sum(sign * matrix[row][column] for sign, matrix in zip(signs, matrices))
            values.append(value % modulus if modulus else value)
        output.append(values)
    return output


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    first_symbols = raw.s91 + raw.matrix_marker_bits
    if len(first_symbols) != 195 or len(raw.s570) != 570:
        raise ValueError("matrix lengths changed")

    first_conventions = {
        "uniform-a0": [ord(symbol) - 97 for symbol in first_symbols],
        "uniform-a1": [ord(symbol) - 96 for symbol in first_symbols],
        "native-s-a1-bits": [
            (ord(symbol) - 96) if index < 91 else (ord(symbol) - 97)
            for index, symbol in enumerate(first_symbols)
        ],
    }
    second_conventions = {
        "a0": [ord(symbol) - 97 for symbol in raw.s570],
        "a1": [ord(symbol) - 96 for symbol in raw.s570],
    }
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, values: list[int]) -> None:
        for serialization, value in _forms(values).items():
            preimages[value].add(f"split15-row-matrix/{label}/{serialization}")

    records: list[dict[str, object]] = []
    for first_name, first_values in first_conventions.items():
        matrix_a = [first_values[offset : offset + 13] for offset in range(0, 195, 13)]
        for second_name, second_values in second_conventions.items():
            rows38 = [second_values[offset : offset + 38] for offset in range(0, 570, 38)]
            matrix_b1 = [row[:13] for row in rows38]
            matrix_b2 = [row[13:26] for row in rows38]
            matrix_b3 = [row[26:] for row in rows38]

            # Shared 15-row lists from each source matrix and their horizontal sum.
            row_a = _rows(matrix_a)
            row_b = _rows(rows38)
            for name, values in {
                "row-sums-a": row_a,
                "row-sums-b": row_b,
                "row-sums-a-plus-b": [a + b for a, b in zip(row_a, row_b)],
                "row-sums-b-minus-a": [b - a for a, b in zip(row_a, row_b)],
            }.items():
                add(f"{first_name}/{second_name}/{name}", values)

            combinations = {
                "a-plus-b1": ((matrix_a, matrix_b1), (1, 1)),
                "a-plus-b2": ((matrix_a, matrix_b2), (1, 1)),
                "a-plus-b1-plus-b2": ((matrix_a, matrix_b1, matrix_b2), (1, 1, 1)),
                "b1-plus-b2": ((matrix_b1, matrix_b2), (1, 1)),
                "a-minus-b1": ((matrix_a, matrix_b1), (1, -1)),
                "a-minus-b2": ((matrix_a, matrix_b2), (1, -1)),
            }
            for name, (matrices, signs) in combinations.items():
                for modulus in (None, 9):
                    combined = _combine(list(matrices), signs, modulus)
                    sums = _columns(combined)
                    add(f"{first_name}/{second_name}/{name}/mod-{modulus or 'none'}/column-sums", sums)
                    records.append({
                        "first": first_name,
                        "second": second_name,
                        "combination": name,
                        "element_modulus": modulus,
                        "column_sums": sums,
                    })

            # The final source-ordered 12-column block is explicitly adjacent to thispassword.
            tail_sums = _columns(matrix_b3)
            key = [ord(character) - 97 for character in raw.password_marker]
            tail_variants = {
                "direct": tail_sums,
                "plus-thispassword-mod26": [(value + key[i]) % 26 for i, value in enumerate(tail_sums)],
                "minus-thispassword-mod26": [(value - key[i]) % 26 for i, value in enumerate(tail_sums)],
                "thispassword-minus-mod26": [(key[i] - value) % 26 for i, value in enumerate(tail_sums)],
            }
            for name, values in tail_variants.items():
                add(f"{first_name}/{second_name}/tail12/{name}", values)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v25c{len(candidates):05d}",
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
        "schema": "salphaseion-source-only-preregistration-v25-split15-row-matrix",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v24_manifest_sha256": V24_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "physical_layout": "15x13 followed by 15x(13+13+12)",
            "width_labels": [
                "len(matrixsumlist)=13",
                "len(lastwordsbeforearchichoice)=26=13+13",
                "len(thispassword)=12",
            ],
            "records": records,
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
            "inherits_v1_rules_verbatim": True, "padding_alone": False,
            "forbidden_evidence": ["expected padding length", "plus/minus block grammar", "Half/Better Half", "target point or address", "community plaintext hashes"],
        },
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def main() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"], "seal_sha256": sha256_hex(encoded)}, indent=2))


if __name__ == "__main__":
    main()
