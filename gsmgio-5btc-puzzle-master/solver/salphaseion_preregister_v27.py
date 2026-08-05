"""Seal the canonical 3x3 Lo Shu matrix-sum alphabet interpretation."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v26 import SEAL_PATH as V26_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v27.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v27.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v27.json"

LO_SHU = ((8, 1, 6), (3, 5, 7), (4, 9, 2))


def _rot(square):
    return tuple(tuple(square[2 - column][row] for column in range(3)) for row in range(3))


def _reflect(square):
    return tuple(tuple(reversed(row)) for row in square)


def _mappings() -> dict[str, dict[str, int]]:
    squares = []
    current = LO_SHU
    for _ in range(4):
        squares.extend((current, _reflect(current)))
        current = _rot(current)
    output = {}
    for index, square in enumerate(squares):
        flat = [value for row in square for value in row]
        direct = {chr(97 + position): value for position, value in enumerate(flat)}
        inverse = {chr(96 + value): position + 1 for position, value in enumerate(flat)}
        output[f"symmetry-{index}/direct"] = direct
        output[f"symmetry-{index}/inverse"] = inverse
    return output


def _integer_bytes(number: int) -> bytes:
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def _base9(values: list[int]) -> bytes:
    number = 0
    for value in values:
        number = number * 9 + (0 if value == 9 else value)
    return _integer_bytes(number)


def _decimal_to_hex(values: list[int]) -> bytes:
    number = int("".join(map(str, values)))
    hexadecimal = format(number, "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def _sum_forms(values: list[int]) -> dict[str, bytes]:
    return {
        "raw-byte-list": bytes(values),
        "decimal-concatenated": "".join(map(str, values)).encode("ascii"),
        "decimal-spaces": " ".join(map(str, values)).encode("ascii"),
        "decimal-commas": ",".join(map(str, values)).encode("ascii"),
        "compact-json": json.dumps(values, separators=(",", ":")).encode("ascii"),
        "mod9-symbols": bytes(97 + value % 9 for value in values),
        "mod26-a0": bytes(97 + value % 26 for value in values),
    }


def _vectors(values: list[int], width: int) -> dict[str, list[int]]:
    rows = [values[offset : offset + width] for offset in range(0, len(values), width)]
    if any(len(row) != width for row in rows):
        raise ValueError("incomplete matrix")
    row_sums = [sum(row) for row in rows]
    column_sums = [sum(row[column] for row in rows) for column in range(width)]
    return {"row-sums": row_sums, "column-sums": column_sums, "rows-then-columns": row_sums + column_sums, "columns-then-rows": column_sums + row_sums}


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"lo-shu-matrixsum/{label}")

    records = []
    fields = {"S91": raw.s91, "S570": raw.s570, "S91+S570": raw.s91 + raw.s570, "completed-first": raw.s91 + raw.matrix_marker_bits}
    for mapping_name, mapping in _mappings().items():
        if sorted(mapping.values()) != list(range(1, 10)):
            raise ValueError("Lo Shu mapping is not a permutation")
        for field_name, symbols in fields.items():
            values = [mapping[symbol] for symbol in symbols]
            add(f"{mapping_name}/{field_name}/digit-string", "".join(map(str, values)).encode("ascii"))
            add(f"{mapping_name}/{field_name}/base9-9-as-zero", _base9(values))
            add(f"{mapping_name}/{field_name}/decimal-to-hex", _decimal_to_hex(values))
        for field_name, symbols, width in (
            ("completed-first-15x13", raw.s91 + raw.matrix_marker_bits, 13),
            ("S570-15x38", raw.s570, 38),
            ("S91-7x13", raw.s91, 13),
        ):
            values = [mapping[symbol] for symbol in symbols]
            for vector_name, vector in _vectors(values, width).items():
                for form_name, value in _sum_forms(vector).items():
                    add(f"{mapping_name}/{field_name}/{vector_name}/{form_name}", value)
        records.append({"mapping": mapping_name, "a_through_i": [mapping[chr(97 + index)] for index in range(9)]})

    candidates = []
    for preimage in sorted(preimages):
        for expansion, password in (("raw", preimage), ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")), ("sha256-raw-digest", hashlib.sha256(preimage).digest())):
            candidates.append({"candidate_id": f"v27c{len(candidates):05d}", "preimage_hex": preimage.hex(), "password_expansion": expansion, "password_hex": password.hex(), "password_sha256": sha256_hex(password), "provenance": sorted(preimages[preimage])})

    blobs = {"salphaseion-short": extracted.chain1_envelope, "phase32-small": extracted.chain2_envelope, "cosmic-duality": extracted.cosmic_envelope}
    return {
        "schema": "salphaseion-source-only-preregistration-v27-lo-shu",
        "status": "SEALED_BEFORE_DECRYPTION", "extends_v26_manifest_sha256": V26_SEAL.read_text(encoding="ascii").strip(),
        "source": {"capture_stability": capture_stability(), "textarea1_sha256": sha256_hex(raw.textarea1), "object": "3x3 Lo Shu magic square", "reason": "nine-symbol alphabet and literal matrix-sum instruction", "base_square": LO_SHU, "mappings": records},
        "blobs": {name: {"length": len(value), "sha256": sha256_hex(value), "salt_hex": value[8:16].hex(), "ciphertext_length": len(value) - 16} for name, value in blobs.items()},
        "declared_crypto": {"cipher": "AES-256-CBC", "password_to_key": "OpenSSL EVP_BytesToKey", "kdf_digests": ["md5", "sha256"], "padding": "strict PKCS#7", "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"]},
        "declared_acceptance": {"inherits_v1_rules_verbatim": True, "padding_alone": False, "forbidden_evidence": ["expected padding length", "plus/minus block grammar", "Half/Better Half", "target point or address", "community plaintext hashes"]},
        "candidate_count": len(candidates), "candidates": candidates,
    }


def main() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"], "seal_sha256": sha256_hex(encoded)}, indent=2))


if __name__ == "__main__":
    main()
