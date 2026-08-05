"""Seal the second, byte-oriented SalPhaseIon candidate round.

This extension is independent of v1 decryption outcomes.  It registers source-
natural serializations omitted from v1: integer-list bytes, their hex and
alphabet reductions, and the authenticated last-bit operation.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister import SEAL_PATH as V1_SEAL_PATH
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v2.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v2.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v2.json"


def _reshape(values: list[int], rows: int, columns: int) -> list[list[int]]:
    if rows * columns != len(values):
        raise ValueError("shape does not consume the field")
    return [values[offset:offset + columns] for offset in range(0, len(values), columns)]


def _pack_bits(bits: str) -> bytes:
    padded = bits + "0" * ((-len(bits)) % 8)
    return bytes(int(padded[offset:offset + 8], 2) for offset in range(0, len(padded), 8))


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(family: str, label: str, value: str | bytes) -> None:
        encoded = value.encode("ascii") if isinstance(value, str) else value
        if encoded:
            preimages[encoded].add(f"{family}/{label}")

    matrix_specs = (
        ("S91", raw.s91, ((7, 13), (13, 7))),
        ("S570", raw.s570, ((19, 30), (30, 19))),
    )
    for field_name, text, shapes in matrix_specs:
        for mapping_name, values in (
            ("one-based", [ord(character) - 96 for character in text]),
            ("zero-based", [ord(character) - 97 for character in text]),
        ):
            # The first puzzle's authenticated instruction says the last bit of
            # each unit matters.  Preserve source order and the page's normal
            # most-significant-bit-first binary convention.
            field_bits = "".join(str(value & 1) for value in values)
            add("last-bit", f"{field_name}/{mapping_name}/ascii-bits", field_bits)
            add("last-bit", f"{field_name}/{mapping_name}/packed-msb-right-zero-pad", _pack_bits(field_bits))

            for rows, columns in shapes:
                grid = _reshape(values, rows, columns)
                row_sums = [sum(row) for row in grid]
                column_sums = [sum(grid[row][column] for row in range(rows)) for column in range(columns)]
                vectors = (
                    ("rows", row_sums),
                    ("columns", column_sums),
                    ("rows-then-columns", row_sums + column_sums),
                    ("columns-then-rows", column_sums + row_sums),
                    ("total", [sum(row_sums)]),
                )
                for vector_name, vector in vectors:
                    base_label = f"{field_name}/{mapping_name}/{rows}x{columns}/{vector_name}"
                    if all(0 <= value <= 255 for value in vector):
                        byte_list = bytes(vector)
                        add("matrix-sum-byte-list", f"{base_label}/raw-bytes", byte_list)
                        add("matrix-sum-byte-list", f"{base_label}/lowerhex", byte_list.hex())
                    add("matrix-sum-byte-list", f"{base_label}/json-spaced", json.dumps(vector))
                    add(
                        "matrix-sum-alphabet",
                        f"{base_label}/one-based-mod26",
                        "".join(chr(97 + ((value - 1) % 26)) for value in vector),
                    )
                    add(
                        "matrix-sum-alphabet",
                        f"{base_label}/zero-based-mod26",
                        "".join(chr(97 + (value % 26)) for value in vector),
                    )
                    sum_bits = "".join(str(value & 1) for value in vector)
                    add("last-bit", f"{base_label}/ascii-bits", sum_bits)
                    add("last-bit", f"{base_label}/packed-msb-right-zero-pad", _pack_bits(sum_bits))

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
        ):
            candidates.append({
                "candidate_id": f"v2c{len(candidates):04d}",
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
        "schema": "salphaseion-source-only-preregistration-v2",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v1_manifest_sha256": V1_SEAL_PATH.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "field_order": [
                raw.matrix_marker, raw.lastwords_marker, raw.password_marker,
                raw.sha_first_hint, raw.enter_marker, raw.sha_answer_too,
            ],
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
            "password_expansions": ["raw", "sha256-lowerhex"],
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
