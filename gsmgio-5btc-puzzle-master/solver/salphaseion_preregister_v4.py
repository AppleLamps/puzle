"""Seal the source-adjacent S91 sum-list -> S570 indexing round."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v3 import SEAL_PATH as V3_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v4.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v4.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v4.json"


def _reshape(values: list[int], rows: int, columns: int) -> list[list[int]]:
    return [values[offset:offset + columns] for offset in range(0, rows * columns, columns)]


def _numeric_decode(text: str, *, zero_based: bool) -> bytes | None:
    digits = "".join(str(ord(character) - (97 if zero_based else 96)) for character in text)
    if not digits or (zero_based and digits[0] == "0"):
        return None
    value = int(digits, 10)
    hex_text = format(value, "x")
    if len(hex_text) % 2:
        hex_text = "0" + hex_text
    return bytes.fromhex(hex_text)


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: str | bytes) -> None:
        encoded = value.encode("ascii") if isinstance(value, str) else value
        if encoded:
            preimages[encoded].add(f"s91-sum-index-s570/{label}")

    for mapping_name, values in (
        ("one-based", [ord(character) - 96 for character in raw.s91]),
        ("zero-based", [ord(character) - 97 for character in raw.s91]),
    ):
        for rows, columns in ((7, 13), (13, 7)):
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
                for index_name, indexes in (
                    ("one-based-index", [value - 1 for value in vector]),
                    ("zero-based-index", vector),
                ):
                    if not all(0 <= index < len(raw.s570) for index in indexes):
                        continue
                    selected = "".join(raw.s570[index] for index in indexes)
                    base = f"{mapping_name}/{rows}x{columns}/{vector_name}/{index_name}"
                    add(f"{base}/selected-letters", selected)
                    add(f"{base}/selected-one-based-digits", "".join(str(ord(character) - 96) for character in selected))
                    add(f"{base}/selected-zero-based-digits", "".join(str(ord(character) - 97) for character in selected))
                    for decode_name, zero_based in (("one-based", False), ("zero-based", True)):
                        decoded = _numeric_decode(selected, zero_based=zero_based)
                        if decoded is not None:
                            add(f"{base}/numeric-decimal-to-hex-bytes/{decode_name}", decoded)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v4c{len(candidates):04d}",
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
        "schema": "salphaseion-source-only-preregistration-v4",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v3_manifest_sha256": V3_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "adjacency_rule": "S91 immediately precedes matrixsumlist, which immediately precedes S570",
            "index_rule": "direct S91 sum values only; one- and zero-based index conventions; no modulo, offset, reversal, or reordering",
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
