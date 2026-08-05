"""Seal the 104 prime-position / matrix-marker alignment before evaluation.

The raw marker encoding ``matrixsumlist`` has 104 binary a/b symbols.  The
immediately following S-field has length 570, and pi(570)=104.  The authenticated
Architect plaintext says RETURN TO THE SOURCE CODES and REINSERTING THE PRIME
BASICS.  This round aligns those two 104-symbol streams in source order and
registers only finite, mechanically specified consequences.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import math

from .extract import ROOT, extract_all
from .salphaseion_preregister_v22 import SEAL_PATH as V22_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v23.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v23.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v23.json"


def _primes(limit: int) -> list[int]:
    return [
        value
        for value in range(2, limit + 1)
        if all(value % divisor for divisor in range(2, math.isqrt(value) + 1))
    ]


def _pack_bits(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("bit stream is not byte aligned")
    return bytes(
        int("".join(str(bit) for bit in bits[offset : offset + 8]), 2)
        for offset in range(0, len(bits), 8)
    )


def _base9_bytes(values: list[int]) -> bytes:
    number = 0
    for value in values:
        number = number * 9 + value
    width = max(1, (number.bit_length() + 7) // 8)
    return number.to_bytes(width, "big")


def _serializations(values: list[int]) -> dict[str, bytes]:
    return {
        "raw-byte-list": bytes(values),
        "decimal-concatenated": "".join(map(str, values)).encode("ascii"),
        "decimal-spaces": " ".join(map(str, values)).encode("ascii"),
        "decimal-commas": ",".join(map(str, values)).encode("ascii"),
        "compact-json": json.dumps(values, separators=(",", ":")).encode("ascii"),
        "mod9-symbols": bytes(97 + (value % 9) for value in values),
        "mod26-a0": bytes(97 + (value % 26) for value in values),
        "mod26-a1": bytes(97 + ((value - 1) % 26) for value in values),
    }


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    primes = _primes(len(raw.s570))
    marker_bits = [0 if symbol == "a" else 1 for symbol in raw.matrix_marker_bits]
    if len(raw.s570) != 570 or len(primes) != 104 or len(marker_bits) != 104:
        raise ValueError("104/pi(570) cardinality changed")
    if _pack_bits(marker_bits) != b"matrixsumlist":
        raise ValueError("marker bit stream changed")

    prime_symbols = [raw.s570[position - 1] for position in primes]
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"prime104-matrix-marker/{label}")

    derived_hashes: list[dict[str, object]] = []
    for origin in (0, 1):
        values = [ord(symbol) - 97 + origin for symbol in prime_symbols]
        parities = [value & 1 for value in values]
        xor_bits = [left ^ right for left, right in zip(parities, marker_bits)]
        xnor_bits = [1 ^ bit for bit in xor_bits]
        direct = {
            "prime-symbols": "".join(prime_symbols).encode("ascii"),
            "prime-base9-bytes": _base9_bytes([ord(symbol) - 97 for symbol in prime_symbols]),
            "prime-parity-bytes": _pack_bits(parities),
            "prime-parity-xor-marker-bytes": _pack_bits(xor_bits),
            "prime-parity-xnor-marker-bytes": _pack_bits(xnor_bits),
        }
        for name, value in direct.items():
            add(f"a{origin}/{name}", value)

        sum_lists = {
            "13x8-row-sums": [sum(values[offset : offset + 8]) for offset in range(0, 104, 8)],
            "8x13-column-sums": [sum(values[row * 13 + column] for row in range(8)) for column in range(13)],
        }
        key = [ord(character) - 97 for character in raw.matrix_marker]
        for layout, sums in sum_lists.items():
            variants = {
                "direct": sums,
                "plus-key-mod26": [(value + key[index]) % 26 for index, value in enumerate(sums)],
                "minus-key-mod26": [(value - key[index]) % 26 for index, value in enumerate(sums)],
                "key-minus-mod26": [(key[index] - value) % 26 for index, value in enumerate(sums)],
            }
            for variant, output in variants.items():
                for serialization, value in _serializations(output).items():
                    add(f"a{origin}/{layout}/{variant}/{serialization}", value)
                derived_hashes.append({
                    "origin": origin,
                    "layout": layout,
                    "variant": variant,
                    "values": output,
                    "raw_byte_sha256": sha256_hex(bytes(output)),
                })

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v23c{len(candidates):04d}",
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
        "schema": "salphaseion-source-only-preregistration-v23-prime104-marker",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v22_manifest_sha256": V22_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "architect_phrases": ["RETURN TO THE SOURCE CODES", "REINSERTING THE PRIME BASICS"],
            "cardinality_rule": "len(matrix marker bits)=104=pi(len(S570))=pi(570)",
            "prime_positions_one_based": primes,
            "alignment": "source-order marker bits with source-order S570 symbols at one-based prime positions",
            "matrix_shapes": ["13x8 row sums", "8x13 column sums"],
            "derived_records": derived_hashes,
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
            "direct_preimage": "UTF-8, at least 95% printable, at least one alphabetic word of length 4",
            "padding_alone": False,
            "forbidden_evidence": [
                "expected padding length", "plus/minus block grammar", "Half/Better Half",
                "target point or address", "community plaintext hashes",
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
