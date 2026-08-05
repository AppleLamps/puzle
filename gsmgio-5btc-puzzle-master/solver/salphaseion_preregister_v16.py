"""Seal the seven-row password interpretation of prime-reinserted S91.

After the lossless prime-tail permutation, S91 is exactly seven rows under the
13-letter ``matrixsumlist`` width.  The authenticated Architect plaintext says
``SEVEN INTERTWINED PASSWORDS``.  This round treats those seven rows (or their
literal matrix row sums) as the seven components and fixes two conventional
ways to combine all seven: source-order concatenation and XOR of their SHA-256
digests.  No candidate is selected from decryption output.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v15 import SEAL_PATH as V15_SEAL, _reinsert_prime_tail
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v16.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v16.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v16.json"


def _decimal_to_hex_bytes(text: str) -> bytes:
    decimal = "".join(str(ord(character) - 96) for character in text)
    hexadecimal = format(int(decimal), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def _base9_bytes(text: str, origin: int) -> bytes:
    number = 0
    for character in text:
        digit = (ord(character) - 97 + origin) % 9
        number = number * 9 + digit
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def _xor_digests(components: list[bytes]) -> bytes:
    output = bytearray(32)
    for component in components:
        digest = hashlib.sha256(component).digest()
        for index, value in enumerate(digest):
            output[index] ^= value
    return bytes(output)


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    reinserted = _reinsert_prime_tail(raw.s91)
    rows = [reinserted[offset:offset + 13] for offset in range(0, 91, 13)]
    if len(rows) != 7 or any(len(row) != len(raw.matrix_marker) for row in rows):
        raise ValueError("seven-by-thirteen password matrix changed")

    component_schemes: dict[str, list[bytes]] = {
        "raw-row-symbols": [row.encode("ascii") for row in rows],
        "decimal-row-digits": [
            "".join(str(ord(character) - 96) for character in row).encode("ascii")
            for row in rows
        ],
        "decimal-to-hex-row-bytes": [_decimal_to_hex_bytes(row) for row in rows],
        "base9-a0-row-bytes": [_base9_bytes(row, 0) for row in rows],
        "base9-a1-i0-row-bytes": [_base9_bytes(row, 1) for row in rows],
    }
    for origin in (0, 1):
        sums = [sum(ord(character) - 97 + origin for character in row) for row in rows]
        component_schemes[f"row-sum-origin-{origin}-decimal"] = [
            str(value).encode("ascii") for value in sums
        ]
        component_schemes[f"row-sum-origin-{origin}-raw-byte"] = [bytes([value]) for value in sums]
        component_schemes[f"row-sum-origin-{origin}-mod9-symbol"] = [
            bytes([97 + value % 9]) for value in sums
        ]
        component_schemes[f"row-sum-origin-{origin}-mod26-symbol"] = [
            bytes([97 + value % 26]) for value in sums
        ]

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"seven-row-passwords/{label}")

    scheme_records: list[dict[str, object]] = []
    for scheme, components in component_schemes.items():
        if len(components) != 7 or any(not value for value in components):
            raise ValueError("password scheme does not have seven components")
        joined = b"".join(components)
        spaced = b" ".join(components)
        xored = _xor_digests(components)
        add(f"{scheme}/concatenated", joined)
        add(f"{scheme}/space-separated", spaced)
        add(f"{scheme}/xor-seven-sha256", xored)
        scheme_records.append({
            "scheme": scheme,
            "component_lengths": [len(value) for value in components],
            "concatenated_sha256": sha256_hex(joined),
            "xor_seven_sha256": xored.hex(),
        })

    # Column-major reading is the literal intertwining of the seven equal rows.
    interleaved = "".join(rows[row][column] for column in range(13) for row in range(7))
    add("raw-row-symbols/column-interleaved", interleaved.encode("ascii"))
    add("raw-row-symbols/column-interleaved-decimal-to-hex", _decimal_to_hex_bytes(interleaved))

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v16c{len(candidates):03d}",
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
        "schema": "salphaseion-source-only-preregistration-v16-seven-row-passwords",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v15_manifest_sha256": V15_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "architect_instruction": "SEVEN INTERTWINED PASSWORDS",
            "matrix_instruction": raw.matrix_marker,
            "dimension_rule": "prime-reinserted S91 is 7 rows x len(matrixsumlist)=13",
            "rows_sha256": [sha256_hex(row.encode("ascii")) for row in rows],
            "candidate_rule": (
                "seven source-order row components represented directly or by established numeric/sum forms; "
                "combine by concatenation, spaces, XOR of seven SHA256 digests, or literal column interleaving"
            ),
            "schemes": scheme_records,
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
                "expected padding length", "community token list", "Half/Better Half",
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
