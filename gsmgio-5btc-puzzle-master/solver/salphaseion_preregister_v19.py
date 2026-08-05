"""Seal the untouched S91 seven-intertwined-password interpretation.

The raw field has 91 symbols, ``matrixsumlist`` has 13 characters, and the
authenticated Architect plaintext says ``SEVEN INTERTWINED PASSWORDS``.  The
least-assumptive joint reading is therefore the untouched S91 field as seven
source-order rows of width 13.  Earlier v16 tested this only after a speculative
prime-tail permutation; this round closes the original-source gap.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v16 import (
    _base9_bytes,
    _decimal_to_hex_bytes,
    _xor_digests,
)
from .salphaseion_preregister_v18 import SEAL_PATH as V18_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v19.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v19.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v19.json"


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    width = len(raw.matrix_marker)
    rows = [raw.s91[offset:offset + width] for offset in range(0, len(raw.s91), width)]
    if width != 13 or len(rows) != 7 or any(len(row) != width for row in rows):
        raise ValueError("untouched S91 is no longer a seven-by-thirteen matrix")

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
            preimages[value].add(f"untouched-s91-seven-passwords/{label}")

    scheme_records: list[dict[str, object]] = []
    for scheme, components in component_schemes.items():
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

    # Reading down each column is the literal, lossless intertwining of seven
    # equal rows.  No route, rotation, or fitted ordering is introduced.
    interleaved = "".join(rows[row][column] for column in range(width) for row in range(7))
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
                "candidate_id": f"v19c{len(candidates):03d}",
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
        "schema": "salphaseion-source-only-preregistration-v19-untouched-seven-rows",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v18_manifest_sha256": V18_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "architect_instruction": "SEVEN INTERTWINED PASSWORDS",
            "matrix_instruction": raw.matrix_marker,
            "dimension_rule": "untouched S91 is 7 rows x len(matrixsumlist)=13",
            "rows": rows,
            "rows_sha256": [sha256_hex(row.encode("ascii")) for row in rows],
            "candidate_rule": (
                "seven untouched source-order rows represented directly or by the page-established "
                "numeric/sum forms; concatenate, space-separate, XOR seven SHA256 digests, or "
                "literally interleave columns"
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
                "expected padding length", "community token list", "plus/minus grammar",
                "Half/Better Half", "target point or address", "known community plaintext hashes",
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
