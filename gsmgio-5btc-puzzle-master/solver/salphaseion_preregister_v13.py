"""Seal the exact 38-byte dual-field bridge before evaluation.

Prime/color reinsertion into S91 followed by the page's numeric decode yields
38 bytes.  Independently, S570 is a 15x38 matrix fixed by the Blue count and
the 38 adjacent decoded characters; its column sums are a 38-entry list.  This
round combines only those equal-width operands using the three elementary byte
operations, optionally followed by the exact 38-character adjacent field.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v12 import (
    SEAL_PATH as V12_SEAL,
    _color_letters,
    _decimal_to_hex_bytes,
    _reinsert,
)
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v13.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v13.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v13.json"


def _combine(left: bytes, right: bytes, operation: str) -> bytes:
    if len(left) != len(right):
        raise ValueError("equal-width operation required")
    if operation == "xor":
        return bytes(a ^ b for a, b in zip(left, right))
    if operation == "left-plus-right":
        return bytes((a + b) % 256 for a, b in zip(left, right))
    if operation == "left-minus-right":
        return bytes((a - b) % 256 for a, b in zip(left, right))
    if operation == "right-minus-left":
        return bytes((b - a) % 256 for a, b in zip(left, right))
    raise ValueError("unknown byte operation")


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    color_routes, image_sha256 = _color_letters()
    key38 = (raw.lastwords_marker + raw.password_marker).encode("ascii")
    if len(key38) != 38:
        raise ValueError("adjacent field width changed")

    left_operands = {
        route: _decimal_to_hex_bytes(_reinsert(raw.s91, colors))
        for route, colors in color_routes.items()
    }
    values0 = [ord(character) - 97 for character in raw.s570]
    values1 = [value + 1 for value in values0]
    right_operands: dict[str, bytes] = {}
    for origin, values in (("a0", values0), ("a1", values1)):
        grid = [values[offset:offset + 38] for offset in range(0, len(values), 38)]
        if len(grid) != 15 or any(len(row) != 38 for row in grid):
            raise ValueError("S570 no longer forms 15x38")
        sums = [sum(row[column] for row in grid) for column in range(38)]
        right_operands[origin] = bytes(sums)

    if any(len(value) != 38 for value in (*left_operands.values(), *right_operands.values())):
        raise ValueError("38-byte bridge invariant changed")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"dual-38-byte-bridge/{label}")

    operations = ("xor", "left-plus-right", "left-minus-right", "right-minus-left")
    direct_records: list[dict[str, object]] = []
    for route, left in left_operands.items():
        for origin, right in right_operands.items():
            add(f"{route}/{origin}/concatenated", left + right)
            for operation in operations:
                paired = _combine(left, right, operation)
                base = f"{route}/{origin}/{operation}"
                add(f"{base}/direct", paired)
                direct_records.append({
                    "route": route,
                    "s570_origin": origin,
                    "operation": operation,
                    "result_sha256": sha256_hex(paired),
                })
                for key_operation in operations:
                    keyed = _combine(paired, key38, key_operation)
                    add(f"{base}/then-adjacent-key/{key_operation}", keyed)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v13c{len(candidates):03d}",
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
        "schema": "salphaseion-source-only-preregistration-v13-dual-38-byte",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v12_manifest_sha256": V12_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "puzzle_image_sha256": image_sha256,
            "equal_width_rules": [
                "prime/color-reinserted S91 decimal-to-hex decode is 38 bytes",
                "S570=15x38 and its column-sum list has 38 byte-sized entries",
                "lastwordsbeforearchichoice+thispassword has 38 ASCII bytes",
            ],
            "candidate_rule": (
                "XOR or modular byte addition/difference of the two authenticated 38-byte operands; "
                "direct result or the same finite operations with the exact adjacent 38-byte field"
            ),
            "direct_records": direct_records,
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
            "direct_combination_bytes_are_evaluated_for_readable_or_exact_structure": True,
            "forbidden_evidence": [
                "expected padding length", "community plus/minus block grammar", "Half/Better Half",
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
