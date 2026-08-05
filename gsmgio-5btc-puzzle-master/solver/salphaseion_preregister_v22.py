"""Seal base-9 byte decoding after the v9 adjacent-key operations."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v21 import SEAL_PATH as V21_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v22.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v22.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v22.json"


def _base9_bytes(values: list[int]) -> bytes:
    number = 0
    for value in values:
        number = number * 9 + value
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    specs = (
        ("S91", raw.s91, raw.matrix_marker),
        ("S570", raw.s570, raw.lastwords_marker + raw.password_marker),
    )
    preimages: dict[bytes, set[str]] = defaultdict(set)
    corresponding: dict[tuple[int, int, str, bool], dict[str, bytes]] = defaultdict(dict)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"adjacent-key-base9-bytes/{label}")

    records: list[dict[str, object]] = []
    for field, text, key in specs:
        if len(text) % len(key):
            raise ValueError("adjacent key no longer tiles its field")
        for field_origin in (0, 1):
            field_values = [(ord(character) - 97 + field_origin) % 9 for character in text]
            for key_origin in (0, 1):
                key_values = [(ord(character) - 97 + key_origin) % 9 for character in key]
                repeated = key_values * (len(text) // len(key))
                for operation in ("field-plus-key", "field-minus-key", "key-minus-field"):
                    if operation == "field-plus-key":
                        adjusted = [(left + right) % 9 for left, right in zip(field_values, repeated)]
                    elif operation == "field-minus-key":
                        adjusted = [(left - right) % 9 for left, right in zip(field_values, repeated)]
                    else:
                        adjusted = [(right - left) % 9 for left, right in zip(field_values, repeated)]
                    for reverse in (False, True):
                        routed = adjusted[::-1] if reverse else adjusted
                        decoded = _base9_bytes(routed)
                        base = (
                            f"{field}/field-origin-{field_origin}/key-origin-{key_origin}/"
                            f"{operation}/{'reverse' if reverse else 'forward'}"
                        )
                        add(base, decoded)
                        corresponding[(field_origin, key_origin, operation, reverse)][field] = decoded
                        records.append({
                            "field": field,
                            "field_origin": field_origin,
                            "key_origin": key_origin,
                            "operation": operation,
                            "reverse": reverse,
                            "decoded_length": len(decoded),
                            "decoded_sha256": sha256_hex(decoded),
                        })

    for rule, fields in corresponding.items():
        if set(fields) == {"S91", "S570"}:
            field_origin, key_origin, operation, reverse = rule
            add(
                f"combined-source-order/field-origin-{field_origin}/key-origin-{key_origin}/"
                f"{operation}/{'reverse' if reverse else 'forward'}",
                fields["S91"] + fields["S570"],
            )

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v22c{len(candidates):03d}",
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
        "schema": "salphaseion-source-only-preregistration-v22-adjacent-key-base9",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v21_manifest_sha256": V21_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "dimension_rules": [
                "S91=7xlen(matrixsumlist)",
                "S570=15xlen(lastwordsbeforearchichoice+thispassword)",
            ],
            "candidate_rule": (
                "apply the v9 repeated adjacent-key add/subtract operations in Z9, "
                "interpret each entire result as a base-9 integer, and use its minimal "
                "big-endian bytes alone or paired in source order"
            ),
            "records": records,
        },
        "blobs": {
            name: {
                "length": len(envelope), "sha256": sha256_hex(envelope),
                "salt_hex": envelope[8:16].hex(), "ciphertext_length": len(envelope) - 16,
            }
            for name, envelope in blobs.items()
        },
        "declared_crypto": {
            "cipher": "AES-256-CBC", "password_to_key": "OpenSSL EVP_BytesToKey",
            "kdf_digests": ["md5", "sha256"], "padding": "strict PKCS#7",
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
        },
        "declared_acceptance": {
            "inherits_v1_rules_verbatim": True, "padding_alone": False,
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
        "manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"],
        "seal_sha256": sha256_hex(encoded),
    }, indent=2))


if __name__ == "__main__":
    main()
