"""Seal adjacent-key columnar routes before evaluation.

S91 is seven rows under the 13-letter adjacent word ``matrixsumlist``.
S570 is fifteen rows under the 38 letters in the two adjacent decoded fields.
Those are exact standard columnar-transposition dimensions.  This round fixes
the conventional encryption and decryption routes, then registers either the
routed symbols, their matrix sum lists, or the page-established numeric
decodings.  The manifest is sealed before AES or readability evaluation.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v10 import SEAL_PATH as V10_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v11.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v11.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v11.json"


def _order(key: str, descending: bool) -> list[int]:
    ascending = sorted(range(len(key)), key=lambda index: (key[index], index))
    return list(reversed(ascending)) if descending else ascending


def _encrypt_route(text: str, key: str, descending: bool) -> str:
    width = len(key)
    rows = [text[offset:offset + width] for offset in range(0, len(text), width)]
    if any(len(row) != width for row in rows):
        raise ValueError("columnar route requires a complete rectangle")
    return "".join(rows[row][column] for column in _order(key, descending)
                   for row in range(len(rows)))


def _decrypt_route(text: str, key: str, descending: bool) -> str:
    width = len(key)
    if len(text) % width:
        raise ValueError("columnar route requires a complete rectangle")
    height = len(text) // width
    columns: list[str | None] = [None] * width
    cursor = 0
    for column in _order(key, descending):
        columns[column] = text[cursor:cursor + height]
        cursor += height
    if cursor != len(text) or any(column is None for column in columns):
        raise ValueError("columnar reconstruction failed")
    return "".join(columns[column][row] for row in range(height)
                   for column in range(width))  # type: ignore[index]


def _serializations(values: list[int]):
    decimal = [str(value) for value in values]
    yield "python-list", repr(values).encode("ascii")
    yield "json-compact", ("[" + ",".join(decimal) + "]").encode("ascii")
    yield "decimal-concatenated", "".join(decimal).encode("ascii")
    yield "decimal-spaces", " ".join(decimal).encode("ascii")
    yield "decimal-commas", ",".join(decimal).encode("ascii")
    if all(0 <= value <= 255 for value in values):
        yield "raw-bytes", bytes(values)
    yield "mod9-a0", "".join(chr(97 + value % 9) for value in values).encode("ascii")
    yield "mod26-a0", "".join(chr(97 + value % 26) for value in values).encode("ascii")
    yield "mod26-a1", "".join(chr(97 + (value - 1) % 26) for value in values).encode("ascii")


def _integer_bytes(digits: list[int], base: int) -> bytes:
    number = 0
    for digit in digits:
        if not 0 <= digit < base:
            raise ValueError("digit outside base")
        number = number * base + digit
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def _decimal_to_hex_bytes(text: str) -> bytes:
    # Reproduce the operation already authenticated by the two z-delimited
    # fields: a=1..i=9, decimal integer -> base16 -> bytes.
    decimal = "".join(str(ord(character) - 96) for character in text)
    hexadecimal = format(int(decimal), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    specs = (
        ("S91", raw.s91, raw.matrix_marker),
        ("S570", raw.s570, raw.lastwords_marker + raw.password_marker),
    )
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"adjacent-key-columnar/{label}")

    corresponding: dict[tuple[str, str, str], bytes] = {}
    for field_name, text, key in specs:
        if len(text) % len(key):
            raise ValueError("authenticated field no longer matches adjacent key width")
        for direction, descending in (("ascending", False), ("descending", True)):
            for route_name, routed in (
                ("encryption-route", _encrypt_route(text, key, descending)),
                ("decryption-route", _decrypt_route(text, key, descending)),
            ):
                base = f"{field_name}/{direction}/{route_name}"
                forms = {
                    "symbols": routed.encode("ascii"),
                    "decimal-to-hex-bytes": _decimal_to_hex_bytes(routed),
                    "base9-a0-integer-bytes": _integer_bytes(
                        [ord(character) - 97 for character in routed], 9),
                    "base9-a1-i0-integer-bytes": _integer_bytes(
                        [(ord(character) - 96) % 9 for character in routed], 9),
                }
                for form_name, encoded in forms.items():
                    add(f"{base}/{form_name}", encoded)
                    corresponding[(field_name, f"{direction}/{route_name}", form_name)] = encoded

                width = len(key)
                for origin in (0, 1):
                    values = [ord(character) - 97 + origin for character in routed]
                    grid = [values[offset:offset + width]
                            for offset in range(0, len(values), width)]
                    vectors = {
                        "row-sums": [sum(row) for row in grid],
                        "column-sums": [sum(row[column] for row in grid)
                                        for column in range(width)],
                    }
                    for vector_name, vector in vectors.items():
                        for serialization, encoded in _serializations(vector):
                            form_name = f"origin-{origin}/{vector_name}/{serialization}"
                            add(f"{base}/{form_name}", encoded)
                            corresponding[(field_name, f"{direction}/{route_name}", form_name)] = encoded

    for route in ("ascending/encryption-route", "ascending/decryption-route",
                  "descending/encryption-route", "descending/decryption-route"):
        representations = {
            form for field, candidate_route, form in corresponding
            if field == "S91" and candidate_route == route
        }
        for representation in sorted(representations):
            left = corresponding.get(("S91", route, representation))
            right = corresponding.get(("S570", route, representation))
            if left is not None and right is not None:
                add(f"combined-source-order/{route}/{representation}", left + right)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v11c{len(candidates):04d}",
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
        "schema": "salphaseion-source-only-preregistration-v11-columnar",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v10_manifest_sha256": V10_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "dimension_rules": [
                "S91 is 7 complete rows under adjacent key matrixsumlist",
                "S570 is 15 complete rows under adjacent key lastwordsbeforearchichoice+thispassword",
            ],
            "candidate_rule": (
                "standard stable duplicate-letter columnar encryption/decryption routes; direct symbols, "
                "matrix sums, page-established decimal-to-hex bytes, and base9 integer bytes"
            ),
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
            "intermediate_readability_not_used_to_select_candidates": True,
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
