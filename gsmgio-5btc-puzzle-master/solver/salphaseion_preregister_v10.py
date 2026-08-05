"""Seal the triangular S91 sum-list interpretation before AES evaluation.

S91 has triangular length T13 = 91 and is immediately followed by the
13-letter decoded instruction ``matrixsumlist`` and then S570.  This round
registers the two source-order triangular row layouts, their row and two
column/diagonal sum lists, direct adjacent-key arithmetic, and the literal use
of such a list as indices into the following field.  The family is fully built
and sealed before any decryption result is inspected.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v9 import SEAL_PATH as V9_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v10.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v10.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v10.json"


def _triangle(values: list[int], ascending: bool) -> list[list[int]]:
    widths = range(1, 14) if ascending else range(13, 0, -1)
    rows: list[list[int]] = []
    cursor = 0
    for width in widths:
        rows.append(values[cursor:cursor + width])
        cursor += width
    if cursor != 91 or any(not row for row in rows):
        raise ValueError("triangle does not consume S91")
    return rows


def _vectors(rows: list[list[int]]) -> dict[str, list[int]]:
    left_columns = [
        sum(row[column] for row in rows if column < len(row))
        for column in range(13)
    ]
    right_columns = [
        sum(row[len(row) - 1 - column] for row in rows if column < len(row))
        for column in range(13)
    ]
    return {
        "row-sums": [sum(row) for row in rows],
        "left-aligned-column-sums": left_columns,
        "right-aligned-column-sums": right_columns,
    }


def _serializations(values: list[int]):
    decimal = [str(value) for value in values]
    yield "python-list", repr(values).encode("ascii")
    yield "json-compact", ("[" + ",".join(decimal) + "]").encode("ascii")
    yield "decimal-concatenated", "".join(decimal).encode("ascii")
    yield "decimal-spaces", " ".join(decimal).encode("ascii")
    yield "decimal-commas", ",".join(decimal).encode("ascii")
    if all(0 <= value <= 255 for value in values):
        raw = bytes(values)
        yield "raw-bytes", raw
        yield "lowerhex", raw.hex().encode("ascii")
    yield "mod9-a0", "".join(chr(97 + value % 9) for value in values).encode("ascii")
    yield "mod9-i0", "".join("iabcdefgh"[value % 9] for value in values).encode("ascii")
    yield "mod26-a0", "".join(chr(97 + value % 26) for value in values).encode("ascii")
    yield "mod26-a1", "".join(chr(97 + (value - 1) % 26) for value in values).encode("ascii")


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    if len(raw.s91) != sum(range(1, 14)) or len(raw.matrix_marker) != 13:
        raise ValueError("T13/source-adjacency invariant changed")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"s91-triangle/{label}")

    for origin in (0, 1):
        values = [ord(character) - 97 + origin for character in raw.s91]
        for orientation, ascending in (("rows-1-through-13", True), ("rows-13-through-1", False)):
            rows = _triangle(values, ascending)
            for vector_name, vector in _vectors(rows).items():
                base = f"origin-{origin}/{orientation}/{vector_name}"
                for serialization, encoded in _serializations(vector):
                    add(f"{base}/direct/{serialization}", encoded)

                # The 13-entry list is aligned with the 13-letter decoded
                # instruction. Register the three arithmetic directions under
                # both alphabet origins, without choosing from plaintext.
                for key_origin in (0, 1):
                    key = [ord(character) - 97 + key_origin for character in raw.matrix_marker]
                    for operation, combined in (
                        ("sum-plus-key", [left + right for left, right in zip(vector, key)]),
                        ("sum-minus-key", [left - right for left, right in zip(vector, key)]),
                        ("key-minus-sum", [right - left for left, right in zip(vector, key)]),
                    ):
                        for serialization, encoded in _serializations(combined):
                            add(f"{base}/{operation}/key-origin-{key_origin}/{serialization}", encoded)

                # Literal source-order relation: the sum list immediately
                # precedes S570. Values are valid direct indices; register the
                # page's established zero- and one-based conventions only.
                for convention, adjustment in (("zero-based", 0), ("one-based", -1)):
                    if all(0 <= value + adjustment < len(raw.s570) for value in vector):
                        selected = "".join(raw.s570[value + adjustment] for value in vector).encode("ascii")
                        add(f"{base}/enter-S570/{convention}/symbols", selected)
                        numeric = [ord(character) - 97 + origin for character in selected.decode("ascii")]
                        for serialization, encoded in _serializations(numeric):
                            add(f"{base}/enter-S570/{convention}/numeric/{serialization}", encoded)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v10c{len(candidates):04d}",
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
        "schema": "salphaseion-source-only-preregistration-v10-triangular-s91",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v9_manifest_sha256": V9_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "dimension_rule": "len(S91)=91=T13 and adjacent len(matrixsumlist)=13",
            "candidate_rule": (
                "fill source order into rows 1..13 or 13..1; take row, left-column, or "
                "right-column sum lists; use directly, combine with the aligned decoded word, "
                "or enter the immediately following S570 at those indices"
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
