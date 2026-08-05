"""Generate and seal the source-only SalPhaseIon candidate manifest.

No AES decryption code is imported here.  Running this module commits the
candidate bytes, KDF choices, blobs, and acceptance rules before evaluation.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path

from .extract import ROOT, extract_all
from .salphaseion_raw import (
    EARLIEST_CAPTURE_TIMESTAMP,
    capture_stability,
    extract_raw,
    sha256_hex,
)


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates.sha256"

ARCHITECT_WORDS_BEFORE_CHOICE = (
    "as", "you", "adequately", "put", "the", "problem", "is"
)
ACCESS_PREIMAGE = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
ACCESS_HASH = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"


def _reshape(values: list[int], rows: int, columns: int) -> list[list[int]]:
    if rows * columns != len(values):
        raise ValueError("shape does not consume the field")
    return [values[offset:offset + columns] for offset in range(0, len(values), columns)]


def _serializations(values: list[int]):
    decimal = [str(value) for value in values]
    yield "decimal-concatenated", "".join(decimal)
    yield "decimal-space-separated", " ".join(decimal)
    yield "decimal-comma-separated", ",".join(decimal)
    yield "json-compact", "[" + ",".join(decimal) + "]"


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    if extracted.chain1_envelope != raw.short_envelope:
        raise ValueError("README short envelope differs from archived raw page")
    if extracted.cosmic_envelope != raw.cosmic_envelope:
        raise ValueError("checked-in Cosmic envelope differs from archived raw page")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(family: str, label: str, value: str | bytes) -> None:
        encoded = value.encode("ascii") if isinstance(value, str) else value
        if encoded:
            preimages[encoded].add(f"{family}/{label}")

    # Family 1: direct decoded fields and contiguous runs, in physical source
    # order.  The order intentionally differs from the community token order.
    ordered = (
        raw.matrix_marker,
        raw.lastwords_marker,
        raw.password_marker,
        raw.sha_first_hint,
        raw.enter_marker,
        raw.sha_answer_too,
    )
    for start in range(len(ordered)):
        for stop in range(start + 1, len(ordered) + 1):
            fields = ordered[start:stop]
            add("source-order", f"fields-{start}-{stop}/compact", "".join(fields))
            add("source-order", f"fields-{start}-{stop}/spaces", " ".join(fields))

    # Family 2: the authenticated clue names the Architect and the word
    # 'choice'.  The externally pinned line is "As you adequately put, the
    # problem is choice."  Pre-register every suffix ending immediately before
    # 'choice', so no suffix length can be selected after seeing decryption.
    for start in range(len(ARCHITECT_WORDS_BEFORE_CHOICE)):
        suffix = ARCHITECT_WORDS_BEFORE_CHOICE[start:]
        add("architect-before-choice", f"suffix-{start}/compact", "".join(suffix))
        add("architect-before-choice", f"suffix-{start}/spaces", " ".join(suffix))

    # Family 3: literal matrix sum lists.  S91 has the unique non-trivial
    # rectangle 7x13; S570 uses its unique closest-to-square factor pair 19x30.
    # Both alphabets actually present on the page are fixed in advance:
    # a=1..i=9 (numeric fields) and a=0..i=8 (a/b binary field).
    matrix_specs = (
        ("S91", raw.s91, ((7, 13), (13, 7))),
        ("S570", raw.s570, ((19, 30), (30, 19))),
    )
    for field_name, text, shapes in matrix_specs:
        for mapping_name, values in (
            ("one-based", [ord(character) - 96 for character in text]),
            ("zero-based", [ord(character) - 97 for character in text]),
        ):
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
                    for serialization_name, serialization in _serializations(vector):
                        add(
                            "matrix-sum-list",
                            f"{field_name}/{mapping_name}/{rows}x{columns}/{vector_name}/{serialization_name}",
                            serialization,
                        )

    # Family 4: exact authenticated access-hint loop.  No case variants or
    # semantic aliases are introduced.
    for label, value in (
        ("audio-first-hint", "HASHTHETEXT"),
        ("access-preimage", ACCESS_PREIMAGE),
        ("access-sha256", ACCESS_HASH),
    ):
        add("access-loop", label, value)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        expansions = (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
        )
        for expansion, password in expansions:
            candidates.append({
                "candidate_id": f"c{len(candidates):04d}",
                "preimage_hex": preimage.hex(),
                "preimage_utf8": preimage.decode("utf-8", "strict"),
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
    manifest: dict[str, object] = {
        "schema": "salphaseion-source-only-preregistration-v1",
        "status": "SEALED_BEFORE_DECRYPTION",
        "source": {
            "earliest_capture_timestamp": EARLIEST_CAPTURE_TIMESTAMP,
            "capture_stability": capture_stability(),
            "field_order": list(ordered),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "textarea2_sha256": sha256_hex(raw.textarea2),
            "s91_length": len(raw.s91),
            "s91_sha256": sha256_hex(raw.s91.encode("ascii")),
            "s570_length": len(raw.s570),
            "s570_sha256": sha256_hex(raw.s570.encode("ascii")),
            "architect_reference_words_before_choice": list(ARCHITECT_WORDS_BEFORE_CHOICE),
            "architect_reference_rule": "all seven suffixes ending immediately before the word choice",
            "architect_reference_urls": [
                "https://www.imdb.com/title/tt0234215/characters/nm0048127",
                "https://assets.scriptslug.com/live/pdf/scripts/the-matrix-reloaded-2003.pdf",
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
            "padding_alone": False,
            "single_blob": "strict padding plus a predeclared readable-text or exact-format validator",
            "cross_blob": "same candidate bytes and same KDF digest validate at least two blobs, and each plaintext independently passes a predeclared readable-text or exact-format validator",
            "readable_text": {
                "utf8": True,
                "minimum_length": 16,
                "printable_or_whitespace_ratio": 0.95,
                "minimum_three_alphabetic_words_of_length_three": True,
            },
            "exact_formats": [
                "JSON", "gzip", "zlib", "ZIP", "PNG", "PEM",
                "nested OpenSSL Salted__ envelope", "Base58Check",
                "hex text that decodes to readable text or an exact format",
                "Base64 text that decodes to readable text or an exact format",
            ],
            "forbidden_evidence": [
                "expected padding length", "plus/minus grammar", "Half/Better Half",
                "target point or address", "known community plaintext hashes",
            ],
        },
        "candidate_count": len(candidates),
        "candidates": candidates,
    }
    return manifest


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
