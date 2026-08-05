"""Seal post-prime matrix-sum entry into the immediately following S570.

The physical source order is S91, ``matrixsumlist``, S570, and later ``enter``.
After the lossless prime-tail reinsertion, this round computes the literal
7x13 row/column sum lists and uses each list directly as flat indices into the
following S570 field under only the page's established zero/one conventions.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v15 import _reinsert_prime_tail
from .salphaseion_preregister_v16 import SEAL_PATH as V16_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v17.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v17.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v17.json"


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    reinserted = _reinsert_prime_tail(raw.s91)
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"post-prime-matrixsum-enter/{label}")

    selection_records: list[dict[str, object]] = []
    for origin in (0, 1):
        values = [ord(character) - 97 + origin for character in reinserted]
        grid = [values[offset:offset + 13] for offset in range(0, 91, 13)]
        vectors = {
            "row-sums": [sum(row) for row in grid],
            "column-sums": [sum(row[column] for row in grid) for column in range(13)],
        }
        for vector_name, vector in vectors.items():
            for convention, adjustment in (("zero-based", 0), ("one-based", -1)):
                indexes = [value + adjustment for value in vector]
                if not all(0 <= index < len(raw.s570) for index in indexes):
                    raise ValueError("direct sum index outside following S570")
                selected = "".join(raw.s570[index] for index in indexes)
                base = f"origin-{origin}/{vector_name}/{convention}"
                add(f"{base}/symbols", selected.encode("ascii"))
                digits0 = bytes(ord(character) - 97 for character in selected)
                digits1 = bytes(ord(character) - 96 for character in selected)
                add(f"{base}/a0-raw-bytes", digits0)
                add(f"{base}/a1-raw-bytes", digits1)
                add(f"{base}/a0-decimal", "".join(str(value) for value in digits0).encode("ascii"))
                add(f"{base}/a1-decimal", "".join(str(value) for value in digits1).encode("ascii"))
                selection_records.append({
                    "origin": origin,
                    "vector": vector_name,
                    "index_convention": convention,
                    "indexes": indexes,
                    "selected_sha256": sha256_hex(selected.encode("ascii")),
                })

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v17c{len(candidates):03d}",
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
        "schema": "salphaseion-source-only-preregistration-v17-post-prime-enter",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v16_manifest_sha256": V16_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "physical_order": ["S91", "matrixsumlist", "S570", "enter"],
            "candidate_rule": (
                "lossless S91 prime-tail reinsertion; literal 7x13 row/column sums; "
                "direct zero/one-based flat selection from immediately following S570"
            ),
            "selections": selection_records,
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
