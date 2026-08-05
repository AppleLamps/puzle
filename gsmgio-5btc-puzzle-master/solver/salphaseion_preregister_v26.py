"""Seal every suffix before Architect-spoken 'choice' in the verified scene."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v25 import SEAL_PATH as V25_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v26.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v26.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v26.json"

TRANSCRIPT_URLS = [
    "https://assets.scriptslug.com/live/pdf/scripts/the-matrix-reloaded-2003.pdf",
    "https://www.matrixfans.net/movies/the-matrix-reloaded/transcript/",
]

# Exact normalized Architect utterance through both occurrences of 'choice'.
WINDOWS = {
    "first-choice": (
        "As I was saying she stumbled upon a solution whereby nearly ninety nine "
        "percent of all test subjects accepted the program as long as they were given a"
    ),
    "second-choice": "even if they were only aware of the",
}


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, text: str) -> None:
        value = text.encode("ascii")
        if value:
            preimages[value].add(f"architect-spoken-choice/{label}")

    for window_name, window in WINDOWS.items():
        words = window.split()
        for start in range(len(words)):
            suffix = words[start:]
            for spacing, text in (("compact", "".join(suffix)), ("spaces", " ".join(suffix))):
                add(f"{window_name}/suffix-{start}/{spacing}/lower", text.lower())
                add(f"{window_name}/suffix-{start}/{spacing}/upper", text.upper())

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v26c{len(candidates):04d}",
                "preimage_hex": preimage.hex(), "password_expansion": expansion,
                "password_hex": password.hex(), "password_sha256": sha256_hex(password),
                "provenance": sorted(preimages[preimage]),
            })

    blobs = {"salphaseion-short": extracted.chain1_envelope, "phase32-small": extracted.chain2_envelope, "cosmic-duality": extracted.cosmic_envelope}
    return {
        "schema": "salphaseion-source-only-preregistration-v26-architect-spoken-choice",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v25_manifest_sha256": V25_SEAL.read_text(encoding="ascii").strip(),
        "source": {"capture_stability": capture_stability(), "textarea1_sha256": sha256_hex(raw.textarea1), "transcript_urls": TRANSCRIPT_URLS, "normalized_windows_before_choice": WINDOWS},
        "blobs": {name: {"length": len(value), "sha256": sha256_hex(value), "salt_hex": value[8:16].hex(), "ciphertext_length": len(value) - 16} for name, value in blobs.items()},
        "declared_crypto": {"cipher": "AES-256-CBC", "password_to_key": "OpenSSL EVP_BytesToKey", "kdf_digests": ["md5", "sha256"], "padding": "strict PKCS#7", "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"]},
        "declared_acceptance": {"inherits_v1_rules_verbatim": True, "padding_alone": False, "forbidden_evidence": ["expected padding length", "plus/minus block grammar", "Half/Better Half", "target point or address", "community plaintext hashes"]},
        "candidate_count": len(candidates), "candidates": candidates,
    }


def main() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"], "seal_sha256": sha256_hex(encoded)}, indent=2))


if __name__ == "__main__":
    main()
