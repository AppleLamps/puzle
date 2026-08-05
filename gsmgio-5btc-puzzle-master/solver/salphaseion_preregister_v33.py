"""Seal the exact words before the Architect's two-door ``choice`` line.

Earlier transcript rounds accidentally covered the 99-percent monologue's two
uses of the word ``choice`` and dialogue around Neo moving to a door, but not
the literal culmination of the two-door speech: ``As you adequately put, the
problem is choice.``  This manifest fixes every whole-word suffix before that
exact occurrence, plus source punctuation, before any decryption.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v32 import SEAL_PATH as V32_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v33.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v33.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v33.json"

TRANSCRIPT_URL = "https://www.matrixfans.net/movies/the-matrix-reloaded/transcript/"
WORDS_BEFORE_CHOICE = ("as", "you", "adequately", "put", "the", "problem", "is")
PUNCTUATED_PREFIX = "As you adequately put, the problem is"


def build_manifest():
    raw = extract_raw()
    extracted = extract_all()
    if raw.lastwords_marker != "lastwordsbeforearchichoice" or raw.password_marker != "thispassword":
        raise ValueError("Architect/password markers changed")
    preimages = defaultdict(set)

    def add(label, text):
        preimages[text.encode("utf-8")].add(f"architect-two-door-choice/{label}")

    for start in range(len(WORDS_BEFORE_CHOICE)):
        suffix = WORDS_BEFORE_CHOICE[start:]
        for spacing, text in (("compact", "".join(suffix)), ("spaces", " ".join(suffix))):
            add(f"suffix-{start}/{spacing}/lower", text.lower())
            add(f"suffix-{start}/{spacing}/upper", text.upper())
            add(f"suffix-{start}/{spacing}/title", text.title())
    for casing, text in (
        ("source", PUNCTUATED_PREFIX),
        ("lower", PUNCTUATED_PREFIX.lower()),
        ("upper", PUNCTUATED_PREFIX.upper()),
    ):
        add(f"full-punctuated/{casing}", text)

    candidates = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v33c{len(candidates):03d}", "preimage_hex": preimage.hex(),
                "preimage_utf8": preimage.decode("utf-8"), "password_expansion": expansion,
                "password_hex": password.hex(), "password_sha256": sha256_hex(password),
                "provenance": sorted(preimages[preimage]),
            })

    blobs = {"salphaseion-short": extracted.chain1_envelope, "phase32-small": extracted.chain2_envelope, "cosmic-duality": extracted.cosmic_envelope}
    return {
        "schema": "salphaseion-source-only-preregistration-v33-architect-two-door-choice",
        "status": "SEALED_BEFORE_DECRYPTION", "extends_v32_manifest_sha256": V32_SEAL.read_text(encoding="ascii").strip(),
        "source": {"capture_stability": capture_stability(), "textarea1_sha256": sha256_hex(raw.textarea1), "transcript_url": TRANSCRIPT_URL, "exact_line": PUNCTUATED_PREFIX + " choice.", "candidate_rule": "every whole-word suffix strictly before choice, compact/spaced in lower/upper/title case, plus full source punctuation"},
        "blobs": {name: {"length": len(value), "sha256": sha256_hex(value), "salt_hex": value[8:16].hex(), "ciphertext_length": len(value) - 16} for name, value in blobs.items()},
        "declared_crypto": {"cipher": "AES-256-CBC", "password_to_key": "OpenSSL EVP_BytesToKey", "kdf_digests": ["md5", "sha256"], "padding": "strict PKCS#7", "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"]},
        "declared_acceptance": {"aes": "existing v1 readable/exact-format rule", "padding_alone": False, "forbidden_evidence": ["expected padding length", "Half/Better Half", "target point", "community plaintext hashes"]},
        "candidate_count": len(candidates), "candidates": candidates,
    }


def main():
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"], "seal_sha256": sha256_hex(encoded)}, indent=2))


if __name__ == "__main__":
    main()
