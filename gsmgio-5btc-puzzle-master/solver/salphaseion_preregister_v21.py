"""Seal the omitted Logic ``The Warning`` phase-choice answers.

The first two solved puzzle stages use consecutive phrases from the song: the
seed is planted, then the flower blossoms through concrete.  The song's next
named phase is The Judgement and asks for a choice between a red rose and a
black rose.  The later authenticated creator hint again says roses are often
Red.  Earlier corrected-blob manifests contain none of these exact answers.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v20 import SEAL_PATH as V20_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v21.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v21.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v21.json"

PHASE_ANSWERS = {
    "creator-rose-selection": ["red", "redrose", "red rose", "theredrose", "the red rose"],
    "song-explicit-alternative": ["black", "blackrose", "black rose", "theblackrose", "the black rose"],
    "song-phase-name-british": ["thejudgement", "the judgement", "judgement"],
    "song-phase-name-american": ["thejudgment", "the judgment", "judgment"],
}


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: str) -> None:
        preimages[value.encode("ascii")].add(label)

    for category, answers in PHASE_ANSWERS.items():
        for answer in answers:
            for casing, value in (
                ("lower", answer.lower()),
                ("upper", answer.upper()),
                ("title", answer.title()),
            ):
                add(f"warning-song/{category}/{answer.replace(' ', '-')}/{casing}", value)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v21c{len(candidates):03d}",
                "preimage_hex": preimage.hex(),
                "preimage_utf8": preimage.decode("ascii"),
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
        "schema": "salphaseion-source-only-preregistration-v21-warning-song-choice",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v20_manifest_sha256": V20_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "authenticated_progression": [
                "THE SEED IS PLANTED",
                "THE FLOWER BLOSSOMS THROUGH WHAT SEEMS TO BE A CONCRETE SURFACE",
                "THE JUDGEMENT: THE RED ROSE OR THE BLACK",
            ],
            "creator_hint": "Roses are White but often Red.",
            "candidate_rule": (
                "the exact red/black rose alternatives and The Judgement phase name, "
                "compact or spaced and lower/upper/title case"
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
