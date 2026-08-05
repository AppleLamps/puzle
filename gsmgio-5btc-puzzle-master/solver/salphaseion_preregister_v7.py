"""Seal the multilingual Architect construction before AES evaluation.

The authenticated Phase 3.2 Architect plaintext ends in ``CIAOBELLAO`` and
SalPhaseIon independently decodes ``lastwordsbeforearchichoice``.  This round
tests the narrow hypothesis that the Italian tail selects the Italian wording
of the Architect's line ending in "choice".  It deliberately admits no Cosmic,
Half/Better-Half, target-point, padding, or community-derived material.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v6 import SEAL_PATH as V6_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v7.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v7.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v7.json"

PHASE32_RECOVERY_PATH = ROOT / "phase32_symbol_recovery.json"
PHASE32_PLAINTEXT_SHA256 = (
    "56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241"
)
AUTHENTICATED_TAIL = "CIAOBELLAO"
ITALIAN_ARCHITECT_WORDS_BEFORE_CHOICE = ("IL", "PROBLEMA", "È", "LA")
ITALIAN_REFERENCE = (
    "https://www.lucianogiustini.org/blog/documents/"
    "dialogo_matrix2_architetto.html"
)


def _ascii_fold(value: str) -> str:
    return value.replace("È", "E").replace("è", "e")


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    recovery_bytes = PHASE32_RECOVERY_PATH.read_bytes()
    recovery = json.loads(recovery_bytes)
    plaintext = recovery["plaintext"]
    if recovery["plaintext_sha256"] != PHASE32_PLAINTEXT_SHA256:
        raise ValueError("Phase 3.2 recovery hash changed")
    if sha256_hex(plaintext.encode("ascii")) != PHASE32_PLAINTEXT_SHA256:
        raise ValueError("Phase 3.2 plaintext does not match its recorded hash")
    if not plaintext.endswith(AUTHENTICATED_TAIL):
        raise ValueError("authenticated Italian tail changed")
    if raw.lastwords_marker != "lastwordsbeforearchichoice":
        raise ValueError("SalPhaseIon Architect instruction changed")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: str) -> None:
        preimages[value.encode("utf-8")].add(label)

    # Exact recovered tail, the README's natural word boundaries, and the
    # prefix before the anomalous final O.  Uppercase preserves the recovered
    # source; lowercase matches the mechanically decoded SalPhaseIon register.
    tail_forms = {
        "exact-compact": AUTHENTICATED_TAIL,
        "editorial-spaces": "CIAO BELLA O",
        "before-final-o-compact": "CIAOBELLA",
        "before-final-o-spaces": "CIAO BELLA",
    }
    for label, value in tail_forms.items():
        add(f"authenticated-architect-tail/{label}/uppercase", value)
        add(f"authenticated-architect-tail/{label}/lowercase", value.lower())

    # The Italian reference gives "Il problema è la scelta."  Register every
    # suffix ending immediately before SCELTA, exactly as v1 registered every
    # English suffix before CHOICE.  Both compact/spaced and source/lower case
    # forms are fixed; ASCII folding handles the only byte-encoding ambiguity.
    words = ITALIAN_ARCHITECT_WORDS_BEFORE_CHOICE
    for start in range(len(words)):
        suffix = words[start:]
        for spacing, value in (
            ("compact", "".join(suffix)),
            ("spaces", " ".join(suffix)),
        ):
            for casing, cased in (
                ("uppercase", value),
                ("lowercase", value.lower()),
            ):
                add(
                    f"italian-architect-before-choice/suffix-{start}/"
                    f"{spacing}/{casing}/utf8",
                    cased,
                )
                folded = _ascii_fold(cased)
                add(
                    f"italian-architect-before-choice/suffix-{start}/"
                    f"{spacing}/{casing}/ascii-fold",
                    folded,
                )

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v7c{len(candidates):04d}",
                "preimage_hex": preimage.hex(),
                "preimage_utf8": preimage.decode("utf-8"),
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
        "schema": "salphaseion-source-only-preregistration-v7-italian-architect",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v6_manifest_sha256": V6_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "salphaseion_instruction": raw.lastwords_marker,
            "phase32_recovery_path": str(PHASE32_RECOVERY_PATH.relative_to(ROOT)),
            "phase32_recovery_file_sha256": sha256_hex(recovery_bytes),
            "phase32_plaintext_sha256": PHASE32_PLAINTEXT_SHA256,
            "authenticated_tail": AUTHENTICATED_TAIL,
            "italian_reference": ITALIAN_REFERENCE,
            "italian_line": "IL PROBLEMA È LA SCELTA",
            "candidate_rule": (
                "exact authenticated Italian tail forms plus every suffix of "
                "the Italian Architect words immediately before SCELTA"
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
            "password_expansions": [
                "raw", "sha256-lowerhex", "sha256-raw-digest"
            ],
        },
        "declared_acceptance": {
            "inherits_v1_rules_verbatim": True,
            "padding_alone": False,
            "forbidden_evidence": [
                "expected padding length",
                "plus/minus grammar",
                "Half/Better Half",
                "target point or address",
                "known community plaintext hashes",
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
