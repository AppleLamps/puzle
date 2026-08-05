"""Seal the literal Architect-door-choice password interpretation.

Earlier rounds read ``lastwordsbeforearchichoice`` as words immediately before
the literal word "choice" in the Architect's monologue.  The unforced reading
is instead an instruction to use the Architect's last words around Neo's door
choice.  This round freezes the three transcript timing boundaries before any
AES evaluation: the last line before Neo moves toward the door, the Hope line
spoken during that movement/pause, and the Architect's final response before
the door opens.

No candidate is derived from padding, community plaintext, Cosmic output,
Half/Better Half, or the prize point.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import re

from .extract import ROOT, extract_all
from .salphaseion_preregister_v17 import SEAL_PATH as V17_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v18.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v18.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v18.json"

TRANSCRIPT_REFERENCE = (
    "https://www.horrorlair.com/movies/scripts/matrixreloaded.pdf"
)

# These are fixed before decryption.  The leading "Humph" is audible/subtitle
# wording in some transcriptions; the screenplay instead describes a chuckle.
BOUNDARIES = {
    "before-neo-moves": (
        "She is going to die, and there is nothing you can do to stop it."
    ),
    "during-door-choice": (
        "Hope. It is the quintessential human delusion, simultaneously the "
        "source of your greatest strength and your greatest weakness."
    ),
    "during-door-choice-with-audible-interjection": (
        "Humph. Hope. It is the quintessential human delusion, simultaneously "
        "the source of your greatest strength and your greatest weakness."
    ),
    "before-door-opens": "We won't.",
}


def _words(value: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[A-Za-z]+", value))


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    if raw.lastwords_marker != "lastwordsbeforearchichoice":
        raise ValueError("SalPhaseIon Architect instruction changed")
    if raw.password_marker != "thispassword":
        raise ValueError("SalPhaseIon password instruction changed")
    if raw.sha_answer_too != "shabefanstoo":
        raise ValueError("SalPhaseIon SHA-answer instruction changed")
    if raw.enter_marker != "enter":
        raise ValueError("SalPhaseIon enter marker changed")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: str) -> None:
        encoded = value.encode("utf-8")
        if encoded:
            preimages[encoded].add(label)

    for boundary, exact in BOUNDARIES.items():
        words = _words(exact)
        # "last words" admits a suffix of the bounded utterance.  Register
        # every suffix now, rather than selecting its length after decryption.
        for start in range(len(words)):
            suffix = words[start:]
            for spacing, normalized in (
                ("compact", "".join(suffix)),
                ("spaces", " ".join(suffix)),
            ):
                add(
                    f"architect-choice/{boundary}/suffix-{start}/{spacing}/lower",
                    normalized.lower(),
                )
                add(
                    f"architect-choice/{boundary}/suffix-{start}/{spacing}/upper",
                    normalized.upper(),
                )

        # Preserve the full transcript punctuation as an independently fixed
        # byte representation.  Apostrophe-less normalized forms are already
        # covered by the suffix construction above.
        add(f"architect-choice/{boundary}/full-punctuated/source-case", exact)
        add(f"architect-choice/{boundary}/full-punctuated/lower", exact.lower())

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v18c{len(candidates):04d}",
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
        "schema": "salphaseion-source-only-preregistration-v18-architect-choice",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v17_manifest_sha256": V17_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "physical_markers": [
                raw.lastwords_marker,
                raw.password_marker,
                raw.enter_marker,
                raw.sha_answer_too,
            ],
            "transcript_reference": TRANSCRIPT_REFERENCE,
            "transcript_boundaries": BOUNDARIES,
            "candidate_rule": (
                "every normalized suffix of each of three fixed Architect "
                "utterance boundaries around Neo's door choice, plus exact "
                "full-line punctuation"
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
                "expected padding length",
                "community token list",
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
