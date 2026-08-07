"""Seal v66: chain-1 phrase-digest construction passwords under legibility gate.

v50 braided and sha256-formatted *raw phrase text* but never:

* XOR-combined the seven 2023-02-23 phrase digests (the cosmic envelope uses
  the same construction on SalPhaseIon *tokens*, not on tier-1 phrases).
* Braided or zipped the *sha256-hex digests* themselves.
* Used the authenticated SalPhaseIon terminal fields
  (``shabefourfirsthintisyourlastcommand``, ``enter``, ``shabefanstoo``) as
  chain-1 password material — distinct from the five-token concat that keeps
  the placeholder ``yourlastcommand`` and duplicates ``matrixsumlist``.

This manifest freezes those constructions against chain1 only. Padding is never
acceptance.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "chain1_phrase_digest_legibility_preregistered.json"
SEAL_PATH = ROOT / "chain1_phrase_digest_legibility_preregistered.sha256"
RESULT_PATH = ROOT / "chain1_phrase_digest_legibility_audit.json"

CREATOR_PHRASES = (
    "yellowblueprimes",
    "matrixsumlist",
    "lastwordsbeforearchichoice",
    "yinyang",
    "wewontgiveawaythepassword",
    "itsinfrontofyoureyesbutyourenotseeingit",
    "verylaststepisatruegiveawaypromised",
)

PASSWORD_FORMS = ("literal", "sha256_hex_lower", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"

# Frozen password construction ids → built at audit time from phrases + raw page.
CONSTRUCTION_IDS = (
    "C01_phrase_xor7_digest",
    "C02_phrase_hex_braid7",
    "C03_phrase_hex_zip7",
    "C04_phrase_hex_concat7",
    "C05_phrase_byte_braid7",
    "C06_phrases_first4_concat",
    "C07_tokens5_sha_first_hint",
    "C08_tokens7_hashthetext_sha_answer",
    "C09_terminal_sha_first",
    "C10_terminal_enter",
    "C11_terminal_sha_answer",
    "C12_terminal_sha_first_enter",
    "C13_terminal_enter_sha_answer",
    "C14_terminal_sha_first_enter_sha_answer",
    "C15_decoded_lastwords_thispassword_sha_first_enter_sha_answer",
)


def _phrase_digests() -> tuple[bytes, ...]:
    return tuple(hashlib.sha256(p.encode("ascii")).digest() for p in CREATOR_PHRASES)


def _phrase_hexes() -> tuple[str, ...]:
    return tuple(d.hexdigest() for d in (hashlib.sha256(p.encode("ascii")) for p in CREATOR_PHRASES))


def _braid(parts: tuple[str, ...]) -> bytes:
    out: list[str] = []
    for index in range(max(len(part) for part in parts)):
        for part in parts:
            if index < len(part):
                out.append(part[index])
    return "".join(out).encode("ascii")


def _zip_shortest(parts: tuple[str, ...]) -> bytes:
    shortest = min(len(part) for part in parts)
    return "".join(part[index] for index in range(shortest) for part in parts).encode("ascii")


def _byte_braid(digests: tuple[bytes, ...]) -> bytes:
    return bytes(digests[index % len(digests)][index // len(digests)] for index in range(len(digests) * len(digests[0])))


def build_constructions() -> dict[str, bytes]:
    digests = _phrase_digests()
    hexes = _phrase_hexes()
    xor7 = bytes(a ^ b ^ c ^ d ^ e ^ f ^ g for a, b, c, d, e, f, g in zip(*digests))
    sha_first = b"shabefourfirsthintisyourlastcommand"
    sha_answer = b"shabefanstoo"
    enter = b"enter"
    return {
        "C01_phrase_xor7_digest": xor7,
        "C02_phrase_hex_braid7": _braid(hexes),
        "C03_phrase_hex_zip7": _zip_shortest(hexes),
        "C04_phrase_hex_concat7": "".join(hexes).encode("ascii"),
        "C05_phrase_byte_braid7": _byte_braid(digests),
        "C06_phrases_first4_concat": "".join(CREATOR_PHRASES[:4]).encode("ascii"),
        "C07_tokens5_sha_first_hint": b"".join(
            [
                b"matrixsumlist",
                enter,
                b"lastwordsbeforearchichoice",
                b"thispassword",
                sha_first,
            ]
        ),
        "C08_tokens7_hashthetext_sha_answer": b"".join(
            [
                b"matrixsumlist",
                enter,
                b"lastwordsbeforearchichoice",
                b"thispassword",
                b"matrixsumlist",
                b"HASHTHETEXT",
                sha_answer,
            ]
        ),
        "C09_terminal_sha_first": sha_first,
        "C10_terminal_enter": enter,
        "C11_terminal_sha_answer": sha_answer,
        "C12_terminal_sha_first_enter": sha_first + enter,
        "C13_terminal_enter_sha_answer": enter + sha_answer,
        "C14_terminal_sha_first_enter_sha_answer": sha_first + enter + sha_answer,
        "C15_decoded_lastwords_thispassword_sha_first_enter_sha_answer": b"".join(
            [
                b"causality",
                b"giveitjustonesecond",
                sha_first,
                enter,
                sha_answer,
            ]
        ),
    }


def expected_aes_trials() -> int:
    return len(CONSTRUCTION_IDS) * len(PASSWORD_FORMS) * len(KDF_DIGESTS)


def expected_scalar_gates() -> int:
    return len(CONSTRUCTION_IDS) * 2


def build_manifest() -> dict[str, object]:
    constructions = build_constructions()
    return {
        "schema": "chain1-phrase-digest-legibility-v66",
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "id": "v66_chain1_phrase_digest_legibility",
        "date": "2026-08-07",
        "hypothesis": (
            "Chain-1 opens under phrase-digest constructions (XOR, hex-braid, "
            "terminal SalPhaseIon fields) with legible plaintext."
        ),
        "creator_phrases": list(CREATOR_PHRASES),
        "construction_ids": list(CONSTRUCTION_IDS),
        "construction_preimages_sha256": {
            cid: hashlib.sha256(preimage).hexdigest()
            for cid, preimage in constructions.items()
        },
        "password_forms": list(PASSWORD_FORMS),
        "kdf_digests": list(KDF_DIGESTS),
        "envelope": "chain1",
        "expected_counts": {
            "aes_trials": expected_aes_trials(),
            "scalar_gates": expected_scalar_gates(),
        },
        "acceptance": (
            "Legible plaintext: printable_ratio>=0.85 and entropy<=5.9, or an "
            "English run of >=6 letters; padding logged, never accepted."
        ),
        "scope_note": (
            "Closes phrase-digest XOR/braid/concat constructions and authenticated "
            "SalPhaseIon terminal assemblies on chain1 only. Does not reopen raw "
            "phrase concatenations (v49), raw phrase intertwines (v50), or "
            "structural operands (v60)."
        ),
        "control_scalar_hex": CONTROL_SCALAR_HEX,
        "targets": {
            "half_uncompressed_pubkey": HALF_PUBLIC_UNCOMPRESSED.hex(),
            "better_half_hash160": BETTER_H160.hex(),
        },
    }


def seal() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")


if __name__ == "__main__":
    seal()
    print(f"sealed {MANIFEST_PATH.name}")
