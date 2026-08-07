"""Seal v57: freeze creator-named cipher catalogues for the 23/16/7 menu.

v56 closed password-composition against chain1/cosmic and left this gap:
which object the 23/16/7 menu selects *as the cipher catalogue*. This family
answers by freezing ONLY the ciphers the creator already named in phase 3.2:

* Beaufort with key material drawn from the Fresco 23/16/7 partition (and the
  already-authenticated key ``THEMATRIXHASYOU``);
* VIC straddling checkerboard with the published alphabets
  ``FUBCDORA.LETHINGKYMVPS.JQZXW`` and ``…/JQZXW``;
* the chess-hint alphabet sentence as a substitution alphabet seed.

No free classical-cipher menu. No Cosmic base-38 / Chain 4. Residual clue
XOR only. Acceptance is ``solver.targets`` or AES legibility — never padding.
"""

from __future__ import annotations

import hashlib
import json

from .ciao_bella_479_audit import MASK_BITS, MASK_DATE, MASK_SOURCE, MASK_VALUE, QUOTE
from .extract import ROOT
from .phase32_classical import BEAUFORT_KEY, PHASE32_PASSWORD
from .targets import BETTER_H160, HALF_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "cipher_catalogue_23_16_7_preregistered.json"
SEAL_PATH = ROOT / "cipher_catalogue_23_16_7_preregistered.sha256"
RESULT_PATH = ROOT / "cipher_catalogue_23_16_7_audit.json"

SCHEMA = "cipher-catalogue-23-16-7-v57"

VIC_ALPHABET_DOT = "FUBCDORA.LETHINGKYMVPS.JQZXW"
VIC_ALPHABET_SLASH = "FUBCDORA.LETHINGKYMVPS/JQZXW"
CHESS_HINT = (
    "Raising the stakes without extra chances of winning. "
    "A fubcd-king & oracle-queen, thingky mvps, on a sad board "
    "but as wide as the first one seen."
)
CHAIN1_SALT_HEX = "3ab585348552415d"
COSMIC_SALT_HEX = "2d3f6fe06dc950e6"
RAW_SOURCE_SHA256 = "bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b"
TRANSLITERATION_SHA256 = "6d66e0e0e2dfdb812d5ecee2be6f54c1f3b8c84b0d74580686cf2053d76a200e"

CIPHERTEXTS = (
    "S91_letters",          # a-i as A-I
    "S570_letters",
    "transliteration",      # authenticated pre-Beaufort a-z
    "raw_pre_beaufort_mod26",  # raw bytes mod 26 → A-Z
)
BEAUFORT_KEYS = (
    "thematrixhasyou",
    "fresco_selected7_lower",
    "fresco_selected16_lower",
    "fresco_intertwine_7_lower",
    "fresco_quote_letters_lower",
    "chess_hint_letters_lower",
)
VIC_ALPHABETS = ("dot", "slash")
VIC_ROW_DIGITS = (("1", "4"), ("4", "1"))
VIC_DIGIT_MAPS = ("a1_i9", "a0_i8")
VIC_FIELDS = ("S91", "S570")

PASSWORD_FORMS = ("literal", "sha256_hex_ascii", "sha256_raw32")
KDF_DIGESTS = ("md5", "sha256")
ENVELOPES = ("chain1", "cosmic")
RESIDUAL_CLUES = (5, 7, 16, 23, 140, 479, 484, 1141)
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def _intertwine(parts: list[str]) -> str:
    if not parts:
        return ""
    width = max(len(part) for part in parts)
    out: list[str] = []
    for index in range(width):
        for part in parts:
            if index < len(part):
                out.append(part[index])
    return "".join(out)


def fresco_key_materials() -> dict[str, str]:
    words = QUOTE.split()
    if len(QUOTE) != 140 or len(words) != 23:
        raise ValueError("Fresco quote must remain 140/23")
    if MASK_SOURCE ^ MASK_DATE != MASK_VALUE or len(MASK_BITS) != 23:
        raise ValueError("mask drifted")
    selected16 = [w for w, b in zip(words, MASK_BITS) if b == "1"]
    selected7 = [w for w, b in zip(words, MASK_BITS) if b == "0"]
    return {
        "thematrixhasyou": BEAUFORT_KEY,
        "fresco_selected7_lower": "".join(selected7).lower(),
        "fresco_selected16_lower": "".join(selected16).lower(),
        "fresco_intertwine_7_lower": _intertwine([w.lower() for w in selected7]),
        "fresco_quote_letters_lower": "".join(ch for ch in QUOTE.lower() if ch.isalpha()),
        "chess_hint_letters_lower": "".join(ch for ch in CHESS_HINT.lower() if ch.isalpha()),
    }


def expected_beaufort_outputs() -> int:
    return len(CIPHERTEXTS) * len(BEAUFORT_KEYS)


def expected_vic_outputs() -> int:
    return len(VIC_FIELDS) * len(VIC_ALPHABETS) * len(VIC_ROW_DIGITS) * len(VIC_DIGIT_MAPS)


def expected_catalogue_outputs() -> int:
    # beaufort outputs + vic outputs + the frozen alphabet/hint strings themselves
    return expected_beaufort_outputs() + expected_vic_outputs() + 4


def expected_aes_trials() -> int:
    return expected_catalogue_outputs() * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(ENVELOPES)


def expected_scalar_gates() -> int:
    return expected_catalogue_outputs() * (2 + len(RESIDUAL_CLUES))


def build_manifest() -> dict[str, object]:
    keys = fresco_key_materials()
    return {
        "schema": SCHEMA,
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "hypothesis": (
            "The 23/16/7 menu selects among creator-named phase-3.2 ciphers "
            "(Beaufort, VIC checkerboard, chess-hint alphabet), with the Fresco "
            "23/16/7 partition supplying key material — not an open classical "
            "cipher catalogue."
        ),
        "distinct_from": {
            "endgame_23_16_7_salphaseion_audit.json": (
                "password composition over SalPhaseIon prime-select; no VIC/Beaufort "
                "catalogue freeze"
            ),
            "ciao_bella_479_audit.json": (
                "open classical menu (Chaocipher/Bellaso/Porta/Vigenere) over the quote"
            ),
            "unity_of_opposites_audit.json": (
                "VIC over S91/S570 with book-phrase alphabet seed, not Fresco 23/16/7 keys"
            ),
            "phase32_classical.json": "positive control reproduction only",
        },
        "frozen_catalogue": {
            "beaufort_authenticated_key": BEAUFORT_KEY,
            "vic_alphabet_dot": VIC_ALPHABET_DOT,
            "vic_alphabet_slash": VIC_ALPHABET_SLASH,
            "chess_hint": CHESS_HINT,
            "no_free_classical_menu": True,
        },
        "frozen_inputs": {
            "fresco_quote_sha256": hashlib.sha256(QUOTE.encode("ascii")).hexdigest(),
            "mask_bits": MASK_BITS,
            "carried_phase32_password_utf8": PHASE32_PASSWORD.decode("ascii"),
            "chain1_salt_hex": CHAIN1_SALT_HEX,
            "cosmic_salt_hex": COSMIC_SALT_HEX,
            "raw_pre_beaufort_sha256": RAW_SOURCE_SHA256,
            "transliteration_sha256": TRANSLITERATION_SHA256,
            "beaufort_key_materials_sha256": {
                name: hashlib.sha256(value.encode("ascii")).hexdigest()
                for name, value in sorted(keys.items())
            },
        },
        "expansion": {
            "ciphertexts": list(CIPHERTEXTS),
            "beaufort_keys": list(BEAUFORT_KEYS),
            "vic_alphabets": list(VIC_ALPHABETS),
            "vic_row_digits": [list(pair) for pair in VIC_ROW_DIGITS],
            "vic_digit_maps": list(VIC_DIGIT_MAPS),
            "vic_fields": list(VIC_FIELDS),
            "password_forms": list(PASSWORD_FORMS),
            "kdf_digests": list(KDF_DIGESTS),
            "envelopes": list(ENVELOPES),
            "residual_clues": list(RESIDUAL_CLUES),
            "expected_beaufort_outputs": expected_beaufort_outputs(),
            "expected_vic_outputs": expected_vic_outputs(),
            "expected_catalogue_outputs": expected_catalogue_outputs(),
            "expected_aes_trials": expected_aes_trials(),
            "expected_scalar_gates": expected_scalar_gates(),
            "raw_aes_key_branch": {
                "enabled": True,
                "iv_rule": "sha256(salt)[:16]",
                "expected_trials": expected_catalogue_outputs() * len(ENVELOPES),
            },
        },
        "acceptance": {
            "aes": "legibility or gated scalar inside plaintext; never padding alone",
            "scalar": "solver.targets.gate_scalar_bytes",
            "half": {
                "exact_public_key": HALF_PUBLIC_UNCOMPRESSED.hex(),
                "hash160": HALF_H160.hex(),
            },
            "better_half": {"hash160": BETTER_H160.hex()},
            "planted_control_scalar": CONTROL_SCALAR_HEX,
            "aes_positive_control": {
                "envelope": "artifacts/bin/phase32_envelope.bin",
                "password": PHASE32_PASSWORD.decode("ascii"),
                "digest": "sha256",
                "must_open_prefix": "I've been waiting for you.",
            },
            "vic_positive_control": {
                "alphabet": VIC_ALPHABET_DOT,
                "row_digits": ["1", "4"],
                "must_contain": "THEPRIVATEKEYSBELONGTOHALFANDBETTERHALF",
            },
        },
        "scope_note": (
            "Closes only Beaufort/VIC/chess-hint catalogue operations keyed by "
            "the Fresco 23/16/7 partition (plus THEMATRIXHASYOU) over SalPhaseIon "
            "letter/digit fields and the authenticated transliteration/raw "
            "record, against chain1/cosmic. Does not open a free cipher menu."
        ),
        "out_of_scope": [
            "Chaocipher, Bellaso, Porta, Vigenere, or any unnamed classical cipher",
            "Cosmic base-38 / Chain 4",
            "open 2^20 residual XOR",
            "HTML or Bitcoin Core source readings",
        ],
    }


def seal() -> str:
    encoded = (json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    SEAL_PATH.write_text(digest + "\n", encoding="ascii")
    return digest


if __name__ == "__main__":
    print(seal())
