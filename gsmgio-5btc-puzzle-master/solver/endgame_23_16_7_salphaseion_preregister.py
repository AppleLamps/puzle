"""Seal v56: 23/16/7 endgame against SalPhaseIon source + both envelopes.

Handoff reading (distinct from Architect-speech reinsertion v55 and from the
v50 intertwined-phrase sweep):

1. Return to the SalPhaseIon *source codes*: S91, S570, the raw pre-Beaufort
   Architect record, and the authenticated literal/token strings.
2. Reinsert the prime basics by selecting (0- and 1-based; with/without
   dropping prime 5) from those sources.
3. Build the 23/16/7 *keyspace* from the Jacque Fresco 23-word / 140-char quote
   under the fitted F73D92⊕A94021 = 5E7DB3 mask, the seven 2023-02-23 pipeline
   phrases, and the authenticated SalPhaseIon literals/tokens.
4. Compose prime-selected source with keyspace materials; disseminate the
   carried phase-3.2 passphrase over the prime-selected bytes; then try the
   two creator-published envelopes (chain1 / cosmic) under the sealed byte
   forms and both EVP digests, and gate every 32-byte object as a scalar.

Residual brute force is deliberately truncated to the clue-number set
{5,7,16,23,140,479,484,1141} — not an open 2^20 XOR. That truncation is
logged in the result.
"""

from __future__ import annotations

import hashlib
import json

from .ciao_bella_479_audit import MASK_BITS, MASK_DATE, MASK_SOURCE, MASK_VALUE, QUOTE
from .extract import ROOT
from .targets import BETTER_H160, HALF_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "endgame_23_16_7_salphaseion_preregistered.json"
SEAL_PATH = ROOT / "endgame_23_16_7_salphaseion_preregistered.sha256"
RESULT_PATH = ROOT / "endgame_23_16_7_salphaseion_audit.json"

SCHEMA = "endgame-23-16-7-salphaseion-v56"

RAW_SOURCE_SHA256 = "bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b"
CHAIN1_SALT_HEX = "3ab585348552415d"
COSMIC_SALT_HEX = "2d3f6fe06dc950e6"
PHASE32_PASSWORD = b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"

PIPELINE_PHRASES = (
    "yellowblueprimes",
    "matrixsumlist",
    "lastwordsbeforearchichoice",
    "yinyang",
    "wewontgiveawaythepassword",
    "itsinfrontofyoureyesbutyourenotseeingit",
    "verylaststepisatruegiveawaypromised",
)
LITERALS = (
    "matrixsumlist",
    "enter",
    "lastwordsbeforearchichoice",
    "thispassword",
    "shabefourfirsthintisyourlastcommand",
    "shabefanstoo",
)
REPORTED_TOKENS = (
    "matrixsumlist",
    "enter",
    "lastwordsbeforearchichoice",
    "thispassword",
    "matrixsumlist",
    "yourlastcommand",
    "secondanswer",
)

SOURCE_FIELDS = ("S91", "S570", "raw_pre_beaufort", "literals_concat", "tokens7_concat")
PRIME_SELECT_MODES = (
    "select-0based",
    "select-1based",
    "select-0based-drop5",
    "select-1based-drop5",
)
KEYSPACE_NAMES = (
    "fresco_quote_140",
    "fresco_letters_lower",
    "fresco_selected16_lower",
    "fresco_selected7_lower",
    "fresco_intertwine_16_rev7_lower",
    "pipeline7_concat",
    "literals6_concat",
    "tokens7_concat",
)
COMPOSE_MODES = (
    "keyspace_alone",
    "prime_alone",
    "keyspace_plus_prime",
    "prime_plus_keyspace",
    "xor_sha256_digests",
    "disseminate_carried_over_prime",
    "disseminate_then_plus_keyspace",
)
PASSWORD_FORMS = (
    "literal",
    "normalized_lower_alnum",
    "sha256_hex_ascii",
    "sha256_raw32",
)
KDF_DIGESTS = ("md5", "sha256")
ENVELOPES = ("chain1", "cosmic")
RESIDUAL_CLUES = (5, 7, 16, 23, 140, 479, 484, 1141)
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def _primes_24() -> list[int]:
    found: list[int] = []
    candidate = 2
    while len(found) < 24:
        if all(candidate % prime for prime in found if prime * prime <= candidate):
            found.append(candidate)
        candidate += 1
    return found


def _intertwine(parts: list[str]) -> str:
    if not parts:
        return ""
    width = max(len(part) for part in parts)
    chars: list[str] = []
    for index in range(width):
        for part in parts:
            if index < len(part):
                chars.append(part[index])
    return "".join(chars)


def fresco_partitions() -> dict[str, str]:
    words = QUOTE.split()
    if len(QUOTE) != 140 or len(words) != 23:
        raise ValueError("Fresco quote must remain 140 chars / 23 words")
    if MASK_SOURCE ^ MASK_DATE != MASK_VALUE:
        raise ValueError("F73D92 XOR A94021 must equal 5E7DB3")
    if len(MASK_BITS) != 23 or (MASK_BITS.count("1"), MASK_BITS.count("0")) != (16, 7):
        raise ValueError("mask must remain 23-bit 16/7")
    selected16 = [word for word, bit in zip(words, MASK_BITS) if bit == "1"]
    selected7 = [word for word, bit in zip(words, MASK_BITS) if bit == "0"]
    return {
        "fresco_quote_140": QUOTE,
        "fresco_letters_lower": "".join(ch for ch in QUOTE.lower() if ch.isalpha()),
        "fresco_selected16_lower": "".join(selected16).lower(),
        "fresco_selected7_lower": "".join(selected7).lower(),
        "fresco_intertwine_16_rev7_lower": _intertwine(
            [word.lower() for word in selected16]
            + [word.lower() for word in reversed(selected7)]
        ),
        "pipeline7_concat": "".join(PIPELINE_PHRASES),
        "literals6_concat": "".join(LITERALS),
        "tokens7_concat": "".join(REPORTED_TOKENS),
    }


def expected_preimage_count() -> int:
    # keyspace_alone: len(KEYSPACE)
    # prime_alone: len(SOURCE_FIELDS)*len(PRIME_SELECT_MODES)
    # paired modes: keyspace × prime_sources × 5 remaining compose modes
    keyspace = len(KEYSPACE_NAMES)
    primes = len(SOURCE_FIELDS) * len(PRIME_SELECT_MODES)
    paired = keyspace * primes * 5
    return keyspace + primes + paired


def expected_aes_trials() -> int:
    # password forms × kdfs × envelopes, except sha256_raw32 also has a raw-key branch
    # counted separately in the audit; sealed AES count is forms*kdf*env*preimages
    return expected_preimage_count() * len(PASSWORD_FORMS) * len(KDF_DIGESTS) * len(ENVELOPES)


def expected_scalar_gates() -> int:
    # sha256(preimage), double_sha256(preimage), plus residual XOR masks on sha256
    return expected_preimage_count() * (2 + len(RESIDUAL_CLUES))


def build_manifest() -> dict[str, object]:
    partitions = fresco_partitions()
    return {
        "schema": SCHEMA,
        "status": "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION",
        "hypothesis": (
            "The Architect endgame is a keyspace definition over SalPhaseIon "
            "source codes: prime-select from S91/S570/raw-pre-Beaufort/literals, "
            "compose with the Fresco 23/16/7 partition and the seven pipeline / "
            "literal / token strings, disseminate the carried phase-3.2 "
            "passphrase, and open the creator-published chain1 or cosmic envelope "
            "— or gate a constructed 32-byte scalar — under a legibility/prize gate."
        ),
        "instruction_order": [
            "return to the SalPhaseIon source codes",
            "reinserting the prime basics (select by prime positions)",
            "select from over 23 ciphers / 16 encryptions / 7 intertwined passwords",
            "bounded residual brute force over clue numbers only",
        ],
        "distinct_from": {
            "prime_basics_source_reinsert_audit.json": "Architect-layer splice; no envelope AES; no 23/16/7 keyspace",
            "intertwined_password_coherence_audit.json": "phrase/token braid only; no SalPhaseIon prime-select composition",
            "salphaseion_t23_16_7_audit.json": "S91 Hill/mask materials as scalars; not envelope passwords from Fresco+primes",
            "ciao_bella_479_audit.json": "classical ciphers over the quote; Cosmic/Chain4 out of this family's envelopes",
            "yinyang_479_continuation_audit.json": "479-indexed Architect text; not SalPhaseIon source passwords",
        },
        "frozen_inputs": {
            "fresco_quote_sha256": hashlib.sha256(QUOTE.encode("ascii")).hexdigest(),
            "fresco_quote_len": len(QUOTE),
            "fresco_word_count": 23,
            "mask_bits": MASK_BITS,
            "mask_value_hex": f"{MASK_VALUE:06x}",
            "raw_pre_beaufort_sha256": RAW_SOURCE_SHA256,
            "chain1_salt_hex": CHAIN1_SALT_HEX,
            "cosmic_salt_hex": COSMIC_SALT_HEX,
            "carried_phase32_password_utf8": PHASE32_PASSWORD.decode("ascii"),
            "pipeline_phrases": list(PIPELINE_PHRASES),
            "literals": list(LITERALS),
            "reported_tokens": list(REPORTED_TOKENS),
            "first_24_primes": _primes_24(),
            "keyspace_preview_sha256": {
                name: hashlib.sha256(value.encode("ascii")).hexdigest()
                for name, value in sorted(partitions.items())
            },
        },
        "expansion": {
            "source_fields": list(SOURCE_FIELDS),
            "prime_select_modes": list(PRIME_SELECT_MODES),
            "keyspace_names": list(KEYSPACE_NAMES),
            "compose_modes": list(COMPOSE_MODES),
            "password_forms": list(PASSWORD_FORMS),
            "kdf_digests": list(KDF_DIGESTS),
            "envelopes": list(ENVELOPES),
            "residual_clues": list(RESIDUAL_CLUES),
            "expected_preimages": expected_preimage_count(),
            "expected_aes_trials": expected_aes_trials(),
            "expected_scalar_gates": expected_scalar_gates(),
            "raw_aes_key_branch": {
                "enabled": True,
                "iv_rule": "sha256(salt)[:16]",
                "expected_trials": expected_preimage_count() * len(ENVELOPES),
            },
            "residual_truncation_note": (
                "Handoff suggested ~2^20 residual XOR; this seal truncates to the "
                "eight clue numbers above and logs the truncation."
            ),
        },
        "acceptance": {
            "aes": "legibility (printable>=0.85 and entropy<=5.9 or >=6-letter English run) or a gated 32-byte scalar inside the plaintext; NEVER padding alone",
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
        },
        "scope_note": (
            "Closes this sealed SalPhaseIon-source × Fresco-23/16/7 × prime-select "
            "composition against chain1 and cosmic only. Does not reopen Cosmic "
            "base-38 / Chain 4, does not claim the Fresco quote selection is "
            "creator-authenticated (it is fitted), and does not run an open 2^20 "
            "residual."
        ),
        "out_of_scope": [
            "Cosmic base-38, Chain 4, Witteveen",
            "open-ended 2^20 residual XOR",
            "HTML/Bitcoin-Core 'source code' readings",
            "personal close-friends identity search",
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
