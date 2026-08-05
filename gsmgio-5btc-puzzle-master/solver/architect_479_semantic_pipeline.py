"""Run one constrained, non-Cosmic Architect-continuation hypothesis."""

from __future__ import annotations

import difflib
import hashlib
import json
import re

from coincurve import PrivateKey

from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import PHASE32_PASSWORD
from .secp256k1_verify import base58check, hash160


RESULT_PATH = ROOT / "architect_479_semantic_pipeline.json"
RECOVERY_PATH = ROOT / "phase32_symbol_recovery.json"
SECOND_DOOR_PATH = ROOT / "second_door_yellowblueprimes_audit.json"
PLAIN_SHA = "56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241"
RAW_SHA = "bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b"
HALF = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
HALF_PUBLIC = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)
QUOTE = (
    "The future is fluid. Each act, each decision, and each development creates "
    "new possibilities and eliminates others. The future is ours to direct."
)
FILM = (
    "THE FUNCTION OF THE ONE IS NOW TO RETURN TO THE SOURCE ALLOWING A TEMPORARY "
    "DISSEMINATION OF THE CODE YOU CARRY REINSERTING THE PRIME PROGRAM AFTER WHICH "
    "YOU WILL BE REQUIRED TO SELECT FROM THE MATRIX 23 INDIVIDUALS 16 FEMALE 7 MALE "
    "TO REBUILD ZION"
)
PUZZLE = (
    "THE FUNCTION OF THE YOU IS NOW TO RETURN TO THE SOURCE CODES ALLOWING A TEMPORARY "
    "DISSEMINATION OF THE CODE YOU HOPEFULLY CARRY REINSERTING THE PRIME BASICS AFTER "
    "WHICH YOU WILL BE REQUIRED TO SELECT FROM OVER TWENTY THREE CIPHERS SIXTEEN "
    "ENCRYPTIONS AND OR SEVEN INTERTWINED PASSWORDS TO FIND THE ACTUAL PRIVATE KEY"
)


def words(value: str) -> list[str]:
    return re.findall(r"[A-Za-z]+|\d+", value.upper())


def is_prime(value: int) -> bool:
    return value > 1 and all(value % divisor for divisor in range(2, int(value**0.5) + 1))


def intertwine(parts: list[str]) -> str:
    return "".join(
        part[column]
        for column in range(max(map(len, parts)))
        for part in parts
        if column < len(part)
    )


def beaufort(ciphertext: str, key: str) -> str:
    clean = "".join(character for character in ciphertext.upper() if character.isalpha())
    key = "".join(character for character in key.upper() if character.isalpha())
    return "".join(
        chr(65 + ((ord(key[index % len(key)]) - 65) - (ord(character) - 65)) % 26)
        for index, character in enumerate(clean)
    )


def address(public: bytes) -> str:
    return base58check(b"\0" + hash160(public))


def source_record() -> bytes:
    outer = decrypt_salted_aes256_cbc(
        extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256"
    ).plaintext
    marker = b"One for one, four for one.\r\n\r\n"
    start = outer.index(marker) + len(marker)
    end = outer.index(b"\r\n\r\n151659", start)
    return outer[start:end]


def run() -> dict[str, object]:
    recovery = json.loads(RECOVERY_PATH.read_text(encoding="utf-8"))
    plaintext = recovery["plaintext"]
    raw = source_record()
    if hashlib.sha256(plaintext.encode()).hexdigest() != PLAIN_SHA:
        raise ValueError("authenticated Architect plaintext changed")
    if hashlib.sha256(raw).hexdigest() != RAW_SHA:
        raise ValueError("raw Phase 3.2 source-code record changed")

    mapping = {int(code, 16): letter for code, letter in recovery["recovered_mapping"].items()}
    transliterated = "".join(mapping[value] for value in raw)
    source = json.loads(SECOND_DOOR_PATH.read_text(encoding="utf-8"))["source"]
    if source["marker_hex"].upper() != "F73D92":
        raise ValueError("rose source code changed")

    quote_words = re.findall(r"[A-Za-z]+", QUOTE)
    quote_140 = " ".join(quote_words)
    prime_date = 11092001
    mask_integer = int(source["marker_hex"], 16) ^ prime_date
    mask = f"{mask_integer:b}"
    if not (is_prime(prime_date) and len(mask) == 23 and mask.count("1") == 16):
        raise ValueError("prime-date 23/16/7 construction changed")
    cipher_words = [word for word, bit in zip(quote_words, mask) if bit == "1"]
    password_words = [word for word, bit in zip(quote_words, mask) if bit == "0"]
    password = intertwine(password_words[::-1])
    decoded = beaufort("".join(cipher_words), password)
    scalar = hashlib.sha256(decoded.encode("ascii")).digest()
    point = PrivateKey(scalar).public_key
    public_u = point.format(compressed=False)
    public_c = point.format(compressed=True)
    addresses = {"uncompressed": address(public_u), "compressed": address(public_c)}

    matcher = difflib.SequenceMatcher(a=words(FILM), b=words(PUZZLE))
    edits = [
        {
            "operation": tag,
            "film": words(FILM)[left_start:left_end],
            "puzzle": words(PUZZLE)[right_start:right_end],
        }
        for tag, left_start, left_end, right_start, right_end in matcher.get_opcodes()
        if tag != "equal"
    ]
    phrases = [
        "PRIVATEKEY",
        "TAKETHISTOHEART",
        "WISEMANABOVE",
        "HUNDREDFOURTY",
        "SOURCECODES",
        "PRIMEBASICS",
        "TWENTYTHREECIPHERS",
        "SIXTEENENCRYPTIONS",
        "SEVENINTERTWINEDPASSWORDS",
        "CIAOBELLAO",
    ]
    anchors = {phrase: plaintext.index(phrase) for phrase in phrases}
    exact = addresses["uncompressed"] in (HALF, BETTER) or addresses["compressed"] in (HALF, BETTER)
    result = {
        "schema": "architect-479-semantic-pipeline-v1",
        "status": "EXACT_PRIZE_MATCH" if exact else "NO_EXACT_PRIZE_MATCH",
        "cosmic_used": False,
        "authenticated_layers": {
            "plaintext_length": len(plaintext),
            "plaintext_sha256": PLAIN_SHA,
            "raw_source_length": len(raw),
            "raw_source_sha256": RAW_SHA,
            "beaufort_key": recovery["beaufort_key"],
            "ibm_1141_evidence_boundary": (
                "One for one, four for one names 1141, but direct standard IBM1141 decoding "
                "of the raw bytes does not yield the published transliteration."
            ),
            "anchors_zero_based": anchors,
            "source_projection_at_479": {
                "raw_hex_32": raw[479:511].hex(),
                "transliterated_32": transliterated[479:511],
                "plaintext_32": plaintext[479:511],
            },
        },
        "film_comparison": {
            "film_clause": FILM,
            "puzzle_clause": PUZZLE,
            "word_edits": edits,
            "warning": "Unchanged film connective words do not independently specify cryptographic operations.",
        },
        "semantic_findings": {
            "source_codes": "Strong altered noun; immediate referent is the raw 1539-byte pre-Beaufort source-code record. F73D92 is a packed poster-marker bitstream, not an RGB value present in the source image.",
            "temporary_dissemination": "Unchanged film wording; repetition of a key is only a proposed operational reading.",
            "code_you_carry": "Unchanged except HOPEFULLY. Immediate candidates are THEMATRIXHASYOU and the 64 ASCII hex Phase 3.2 passphrase; neither is uniquely selected by this phrase.",
            "prime_basics": "Strong PROGRAM-to-BASICS substitution plus creator prime/zero hints; it authenticates primes, not a unique insertion algorithm.",
            "ciao_bella_o": "Exact word-order reversal of the song refrain O BELLA CIAO; cipher-name readings require spelling edits and are weaker.",
        },
        "constrained_pipeline": {
            "confidence": "hypothesis",
            "rose_source_hex": source["marker_hex"].upper(),
            "prime_date_decimal": prime_date,
            "prime_date_hex": f"{prime_date:X}",
            "prime_date_is_prime": is_prime(prime_date),
            "xor_hex": f"{mask_integer:X}",
            "mask": mask,
            "quote_no_punctuation_length": len(quote_140),
            "quote_word_count": len(quote_words),
            "cipher_words_16": cipher_words,
            "password_words_7": password_words,
            "password_order": list(reversed(password_words)),
            "intertwined_password": password,
            "beaufort_output": decoded,
            "scalar_sha256": scalar.hex(),
            "candidate_addresses": addresses,
            "half_public_key_match": public_u == HALF_PUBLIC,
            "prize_match": exact,
        },
        "representation_correction": {
            "phase32_openssl_passphrase_ascii": PHASE32_PASSWORD.decode("ascii"),
            "passphrase_byte_length": len(PHASE32_PASSWORD),
            "note": "The Phase 3.2 OpenSSL passphrase is 64 ASCII hex bytes, not the 32 decoded digest bytes.",
        },
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({"status": output["status"], "pipeline": output["constrained_pipeline"]}, indent=2))
