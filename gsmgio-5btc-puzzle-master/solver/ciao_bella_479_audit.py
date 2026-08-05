"""Bounded CIAO/BELLA audit for the 479 Architect continuation.

The final Architect words, ``CIAO BELLA O``, plausibly name Chaocipher and
Bellaso.  This module implements those ciphers directly, verifies Chaocipher
against Byrne's published exhibit, and applies only clue-justified layouts to
the exact 23/16/7 Jacque Fresco partition.  Cosmic material is never used.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import re

from coincurve import PrivateKey

from .extract import ROOT
from .secp256k1_verify import BASE58, N, hash160, wif


RESULT_PATH = ROOT / "ciao_bella_479_audit.json"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
QUOTE = (
    "The future is fluid Each act each decision and each development creates "
    "new possibilities and eliminates others The future is ours to direct"
)
MASK_VALUE = 0x5E7DB3
MASK_SOURCE = 0xF73D92
MASK_DATE = 0xA94021
MASK_BITS = f"{MASK_VALUE:023b}"

HALF_PUBLIC = bytes.fromhex(
    "04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)
HALF_H160 = bytes.fromhex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")
BETTER_H160 = bytes.fromhex("4bc468447fe1b048ad030a2f9a125478eabc4ed6")

CHAO_EXHIBIT_LEFT = "HXUCZVAMDSLKPEFJRIGTWOBNYQ"
CHAO_EXHIBIT_RIGHT = "PTLNBQDEOYSFAVZKGJRIHWXUMC"
CHAO_EXHIBIT_PLAINTEXT = "WELLDONEISBETTERTHANWELLSAID"
CHAO_EXHIBIT_CIPHERTEXT = "OAHQHCNYNXTSZJRRHJBYHQKSOUJY"


def clean(text: str) -> str:
    return "".join(character for character in text.upper() if character in ALPHABET)


def keyed_alphabet(keyword: str) -> str:
    """Return the conventional de-duplicated keyword alphabet."""
    return "".join(dict.fromkeys(clean(keyword) + ALPHABET))


def intertwine(parts: list[str]) -> str:
    """Read a ragged list by columns, retaining the supplied row order."""
    return "".join(
        part[column]
        for column in range(max(map(len, parts), default=0))
        for part in parts
        if column < len(part)
    )


def _rotate(value: list[str], amount: int) -> list[str]:
    amount %= len(value)
    return value[amount:] + value[:amount]


def _chaocipher_permute(left: list[str], right: list[str], index: int) -> tuple[list[str], list[str]]:
    """Apply the standard post-letter Chaocipher disk permutation."""
    left = _rotate(left, index)
    left.insert(13, left.pop(1))
    right = _rotate(right, index + 1)
    right.insert(13, right.pop(2))
    return left, right


def chaocipher(
    text: str,
    left_alphabet: str,
    right_alphabet: str,
    *,
    decrypt: bool = False,
) -> str:
    """Encrypt/decrypt with the standard two dynamically permuted alphabets."""
    left = list(clean(left_alphabet))
    right = list(clean(right_alphabet))
    if sorted(left) != list(ALPHABET) or sorted(right) != list(ALPHABET):
        raise ValueError("Chaocipher alphabets must each be A-Z permutations")
    output: list[str] = []
    for character in clean(text):
        source, destination = (left, right) if decrypt else (right, left)
        index = source.index(character)
        output.append(destination[index])
        left, right = _chaocipher_permute(left, right, index)
    return "".join(output)


def vigenere(text: str, key: str, mode: str) -> str:
    """Vigenere, variant-Beaufort, or Beaufort over A=0..Z=25."""
    source, password = clean(text), clean(key)
    if not source or not password:
        return ""
    output: list[str] = []
    for index, character in enumerate(source):
        value = ALPHABET.index(character)
        shift = ALPHABET.index(password[index % len(password)])
        if mode == "vigenere-encrypt":
            result = value + shift
        elif mode == "vigenere-decrypt":
            result = value - shift
        elif mode == "beaufort":
            result = shift - value
        else:
            raise ValueError(f"unknown Vigenere-family mode: {mode}")
        output.append(ALPHABET[result % 26])
    return "".join(output)


def porta(text: str, key: str) -> str:
    """Porta's reciprocal cipher (13 rows selected by AB, CD, ..., YZ)."""
    source, password = clean(text), clean(key)
    if not source or not password:
        return ""
    output: list[str] = []
    for index, character in enumerate(source):
        value = ALPHABET.index(character)
        row = ALPHABET.index(password[index % len(password)]) // 2
        if value < 13:
            result = 13 + (value + row) % 13
        else:
            result = (value - 13 - row) % 13
        output.append(ALPHABET[result])
    return "".join(output)


def bellaso_1553(text: str, key: str, alphabet_keyword: str = "") -> str:
    """Bellaso's reciprocal 1553 construction over a straight or keyed alphabet.

    The alphabet is split into two 13-letter halves.  A key letter's position
    modulo 13 selects the rotation between opposite halves.  Applying the same
    operation twice recovers the input.
    """
    source, password = clean(text), clean(key)
    alphabet = keyed_alphabet(alphabet_keyword)
    if not source or not password:
        return ""
    output: list[str] = []
    for index, character in enumerate(source):
        value = alphabet.index(character)
        row = alphabet.index(password[index % len(password)]) % 13
        if value < 13:
            result = 13 + (value + row) % 13
        else:
            result = (value - 13 - row) % 13
        output.append(alphabet[result])
    return "".join(output)


def primes_through(limit: int) -> list[int]:
    return [
        value
        for value in range(2, limit + 1)
        if all(value % divisor for divisor in range(2, math.isqrt(value) + 1))
    ]


def _b58check_payload(value: str) -> bytes | None:
    if not value or any(character not in BASE58 for character in value):
        return None
    number = 0
    for character in value:
        number = number * 58 + BASE58.index(character)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    decoded = b"\0" * (len(value) - len(value.lstrip("1"))) + decoded
    if len(decoded) < 5:
        return None
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return payload if checksum == expected else None


def _english_score(value: str) -> float:
    """A reproducible ranking heuristic, not a claim of decryption."""
    text = clean(value)
    if not text:
        return -1e9
    expected = {
        "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97, "N": 6.75,
        "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25, "L": 4.03, "U": 2.76,
    }
    counts = Counter(text)
    chi = sum(
        (counts[letter] - len(text) * frequency / 100) ** 2
        / max(len(text) * frequency / 100, 0.01)
        for letter, frequency in expected.items()
    )
    common = ("THE", "THIS", "THAT", "PRIVATE", "KEY", "FUTURE", "IS", "TO", "OUR", "ONE")
    bonus = sum(len(token) ** 2 for token in common if token in text)
    vowel_ratio = sum(counts[letter] for letter in "AEIOU") / len(text)
    return round(bonus - chi - 100 * abs(vowel_ratio - 0.38), 6)


def _word_layouts(parts: list[str], prefix: str) -> dict[str, str]:
    variants = {
        f"{prefix}/concat-forward": "".join(parts),
        f"{prefix}/concat-reverse-words": "".join(parts[::-1]),
        f"{prefix}/concat-reverse-letters": "".join(part[::-1] for part in parts),
        f"{prefix}/concat-reverse-both": "".join(part[::-1] for part in parts[::-1]),
        f"{prefix}/intertwine-forward": intertwine(parts),
        f"{prefix}/intertwine-reverse-words": intertwine(parts[::-1]),
        f"{prefix}/intertwine-reverse-letters": intertwine([part[::-1] for part in parts]),
        f"{prefix}/intertwine-reverse-both": intertwine([part[::-1] for part in parts[::-1]),
    }
    return {label: clean(value) for label, value in variants.items()}


def _transform_wordwise(
    words: list[str],
    operation,
    *,
    reverse_words: bool,
    reverse_letters: bool,
) -> str:
    selected = words[::-1] if reverse_words else words
    if reverse_letters:
        selected = [word[::-1] for word in selected]
    return "".join(operation(word) for word in selected)


class CandidateAudit:
    def __init__(self) -> None:
        self.outputs: dict[str, str] = {}
        self.output_families: Counter[str] = Counter()
        self.scalar_labels: dict[bytes, list[str]] = {}
        self.scalar_derivations = 0
        self.matches: list[dict[str, object]] = []
        self.direct_encodings: list[dict[str, object]] = []
        self.direct_hash_matches: list[dict[str, object]] = []

    def add(self, family: str, label: str, value: str) -> None:
        rendered = clean(value)
        if not rendered:
            return
        full_label = f"{family}/{label}"
        previous = self.outputs.get(full_label)
        if previous is not None and previous != rendered:
            raise ValueError(f"output label collision: {full_label}")
        if previous is None:
            self.outputs[full_label] = rendered
            self.output_families[family] += 1

    def derive(self) -> None:
        for label, rendered in sorted(self.outputs.items()):
            raw = rendered.encode("ascii")
            direct_h160 = hash160(raw)
            if direct_h160 in (HALF_H160, BETTER_H160):
                self.direct_hash_matches.append(
                    {
                        "label": label,
                        "operation": "HASH160(ciphertext-ascii)",
                        "target": "Half" if direct_h160 == HALF_H160 else "Better_Half",
                    }
                )
            if raw == HALF_PUBLIC:
                self.direct_hash_matches.append(
                    {"label": label, "operation": "direct-public-key", "target": "Half"}
                )

            candidates = {
                "sha256-ascii": hashlib.sha256(raw).digest(),
                "double-sha256-ascii": hashlib.sha256(hashlib.sha256(raw).digest()).digest(),
            }
            if len(raw) == 32:
                candidates["direct-ascii32"] = raw
            if re.fullmatch(r"[0-9A-Fa-f]{64}", rendered):
                candidates["direct-hex32"] = bytes.fromhex(rendered)
                self.direct_encodings.append({"label": label, "kind": "hex-32"})
            if re.fullmatch(r"[0-9A-Fa-f]{40}", rendered):
                decoded = bytes.fromhex(rendered)
                self.direct_encodings.append({"label": label, "kind": "hex-hash160"})
                if decoded in (HALF_H160, BETTER_H160):
                    self.direct_hash_matches.append(
                        {
                            "label": label,
                            "operation": "direct-hex-hash160",
                            "target": "Half" if decoded == HALF_H160 else "Better_Half",
                        }
                    )
            payload = _b58check_payload(rendered)
            if payload is not None and payload[:1] == b"\x80" and len(payload) in (33, 34):
                compressed = len(payload) == 34 and payload[-1:] == b"\x01"
                private = payload[1:-1] if compressed else payload[1:]
                candidates[f"direct-WIF-{'compressed' if compressed else 'uncompressed'}"] = private
                self.direct_encodings.append(
                    {"label": label, "kind": "WIF", "compressed": compressed}
                )

            for derivation, private in candidates.items():
                scalar = int.from_bytes(private, "big")
                if not 1 <= scalar < N:
                    continue
                self.scalar_derivations += 1
                scalar_labels = self.scalar_labels.setdefault(private, [])
                scalar_labels.append(f"{label}/{derivation}")

        for private, labels in sorted(self.scalar_labels.items()):
            public = PrivateKey(private).public_key
            public_u = public.format(compressed=False)
            public_c = public.format(compressed=True)
            hashes = {
                "uncompressed": hash160(public_u),
                "compressed": hash160(public_c),
            }
            target = None
            serialization = None
            if public_u == HALF_PUBLIC or hashes["uncompressed"] == HALF_H160:
                target, serialization = "Half", "uncompressed"
            elif hashes["compressed"] == HALF_H160:
                target, serialization = "Half", "compressed"
            elif hashes["uncompressed"] == BETTER_H160:
                target, serialization = "Better_Half", "uncompressed"
            elif hashes["compressed"] == BETTER_H160:
                target, serialization = "Better_Half", "compressed"
            if target:
                self.matches.append(
                    {
                        "target": target,
                        "serialization": serialization,
                        "labels": labels,
                        "private_key_hex": private.hex(),
                        "wif": wif(private, compressed=serialization == "compressed"),
                    }
                )


def _add_classical_outputs(
    audit: CandidateAudit,
    family: str,
    message_label: str,
    message: str,
    key_label: str,
    key: str,
) -> None:
    for mode in ("vigenere-encrypt", "vigenere-decrypt", "beaufort"):
        audit.add(family, f"{message_label}/{key_label}/{mode}", vigenere(message, key, mode))
    audit.add(family, f"{message_label}/{key_label}/porta-reciprocal", porta(message, key))
    audit.add(
        family,
        f"{message_label}/{key_label}/bellaso-1553-straight-reciprocal",
        bellaso_1553(message, key),
    )
    audit.add(
        family,
        f"{message_label}/{key_label}/bellaso-1553-keyed-reciprocal",
        bellaso_1553(message, key, key),
    )


def _known_answer_tests() -> dict[str, object]:
    encrypted = chaocipher(
        CHAO_EXHIBIT_PLAINTEXT, CHAO_EXHIBIT_LEFT, CHAO_EXHIBIT_RIGHT
    )
    decrypted = chaocipher(
        CHAO_EXHIBIT_CIPHERTEXT,
        CHAO_EXHIBIT_LEFT,
        CHAO_EXHIBIT_RIGHT,
        decrypt=True,
    )
    tests = {
        "chaocipher_byne_exhibit_encrypt": encrypted == CHAO_EXHIBIT_CIPHERTEXT,
        "chaocipher_byne_exhibit_decrypt": decrypted == CHAO_EXHIBIT_PLAINTEXT,
        "porta_reciprocal_roundtrip": porta(porta("THEFUTUREISOURS", "PASSWORD"), "PASSWORD")
        == "THEFUTUREISOURS",
        "bellaso_1553_straight_roundtrip": bellaso_1553(
            bellaso_1553("THEFUTUREISOURS", "PASSWORD"), "PASSWORD"
        )
        == "THEFUTUREISOURS",
        "bellaso_1553_keyed_roundtrip": bellaso_1553(
            bellaso_1553("THEFUTUREISOURS", "PASSWORD", "SECRET"),
            "PASSWORD",
            "SECRET",
        )
        == "THEFUTUREISOURS",
    }
    if not all(tests.values()):
        raise AssertionError(f"cipher known-answer/self-inverse test failed: {tests}")
    return tests


def run() -> dict[str, object]:
    known_answers = _known_answer_tests()
    quote_words = QUOTE.split()
    if len(QUOTE) != 140 or len(quote_words) != 23:
        raise ValueError("the exact quote must remain 23 words and 140 characters")
    if MASK_SOURCE ^ MASK_DATE != MASK_VALUE:
        raise ValueError("F73D92 XOR A94021 no longer equals 5E7DB3")
    if len(MASK_BITS) != 23 or (MASK_BITS.count("1"), MASK_BITS.count("0")) != (16, 7):
        raise ValueError("the XOR mask must remain a 23-bit 16/7 partition")

    message_words = [word for word, bit in zip(quote_words, MASK_BITS) if bit == "1"]
    password_words = [word for word, bit in zip(quote_words, MASK_BITS) if bit == "0"]
    expected_passwords = ["future", "Each", "decision", "possibilities", "others", "is", "ours"]
    if password_words != expected_passwords:
        raise ValueError(f"unexpected zero-selected words: {password_words}")

    message_layouts = _word_layouts(message_words, "selected16")
    key_layouts = _word_layouts(password_words, "selected7")
    primes = primes_through(140)
    prime_layouts: dict[str, str] = {}
    for basis in (0, 1):
        selected = "".join(QUOTE[index - basis] for index in primes[:23])
        prime_layouts[f"quote140/first23-primes/{basis}-based"] = clean(selected)
        all_selected = "".join(
            QUOTE[index - basis] for index in primes if 0 <= index - basis < len(QUOTE)
        )
        prime_layouts[f"quote140/all-primes/{basis}-based"] = clean(all_selected)
    message_layouts.update(prime_layouts)

    audit = CandidateAudit()

    # Bellaso/Vigenere/Porta readings: whole streams and each of the sixteen
    # selected words encrypted independently with a reset key.
    for message_label, message in message_layouts.items():
        for key_label, key in key_layouts.items():
            _add_classical_outputs(
                audit, "classical-continuous", message_label, message, key_label, key
            )
    for reverse_words in (False, True):
        for reverse_letters in (False, True):
            direction = (
                f"wordwise-reset/reverse-words-{reverse_words}/"
                f"reverse-letters-{reverse_letters}"
            )
            for key_label, key in key_layouts.items():
                operations = {
                    "vigenere-encrypt": lambda word, k=key: vigenere(word, k, "vigenere-encrypt"),
                    "vigenere-decrypt": lambda word, k=key: vigenere(word, k, "vigenere-decrypt"),
                    "beaufort": lambda word, k=key: vigenere(word, k, "beaufort"),
                    "porta-reciprocal": lambda word, k=key: porta(word, k),
                    "bellaso-1553-straight": lambda word, k=key: bellaso_1553(word, k),
                    "bellaso-1553-keyed": lambda word, k=key: bellaso_1553(word, k, k),
                }
                for mode, operation in operations.items():
                    output = _transform_wordwise(
                        message_words,
                        operation,
                        reverse_words=reverse_words,
                        reverse_letters=reverse_letters,
                    )
                    audit.add(
                        "classical-16-word-reset",
                        f"{direction}/{key_label}/{mode}",
                        output,
                    )

    # Chaocipher's key is a pair of alphabets.  The fixed configurations use
    # the published exhibit, straight disks, and the literal CIAO/BELLA order.
    fixed_chao = {
        "byrne-exhibit": (CHAO_EXHIBIT_LEFT, CHAO_EXHIBIT_RIGHT),
        "straight": (ALPHABET, ALPHABET),
        "ciao-bella": (keyed_alphabet("CIAO"), keyed_alphabet("BELLA")),
        "bella-ciao": (keyed_alphabet("BELLA"), keyed_alphabet("CIAO")),
        "ciaobellao-reverse": (
            keyed_alphabet("CIAOBELLAO"),
            keyed_alphabet("OAOLLEBAOIC"),
        ),
    }
    chao_outputs: dict[str, str] = {}
    for message_label, message in message_layouts.items():
        for alphabet_label, (left, right) in fixed_chao.items():
            for direction, decrypt in (("encrypt", False), ("decrypt", True)):
                output = chaocipher(message, left, right, decrypt=decrypt)
                label = f"{message_label}/{alphabet_label}/{direction}"
                audit.add("chaocipher-fixed-alphabets", label, output)
                chao_outputs[label] = output

    # Treat each seven-word layout as the password that keys one disk, while
    # CIAO BELLA O keys the other; include both disk assignments.
    for message_label, message in message_layouts.items():
        for key_label, key in key_layouts.items():
            configurations = {
                "password-left-ciaobellao-right": (
                    keyed_alphabet(key),
                    keyed_alphabet("CIAOBELLAO"),
                ),
                "ciaobellao-left-password-right": (
                    keyed_alphabet("CIAOBELLAO"),
                    keyed_alphabet(key),
                ),
                "password-ciao-left-password-bella-right": (
                    keyed_alphabet(key + "CIAO"),
                    keyed_alphabet(key + "BELLA"),
                ),
                "password-bella-left-password-ciao-right": (
                    keyed_alphabet(key + "BELLA"),
                    keyed_alphabet(key + "CIAO"),
                ),
            }
            for alphabet_label, (left, right) in configurations.items():
                for direction, decrypt in (("encrypt", False), ("decrypt", True)):
                    output = chaocipher(message, left, right, decrypt=decrypt)
                    label = (
                        f"{message_label}/{key_label}/{alphabet_label}/{direction}"
                    )
                    audit.add("chaocipher-password-alphabets", label, output)
                    chao_outputs[label] = output

    # CIAO then BELLA, and the reverse reading, over the same bounded layouts.
    # Bellaso here includes its historically reciprocal form plus Porta;
    # Vigenere is retained because it is commonly (but imprecisely) called
    # Bellaso's cipher in modern implementations.
    pipeline_modes = {
        "porta": lambda text, key: porta(text, key),
        "bellaso-1553-straight": lambda text, key: bellaso_1553(text, key),
        "bellaso-1553-keyed": lambda text, key: bellaso_1553(text, key, key),
        "vigenere-encrypt": lambda text, key: vigenere(text, key, "vigenere-encrypt"),
        "vigenere-decrypt": lambda text, key: vigenere(text, key, "vigenere-decrypt"),
    }
    for chao_label, chao_output in chao_outputs.items():
        for key_label, key in key_layouts.items():
            for mode, operation in pipeline_modes.items():
                audit.add(
                    "pipeline-ciao-then-bella",
                    f"{chao_label}/{key_label}/{mode}",
                    operation(chao_output, key),
                )
    for message_label, message in message_layouts.items():
        for key_label, key in key_layouts.items():
            for mode, operation in pipeline_modes.items():
                bellaso_output = operation(message, key)
                for alphabet_label, (left, right) in fixed_chao.items():
                    for direction, decrypt in (("encrypt", False), ("decrypt", True)):
                        audit.add(
                            "pipeline-bella-then-ciao",
                            (
                                f"{message_label}/{key_label}/{mode}/"
                                f"{alphabet_label}/{direction}"
                            ),
                            chaocipher(bellaso_output, left, right, decrypt=decrypt),
                        )

    audit.derive()
    ranked = sorted(
        (
            {
                "label": label,
                "output": output,
                "length": len(output),
                "english_score": _english_score(output),
            }
            for label, output in audit.outputs.items()
        ),
        key=lambda record: (record["english_score"], record["label"]),
        reverse=True,
    )
    commitment = hashlib.sha256(
        b"\n".join(
            label.encode("utf-8") + b"\0" + output.encode("ascii")
            for label, output in sorted(audit.outputs.items())
        )
    ).hexdigest()

    result: dict[str, object] = {
        "schema": "ciao-bella-479-audit-v1",
        "status": "EXACT_MATCH" if audit.matches or audit.direct_hash_matches else "NO_EXACT_MATCH",
        "cosmic_used": False,
        "facts": {
            "quote": QUOTE,
            "quote_characters": len(QUOTE),
            "quote_words": len(quote_words),
            "xor": {
                "F73D92": MASK_SOURCE,
                "A94021": MASK_DATE,
                "result_hex": f"{MASK_VALUE:06X}",
                "result_bits": MASK_BITS,
                "ones": MASK_BITS.count("1"),
                "zeros": MASK_BITS.count("0"),
            },
            "selected_16_words": message_words,
            "selected_7_words": password_words,
            "selected_16_concat": "".join(message_words),
            "selected_7_concat": "".join(password_words),
            "selected_7_intertwined": intertwine(password_words),
            "selected_7_intertwined_reversed": intertwine(password_words[::-1]),
            "prime_character_layouts": prime_layouts,
            "architect_ending": "CIAO BELLA O",
        },
        "implementation_checks": known_answers,
        "cipher_definitions": {
            "chaocipher": (
                "Standard left=ciphertext/right=plaintext dynamic alphabets; "
                "left zenith+1 and right zenith+2 moved to nadir after rotation."
            ),
            "bellaso_1553": (
                "Reciprocal opposite-half substitution; key position modulo 13 "
                "rotates a straight or keyword-mixed alphabet."
            ),
            "porta": "Reciprocal 13-row AB/CD/.../YZ tableau.",
            "vigenere_family": "A=0..Z=25 encrypt, decrypt, and Beaufort formulas.",
        },
        "scope": {
            "message_layouts": len(message_layouts),
            "key_layouts": len(key_layouts),
            "message_layout_labels": sorted(message_layouts),
            "key_layout_labels": sorted(key_layouts),
            "prime_bases": [0, 1],
            "prime_sets": ["first 23 primes", "all primes <= 140"],
            "directions": [
                "source/reversed word order",
                "source/reversed letters within words",
                "continuous/wordwise-reset",
                "Chaocipher encrypt/decrypt",
                "CIAO then BELLA/BELLA then CIAO",
            ],
            "excluded": ["Cosmic", "unbounded key guesses", "arbitrary transpositions"],
        },
        "counts": {
            "outputs": len(audit.outputs),
            "outputs_by_family": dict(sorted(audit.output_families.items())),
            "unique_scalar_candidates": len(audit.scalar_labels),
            "scalar_derivations": audit.scalar_derivations,
            "direct_encodings": len(audit.direct_encodings),
        },
        "candidate_set_sha256": commitment,
        "exact_matches": audit.matches,
        "direct_hash_matches": audit.direct_hash_matches,
        "valid_direct_hex_or_wif": audit.direct_encodings,
        "readability_ranking_note": (
            "Heuristic uses English letter frequencies plus literal clue-word bonuses; "
            "ranking is diagnostic and is not evidence of a valid decryption."
        ),
        "top_readable_outputs": ranked[:30],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(
        json.dumps(
            {
                "status": output["status"],
                "facts": output["facts"],
                "implementation_checks": output["implementation_checks"],
                "counts": output["counts"],
                "candidate_set_sha256": output["candidate_set_sha256"],
                "exact_matches": output["exact_matches"],
                "direct_hash_matches": output["direct_hash_matches"],
                "valid_direct_hex_or_wif": output["valid_direct_hex_or_wif"],
                "top_readable_outputs": output["top_readable_outputs"][:10],
            },
            indent=2,
            sort_keys=True,
        )
    )
