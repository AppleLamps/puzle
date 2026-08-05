"""Reproduce the published Phase 3.2 symbol, Beaufort, and VIC stages."""

from __future__ import annotations

import hashlib
import json
import re

from .extract import README, ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc


RESULT_PATH = ROOT / "phase32_classical.json"
PHASE32_PASSWORD = b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
BEAUFORT_KEY = "thematrixhasyou"


def _letters(text: str) -> str:
    return "".join(character for character in text.upper() if "A" <= character <= "Z")


def _beaufort(ciphertext: str, key: str) -> str:
    key_values = [ord(character) - ord("a") for character in key.lower()]
    return "".join(
        chr(ord("A") + (key_values[index % len(key_values)] - (ord(character) - ord("a"))) % 26)
        for index, character in enumerate(ciphertext)
    )


def _vic_decode(digits: str, alphabet: str, row_digits: tuple[str, str]) -> str:
    if len(alphabet) != 28 or len(set(row_digits)) != 2:
        raise ValueError("unexpected VIC checkerboard parameters")
    top_digits = [str(value) for value in range(10) if str(value) not in row_digits]
    table = {digit: alphabet[index] for index, digit in enumerate(top_digits)}
    for row, prefix in enumerate(row_digits):
        for value in range(10):
            table[prefix + str(value)] = alphabet[8 + row * 10 + value]
    decoded: list[str] = []
    offset = 0
    while offset < len(digits):
        width = 2 if digits[offset] in row_digits else 1
        code = digits[offset : offset + width]
        if len(code) != width or code not in table:
            raise ValueError(f"invalid VIC code at digit {offset}")
        decoded.append(table[code])
        offset += width
    return "".join(decoded)


def run() -> dict[str, object]:
    inputs = extract_all()
    phase32 = decrypt_salted_aes256_cbc(inputs.phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    plaintext = phase32.plaintext
    symbol_marker = b"One for one, four for one.\r\n\r\n"
    symbol_start = plaintext.index(symbol_marker) + len(symbol_marker)
    symbol_end = plaintext.index(b"\r\n\r\n151659", symbol_start)
    symbols = plaintext[symbol_start:symbol_end]

    readme = README.read_text(encoding="utf-8-sig")
    ciphertext_match = re.search(
        r"- phase 3\.2\.1\s+The first blob.*?converted to letters:\s*\n\s*([a-z]+)",
        readme,
        re.DOTALL,
    )
    if ciphertext_match is None:
        raise ValueError("published Phase 3.2.1 ciphertext not found")
    beaufort_ciphertext = ciphertext_match.group(1)
    if len(symbols) != len(beaufort_ciphertext):
        raise ValueError("symbol record and published transliteration have different lengths")
    symbol_map: dict[int, str] = {}
    reverse_map: dict[str, int] = {}
    for symbol, letter in zip(symbols, beaufort_ciphertext):
        if symbol in symbol_map and symbol_map[symbol] != letter:
            raise ValueError("published symbol transliteration is not functional")
        if letter in reverse_map and reverse_map[letter] != symbol:
            raise ValueError("published symbol transliteration is not one-to-one")
        symbol_map[symbol] = letter
        reverse_map[letter] = symbol
    if set(reverse_map) != set("abcdefghijklmnopqrstuvwxyz"):
        raise ValueError("published symbol transliteration does not cover the alphabet")

    architect = _beaufort(beaufort_ciphertext, BEAUFORT_KEY)
    architect_match = re.search(
        r"The result of decryption:\s*\n\s*```\s*(.*?)\s*```\s*\n\s*- phase 3\.2\.2",
        readme[ciphertext_match.end() :],
        re.DOTALL,
    )
    if architect_match is None:
        raise ValueError("published Architect plaintext not found")
    published_architect_letters = _letters(architect_match.group(1))
    if architect != published_architect_letters:
        raise ValueError("independent Beaufort result differs from the published Architect text")

    numeric_match = re.search(rb"\r\n\r\n(\d+)\r\n\r\nRaising the stakes", plaintext)
    if numeric_match is None:
        raise ValueError("Phase 3.2 VIC digit record not found")
    vic_digits = numeric_match.group(1).decode("ascii")
    alphabet_match = re.search(r"alphabet:\s*([A-Z.]+)\s*\ndigit 1:\s*(\d)\s*\ndigit 2:\s*(\d)", readme)
    if alphabet_match is None:
        raise ValueError("published VIC alphabet not found")
    vic_alphabet = alphabet_match.group(1)
    row_digits = (alphabet_match.group(2), alphabet_match.group(3))
    vic_plaintext = _vic_decode(vic_digits, vic_alphabet, row_digits)
    expected_vic = "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE"
    if vic_plaintext != expected_vic:
        raise ValueError("VIC checkerboard result differs from the documented instruction")

    result: dict[str, object] = {
        "status": "REPRODUCED",
        "phase32_plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "symbol_record": {
            "offset": symbol_start,
            "length": len(symbols),
            "sha256": hashlib.sha256(symbols).hexdigest(),
            "unique_symbols": len(symbol_map),
            "bijective_alphabet": True,
            "mapping": {f"{symbol:02x}": symbol_map[symbol] for symbol in sorted(symbol_map)},
            "evidence_boundary": "The byte-to-letter transliteration is validated against the published README line; it is not independently derived from a bundled CCSID-1141 table.",
        },
        "beaufort": {
            "key": BEAUFORT_KEY.upper(),
            "ciphertext_length": len(beaufort_ciphertext),
            "ciphertext_sha256": hashlib.sha256(beaufort_ciphertext.encode("ascii")).hexdigest(),
            "plaintext_length": len(architect),
            "plaintext_sha256": hashlib.sha256(architect.encode("ascii")).hexdigest(),
            "contains_take_private_key_phrase": "TAKETHEPRIVATEKEY" in architect,
            "contains_prime_basics_phrase": "REINSERTINGTHEPRIMEBASICS" in architect,
            "contains_seven_intertwined_passwords_phrase": "SEVENINTERTWINEDPASSWORDS" in architect,
            "ends_ciao_bella_o": architect.endswith("CIAOBELLAO"),
        },
        "vic": {
            "digit_count": len(vic_digits),
            "digits_sha256": hashlib.sha256(vic_digits.encode("ascii")).hexdigest(),
            "alphabet": vic_alphabet,
            "row_digits": list(row_digits),
            "plaintext": vic_plaintext,
            "plaintext_sha256": hashlib.sha256(vic_plaintext.encode("ascii")).hexdigest(),
        },
        "layer_ownership": "The three Issue #87 phrases are reproduced inside Phase 3.2.1, not derived from Chain 4.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
