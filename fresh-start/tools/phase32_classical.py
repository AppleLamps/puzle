#!/usr/bin/env python3
"""Take the phase 3.2 plaintext apart: symbol record, Beaufort, VIC checkerboard.

Reads `derived/phase32_plaintext.bin` (written by `phase2_phase3.py`) and works
through the three classical stages the plaintext itself sets up:

1. **Symbol record.** 1,539 bytes of high-bit glyphs. The preamble's "One for
   one, four for one" reads as 1141 — IBM EBCDIC code page 1141. Each byte,
   taken as its Latin-1 character and encoded to EBCDIC, becomes one ASCII
   lowercase letter. That is a bijection over exactly 26 symbols, which is the
   check that the reading is right: a wrong code page does not close.
   (Python ships cp273, EBCDIC Germany/Austria; 1141 is cp273 plus the euro
   sign, and the two agree on every byte in this record.)

2. **Beaufort.** "I've designed you a beautiful strategic position" reads as
   Beaufort. Key `THEMATRIXHASYOU` ("the matrix has you", with Neo replaced by
   you, as elsewhere in this puzzle), P = K − C mod 26.

3. **VIC straddling checkerboard.** The 149-digit line, against the alphabet
   named in the plaintext's own sentence ("A fubcd-king & oracle-queen, thingky
   mvps, on a sad board…"), with 1 and 4 as the straddle rows.

Every step is checked by its output being readable English or by a stated
SHA-256, not by the absence of an error.
"""

from __future__ import annotations

import hashlib
import string

from _paths import ARTIFACTS, DERIVED, derived

EBCDIC = "cp273"

BEAUFORT_KEY = "THEMATRIXHASYOU"

# From the plaintext line "A fubcd-king & oracle-queen, thingky mvps, on a sad
# board but as wide as the first one seen." Row 0 holds eight letters; 1 and 4
# are the straddle prefixes for two rows of ten.
CHECKERBOARD_ALPHABET = "FUBCDORA.LETHINGKYMVPS.JQZXW"
TOP_DIGITS = [0, 2, 3, 5, 6, 7, 8, 9]

EXPECTED = {
    "symbol_record": "bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b",
    "architect_plaintext": "56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241",
    "checkerboard": "878b7afacc9e35412e76b8506cc8297fa5aeba5381e108dc421b71a0ab8993d8",
}


def sections(payload: bytes) -> list[bytes]:
    return [line.rstrip(b"\r") for line in payload.split(b"\n")]


def to_letters(record: bytes) -> str:
    """EBCDIC-decode the symbol record. Raises if the mapping is not a 26-letter bijection."""
    letters = []
    for byte in record:
        encoded = bytes([byte]).decode("latin-1").encode(EBCDIC)
        if len(encoded) != 1 or chr(encoded[0]) not in string.ascii_lowercase:
            raise ValueError(f"byte {byte:#04x} does not map to a lowercase letter under {EBCDIC}")
        letters.append(chr(encoded[0]))
    distinct = set(letters)
    if len(distinct) != 26:
        raise ValueError(f"expected 26 distinct letters, got {len(distinct)}")
    return "".join(letters)


def beaufort(ciphertext: str, key: str) -> str:
    """P = K − C (mod 26). Beaufort is its own inverse, so this both encrypts and decrypts."""
    out = []
    for i, c in enumerate(ciphertext):
        k = ord(key[i % len(key)].upper()) - 65
        out.append(chr((k - (ord(c.lower()) - 97)) % 26 + 65))
    return "".join(out)


def checkerboard(digits: str, alphabet: str = CHECKERBOARD_ALPHABET) -> str:
    row0, row1, row4 = alphabet[:8], alphabet[8:18], alphabet[18:28]
    table = {str(d): row0[i] for i, d in enumerate(TOP_DIGITS)}
    for i in range(10):
        table["1" + str(i)] = row1[i]
        table["4" + str(i)] = row4[i]
    out, i = [], 0
    while i < len(digits):
        width = 2 if digits[i] in "14" else 1
        out.append(table[digits[i:i + width]])
        i += width
    return "".join(out)


def check(name: str, data: bytes) -> None:
    got = hashlib.sha256(data).hexdigest()
    want = EXPECTED[name]
    print(f"    sha256 {got}  {'MATCH' if got == want else 'DIFFERS FROM ' + want}")


def main() -> None:
    payload = (DERIVED / "phase32_plaintext.bin").read_bytes()
    lines = sections(payload)
    record = max(lines, key=len)
    digits = next(l for l in lines if l.isdigit())

    print(f"=== symbol record: {len(record)} bytes, {len(set(record))} distinct symbols")
    check("symbol_record", record)

    letters = to_letters(record)
    print(f"\n=== EBCDIC ({EBCDIC}) → letters")
    print("    " + letters[:96] + "…")
    derived("architect_ciphertext.txt").write_text(letters)

    architect = beaufort(letters, BEAUFORT_KEY)
    print(f"\n=== Beaufort, key {BEAUFORT_KEY}, P = K − C mod 26 ({len(architect)} letters)")
    check("architect_plaintext", architect.encode())
    print("    " + architect[:96] + "…")
    derived("architect_plaintext.txt").write_text(architect)

    committed = (ARTIFACTS / "architect_plaintext.txt").read_text().strip()
    print(f"    matches artifacts/architect_plaintext.txt: {architect == committed}")

    print(f"\n=== VIC checkerboard ({len(digits)} digits, alphabet {CHECKERBOARD_ALPHABET})")
    message = checkerboard(digits.decode())
    check("checkerboard", message.encode())
    print("    " + message)
    derived("checkerboard_message.txt").write_text(message)

    # The published alphabet has 28 positions but only 27 distinct characters:
    # `.` appears twice. Both `.` cells sit at digits this ciphertext never
    # selects, so nothing above depends on it — but a decode that did reach one
    # of those cells would be reading an unresolved character.
    used = set()
    i = 0
    d = digits.decode()
    while i < len(d):
        width = 2 if d[i] in "14" else 1
        used.add(d[i:i + width])
        i += width
    print(f"\n    note: alphabet has {len(set(CHECKERBOARD_ALPHABET))} distinct of "
          f"{len(CHECKERBOARD_ALPHABET)} positions; '.' cells used by this ciphertext: "
          f"{sorted(c for c in used if checkerboard(c) == '.')}")


if __name__ == "__main__":
    main()
