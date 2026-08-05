#!/usr/bin/env python3
"""Extract and decode what is readable in GSMG puzzle phases 2 and 3.

Phase 2 lives at gsmg.io/choiceisanillusion...iwroteitmyself and phase 3 at
gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32 — that
slug is a sha-256 digest, which is exactly what phase 2 says its answer is
("parts 1..7 --> sha-256 -> dgst is the password to enter Phase 3").

Both pages carry `openssl enc -aes-256-cbc -a` blobs. This pulls them out,
decodes the parts of phase 3's "SalPhaseIon" stream that are readable without a
key, and runs a candidate passphrase sweep against every blob.
"""

import base64
import hashlib
import re

from Crypto.Cipher import AES

PHASE2_HTML = "GSMG Puzzle3 - phase2.html"
PHASE3_HTML = "GSMG Puzzle4 - phase3 salphaseion.html"

PHASE2_DIGEST = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"


def textareas(path):
    html = open(path, encoding="utf-8", errors="replace").read()
    return ["".join(t.split()) for t in re.findall(r"<textarea[^>]*>([\s\S]*?)</textarea>", html)]


def describe(name, b64):
    blob = base64.b64decode(b64)
    assert blob[:8] == b"Salted__", name
    print(f"  {name:22} {len(blob):5} bytes  salt={blob[8:16].hex()}  ciphertext={len(blob) - 16}")
    return blob


def bits_to_bytes(run, zero="a"):
    bits = "".join("0" if c == zero else "1" for c in run)
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits) // 8 * 8, 8))


def decode_salphaseion(stream):
    """The stream is digits (a..i = 1..9, o = 0) with runs of pure a/b hiding ASCII."""
    literal = stream.find("shabefour")
    head, tail = stream[:literal], stream[literal:]

    print("\nSalPhaseIon stream")
    print(f"  total {len(stream)} chars; digit head {len(head)}; literal tail {len(tail)}")

    for match in re.finditer(r"[ab]{16,}", head):
        print(f"  hidden binary at offset {match.start()}: {bits_to_bytes(match.group())!r}")

    digits = {c: str(n) for n, c in enumerate("abcdefghi", 1)}
    digits["o"] = "0"
    segments, current = [], ""
    for ch in head:
        if ch == "z":
            segments.append(current)
            current = ""
        elif ch in digits:
            current += digits[ch]
    segments.append(current)
    print("  z-separated digit segments (a..i = 1..9, o = 0):")
    for i, seg in enumerate(s for s in segments if s):
        print(f"    seg{i} ({len(seg)}): {seg}")

    parsed = re.match(
        r"shabefour(.*?)(U2FsdGVkX18[A-Za-z0-9+/=]*?)([ab]{20,})([A-Za-z0-9+/=]+?)shabefanstoo", tail
    )
    hint, first, run, second = parsed.groups()
    print(f"  literal hint: {hint!r}")
    print(f"  a/b run between the two base64 halves decodes to {bits_to_bytes(run)!r}")
    return first + second


def evp_bytes_to_key(passphrase, salt, digest, key_len=32, iv_len=16):
    data, block = b"", b""
    while len(data) < key_len + iv_len:
        block = hashlib.new(digest, block + passphrase + salt).digest()
        data += block
    return data[:key_len], data[key_len : key_len + iv_len]


def sweep(blob, words):
    salt, ciphertext = blob[8:16], blob[16:]
    for word in words:
        forms = (
            ("raw", word.encode()),
            ("sha256hex", hashlib.sha256(word.encode()).hexdigest().encode()),
            ("sha256raw", hashlib.sha256(word.encode()).digest()),
        )
        for label, passphrase in forms:
            for digest in ("md5", "sha256", "sha1"):
                key, iv = evp_bytes_to_key(passphrase, salt, digest)
                plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
                pad = plain[-1]
                if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
                    continue
                body = plain[:-pad]
                if sum(32 <= b < 127 or b in (9, 10, 13) for b in body) >= len(body) * 0.9:
                    return word, label, digest, body
    return None


CANDIDATES = [
    PHASE2_DIGEST,
    PHASE2_DIGEST.upper(),
    "matrixsumlist",
    "enter",
    "salphaseion",
    "cosmicduality",
    "theseedisplanted",
    "cryptologicwarningcanyoudigit",
    "keymaker",
    "theprivatekeymaker",
    "11110",
]


def main():
    print("ciphertexts")
    phase2_blob, phase3_blob = (describe(n, b) for n, b in zip(
        ("phase 2 (keymaker)", "phase 3 (from page 2)"), textareas(PHASE2_HTML)))
    stream, cosmic_b64 = textareas(PHASE3_HTML)
    cosmic_blob = describe("cosmic duality", cosmic_b64)

    embedded_b64 = decode_salphaseion(stream)
    embedded_blob = describe("embedded in stream", embedded_b64)

    print("\npassphrase sweep")
    for name, blob in (
        ("phase 2 (keymaker)", phase2_blob),
        ("phase 3 (from page 2)", phase3_blob),
        ("cosmic duality", cosmic_blob),
        ("embedded in stream", embedded_blob),
    ):
        hit = sweep(blob, CANDIDATES)
        print(f"  {name:22} {'HIT ' + repr(hit) if hit else 'no hit'}")


if __name__ == "__main__":
    main()
