"""Shared legibility-gated AES helpers for sealed envelope audits."""

from __future__ import annotations

import hashlib
import math
import re

from Crypto.Cipher import AES

from .openssl_compat import decrypt_salted_aes256_cbc, evp_bytes_to_key, strict_pkcs7_unpad


ENGLISH_RUN = re.compile(rb"[A-Za-z]{6,}")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in b"\t\n\r" or 32 <= b <= 126 for b in data) / len(data)


def legible(data: bytes) -> bool:
    if printable_ratio(data) < 0.85:
        return False
    return entropy(data) <= 5.9 or bool(ENGLISH_RUN.search(data))


def password_bytes(preimage: bytes, form: str) -> bytes:
    if form == "literal":
        return preimage
    digest = hashlib.sha256(preimage).digest()
    if form == "sha256_hex_lower":
        return digest.hex().encode("ascii")
    if form == "sha256_raw32":
        return digest
    raise ValueError(form)


def decrypt_target(
    target: str,
    chain1: bytes,
    env48: bytes,
    raw48: bytes,
    password: bytes,
    digest: str,
) -> bytes | None:
    if target == "chain1":
        try:
            return decrypt_salted_aes256_cbc(chain1, password, digest=digest).plaintext
        except ValueError:
            return None
    if target == "env48":
        try:
            return decrypt_salted_aes256_cbc(env48, password, digest=digest).plaintext
        except ValueError:
            return None
    salt = env48[8:16]
    key, evp_iv = evp_bytes_to_key(password, salt, digest=digest)
    iv = evp_iv if target == "raw48_evp_iv" else env48[32:48]
    try:
        padded = AES.new(key, AES.MODE_CBC, iv).decrypt(raw48)
        plaintext, _ = strict_pkcs7_unpad(padded)
        return plaintext
    except ValueError:
        return None


def xor_extend(left: bytes, right: bytes) -> bytes:
    length = max(len(left), len(right))
    return bytes(left[i % len(left)] ^ right[i % len(right)] for i in range(length))


def add_mod256(left: bytes, right: bytes) -> bytes:
    length = max(len(left), len(right))
    return bytes((left[i % len(left)] + right[i % len(right)]) % 256 for i in range(length))


def interleave_bytes(left: bytes, right: bytes) -> bytes:
    out = bytearray()
    for index in range(max(len(left), len(right))):
        if index < len(left):
            out.append(left[index])
        if index < len(right):
            out.append(right[index])
    return bytes(out)


def pack_bits(bits: str) -> bytes:
    if not bits:
        return b"\0"
    usable = len(bits) // 8 * 8
    if usable == 0:
        return bytes([int(bits.ljust(8, "0"), 2)])
    return bytes(int(bits[i : i + 8], 2) for i in range(0, usable, 8))
