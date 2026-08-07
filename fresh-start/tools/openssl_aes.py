"""OpenSSL `enc -aes-256-cbc -a` compatible decryption.

Every encrypted payload in this puzzle is an OpenSSL "salted" envelope: the
plaintext bytes `Salted__`, then an 8-byte salt, then AES-256-CBC ciphertext,
Base64 armoured. The key and IV come from `EVP_BytesToKey`, which is a simple
iterated digest of (previous block || password || salt).

The digest matters. OpenSSL 1.0.x defaulted to MD5, 1.1.0+ defaults to SHA-256.
Both appear in this puzzle's stages, so callers pass the digest explicitly and
`try_digests` sweeps the plausible ones.

Only the standard library and the sibling `aes` module are used, so this file
runs on a bare Python 3 install and depends on nothing outside this folder.
"""

from __future__ import annotations

import base64
import hashlib
import re

from aes import cbc_decrypt

MAGIC = b"Salted__"


def unarmour(text: str) -> bytes:
    """Decode Base64 armour, tolerating whitespace and surrounding markup text."""
    packed = "".join(text.split())
    return base64.b64decode(packed)


def evp_bytes_to_key(password: bytes, salt: bytes, digest: str,
                     key_len: int = 32, iv_len: int = 16) -> tuple[bytes, bytes]:
    data, block = b"", b""
    while len(data) < key_len + iv_len:
        block = hashlib.new(digest, block + password + salt).digest()
        data += block
    return data[:key_len], data[key_len:key_len + iv_len]


def _unpad(plain: bytes) -> bytes | None:
    """Strip PKCS#7 padding, or return None if the padding is invalid.

    Valid padding is NOT evidence that the password is right — with a large
    enough candidate space it arises by chance roughly 1 time in 256. Treat it
    only as a cheap filter, never as a result.
    """
    if not plain:
        return None
    pad = plain[-1]
    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
        return None
    return plain[:-pad]


def decrypt(blob: bytes, password: bytes, digest: str = "sha256") -> bytes | None:
    """Decrypt one `Salted__` envelope. Returns None on invalid padding."""
    if blob[:8] != MAGIC:
        raise ValueError("not an OpenSSL salted envelope")
    salt, ciphertext = blob[8:16], blob[16:]
    key, iv = evp_bytes_to_key(password, salt, digest)
    return _unpad(cbc_decrypt(key, iv, ciphertext))


def try_digests(blob: bytes, password: bytes,
                digests: tuple[str, ...] = ("md5", "sha256", "sha1")) -> tuple[str, bytes] | None:
    """Return (digest, plaintext) for the first digest that unpads cleanly."""
    for digest in digests:
        plain = decrypt(blob, password, digest)
        if plain is not None:
            return digest, plain
    return None


def sha256_hex(text: str) -> bytes:
    """The password form this puzzle uses: 64 ASCII hex characters, not 32 raw bytes."""
    return hashlib.sha256(text.encode()).hexdigest().encode()


def find_envelopes(html: str) -> list[str]:
    """Every Base64 `Salted__` blob in a page or plaintext, in document order."""
    return [
        "".join(m.group(0).split())
        for m in re.finditer(r"U2FsdGVkX1[A-Za-z0-9+/=\s]{20,}", html)
    ]
