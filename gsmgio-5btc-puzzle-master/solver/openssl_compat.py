"""Strict compatibility helpers for legacy ``openssl enc`` envelopes."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from Crypto.Cipher import AES


@dataclass(frozen=True)
class OpenSSLDecryption:
    envelope: bytes
    salt: bytes
    ciphertext: bytes
    password: bytes
    key: bytes
    iv: bytes
    padded_plaintext: bytes
    plaintext: bytes
    padding_length: int
    kdf_digest: str


def decode_base64_envelope(value: str) -> bytes:
    compact = "".join(value.split())
    try:
        envelope = base64.b64decode(compact, validate=True)
    except Exception as exc:  # binascii.Error differs slightly by Python version
        raise ValueError("invalid base64 OpenSSL envelope") from exc
    validate_envelope(envelope)
    return envelope


def validate_envelope(envelope: bytes) -> None:
    if len(envelope) < 32:
        raise ValueError("OpenSSL envelope is too short")
    if envelope[:8] != b"Salted__":
        raise ValueError("missing OpenSSL Salted__ header")
    if (len(envelope) - 16) % AES.block_size:
        raise ValueError("ciphertext is not AES block aligned")


def evp_bytes_to_key(password: bytes, salt: bytes, digest: str = "md5") -> tuple[bytes, bytes]:
    """Derive an AES-256 key and CBC IV using OpenSSL's historical KDF."""

    if len(salt) != 8:
        raise ValueError("EVP_BytesToKey OpenSSL salt must be exactly 8 bytes")
    material = bytearray()
    previous = b""
    while len(material) < 48:
        previous = hashlib.new(digest, previous + password + salt).digest()
        material.extend(previous)
    return bytes(material[:32]), bytes(material[32:48])


def evp_bytes_to_key_md5(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Derive using the pre-OpenSSL-1.1.0 MD5 default."""

    return evp_bytes_to_key(password, salt, "md5")


def strict_pkcs7_unpad(padded: bytes, block_size: int = AES.block_size) -> tuple[bytes, int]:
    if not padded or len(padded) % block_size:
        raise ValueError("padded plaintext is not block aligned")
    padding_length = padded[-1]
    if not 1 <= padding_length <= block_size:
        raise ValueError("invalid PKCS#7 padding length")
    if padded[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("invalid PKCS#7 padding bytes")
    return padded[:-padding_length], padding_length


def decrypt_salted_aes256_cbc(
    envelope: bytes, password: bytes, *, digest: str = "md5"
) -> OpenSSLDecryption:
    validate_envelope(envelope)
    salt = envelope[8:16]
    ciphertext = envelope[16:]
    key, iv = evp_bytes_to_key(password, salt, digest)
    padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    plaintext, padding_length = strict_pkcs7_unpad(padded)
    return OpenSSLDecryption(
        envelope=envelope,
        salt=salt,
        ciphertext=ciphertext,
        password=password,
        key=key,
        iv=iv,
        padded_plaintext=padded,
        plaintext=plaintext,
        padding_length=padding_length,
        kdf_digest=digest,
    )


def pkcs7_pad(plaintext: bytes, block_size: int = AES.block_size) -> bytes:
    padding_length = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_length]) * padding_length


def encrypt_salted_aes256_cbc(
    plaintext: bytes, password: bytes, salt: bytes, *, digest: str = "md5"
) -> bytes:
    key, iv = evp_bytes_to_key(password, salt, digest)
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(plaintext))
    return b"Salted__" + salt + ciphertext
