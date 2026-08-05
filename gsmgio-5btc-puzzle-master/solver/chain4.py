"""Reconstruct the masked embedded OpenSSL layer called Chain 4."""

from __future__ import annotations

from dataclasses import dataclass

from .chains import ChainsResult
from .openssl_compat import OpenSSLDecryption, decrypt_salted_aes256_cbc


MASK = bytes.fromhex("b657264f2f6e6921")


@dataclass(frozen=True)
class Chain4Result:
    trimmed_remainder: bytes
    embedded_envelope: bytes
    password: bytes
    decryption: OpenSSLDecryption
    marker: bytes
    operand: bytes
    opcode: bytes
    opcode_operand: bytes
    blocks: tuple[bytes, ...]
    structured_prefix: bytes
    tail_905: bytes


def reconstruct_chain4(chains: ChainsResult) -> Chain4Result:
    trimmed = chains.cosmic_remainder[:1168]
    embedded = bytes(value ^ MASK[i % len(MASK)] for i, value in enumerate(trimmed))
    password = chains.chain1.extension + chains.chain2.extension + chains.cosmic_b.extension[:2]
    decryption = decrypt_salted_aes256_cbc(embedded, password)
    plaintext = decryption.plaintext
    if len(plaintext) != 1151:
        raise ValueError("unexpected Chain 4 plaintext length")
    marker = plaintext[:2]
    if marker != b"+-":
        raise ValueError("missing Chain 4 '+-' marker")
    # 1151 = 31 + 35*32. The only exact block alignment is byte 31.
    structured_prefix = plaintext[:31]
    operand = plaintext[2:31]
    opcode = plaintext[:1]
    opcode_operand = plaintext[1:31]
    blocks = tuple(plaintext[i : i + 32] for i in range(31, len(plaintext), 32))
    if len(blocks) != 35 or any(len(block) != 32 for block in blocks):
        raise ValueError("Chain 4 block region is malformed")
    return Chain4Result(
        trimmed_remainder=trimmed,
        embedded_envelope=embedded,
        password=password,
        decryption=decryption,
        marker=marker,
        operand=operand,
        opcode=opcode,
        opcode_operand=opcode_operand,
        blocks=blocks,
        structured_prefix=structured_prefix,
        tail_905=plaintext[246:],
    )
