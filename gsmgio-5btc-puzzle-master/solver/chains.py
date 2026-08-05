"""Reconstruct Chains 1-3 and justify their byte-field parsing."""

from __future__ import annotations

from dataclasses import dataclass

from .extract import ExtractedInputs
from .openssl_compat import OpenSSLDecryption, decrypt_salted_aes256_cbc
from .salphaseion import SalPhaseIonResult
from .secp256k1_verify import wif


@dataclass(frozen=True)
class Triplet:
    key1: bytes
    key2: bytes
    extension: bytes


@dataclass(frozen=True)
class ChainsResult:
    chain1_decryption: OpenSSLDecryption
    chain1: Triplet
    chain1_wif: str
    chain2_decryption: OpenSSLDecryption
    chain2: Triplet
    cosmic_decryption: OpenSSLDecryption
    cosmic_b: Triplet
    cosmic_h: Triplet
    cosmic_remainder: bytes


def parse_triplet(plaintext: bytes) -> Triplet:
    if len(plaintext) != 79:
        raise ValueError(f"expected 79-byte 32+32+15 triplet, got {len(plaintext)}")
    return Triplet(plaintext[:32], plaintext[32:64], plaintext[64:79])


def reconstruct(inputs: ExtractedInputs, salphaseion: SalPhaseIonResult) -> ChainsResult:
    chain1_password = "".join(salphaseion.tokens[:5]).encode("ascii")
    chain1_dec = decrypt_salted_aes256_cbc(inputs.chain1_envelope, chain1_password)
    chain1 = parse_triplet(chain1_dec.plaintext)
    chain1_wif = wif(chain1.key1, compressed=False)

    chain2_dec = decrypt_salted_aes256_cbc(inputs.chain2_envelope, chain1_wif.encode("ascii"))
    chain2 = parse_triplet(chain2_dec.plaintext)

    cosmic_dec = decrypt_salted_aes256_cbc(inputs.cosmic_envelope, salphaseion.xor_password)
    if len(cosmic_dec.plaintext) != 1327:
        raise ValueError("unexpected Cosmic plaintext length")
    cosmic_b = parse_triplet(cosmic_dec.plaintext[:79])
    cosmic_h = parse_triplet(cosmic_dec.plaintext[79:158])
    remainder = cosmic_dec.plaintext[158:]
    if len(remainder) != 1169:
        raise ValueError("unexpected Cosmic remainder length")
    return ChainsResult(
        chain1_decryption=chain1_dec,
        chain1=chain1,
        chain1_wif=chain1_wif,
        chain2_decryption=chain2_dec,
        chain2=chain2,
        cosmic_decryption=cosmic_dec,
        cosmic_b=cosmic_b,
        cosmic_h=cosmic_h,
        cosmic_remainder=remainder,
    )

