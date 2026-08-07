"""Seal v67: the ``Salted__`` envelopes under OpenSSL ciphers other than AES-256-CBC.

Every prior audit in this repository decrypted the post-3.2 envelopes with
``aes-256-cbc`` and only varied the password.  That is an assumption, not an
authenticated fact: the ``Salted__`` header is written by ``openssl enc`` for
*every* cipher it supports, and the creator's own Architect instruction speaks
of selecting "FROM OVER TWENTYTHREE CIPHERS SIXTEEN ENCRYPTIONS".

So the cipher itself is a free parameter that was never swept.  If the
five-token chain-1 password is right but the cipher is wrong, the observed
symptom would be exactly what v49 measured: valid padding at the chance rate
and high-entropy, unreadable output.

This manifest freezes the OpenSSL cipher catalogue (the block sizes, key
lengths and modes ``openssl enc`` actually offers, restricted to those
PyCryptodome implements) against the authenticated password set, under both
EVP KDF digests.  Stream modes carry no padding, so they are gated purely on
legibility; block modes must additionally unpad.  Padding is never acceptance.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "openssl_cipher_catalogue_preregistered.json"
SEAL_PATH = ROOT / "openssl_cipher_catalogue_preregistered.sha256"
RESULT_PATH = ROOT / "openssl_cipher_catalogue_audit.json"

KDF_DIGESTS = ("md5", "sha256")
ENVELOPES = ("chain1", "chain2", "cosmic")
CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"

# (cipher_id, algorithm, key_len, iv_len, mode, block_size)
# iv_len 0 means the mode takes no IV; block_size 1 marks a stream cipher whose
# output carries no PKCS#7 padding.
CIPHER_SPECS = (
    ("aes-256-cbc", "AES", 32, 16, "CBC", 16),
    ("aes-192-cbc", "AES", 24, 16, "CBC", 16),
    ("aes-128-cbc", "AES", 16, 16, "CBC", 16),
    ("aes-256-ecb", "AES", 32, 0, "ECB", 16),
    ("aes-192-ecb", "AES", 24, 0, "ECB", 16),
    ("aes-128-ecb", "AES", 16, 0, "ECB", 16),
    ("aes-256-cfb", "AES", 32, 16, "CFB", 1),
    ("aes-192-cfb", "AES", 24, 16, "CFB", 1),
    ("aes-128-cfb", "AES", 16, 16, "CFB", 1),
    ("aes-256-ofb", "AES", 32, 16, "OFB", 1),
    ("aes-128-ofb", "AES", 16, 16, "OFB", 1),
    ("aes-256-ctr", "AES", 32, 16, "CTR", 1),
    ("aes-128-ctr", "AES", 16, 16, "CTR", 1),
    ("des-ede3-cbc", "DES3", 24, 8, "CBC", 8),
    ("des-ede3-ecb", "DES3", 24, 0, "ECB", 8),
    ("des-ede-cbc", "DES3", 16, 8, "CBC", 8),
    ("des-cbc", "DES", 8, 8, "CBC", 8),
    ("des-ecb", "DES", 8, 0, "ECB", 8),
    ("bf-cbc", "Blowfish", 16, 8, "CBC", 8),
    ("bf-ecb", "Blowfish", 16, 0, "ECB", 8),
    ("bf-ofb", "Blowfish", 16, 8, "OFB", 1),
    ("cast5-cbc", "CAST", 16, 8, "CBC", 8),
    ("cast5-ecb", "CAST", 16, 0, "ECB", 8),
    ("rc2-cbc", "ARC2", 16, 8, "CBC", 8),
    ("rc2-ecb", "ARC2", 16, 0, "ECB", 8),
    ("rc4", "ARC4", 16, 0, "STREAM", 1),
    ("rc4-40", "ARC4", 5, 0, "STREAM", 1),
)

# Authenticated / creator-published password material only.
PASSWORD_IDS = (
    "P01_canonical_5token_concat",
    "P02_phase32_password",
    "P03_chain1_wif",
    "P04_phrases_all7_concat",
    "P05_phrases_first4_concat",
    "P06_phrase_yellowblueprimes",
    "P07_phrase_matrixsumlist",
    "P08_phrase_lastwordsbeforearchichoice",
    "P09_phrase_yinyang",
    "P10_phrase_wewontgiveawaythepassword",
    "P11_phrase_itsinfrontofyoureyesbutyourenotseeingit",
    "P12_phrase_verylaststepisatruegiveawaypromised",
    "P13_token_thispassword",
    "P14_token_enter",
    "P15_sha_first_hint",
    "P16_sha_answer_too",
    "P17_hashthetext",
    "P18_salvation",
    "P19_theflowerblossoms",
    "P20_phrase_xor7_digest",
)


def expected_trials() -> int:
    return len(CIPHER_SPECS) * len(PASSWORD_IDS) * len(KDF_DIGESTS) * len(ENVELOPES)


def build_manifest() -> dict[str, object]:
    return {
        "schema": "openssl-cipher-catalogue-v67",
        "status": "SEALED_BEFORE_DECRYPTION",
        "id": "v67_openssl_cipher_catalogue",
        "date": "2026-08-07",
        "hypothesis": (
            "The post-3.2 Salted__ envelopes were produced by an openssl enc "
            "cipher other than aes-256-cbc, so the authenticated password set "
            "yields legible plaintext under a different algorithm or mode."
        ),
        "why_new": (
            "Every prior audit fixed the cipher at aes-256-cbc and varied only "
            "the password. The Salted__ header does not identify the cipher, and "
            "the Architect instruction names 'over twenty-three ciphers'."
        ),
        "cipher_specs": [
            {
                "cipher_id": cid,
                "algorithm": algo,
                "key_len": klen,
                "iv_len": ivlen,
                "mode": mode,
                "block_size": block,
            }
            for cid, algo, klen, ivlen, mode, block in CIPHER_SPECS
        ],
        "password_ids": list(PASSWORD_IDS),
        "envelopes": list(ENVELOPES),
        "kdf_digests": list(KDF_DIGESTS),
        "expected_counts": {"decryption_trials": expected_trials()},
        "acceptance": (
            "Legible plaintext (printable_ratio>=0.85 and entropy<=5.9, or an "
            "English run of >=6 letters) or a 32-byte window gating to a prize "
            "target. Block modes must also unpad; padding alone is never "
            "acceptance."
        ),
        "controls": [
            "aes-256-cbc + canonical 5-token password + md5 must reproduce the "
            "pinned 79-byte chain-1 plaintext",
            "phase 3.2 envelope under its authenticated password must be legible",
            "a planted control scalar must be accepted by the gate under an "
            "overridden target and rejected by the production gate",
        ],
        "scope_note": (
            "Closes the PyCryptodome-implementable subset of the openssl enc "
            "cipher catalogue against twenty authenticated passwords on "
            "chain1/chain2/cosmic under EVP MD5 and SHA-256. It does not test "
            "Camellia, SEED, GOST or IDEA (unavailable), non-EVP KDFs such as "
            "PBKDF2, or passwords outside the frozen list."
        ),
        "control_scalar_hex": CONTROL_SCALAR_HEX,
        "targets": {
            "half_uncompressed_pubkey": HALF_PUBLIC_UNCOMPRESSED.hex(),
            "better_half_hash160": BETTER_H160.hex(),
        },
    }


def seal() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")


if __name__ == "__main__":
    seal()
    print(f"sealed {MANIFEST_PATH.name}")
