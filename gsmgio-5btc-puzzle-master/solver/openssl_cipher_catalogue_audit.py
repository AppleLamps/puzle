"""Evaluate sealed v67: the Salted__ envelopes under the openssl enc cipher catalogue."""

from __future__ import annotations

import hashlib
import json

from Crypto.Cipher import AES, ARC2, ARC4, CAST, DES, DES3, Blowfish
from Crypto.Util import Counter

from . import targets
from .extract import extract_all
from .openssl_cipher_catalogue_preregister import (
    CIPHER_SPECS,
    ENVELOPES,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_IDS,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_trials,
)
from .openssl_compat import decrypt_salted_aes256_cbc, strict_pkcs7_unpad
from .phase32_classical import PHASE32_PASSWORD
from .pipeline_operand_split_envelope_audit import _entropy, _legible, _printable_ratio
from .salphaseion import derive_tokens
from .salphaseion_raw import extract_raw
from .secp256k1_verify import wif


ALGORITHMS = {
    "AES": AES,
    "DES3": DES3,
    "DES": DES,
    "Blowfish": Blowfish,
    "CAST": CAST,
    "ARC2": ARC2,
    "ARC4": ARC4,
}

CHAIN1_PLAINTEXT_SHA256 = "1449a2178eea7c0e3fabac8c1ad2afa294be4fc1800c594a025a056e88c626bf"

CREATOR_PHRASES = (
    "yellowblueprimes",
    "matrixsumlist",
    "lastwordsbeforearchichoice",
    "yinyang",
    "wewontgiveawaythepassword",
    "itsinfrontofyoureyesbutyourenotseeingit",
    "verylaststepisatruegiveawaypromised",
)


def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int, digest: str):
    """OpenSSL's historical KDF, generalised to any key and IV length."""
    material = bytearray()
    previous = b""
    while len(material) < key_len + iv_len:
        previous = hashlib.new(digest, previous + password + salt).digest()
        material.extend(previous)
    return bytes(material[:key_len]), bytes(material[key_len : key_len + iv_len])


def _new_cipher(algo: str, mode: str, key: bytes, iv: bytes):
    module = ALGORITHMS[algo]
    if algo == "ARC4":
        return module.new(key)
    if mode == "ECB":
        return module.new(key, module.MODE_ECB)
    if mode == "CBC":
        return module.new(key, module.MODE_CBC, iv)
    if mode == "CFB":
        return module.new(key, module.MODE_CFB, iv, segment_size=8)
    if mode == "OFB":
        return module.new(key, module.MODE_OFB, iv)
    if mode == "CTR":
        counter = Counter.new(len(iv) * 8, initial_value=int.from_bytes(iv, "big"))
        return module.new(key, module.MODE_CTR, counter=counter)
    raise ValueError(mode)


def _build_passwords() -> dict[str, bytes]:
    raw = extract_raw()
    tokens = derive_tokens().tokens
    inputs = extract_all()
    canonical = "".join(tokens[:5]).encode("ascii")
    chain1_plaintext = decrypt_salted_aes256_cbc(inputs.chain1_envelope, canonical).plaintext
    if hashlib.sha256(chain1_plaintext).hexdigest() != CHAIN1_PLAINTEXT_SHA256:
        raise ValueError("chain-1 canonical plaintext drift")
    chain1_wif = wif(chain1_plaintext[:32], compressed=False)
    digests = [hashlib.sha256(p.encode("ascii")).digest() for p in CREATOR_PHRASES]
    xor7 = bytes(a ^ b ^ c ^ d ^ e ^ f ^ g for a, b, c, d, e, f, g in zip(*digests))
    return {
        "P01_canonical_5token_concat": canonical,
        "P02_phase32_password": PHASE32_PASSWORD,
        "P03_chain1_wif": chain1_wif.encode("ascii"),
        "P04_phrases_all7_concat": "".join(CREATOR_PHRASES).encode("ascii"),
        "P05_phrases_first4_concat": "".join(CREATOR_PHRASES[:4]).encode("ascii"),
        "P06_phrase_yellowblueprimes": b"yellowblueprimes",
        "P07_phrase_matrixsumlist": b"matrixsumlist",
        "P08_phrase_lastwordsbeforearchichoice": b"lastwordsbeforearchichoice",
        "P09_phrase_yinyang": b"yinyang",
        "P10_phrase_wewontgiveawaythepassword": b"wewontgiveawaythepassword",
        "P11_phrase_itsinfrontofyoureyesbutyourenotseeingit": b"itsinfrontofyoureyesbutyourenotseeingit",
        "P12_phrase_verylaststepisatruegiveawaypromised": b"verylaststepisatruegiveawaypromised",
        "P13_token_thispassword": b"thispassword",
        "P14_token_enter": b"enter",
        "P15_sha_first_hint": raw.sha_first_hint.encode("ascii"),
        "P16_sha_answer_too": raw.sha_answer_too.encode("ascii"),
        "P17_hashthetext": b"HASHTHETEXT",
        "P18_salvation": b"salvation",
        "P19_theflowerblossoms": b"theflowerblossomsthroughwhatseemstobeaconcretesurface",
        "P20_phrase_xor7_digest": xor7,
    }


def _gate_windows(plaintext: bytes) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    for offset in range(0, max(0, len(plaintext) - 31)):
        hit = targets.gate_scalar_bytes(plaintext[offset : offset + 32])
        if hit is not None:
            matches.append({"offset": offset, **hit})
    return matches


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    inputs = extract_all()
    envelopes = {
        "chain1": inputs.chain1_envelope,
        "chain2": inputs.chain2_envelope,
        "cosmic": inputs.cosmic_envelope,
    }
    passwords = _build_passwords()
    for pid in PASSWORD_IDS:
        if pid not in passwords:
            raise ValueError(f"missing password {pid}")

    phase32 = decrypt_salted_aes256_cbc(inputs.phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    scalar = int(manifest["control_scalar_hex"], 16)
    x, y = targets._public_point(scalar)
    planted = targets.gate_point(x, y, half_public=targets.serializations(x, y)["uncompressed"])

    trials = 0
    padding_hits = 0
    legible_records: list[dict[str, object]] = []
    prize_matches: list[dict[str, object]] = []
    per_cipher: dict[str, dict[str, int]] = {}
    control_reproduced = False

    for cipher_id, algo, key_len, iv_len, mode, block_size in CIPHER_SPECS:
        stats = per_cipher.setdefault(cipher_id, {"trials": 0, "padding_hits": 0, "legible": 0})
        for envelope_name in ENVELOPES:
            envelope = envelopes[envelope_name]
            salt = envelope[8:16]
            body = envelope[16:]
            for pid in PASSWORD_IDS:
                password = passwords[pid]
                for kdf in KDF_DIGESTS:
                    trials += 1
                    stats["trials"] += 1
                    key, iv = evp_bytes_to_key(password, salt, key_len, iv_len, kdf)
                    if block_size > 1 and len(body) % block_size:
                        continue
                    try:
                        cipher = _new_cipher(algo, mode, key, iv)
                        raw_out = cipher.decrypt(body)
                    except ValueError:
                        continue
                    if block_size > 1:
                        try:
                            plaintext, _ = strict_pkcs7_unpad(raw_out, block_size)
                        except ValueError:
                            continue
                        padding_hits += 1
                        stats["padding_hits"] += 1
                    else:
                        plaintext = raw_out

                    if (
                        cipher_id == "aes-256-cbc"
                        and envelope_name == "chain1"
                        and pid == "P01_canonical_5token_concat"
                        and kdf == "md5"
                    ):
                        control_reproduced = (
                            hashlib.sha256(plaintext).hexdigest() == CHAIN1_PLAINTEXT_SHA256
                        )

                    window_hits = _gate_windows(plaintext)
                    if window_hits:
                        prize_matches.extend(
                            {
                                "cipher_id": cipher_id,
                                "envelope": envelope_name,
                                "password_id": pid,
                                "kdf": kdf,
                                **hit,
                            }
                            for hit in window_hits
                        )
                    if _legible(plaintext):
                        stats["legible"] += 1
                        legible_records.append(
                            {
                                "cipher_id": cipher_id,
                                "envelope": envelope_name,
                                "password_id": pid,
                                "kdf": kdf,
                                "length": len(plaintext),
                                "entropy_bits_per_byte": _entropy(plaintext),
                                "printable_ratio": _printable_ratio(plaintext),
                                "opening_bytes_repr": repr(plaintext[:64]),
                                "sha256": hashlib.sha256(plaintext).hexdigest(),
                            }
                        )

    if trials != expected_trials():
        raise ValueError(f"trial drift: {trials} != {expected_trials()}")

    status = "COMPLETE_NO_MATCH" if not prize_matches and not legible_records else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "controls": {
            "aes256cbc_canonical_reproduces_pinned_chain1": control_reproduced,
            "phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you."),
            "planted_scalar_accepted": planted is not None,
            "production_rejects_control_scalar": targets.gate_scalar_bytes(
                bytes.fromhex(manifest["control_scalar_hex"])
            )
            is None,
        },
        "counts": {
            "decryption_trials": trials,
            "padding_hits": padding_hits,
            "legible_outputs": len(legible_records),
            "prize_matches": len(prize_matches),
        },
        "per_cipher": per_cipher,
        "prize_matches": prize_matches,
        "legible_records": legible_records,
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import json as _json

    output = run()
    print(_json.dumps({"status": output["status"], **output["counts"]}, indent=2))
