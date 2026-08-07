"""Execute v79: null calibration for the three recorded post-3.2 opens.

See :mod:`solver.chance_padding_null_calibration_preregister` for the sealed
hypothesis and the five predictions.  Nothing here can accept a prize
candidate; the output is a set of rates.
"""

from __future__ import annotations

import hashlib
import json
import random

from Crypto.Cipher import AES

from .chains import reconstruct
from .extract import extract_all
from .openssl_compat import decrypt_salted_aes256_cbc, encrypt_salted_aes256_cbc
from .salphaseion import derive_tokens
from .secp256k1_verify import base58check
from .chance_padding_null_calibration_preregister import (
    CASCADE_KDFS,
    CASCADE_MENU,
    MANIFEST_PATH,
    PREDICTIONS,
    RECORDED_PADDING_LENGTHS,
    RESULT_PATH,
    SEAL_PATH,
    SEED,
    TRIALS,
    build_manifest,
)


PHASE32_PASSWORD = hashlib.sha256(
    b"jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
).hexdigest().encode("ascii")


def _evp(password: bytes, salt: bytes, digest: str) -> tuple[bytes, bytes]:
    material = bytearray()
    previous = b""
    while len(material) < 48:
        previous = hashlib.new(digest, previous + password + salt).digest()
        material.extend(previous)
    return bytes(material[:32]), bytes(material[32:48])


def _unpad(padded: bytes) -> bytes | None:
    length = padded[-1]
    if not 1 <= length <= 16 or padded[-length:] != bytes([length]) * length:
        return None
    return padded[:-length]


def _open(salt: bytes, ciphertext: bytes, password: bytes, digest: str = "md5") -> bytes | None:
    key, iv = _evp(password, salt, digest)
    return _unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))


def _wif(private_key: bytes, compressed: bool) -> bytes:
    payload = b"\x80" + private_key + (b"\x01" if compressed else b"")
    return base58check(payload).encode("ascii")


def cascade_passwords(plaintext: bytes) -> list[bytes]:
    """The menu in the sealed order; index 0 is the canonical cascade rule."""
    key1, key2, extension = plaintext[:32], plaintext[32:64], plaintext[64:]
    by_name = {
        "wif_key1_uncompressed": _wif(key1, False),
        "wif_key1_compressed": _wif(key1, True),
        "key1_hex": key1.hex().encode("ascii"),
        "key1_raw": key1,
        "key1_sha256_hex": hashlib.sha256(key1).hexdigest().encode("ascii"),
        "wif_key2_uncompressed": _wif(key2, False),
        "wif_key2_compressed": _wif(key2, True),
        "key2_hex": key2.hex().encode("ascii"),
        "key2_raw": key2,
        "key2_sha256_hex": hashlib.sha256(key2).hexdigest().encode("ascii"),
        "extension_raw": extension,
        "plaintext_raw": plaintext,
    }
    return [by_name[name] for name in CASCADE_MENU]


def calibrate(trials: int, seed: int) -> dict[str, object]:
    inputs = extract_all()
    c1_salt, c1_ct = inputs.chain1_envelope[8:16], inputs.chain1_envelope[16:]
    c2_salt, c2_ct = inputs.chain2_envelope[8:16], inputs.chain2_envelope[16:]
    expected_length = len(c1_ct) - 1

    rng = random.Random(seed)
    unpads = 0
    at_expected_length = 0
    single_hits = 0
    menu_hits = 0
    lengths: dict[int, int] = {}

    for _ in range(trials):
        password = rng.randbytes(16).hex().encode("ascii")
        plaintext = _open(c1_salt, c1_ct, password)
        if plaintext is None:
            continue
        unpads += 1
        lengths[len(plaintext)] = lengths.get(len(plaintext), 0) + 1
        if len(plaintext) != expected_length:
            continue
        at_expected_length += 1
        candidates = cascade_passwords(plaintext)
        if _open(c2_salt, c2_ct, candidates[0]) is not None:
            single_hits += 1
        for candidate in candidates:
            if any(_open(c2_salt, c2_ct, candidate, kdf) is not None for kdf in CASCADE_KDFS):
                menu_hits += 1
                break

    denominator = max(at_expected_length, 1)
    return {
        "trials": trials,
        "seed": seed,
        "chain1_unpads": unpads,
        "chain1_unpad_rate": unpads / trials,
        "expected_length": expected_length,
        "unpads_at_expected_length": at_expected_length,
        "len79_share_of_unpads": at_expected_length / max(unpads, 1),
        "plaintext_length_histogram": {str(k): v for k, v in sorted(lengths.items())},
        "cascade_single_rule_hits": single_hits,
        "cascade_single_rule_rate": single_hits / denominator,
        "cascade_menu_hits": menu_hits,
        "cascade_menu_rate": menu_hits / denominator,
    }


def observed_padding_lengths() -> dict[str, int]:
    inputs = extract_all()
    chains = reconstruct(inputs, derive_tokens())
    phase32 = decrypt_salted_aes256_cbc(inputs.phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    return {
        "chain1": chains.chain1_decryption.padding_length,
        "chain2": chains.chain2_decryption.padding_length,
        "cosmic": chains.cosmic_decryption.padding_length,
        "phase32": phase32.padding_length,
    }


def _designed_payload_control() -> dict[str, object]:
    """A payload of an arbitrary designed length does not strip one byte."""
    payload = b"A designed record of no particular length."
    envelope = encrypt_salted_aes256_cbc(payload, b"control-password", b"\x00" * 8)
    decryption = decrypt_salted_aes256_cbc(envelope, b"control-password")
    return {
        "payload_length": len(payload),
        "padding_length": decryption.padding_length,
        "round_trips": decryption.plaintext == payload,
    }


def run(trials: int = TRIALS, seed: int = SEED, write: bool = True) -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("manifest seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    padding = observed_padding_lengths()
    if padding != RECORDED_PADDING_LENGTHS:
        raise ValueError(f"recorded padding lengths drifted: {padding}")

    measured = calibrate(trials, seed)
    checks = {
        "P1_chain1_unpad_rate": measured["chain1_unpad_rate"],
        "P2_len79_share_of_unpads": measured["len79_share_of_unpads"],
        "P3_cascade_single_rule_rate": measured["cascade_single_rule_rate"],
        "P4_cascade_menu_rate": measured["cascade_menu_rate"],
    }
    prediction_results = {}
    null_survives = True
    for name, value in checks.items():
        band = PREDICTIONS[name]
        inside = band["low"] <= value <= band["high"]
        prediction_results[name] = {
            "measured": value,
            "band": [band["low"], band["high"]],
            "analytic": band["analytic"],
            "inside_band": inside,
        }
        null_survives = null_survives and inside
    prediction_results["P5_phase32_padding_not_one"] = {
        "measured": padding["phase32"],
        "inside_band": padding["phase32"] != 1,
    }
    null_survives = null_survives and padding["phase32"] != 1

    result = {
        "schema": manifest["schema"],
        "status": "NULL_SURVIVES" if null_survives else "NULL_REJECTED",
        "scope_note": manifest["scope_note"],
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        "observed_padding_lengths": padding,
        "calibration": measured,
        "predictions": prediction_results,
        "controls": {
            "phase32_legible": decrypt_salted_aes256_cbc(
                extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256"
            ).plaintext.startswith(b"I've been waiting for you."),
            "designed_payload": _designed_payload_control(),
        },
        "conclusion": (
            "The three recorded post-3.2 opens carry no evidential weight. Each "
            "strips exactly one padding byte, which is the signature of a chance "
            "hit; the 79-byte 32+32+15 record is the length that "
            f"{measured['len79_share_of_unpads']:.1%} of chance unpads produce; and "
            "the chain1 to chain2 WIF cascade, cited as proof the link is real, "
            f"arises for {measured['cascade_menu_rate']:.1%} of chance unpads under "
            "the natural serialisation menu. The authenticated phase 3.2 open "
            f"strips {padding['phase32']} bytes by contrast."
        ),
    }
    if write:
        RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({k: output[k] for k in ("status", "calibration", "predictions")}, indent=2))
