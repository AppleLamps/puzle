"""Evaluate sealed v69: chain-1 PBKDF2, sequential layers, and 479 anchors."""

from __future__ import annotations

import hashlib
import json

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from . import targets
from .chain1_pbkdf2_legibility_preregister import (
    ANCHOR_PASSWORD_IDS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    PBKDF2_ITERATIONS,
    PBKDF2_PASSWORD_IDS,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_anchor_trials,
    expected_pbkdf2_trials,
    expected_sequential_paths,
)
from .extract import extract_all
from .openssl_compat import decrypt_salted_aes256_cbc, strict_pkcs7_unpad
from .phase32_classical import BEAUFORT_KEY, PHASE32_PASSWORD, README, _beaufort
from .pipeline_operand_split_envelope_audit import _gate_plaintext, _password_bytes
from .salphaseion import derive_tokens
from .salphaseion_raw import extract_raw


CREATOR_PHRASES = (
    "yellowblueprimes",
    "matrixsumlist",
    "lastwordsbeforearchichoice",
    "yinyang",
    "wewontgiveawaythepassword",
    "itsinfrontofyoureyesbutyourenotseeingit",
    "verylaststepisatruegiveawaypromised",
)


def _architect_plaintext() -> str:
    readme = README.read_text(encoding="utf-8-sig")
    match = __import__("re").search(
        r"- phase 3\.2\.1\s+The first blob.*?converted to letters:\s*\n\s*([a-z]+)",
        readme,
        __import__("re").DOTALL,
    )
    if match is None:
        raise ValueError("published Phase 3.2.1 ciphertext not found")
    return _beaufort(match.group(1), BEAUFORT_KEY)


def _phrase_xor7() -> bytes:
    digests = [hashlib.sha256(p.encode("ascii")).digest() for p in CREATOR_PHRASES]
    return bytes(a ^ b ^ c ^ d ^ e ^ f ^ g for a, b, c, d, e, f, g in zip(*digests))


def _build_passwords() -> dict[str, bytes]:
    raw = extract_raw()
    tokens = derive_tokens().tokens
    architect = _architect_plaintext()
    sha_first = raw.sha_first_hint.encode("ascii")
    sha_answer = raw.sha_answer_too.encode("ascii")
    return {
        "P01_canonical_5token_concat": "".join(tokens[:5]).encode("ascii"),
        "P02_phase32_password": PHASE32_PASSWORD,
        "P03_phrases_all7_concat": "".join(CREATOR_PHRASES).encode("ascii"),
        "P04_phrases_first4_concat": "".join(CREATOR_PHRASES[:4]).encode("ascii"),
        "P05_phrase_yinyang": b"yinyang",
        "P06_sha_first_hint": sha_first,
        "P07_sha_answer_too": sha_answer,
        "P08_salvation": b"salvation",
        "P09_hashthetext": b"HASHTHETEXT",
        "P10_architect_479_33": architect[479:512].encode("ascii"),
        "P11_architect_takethe_privatekey": architect[472:492].encode("ascii"),
        "P12_yellow479blue484": b"yellow479blue484",
        "P13_479479": b"479479",
        "P14_theflowerblossoms": b"theflowerblossomsthroughwhatseemstobeaconcretesurface",
        "P15_enter": b"enter",
        "P16_token_thispassword": b"thispassword",
        "P17_phrase_xor7_digest": _phrase_xor7(),
        "P18_tokens7_hashthetext_sha_answer": b"".join(
            [
                b"matrixsumlist",
                b"enter",
                b"lastwordsbeforearchichoice",
                b"thispassword",
                b"matrixsumlist",
                b"HASHTHETEXT",
                sha_answer,
            ]
        ),
        "A01_479": b"479",
        "A02_484": b"484",
        "A03_479479": b"479479",
        "A04_484479": b"484479",
        "A05_yellow479blue484": b"yellow479blue484",
        "A06_architect_takethe_privatekey": architect[472:492].encode("ascii"),
        "A07_architect_479_33": architect[479:512].encode("ascii"),
    }


def _pbkdf2_decrypt(envelope: bytes, password: bytes, iterations: int) -> bytes | None:
    if envelope[:8] != b"Salted__":
        return None
    salt = envelope[8:16]
    ciphertext = envelope[16:]
    if len(ciphertext) % AES.block_size:
        return None
    key_iv = PBKDF2(password, salt, dkLen=48, count=iterations, hmac_hash_module=SHA256)
    try:
        padded = AES.new(key_iv[:32], AES.MODE_CBC, key_iv[32:48]).decrypt(ciphertext)
        plaintext, _ = strict_pkcs7_unpad(padded)
        return plaintext
    except ValueError:
        return None


def _sequential_layer_decrypt(envelope: bytes, phrases: tuple[str, ...], form: str, kdf: str) -> bytes | None:
    current = envelope
    for phrase in phrases:
        password = _password_bytes(phrase.encode("ascii"), form)
        try:
            plaintext = decrypt_salted_aes256_cbc(current, password, digest=kdf).plaintext
        except ValueError:
            return None
        if plaintext.startswith(b"Salted__") and len(plaintext) >= 32:
            current = plaintext
            continue
        return plaintext
    return None


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    chain1 = extract_all().chain1_envelope
    passwords = _build_passwords()
    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")

    aes_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for pid in PBKDF2_PASSWORD_IDS:
        preimage = passwords[pid]
        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for iterations in PBKDF2_ITERATIONS:
                plaintext = _pbkdf2_decrypt(chain1, password, iterations)
                record = {
                    "family": "pbkdf2",
                    "password_id": pid,
                    "form": form,
                    "iterations": iterations,
                    "padding_valid": plaintext is not None,
                }
                if plaintext is None:
                    aes_results.append(record)
                    continue
                padding_hits += 1
                gate = _gate_plaintext(plaintext)
                record.update(gate)
                if gate["legible"]:
                    legible_outputs += 1
                if gate["prize_matches"]:
                    prize_matches.extend({"family": "pbkdf2", "password_id": pid, **m} for m in gate["prize_matches"])
                aes_results.append(record)

    for pid in ANCHOR_PASSWORD_IDS:
        preimage = passwords[pid]
        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for kdf in ("md5", "sha256"):
                try:
                    plaintext = decrypt_salted_aes256_cbc(chain1, password, digest=kdf).plaintext
                except ValueError:
                    aes_results.append(
                        {
                            "family": "anchor479",
                            "password_id": pid,
                            "form": form,
                            "kdf": kdf,
                            "padding_valid": False,
                        }
                    )
                    continue
                padding_hits += 1
                gate = _gate_plaintext(plaintext)
                record = {
                    "family": "anchor479",
                    "password_id": pid,
                    "form": form,
                    "kdf": kdf,
                    "padding_valid": True,
                    **gate,
                }
                if gate["legible"]:
                    legible_outputs += 1
                if gate["prize_matches"]:
                    prize_matches.extend({"family": "anchor479", "password_id": pid, **m} for m in gate["prize_matches"])
                aes_results.append(record)

    for form in PASSWORD_FORMS:
        for kdf in ("md5", "sha256"):
            plaintext = _sequential_layer_decrypt(chain1, CREATOR_PHRASES, form, kdf)
            record = {
                "family": "sequential7",
                "form": form,
                "kdf": kdf,
                "padding_valid": plaintext is not None,
            }
            if plaintext is None:
                aes_results.append(record)
                continue
            padding_hits += 1
            gate = _gate_plaintext(plaintext)
            record.update(gate)
            if gate["legible"]:
                legible_outputs += 1
            if gate["prize_matches"]:
                prize_matches.extend({"family": "sequential7", **m} for m in gate["prize_matches"])
            aes_results.append(record)

    expected = expected_pbkdf2_trials() + expected_anchor_trials() + expected_sequential_paths()
    if len(aes_results) != expected:
        raise ValueError(f"trial drift: {len(aes_results)} != {expected}")

    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "controls": {
            "phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you."),
        },
        "counts": {
            "aes_trials": len(aes_results),
            "padding_hits": padding_hits,
            "legible_outputs": legible_outputs,
            "prize_matches": len(prize_matches),
        },
        "prize_matches": prize_matches,
        "legible_records": [r for r in aes_results if r.get("legible")],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import json as _json

    print(_json.dumps(run()["counts"], indent=2))
