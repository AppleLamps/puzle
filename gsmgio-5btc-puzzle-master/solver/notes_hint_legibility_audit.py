"""Evaluate sealed v61: NOTES hint legibility audit."""

from __future__ import annotations

import hashlib
import json

from Crypto.Cipher import AES

from . import targets
from .extract import extract_all
from .notes_hint_legibility_preregister import (
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    PHRASES,
    RAW48_IV_MODES,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_aes_trials,
    expected_scalar_gates,
)
from .openssl_compat import decrypt_salted_aes256_cbc, evp_bytes_to_key, strict_pkcs7_unpad
from .phase32_classical import PHASE32_PASSWORD
from .pipeline_operand_split_envelope_audit import _gate_plaintext, _password_bytes
from .salphaseion_split_envelope_preregister import split_envelope


def _decrypt_raw48(
    raw48: bytes,
    env48: bytes,
    password: bytes,
    digest: str,
    iv_mode: str,
) -> bytes | None:
    salt = env48[8:16]
    if iv_mode == "evp_iv":
        key, iv = evp_bytes_to_key(password, salt, digest=digest)
    elif iv_mode == "continuation_iv":
        key, _ = evp_bytes_to_key(password, salt, digest=digest)
        iv = env48[32:48]
    else:
        raise ValueError(iv_mode)
    try:
        padded = AES.new(key, AES.MODE_CBC, iv).decrypt(raw48)
        plaintext, _ = strict_pkcs7_unpad(padded)
        return plaintext
    except ValueError:
        return None


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    env48, raw48 = split_envelope()
    chain1 = extract_all().chain1_envelope
    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")

    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for phrase in PHRASES:
        preimage = phrase.encode("utf-8")
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(preimage).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append({"phrase": phrase, "derivation": derivation, "prize_match": hit})
            if hit is not None:
                prize_matches.append({"kind": "scalar", "phrase": phrase, **hit})

        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for digest in KDF_DIGESTS:
                for target, blob in (("env48", env48), ("chain1", chain1)):
                    try:
                        plaintext = decrypt_salted_aes256_cbc(blob, password, digest=digest).plaintext
                    except ValueError:
                        aes_results.append(
                            {
                                "phrase": phrase,
                                "target": target,
                                "form": form,
                                "kdf": digest,
                                "padding_valid": False,
                            }
                        )
                        continue
                    padding_hits += 1
                    gate = _gate_plaintext(plaintext)
                    record = {
                        "phrase": phrase,
                        "target": target,
                        "form": form,
                        "kdf": digest,
                        "padding_valid": True,
                        **gate,
                    }
                    if gate["legible"]:
                        legible_outputs += 1
                    if gate["prize_matches"]:
                        prize_matches.extend(
                            {"kind": f"aes_{target}", "phrase": phrase, **m} for m in gate["prize_matches"]
                        )
                    aes_results.append(record)

                for iv_mode in RAW48_IV_MODES:
                    plaintext = _decrypt_raw48(raw48, env48, password, digest, iv_mode)
                    record = {
                        "phrase": phrase,
                        "target": "raw48",
                        "iv_mode": iv_mode,
                        "form": form,
                        "kdf": digest,
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
                        prize_matches.extend(
                            {"kind": "aes_raw48", "phrase": phrase, **m} for m in gate["prize_matches"]
                        )
                    aes_results.append(record)

    if len(aes_results) != expected_aes_trials():
        raise ValueError(f"aes drift: {len(aes_results)} != {expected_aes_trials()}")
    if len(scalar_results) != expected_scalar_gates():
        raise ValueError("scalar drift")

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
            "scalar_gates": len(scalar_results),
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
