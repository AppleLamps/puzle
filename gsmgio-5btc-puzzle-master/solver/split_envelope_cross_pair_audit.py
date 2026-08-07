"""Evaluate sealed v65: split-envelope cross-half and paired operands."""

from __future__ import annotations

import hashlib
import json

from Crypto.Cipher import AES

from . import targets
from .extract import extract_all
from .openssl_compat import decrypt_salted_aes256_cbc, evp_bytes_to_key, strict_pkcs7_unpad
from .phase32_classical import PHASE32_PASSWORD
from .pipeline_operand_split_envelope_audit import _build_operands, _gate_plaintext, _password_bytes
from .salphaseion_split_envelope_preregister import split_envelope
from .split_envelope_cross_pair_preregister import (
    CONCAT_ORDERS,
    ENV48_OPERAND_IDS,
    FROZEN_PAIRS,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    RAW48_IV_MODES,
    RAW48_OPERAND_IDS,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_cross_aes,
    expected_pair_aes,
    expected_scalar_gates,
)


def _decrypt_raw48(raw48, env48, password, digest, iv_mode):
    salt = env48[8:16]
    if iv_mode == "evp_iv":
        key, iv = evp_bytes_to_key(password, salt, digest=digest)
    else:
        key, _ = evp_bytes_to_key(password, salt, digest=digest)
        iv = env48[32:48]
    try:
        padded = AES.new(key, AES.MODE_CBC, iv).decrypt(raw48)
        plaintext, _ = strict_pkcs7_unpad(padded)
        return plaintext
    except ValueError:
        return None


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    operands = _build_operands()
    env48, raw48 = split_envelope()
    chain1 = extract_all().chain1_envelope
    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")

    aes_results = []
    scalar_results = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches = []

    # Part A: cross-half
    for operand_id in ENV48_OPERAND_IDS:
        preimage = operands[operand_id]
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(preimage).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append({"part": "cross", "operand_id": operand_id, "derivation": derivation, "prize_match": hit})
            if hit:
                prize_matches.append({"kind": "scalar", "operand_id": operand_id, **hit})
        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for digest in KDF_DIGESTS:
                for iv_mode in RAW48_IV_MODES:
                    plaintext = _decrypt_raw48(raw48, env48, password, digest, iv_mode)
                    record = {"part": "cross_env_on_raw", "operand_id": operand_id, "iv_mode": iv_mode, "form": form, "kdf": digest, "padding_valid": plaintext is not None}
                    if plaintext is None:
                        aes_results.append(record)
                        continue
                    padding_hits += 1
                    gate = _gate_plaintext(plaintext)
                    record.update(gate)
                    if gate["legible"]:
                        legible_outputs += 1
                    if gate["prize_matches"]:
                        prize_matches.extend({"kind": "aes_raw48_cross", "operand_id": operand_id, **m} for m in gate["prize_matches"])
                    aes_results.append(record)

    for operand_id in RAW48_OPERAND_IDS:
        preimage = operands[operand_id]
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(preimage).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append({"part": "cross", "operand_id": operand_id, "derivation": derivation, "prize_match": hit})
            if hit:
                prize_matches.append({"kind": "scalar", "operand_id": operand_id, **hit})
        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for digest in KDF_DIGESTS:
                try:
                    plaintext = decrypt_salted_aes256_cbc(env48, password, digest=digest).plaintext
                except ValueError:
                    aes_results.append({"part": "cross_raw_on_env", "operand_id": operand_id, "form": form, "kdf": digest, "padding_valid": False})
                    continue
                padding_hits += 1
                gate = _gate_plaintext(plaintext)
                record = {"part": "cross_raw_on_env", "operand_id": operand_id, "form": form, "kdf": digest, "padding_valid": True, **gate}
                if gate["legible"]:
                    legible_outputs += 1
                if gate["prize_matches"]:
                    prize_matches.extend({"kind": "aes_env48_cross", "operand_id": operand_id, **m} for m in gate["prize_matches"])
                aes_results.append(record)

    cross_count = len(aes_results)

    # Part B: frozen pairs on chain1
    for env_id, raw_id in FROZEN_PAIRS:
        env_bytes = operands[env_id]
        raw_bytes = operands[raw_id]
        for order in CONCAT_ORDERS:
            preimage = env_bytes + raw_bytes if order == "env_then_raw" else raw_bytes + env_bytes
            for derivation in ("sha256", "double_sha256"):
                digest = hashlib.sha256(preimage).digest()
                if derivation == "double_sha256":
                    digest = hashlib.sha256(digest).digest()
                hit = targets.gate_scalar_bytes(digest)
                scalar_results.append({"part": "pair", "env_id": env_id, "raw_id": raw_id, "order": order, "derivation": derivation, "prize_match": hit})
                if hit:
                    prize_matches.append({"kind": "scalar_pair", "env_id": env_id, "raw_id": raw_id, **hit})
            for form in PASSWORD_FORMS:
                password = _password_bytes(preimage, form)
                for digest in KDF_DIGESTS:
                    try:
                        plaintext = decrypt_salted_aes256_cbc(chain1, password, digest=digest).plaintext
                    except ValueError:
                        aes_results.append({"part": "pair_chain1", "env_id": env_id, "raw_id": raw_id, "order": order, "form": form, "kdf": digest, "padding_valid": False})
                        continue
                    padding_hits += 1
                    gate = _gate_plaintext(plaintext)
                    record = {"part": "pair_chain1", "env_id": env_id, "raw_id": raw_id, "order": order, "form": form, "kdf": digest, "padding_valid": True, **gate}
                    if gate["legible"]:
                        legible_outputs += 1
                    if gate["prize_matches"]:
                        prize_matches.extend({"kind": "aes_chain1_pair", "env_id": env_id, "raw_id": raw_id, **m} for m in gate["prize_matches"])
                    aes_results.append(record)

    if cross_count != expected_cross_aes():
        raise ValueError(f"cross aes drift {cross_count} != {expected_cross_aes()}")
    if len(aes_results) - cross_count != expected_pair_aes():
        raise ValueError("pair aes drift")
    if len(scalar_results) != expected_scalar_gates():
        raise ValueError(f"scalar drift {len(scalar_results)} != {expected_scalar_gates()}")

    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "controls": {"phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you.")},
        "counts": {
            "cross_aes_trials": cross_count,
            "pair_chain1_aes_trials": len(aes_results) - cross_count,
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
