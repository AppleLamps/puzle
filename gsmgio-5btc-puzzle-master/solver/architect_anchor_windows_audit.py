"""Evaluate sealed v63: Architect anchor-window audit."""

from __future__ import annotations

import hashlib
import json

from Crypto.Cipher import AES

from . import targets
from .architect_anchor_windows_preregister import (
    ANCHORS,
    AES_ENVELOPES,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    RAW48_IV_MODES,
    RESULT_PATH,
    SEAL_PATH,
    WINDOWS,
    build_manifest,
    expected_aes_trials,
    expected_scalar_gates,
)
from .extract import extract_all
from .intertwined_password_coherence_audit import _architect_plaintext
from .openssl_compat import decrypt_salted_aes256_cbc, evp_bytes_to_key, strict_pkcs7_unpad
from .phase32_classical import PHASE32_PASSWORD
from .pipeline_operand_split_envelope_audit import _gate_plaintext, _password_bytes
from .salphaseion_split_envelope_preregister import split_envelope


def _windows() -> dict[str, bytes]:
    text = _architect_plaintext()
    if len(text) != 1539:
        raise ValueError("architect length drift")
    if text[472:479] != "TAKETHE" and text[472:479] != "LETAKET"[:7]:
        pass  # LETAKETHE at 472 - check
    if "TAKETHE" not in text[470:480]:
        raise ValueError("TAKETHE anchor drift")
    if text[479:489] != "PRIVATEKEY":
        raise ValueError("PRIVATEKEY anchor drift")
    if text[1010:1016] != "RETURN":
        raise ValueError("RETURN anchor drift")
    if text[1021:1032] != "SOURCECODES":
        raise ValueError("SOURCECODES anchor drift")
    if text[1089:1100] != "REINSERTING":
        raise ValueError("REINSERTING anchor drift")

    take = ANCHORS["TAKETHE"]
    pk = ANCHORS["PRIVATEKEY_FIRST"]
    ret = ANCHORS["RETURN"]
    src = ANCHORS["SOURCECODES"]
    reinsert = ANCHORS["REINSERTING"]

    return {
        "W01_take_through_return": text[take:ret].encode("ascii"),
        "W02_privatekey_through_return": text[pk:ret].encode("ascii"),
        "W03_privatekey_120": text[pk : pk + 120].encode("ascii"),
        "W04_privatekey_60": text[pk : pk + 60].encode("ascii"),
        "W05_return_through_reinsert": text[ret:reinsert].encode("ascii"),
        "W06_sourcecodes_through_reinsert": text[src:reinsert].encode("ascii"),
        "W07_reinsert_120": text[reinsert : reinsert + 120].encode("ascii"),
        "W08_reinsert_60": text[reinsert : reinsert + 60].encode("ascii"),
        "W09_take_through_reinsert": text[take:reinsert].encode("ascii"),
    }


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
    windows = _windows()
    env48, raw48 = split_envelope()
    chain1 = extract_all().chain1_envelope
    blobs = {"chain1": chain1, "env48": env48}
    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")

    aes_results = []
    scalar_results = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches = []

    for window_id in WINDOWS:
        preimage = windows[window_id]
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(preimage).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append({"window_id": window_id, "derivation": derivation, "prize_match": hit})
            if hit:
                prize_matches.append({"kind": "scalar", "window_id": window_id, **hit})

        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for digest in KDF_DIGESTS:
                for target, blob in blobs.items():
                    try:
                        plaintext = decrypt_salted_aes256_cbc(blob, password, digest=digest).plaintext
                    except ValueError:
                        aes_results.append({"window_id": window_id, "target": target, "form": form, "kdf": digest, "padding_valid": False})
                        continue
                    padding_hits += 1
                    gate = _gate_plaintext(plaintext)
                    record = {"window_id": window_id, "target": target, "form": form, "kdf": digest, "padding_valid": True, **gate}
                    if gate["legible"]:
                        legible_outputs += 1
                    if gate["prize_matches"]:
                        prize_matches.extend({"kind": f"aes_{target}", "window_id": window_id, **m} for m in gate["prize_matches"])
                    aes_results.append(record)
                for iv_mode in RAW48_IV_MODES:
                    plaintext = _decrypt_raw48(raw48, env48, password, digest, iv_mode)
                    record = {"window_id": window_id, "target": "raw48", "iv_mode": iv_mode, "form": form, "kdf": digest, "padding_valid": plaintext is not None}
                    if plaintext is None:
                        aes_results.append(record)
                        continue
                    padding_hits += 1
                    gate = _gate_plaintext(plaintext)
                    record.update(gate)
                    if gate["legible"]:
                        legible_outputs += 1
                    if gate["prize_matches"]:
                        prize_matches.extend({"kind": "aes_raw48", "window_id": window_id, **m} for m in gate["prize_matches"])
                    aes_results.append(record)

    if len(aes_results) != expected_aes_trials():
        raise ValueError(f"aes drift {len(aes_results)} != {expected_aes_trials()}")
    if len(scalar_results) != expected_scalar_gates():
        raise ValueError("scalar drift")

    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "window_lengths": {k: len(v) for k, v in windows.items()},
        "controls": {"phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you.")},
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
