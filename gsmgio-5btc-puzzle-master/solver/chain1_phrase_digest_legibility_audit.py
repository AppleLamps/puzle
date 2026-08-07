"""Evaluate sealed v66: chain-1 phrase-digest construction legibility audit."""

from __future__ import annotations

import hashlib
import json

from . import targets
from .chain1_phrase_digest_legibility_preregister import (
    CONSTRUCTION_IDS,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    RESULT_PATH,
    SEAL_PATH,
    build_constructions,
    build_manifest,
    expected_aes_trials,
    expected_scalar_gates,
)
from .extract import extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import PHASE32_PASSWORD
from .pipeline_operand_split_envelope_audit import _gate_plaintext, _password_bytes


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    chain1 = extract_all().chain1_envelope
    constructions = build_constructions()
    for cid in CONSTRUCTION_IDS:
        if cid not in constructions:
            raise ValueError(f"missing construction {cid}")

    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    scalar = int(manifest["control_scalar_hex"], 16)
    x, y = targets._public_point(scalar)
    planted = targets.gate_point(x, y, half_public=targets.serializations(x, y)["uncompressed"])

    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for cid in CONSTRUCTION_IDS:
        preimage = constructions[cid]
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(preimage).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append(
                {"construction_id": cid, "derivation": derivation, "prize_match": hit}
            )
            if hit is not None:
                prize_matches.append({"kind": "scalar", "construction_id": cid, **hit})

        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for digest in KDF_DIGESTS:
                try:
                    plaintext = decrypt_salted_aes256_cbc(chain1, password, digest=digest).plaintext
                except ValueError:
                    aes_results.append(
                        {
                            "construction_id": cid,
                            "form": form,
                            "kdf": digest,
                            "padding_valid": False,
                        }
                    )
                    continue
                padding_hits += 1
                gate = _gate_plaintext(plaintext)
                record = {
                    "construction_id": cid,
                    "form": form,
                    "kdf": digest,
                    "padding_valid": True,
                    **gate,
                }
                if gate["legible"]:
                    legible_outputs += 1
                if gate["prize_matches"]:
                    prize_matches.extend(
                        {"kind": "aes_chain1", "construction_id": cid, **match}
                        for match in gate["prize_matches"]
                    )
                aes_results.append(record)

    if len(aes_results) != expected_aes_trials():
        raise ValueError(f"aes trial drift: {len(aes_results)} != {expected_aes_trials()}")
    if len(scalar_results) != expected_scalar_gates():
        raise ValueError("scalar gate drift")

    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "controls": {
            "phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you."),
            "planted_scalar_accepted": planted is not None,
            "production_rejects_control_scalar": targets.gate_scalar_bytes(
                bytes.fromhex(manifest["control_scalar_hex"])
            )
            is None,
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
