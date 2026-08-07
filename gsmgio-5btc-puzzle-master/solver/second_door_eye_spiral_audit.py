"""Evaluate sealed v62: second-door eye spiral bit-operation audit."""

from __future__ import annotations

import hashlib
import json

from . import targets
from .extract import extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import PHASE32_PASSWORD
from .pipeline_operand_split_envelope_audit import _gate_plaintext, _password_bytes
from .salphaseion_split_envelope_preregister import split_envelope
from .second_door_eye_spiral_preregister import (
    BIT_EDITS,
    EYE_SPIRAL_INDEX,
    ENVELOPES,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PARTNER_SPIRAL_INDEX,
    PASSWORD_FORMS,
    RESULT_PATH,
    SEAL_PATH,
    SERIALIZATIONS,
    build_manifest,
    expected_aes_trials,
    expected_scalar_gates,
)
from .second_door_yellowblueprimes_audit import (
    BLACK,
    BLUE,
    FALLBACK_IMAGE,
    IMAGE,
    URL,
    _majority_grid,
    _spiral_positions,
)


def _body_bits() -> str:
    grid = _majority_grid(IMAGE if IMAGE.exists() else FALLBACK_IMAGE)
    order = _spiral_positions(14)
    colours = [grid[row][col] for row, col in order]
    return "".join("1" if colour in (BLACK, BLUE) else "0" for colour in colours)


def _apply_edit(bits: str, edit: str) -> str:
    if len(bits) != 196:
        raise ValueError("expected 196 spiral bits")
    chars = list(bits)
    if edit == "baseline_body196":
        return bits
    if edit == "flip_bit_163":
        chars[EYE_SPIRAL_INDEX] = "0" if chars[EYE_SPIRAL_INDEX] == "1" else "1"
    elif edit == "swap_bits_163_173":
        chars[EYE_SPIRAL_INDEX], chars[PARTNER_SPIRAL_INDEX] = (
            chars[PARTNER_SPIRAL_INDEX],
            chars[EYE_SPIRAL_INDEX],
        )
    elif edit == "force_bit_163_one":
        chars[EYE_SPIRAL_INDEX] = "1"
    elif edit == "force_bit_163_zero":
        chars[EYE_SPIRAL_INDEX] = "0"
    elif edit == "xor_bits_163_173_into_163":
        a = chars[EYE_SPIRAL_INDEX] == "1"
        b = chars[PARTNER_SPIRAL_INDEX] == "1"
        chars[EYE_SPIRAL_INDEX] = "1" if a ^ b else "0"
    else:
        raise ValueError(edit)
    return "".join(chars)


def _serialize(bits: str, name: str) -> bytes:
    packed = bytes(int(bits[:192][offset : offset + 8], 2) for offset in range(0, 192, 8))
    if name == "packed_first_192":
        return packed
    if name == "sha256_of_packed192":
        return hashlib.sha256(packed).digest()
    raise ValueError(name)


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    baseline = _body_bits()
    if _serialize(baseline, "packed_first_192") != URL:
        raise ValueError("baseline URL drift")

    env48, _ = split_envelope()
    chain1 = extract_all().chain1_envelope
    envelopes = {"chain1": chain1, "env48": env48}
    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")

    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for edit in BIT_EDITS:
        bits = _apply_edit(baseline, edit)
        for serialization in SERIALIZATIONS:
            material = _serialize(bits, serialization)
            for derivation in ("sha256", "double_sha256"):
                digest = hashlib.sha256(material).digest()
                if derivation == "double_sha256":
                    digest = hashlib.sha256(digest).digest()
                hit = targets.gate_scalar_bytes(digest)
                scalar_results.append(
                    {
                        "edit": edit,
                        "serialization": serialization,
                        "derivation": derivation,
                        "prize_match": hit,
                    }
                )
                if hit is not None:
                    prize_matches.append({"kind": "scalar", "edit": edit, **hit})

            for form in PASSWORD_FORMS:
                password = _password_bytes(material, form)
                for digest in KDF_DIGESTS:
                    for envelope_name, blob in envelopes.items():
                        try:
                            plaintext = decrypt_salted_aes256_cbc(blob, password, digest=digest).plaintext
                        except ValueError:
                            aes_results.append(
                                {
                                    "edit": edit,
                                    "serialization": serialization,
                                    "envelope": envelope_name,
                                    "form": form,
                                    "kdf": digest,
                                    "padding_valid": False,
                                }
                            )
                            continue
                        padding_hits += 1
                        gate = _gate_plaintext(plaintext)
                        record = {
                            "edit": edit,
                            "serialization": serialization,
                            "envelope": envelope_name,
                            "form": form,
                            "kdf": digest,
                            "padding_valid": True,
                            **gate,
                        }
                        if gate["legible"]:
                            legible_outputs += 1
                        if gate["prize_matches"]:
                            prize_matches.extend(
                                {"kind": f"aes_{envelope_name}", "edit": edit, **m}
                                for m in gate["prize_matches"]
                            )
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
        "controls": {
            "baseline_url_matches": _serialize(baseline, "packed_first_192") == URL,
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
