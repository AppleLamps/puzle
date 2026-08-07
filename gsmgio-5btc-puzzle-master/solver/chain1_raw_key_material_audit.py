"""Evaluate sealed v73: chain1 96-byte blob as raw key material (non-AES)."""

from __future__ import annotations

import hashlib
import json

from . import targets
from .extract import extract_all
from .salphaseion_blind_eval import _base58check, _formats
from .salphaseion_split_envelope_preregister import split_envelope
from .chain1_raw_key_material_preregister import (
    BLOB_SCOPES,
    COMBINE_RULES,
    DERIVATIONS,
    MANIFEST_PATH,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_scalar_gates,
)


def _blobs() -> dict[str, bytes]:
    env48, raw48 = split_envelope()
    glued = extract_all().chain1_envelope
    if glued != env48 + raw48:
        raise ValueError("chain1 glued envelope drift")
    return {
        "chain1_glued_96": glued,
        "env48_half": env48,
        "raw48_half": raw48,
    }


def _derive(window: bytes, derivation: str) -> bytes:
    if derivation == "raw32_window":
        return window
    digest = hashlib.sha256(window).digest()
    if derivation == "sha256_window":
        return digest
    if derivation == "double_sha256_window":
        return hashlib.sha256(digest).digest()
    raise ValueError(derivation)


def _combine(rule: str, env48: bytes, raw48: bytes) -> bytes:
    if rule == "xor_halves":
        return bytes(a ^ b for a, b in zip(env48, raw48))
    if rule == "add_mod256_halves":
        return bytes((a + b) % 256 for a, b in zip(env48, raw48))
    if rule == "xor_env_ct_raw48":
        return bytes(a ^ b for a, b in zip(env48[16:48], raw48[:32]))
    if rule == "xor_env_salt_raw48":
        return bytes(a ^ b for a, b in zip(env48[8:16], raw48[:8])) + raw48[8:]
    raise ValueError(rule)


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    blobs = _blobs()
    env48 = blobs["env48_half"]
    raw48 = blobs["raw48_half"]

    scalar_results: list[dict[str, object]] = []
    prize_matches: list[dict[str, object]] = []
    base58_hits: list[dict[str, object]] = []
    format_hits: list[dict[str, object]] = []

    def gate_window(scope: str, offset: int, window: bytes, derivation: str) -> None:
        material = _derive(window, derivation)
        hit = targets.gate_scalar_bytes(material)
        scalar_results.append(
            {
                "kind": "window",
                "scope": scope,
                "offset": offset,
                "derivation": derivation,
                "prize_match": hit,
            }
        )
        if hit is not None:
            prize_matches.append(
                {
                    "kind": "window",
                    "scope": scope,
                    "offset": offset,
                    "derivation": derivation,
                    **hit,
                }
            )

    for scope, blob in blobs.items():
        for offset in range(len(blob) - 31):
            window = blob[offset : offset + 32]
            for derivation in DERIVATIONS:
                gate_window(scope, offset, window, derivation)
        for derivation in DERIVATIONS:
            whole = _derive(blob[:32] if len(blob) >= 32 else blob.ljust(32, b"\0"), derivation)
            hit = targets.gate_scalar_bytes(whole)
            scalar_results.append(
                {"kind": "whole_prefix32", "scope": scope, "derivation": derivation, "prize_match": hit}
            )
            if hit is not None:
                prize_matches.append({"kind": "whole_prefix32", "scope": scope, "derivation": derivation, **hit})
        if 26 <= len(blob) <= 60 and _base58check(blob):
            base58_hits.append({"scope": scope, "blob_sha256": hashlib.sha256(blob).hexdigest()})
        formats = _formats(blob)
        if formats:
            format_hits.append({"scope": scope, "formats": formats})

    for rule in COMBINE_RULES:
        combined = _combine(rule, env48, raw48)
        window = combined[:32] if len(combined) >= 32 else combined.ljust(32, b"\0")
        for derivation in DERIVATIONS:
            gate_window(f"combine:{rule}", 0, window, derivation)

    if len(scalar_results) != expected_scalar_gates():
        raise ValueError(f"scalar gate count drift: got {len(scalar_results)}, expected {expected_scalar_gates()}")

    status = "COMPLETE_NO_MATCH" if not prize_matches else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        "counts": {
            "scalar_gates": len(scalar_results),
            "prize_matches": len(prize_matches),
            "base58check_hits": len(base58_hits),
            "format_hits": len(format_hits),
        },
        "prize_matches": prize_matches,
        "base58check_hits": base58_hits,
        "format_hits": format_hits,
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import json as _json

    print(_json.dumps(run()["counts"], indent=2))
