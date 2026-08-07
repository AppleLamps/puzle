"""Evaluate sealed v74: exhaustive chain1 non-AES scalar material."""

from __future__ import annotations

import hashlib
import json

from . import targets
from .chains import reconstruct
from .extract import extract_all
from .salphaseion import derive_tokens
from .salphaseion_blind_eval import _base58check, _formats
from .salphaseion_split_envelope_preregister import split_envelope
from .chain1_raw_key_material_extended_preregister import (
    MANIFEST_PATH,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_tier_counts,
)
from .chain1_scalar_material import (
    ALL_DERIVATIONS,
    all_transforms,
    gate_prefix32,
    gate_triplet_direct,
    gate_window,
    window_count,
)


def _triplet_views(plaintext: bytes) -> dict[str, bytes]:
    if len(plaintext) != 79:
        raise ValueError("expected 79-byte chain1 plaintext")
    key1 = plaintext[:32]
    key2 = plaintext[32:64]
    extension = plaintext[64:79]
    return {
        "decrypted_plaintext_79": plaintext,
        "decrypted_key1_32": key1,
        "decrypted_key2_32": key2,
        "decrypted_extension_zero_pad32": extension.ljust(32, b"\0"),
        "decrypted_xor_key1_key2": bytes(a ^ b for a, b in zip(key1, key2)),
        "decrypted_add_mod256_key1_key2": bytes((a + b) % 256 for a, b in zip(key1, key2)),
    }


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    env48, raw48 = split_envelope()
    glued = extract_all().chain1_envelope
    if glued != env48 + raw48:
        raise ValueError("chain1 glued envelope drift")

    inputs = extract_all()
    chains = reconstruct(inputs, derive_tokens())

    scalar_results: list[dict[str, object]] = []
    prize_matches: list[dict[str, object]] = []
    base58_hits: list[dict[str, object]] = []
    format_hits: list[dict[str, object]] = []

    def absorb(record: dict[str, object]) -> None:
        scalar_results.append(record)
        match = record.get("match")
        if match is not None:
            prize_matches.append({"kind": record["kind"], "scope": record["scope"], **match})

    transforms = all_transforms()
    for scope, transform in transforms.items():
        blob = transform(env48, raw48, glued)
        for offset in range(window_count(len(blob))):
            window = blob[offset : offset + 32]
            for derivation in ALL_DERIVATIONS:
                absorb(gate_window(scope, offset, window, derivation))
        if len(blob) >= 32:
            for derivation in ALL_DERIVATIONS:
                absorb(gate_prefix32(scope, blob, derivation))
        if 26 <= len(blob) <= 60 and _base58check(blob):
            base58_hits.append({"scope": scope, "blob_sha256": hashlib.sha256(blob).hexdigest()})
        formats = _formats(blob)
        if formats:
            format_hits.append({"scope": scope, "formats": formats})

    for index, label in enumerate(("glued_slice0_32", "glued_slice32_64", "glued_slice64_96")):
        start = index * 32
        chunk = glued[start : start + 32]
        for derivation in ALL_DERIVATIONS:
            absorb(gate_window(label, 0, chunk, derivation))

    triplet_views = _triplet_views(chains.chain1_decryption.plaintext)
    for scope, blob in triplet_views.items():
        if scope == "decrypted_plaintext_79":
            for offset in range(window_count(len(blob))):
                window = blob[offset : offset + 32]
                for derivation in ALL_DERIVATIONS:
                    absorb(gate_window(scope, offset, window, derivation))
        else:
            for derivation in ALL_DERIVATIONS:
                absorb(gate_triplet_direct(scope, blob, derivation))

    expected = expected_tier_counts()
    if len(scalar_results) != expected["total_scalar_gates"]:
        raise ValueError(
            f"scalar gate count drift: got {len(scalar_results)}, expected {expected['total_scalar_gates']}"
        )

    status = "COMPLETE_NO_MATCH" if not prize_matches else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        "tier_counts": expected,
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

    print(_json.dumps(run(), indent=2))
