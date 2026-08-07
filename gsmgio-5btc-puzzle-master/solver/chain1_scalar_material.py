"""Shared chain1 byte views, derivations, and scalar gating helpers."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from . import targets
from .secp256k1_verify import N


TransformFn = Callable[[bytes, bytes, bytes], bytes]

# --- Tier A: v73 combine rules (full sliding in v74) ---
V73_COMBINE_RULES: dict[str, TransformFn] = {
    "xor_halves": lambda env48, raw48, glued: bytes(a ^ b for a, b in zip(env48, raw48)),
    "add_mod256_halves": lambda env48, raw48, glued: bytes((a + b) % 256 for a, b in zip(env48, raw48)),
    "xor_env_ct_raw48": lambda env48, raw48, glued: bytes(a ^ b for a, b in zip(env48[16:48], raw48[:32])),
    "xor_env_salt_raw48": lambda env48, raw48, glued: bytes(a ^ b for a, b in zip(env48[8:16], raw48[:8])) + raw48[8:],
}

# --- Tier C: additional fixed transforms ---
EXTENDED_TRANSFORMS: dict[str, TransformFn] = {
    "strip_salted_header": lambda env48, raw48, glued: glued[8:],
    "reverse_glued": lambda env48, raw48, glued: glued[::-1],
    "reverse_env48": lambda env48, raw48, glued: env48[::-1],
    "reverse_raw48": lambda env48, raw48, glued: raw48[::-1],
    "interleave_env_raw": lambda env48, raw48, glued: bytes(b for pair in zip(env48, raw48) for b in pair),
    "env48_ciphertext_only": lambda env48, raw48, glued: env48[16:48],
    "concat_env_ct_raw48": lambda env48, raw48, glued: env48[16:48] + raw48,
    "raw48_plus_env_salt": lambda env48, raw48, glued: env48[8:16] + raw48,
    "xor_env_header_raw48": lambda env48, raw48, glued: bytes(a ^ b for a, b in zip(env48[:8], raw48[:8]))
    + env48[8:]
    + raw48[8:],
    "sub_mod256_halves": lambda env48, raw48, glued: bytes((a - b) % 256 for a, b in zip(env48, raw48)),
}

BASE_SCOPES: dict[str, TransformFn] = {
    "chain1_glued_96": lambda env48, raw48, glued: glued,
    "env48_half": lambda env48, raw48, glued: env48,
    "raw48_half": lambda env48, raw48, glued: raw48,
}

V73_DERIVATIONS = (
    "raw32_window",
    "sha256_window",
    "double_sha256_window",
)

EXTENDED_DERIVATIONS = (
    "sha256_xor_0x7f",
    "sha256_reversed_digest",
    "sha256_of_reversed_window",
    "mod_n_big_endian",
    "mod_n_little_endian",
)

ALL_DERIVATIONS = V73_DERIVATIONS + EXTENDED_DERIVATIONS


def window_count(length: int) -> int:
    return max(0, length - 32 + 1)


def all_transforms() -> dict[str, TransformFn]:
    merged = dict(BASE_SCOPES)
    merged.update(V73_COMBINE_RULES)
    merged.update(EXTENDED_TRANSFORMS)
    return merged


def derive_scalar(window: bytes, derivation: str) -> bytes:
    if len(window) != 32:
        raise ValueError("window must be 32 bytes")
    if derivation == "raw32_window":
        return window
    digest = hashlib.sha256(window).digest()
    if derivation == "sha256_window":
        return digest
    if derivation == "double_sha256_window":
        return hashlib.sha256(digest).digest()
    if derivation == "sha256_xor_0x7f":
        return bytes(b ^ 0x7F for b in digest)
    if derivation == "sha256_reversed_digest":
        return digest[::-1]
    if derivation == "sha256_of_reversed_window":
        return hashlib.sha256(window[::-1]).digest()
    if derivation == "mod_n_big_endian":
        value = int.from_bytes(window, "big") % N
        return value.to_bytes(32, "big")
    if derivation == "mod_n_little_endian":
        value = int.from_bytes(window, "little") % N
        return value.to_bytes(32, "big")
    raise ValueError(derivation)


def gate_window(scope: str, offset: int, window: bytes, derivation: str) -> dict[str, object]:
    material = derive_scalar(window, derivation)
    hit = targets.gate_scalar_bytes(material)
    record: dict[str, object] = {
        "kind": "window",
        "scope": scope,
        "offset": offset,
        "derivation": derivation,
        "prize_match": hit,
    }
    if hit is not None:
        record["match"] = hit
    return record


def gate_prefix32(scope: str, blob: bytes, derivation: str) -> dict[str, object]:
    window = blob[:32] if len(blob) >= 32 else blob.ljust(32, b"\0")
    material = derive_scalar(window, derivation)
    hit = targets.gate_scalar_bytes(material)
    record: dict[str, object] = {
        "kind": "prefix32",
        "scope": scope,
        "derivation": derivation,
        "prize_match": hit,
    }
    if hit is not None:
        record["match"] = hit
    return record


def gate_triplet_direct(scope: str, blob: bytes, derivation: str) -> dict[str, object]:
    window = blob[:32].ljust(32, b"\0")
    material = derive_scalar(window, derivation)
    hit = targets.gate_scalar_bytes(material)
    record: dict[str, object] = {
        "kind": "triplet_direct",
        "scope": scope,
        "derivation": derivation,
        "prize_match": hit,
    }
    if hit is not None:
        record["match"] = hit
    return record


def expected_gates_for_transforms(
    transforms: dict[str, TransformFn],
    derivations: tuple[str, ...],
    *,
    include_prefix32: bool,
    include_glued_triplet_slices: bool,
) -> int:
    env48 = b"\0" * 48
    raw48 = b"\0" * 48
    glued = env48 + raw48
    total = 0
    for name, fn in transforms.items():
        blob = fn(env48, raw48, glued)
        total += window_count(len(blob)) * len(derivations)
        if include_prefix32 and len(blob) >= 32:
            total += len(derivations)
    if include_glued_triplet_slices:
        total += 3 * len(derivations)
    return total


def expected_triplet_gates(derivations: tuple[str, ...]) -> int:
    # 79-byte plaintext windows + five direct 32-byte views.
    return window_count(79) * len(derivations) + 5 * len(derivations)
