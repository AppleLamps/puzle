"""Exhaust the one-byte completion implied by Chain 4's 31-byte prefix."""

from __future__ import annotations

import hashlib
import json

from coincurve import PrivateKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .frontier_experiment import TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N


RESULT_PATH = ROOT / "chain4_prefix_completion_audit.json"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")


def run() -> dict[str, object]:
    chain4 = reconstruct_chain4(reconstruct(extract_all(), derive_tokens()))
    prefix = chain4.structured_prefix
    if len(prefix) != 31:
        raise AssertionError("Chain 4 prefix is not 31 bytes")

    completions: dict[bytes, tuple[int, int]] = {}
    for position in range(32):
        for value in range(256):
            word = prefix[:position] + bytes([value]) + prefix[position:]
            completions.setdefault(word, (position, value))

    candidate_stream = hashlib.sha256()
    seen: set[int] = set()
    matches: list[dict[str, object]] = []
    generated = 0

    def submit(raw: int, word: bytes, position: int, value: int, transform: str) -> None:
        nonlocal generated
        generated += 1
        scalar = raw % N
        if scalar == 0 or scalar in seen:
            return
        seen.add(scalar)
        candidate_stream.update(scalar.to_bytes(32, "big"))
        if PrivateKey.from_int(scalar).public_key.format(compressed=True) == TARGET_COMPRESSED:
            matches.append(
                {
                    "position": position,
                    "inserted_byte": value,
                    "transform": transform,
                    "completed_word_hex": word.hex(),
                    "private_hex": f"{scalar:064x}",
                }
            )

    for word, (position, value) in completions.items():
        big = int.from_bytes(word, "big")
        little = int.from_bytes(word, "little")
        digest = hashlib.sha256(word).digest()
        reverse_digest = hashlib.sha256(word[::-1]).digest()
        for raw, transform in (
            (big, "direct-big"),
            (-big, "negative-direct-big"),
            (little, "direct-little"),
            (-little, "negative-direct-little"),
            (int.from_bytes(digest, "big"), "sha256"),
            (int.from_bytes(reverse_digest, "big"), "sha256-reversed-word"),
        ):
            submit(raw, word, position, value, transform)

    # Independent positive control for point serialization and equality.
    control_scalar = 1
    control_public = PrivateKey.from_int(control_scalar).public_key.format(compressed=True)
    if control_public.hex() != "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798":
        raise AssertionError("secp256k1 positive control failed")

    result: dict[str, object] = {
        "status": "MATCH" if matches else "NO_MATCH_IN_EXHAUSTIVE_ONE_BYTE_COMPLETION_FAMILY",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "prefix31_hex": prefix.hex(),
        "insertion_positions": 32,
        "inserted_byte_values": 256,
        "unique_completed_words": len(completions),
        "transforms": [
            "direct-big",
            "negative-direct-big",
            "direct-little",
            "negative-direct-little",
            "sha256",
            "sha256-reversed-word",
        ],
        "generated_candidates": generated,
        "unique_nonzero_scalars": len(seen),
        "candidate_stream_sha256": candidate_stream.hexdigest(),
        "target_compressed_public_key": TARGET_COMPRESSED.hex(),
        "positive_control": {"scalar": control_scalar, "compressed_public_key": control_public.hex()},
        "matches": matches,
        "scope_note": (
            "This exhausts every insertion of one arbitrary byte into the verified 31-byte Chain 4 "
            "prefix under the six recorded scalar transforms. It does not test multi-byte completion "
            "of the 29-byte operand or transforms involving the 35 following blocks."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
