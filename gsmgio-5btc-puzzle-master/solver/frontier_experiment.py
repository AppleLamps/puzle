"""Bounded cross-branch experiment over verified Chain 4 and matrix artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .salphaseion import derive_tokens
from .secp256k1_verify import N
from .targets import HALF_X, HALF_Y


TARGET_X = HALF_X
TARGET_Y = HALF_Y
RESULT_PATH = ROOT / "frontier_experiment.json"


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _target_match(candidate: int) -> bool:
    candidate %= N
    if not candidate:
        return False
    public = ec.derive_private_key(candidate, ec.SECP256K1()).public_key().public_numbers()
    return public.x == TARGET_X and public.y == TARGET_Y


def run() -> dict[str, object]:
    sal = derive_tokens()
    chains = reconstruct(extract_all(), sal)
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)
    plaintext = chain4.decryption.plaintext
    windows = [(offset, plaintext[offset : offset + 32]) for offset in range(len(plaintext) - 31)]

    prefix = chain4.structured_prefix
    constants = {
        "half": matrix.half,
        "better_half": matrix.better_half,
        "half_xor_better": bytes(a ^ b for a, b in zip(matrix.half, matrix.better_half)),
        "half_plus_better_mod_n": ((int.from_bytes(matrix.half, "big") + int.from_bytes(matrix.better_half, "big")) % N).to_bytes(32, "big"),
        "half_minus_better_mod_n": ((int.from_bytes(matrix.half, "big") - int.from_bytes(matrix.better_half, "big")) % N).to_bytes(32, "big"),
        "better_minus_half_mod_n": ((int.from_bytes(matrix.better_half, "big") - int.from_bytes(matrix.half, "big")) % N).to_bytes(32, "big"),
        "trail1_repeated": matrix.trail1 * 8,
        "sha256_trail1": _sha(matrix.trail1),
        "opcode_operand30_leftpad": prefix[1:].rjust(32, b"\0"),
        "opcode_operand30_rightpad": prefix[1:].ljust(32, b"\0"),
        "marker_operand29_leftpad": prefix[2:].rjust(32, b"\0"),
        "sha256_prefix31": _sha(prefix),
    }

    seen: set[int] = set()
    matches: list[dict[str, object]] = []
    generated = 0

    def submit(value: int, offset: int, operation: str) -> None:
        nonlocal generated
        generated += 1
        value %= N
        if not value or value in seen:
            return
        seen.add(value)
        if _target_match(value):
            matches.append({"offset": offset, "operation": operation, "private_hex": f"{value:064x}"})

    for offset, window in windows:
        x = int.from_bytes(window, "big")
        submit(x, offset, "window")
        for label, constant in constants.items():
            c = int.from_bytes(constant, "big")
            submit(x ^ c, offset, f"window XOR {label}")
            submit(x + c, offset, f"window + {label}")
            submit(x - c, offset, f"window - {label}")
            submit(c - x, offset, f"{label} - window")
            submit(int.from_bytes(_sha(window + constant), "big"), offset, f"SHA256(window || {label})")
            submit(int.from_bytes(_sha(constant + window), "big"), offset, f"SHA256({label} || window)")

    result: dict[str, object] = {
        "status": "MATCH" if matches else "NO_MATCH_IN_BOUNDED_FAMILY",
        "chain4_sha256": hashlib.sha256(plaintext).hexdigest(),
        "half_sha256": hashlib.sha256(matrix.half).hexdigest(),
        "better_half_sha256": hashlib.sha256(matrix.better_half).hexdigest(),
        "trail1_hex": matrix.trail1.hex(),
        "window_count": len(windows),
        "constant_count": len(constants),
        "generated_candidates": generated,
        "unique_nonzero_scalars": len(seen),
        "operations": [
            "window",
            "window XOR constant",
            "window + constant mod n",
            "window - constant mod n",
            "constant - window mod n",
            "SHA256(window || constant)",
            "SHA256(constant || window)",
        ],
        "constants": {name: value.hex() for name, value in constants.items()},
        "target": {"x": f"{TARGET_X:064x}", "y": f"{TARGET_Y:064x}"},
        "matches": matches,
        "scope_note": "This falsifies only the enumerated elementary cross-branch family; it is not a general impossibility result.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))

