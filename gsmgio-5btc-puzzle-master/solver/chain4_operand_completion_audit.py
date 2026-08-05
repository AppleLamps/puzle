"""Exhaust contiguous three-byte completions of Chain 4's 29-byte operand."""

from __future__ import annotations

import hashlib
import json

from coincurve import PrivateKey, PublicKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .frontier_experiment import TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N


RESULT_PATH = ROOT / "chain4_operand_completion_audit.json"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")
TARGET_POINT = PublicKey(TARGET_COMPRESSED)
NEG_TARGET_POINT = TARGET_POINT.multiply((N - 1).to_bytes(32, "big"))
WIDTH = 1 << 24
BABY_WIDTH = 1 << 12


def _point_for_scalar(scalar: int) -> PublicKey:
    return PrivateKey.from_int(scalar % N).public_key


def _negate(point: PublicKey) -> PublicKey:
    return point.multiply((N - 1).to_bytes(32, "big"))


def _solve_interval(base: int, step: int, target: PublicKey, baby: dict[bytes, int]) -> int | None:
    """Solve target = (base + t*step)G for 0 <= t < 2^24."""
    target_bytes = target.format(compressed=True)
    giant_delta = (BABY_WIDTH * step) % N
    giant_scalar = base % N
    for giant_index in range(BABY_WIDTH):
        if giant_scalar == 0:
            residual = target
        else:
            giant_point = _point_for_scalar(giant_scalar)
            giant_bytes = giant_point.format(compressed=True)
            if giant_bytes == target_bytes:
                return giant_index * BABY_WIDTH
            residual = PublicKey.combine_keys([target, _negate(giant_point)])
        baby_index = baby.get(residual.format(compressed=True))
        if baby_index is not None:
            value = giant_index * BABY_WIDTH + baby_index
            if value < WIDTH:
                return value
        giant_scalar = (giant_scalar + giant_delta) % N
    return None


def _baby_table(step: int) -> dict[bytes, int]:
    # Index zero is the point at infinity and is handled explicitly in the
    # giant loop. All other 4095 points have unique encodings in this range.
    return {
        _point_for_scalar(index * step).format(compressed=True): index
        for index in range(1, BABY_WIDTH)
    }


def run() -> dict[str, object]:
    chain4 = reconstruct_chain4(reconstruct(extract_all(), derive_tokens()))
    operand = chain4.operand
    if len(operand) != 29:
        raise AssertionError("Chain 4 operand is not 29 bytes")

    matches: list[dict[str, object]] = []
    checkpoints: list[dict[str, object]] = []
    checkpoint_stream = hashlib.sha256()
    family_count = 0

    for position in range(30):
        suffix_bytes = 29 - position
        step = pow(256, suffix_bytes, N)
        baby = _baby_table(step)
        if len(baby) != BABY_WIDTH - 1:
            raise AssertionError("baby-step collision")

        for orientation, source in (("forward", operand), ("reversed", operand[::-1])):
            base_word = source[:position] + b"\0\0\0" + source[position:]
            base = int.from_bytes(base_word, "big")
            for sign, target in (("positive", TARGET_POINT), ("negative", NEG_TARGET_POINT)):
                family_count += 1
                recovered = _solve_interval(base, step, target, baby)
                terminal = {
                    "position": position,
                    "orientation": orientation,
                    "sign": sign,
                    "base_hex": f"{base:064x}",
                    "step_hex": f"{step:064x}",
                    "recovered_24bit_value": recovered,
                }
                checkpoint_stream.update(json.dumps(terminal, sort_keys=True).encode("ascii"))
                if len(checkpoints) < 8 or position == 29:
                    checkpoints.append(terminal)
                if recovered is not None:
                    inserted = recovered.to_bytes(3, "big")
                    word = source[:position] + inserted + source[position:]
                    scalar = int.from_bytes(word, "big") % N
                    if sign == "negative":
                        scalar = (-scalar) % N
                    if PrivateKey.from_int(scalar).public_key.format(compressed=True) != TARGET_COMPRESSED:
                        raise AssertionError("BSGS candidate failed exact target gate")
                    matches.append(
                        {
                            "position": position,
                            "orientation": orientation,
                            "sign": sign,
                            "inserted_hex": inserted.hex(),
                            "completed_word_hex": word.hex(),
                            "private_hex": f"{scalar:064x}",
                        }
                    )

    # A synthetic 24-bit recovery proves the interval engine and point signs.
    control_base = int.from_bytes(operand[:7] + b"\0\0\0" + operand[7:], "big")
    control_step = pow(256, 29 - 7, N)
    control_value = 0xA1B2C3
    control_scalar = (control_base + control_value * control_step) % N
    control_recovered = _solve_interval(
        control_base,
        control_step,
        _point_for_scalar(control_scalar),
        _baby_table(control_step),
    )
    if control_recovered != control_value:
        raise AssertionError("synthetic BSGS positive control failed")

    result: dict[str, object] = {
        "status": "MATCH" if matches else "NO_MATCH_IN_EXHAUSTIVE_CONTIGUOUS_THREE_BYTE_COMPLETION_FAMILY",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "operand29_hex": operand.hex(),
        "unknown_byte_count": 3,
        "values_per_family": WIDTH,
        "insertion_positions": 30,
        "orientations": ["forward", "reversed"],
        "signs": ["positive", "negative"],
        "family_count": family_count,
        "logical_candidate_space": family_count * WIDTH,
        "baby_width": BABY_WIDTH,
        "checkpoint_stream_sha256": checkpoint_stream.hexdigest(),
        "checkpoint_examples": checkpoints,
        "positive_control": {
            "inserted_hex": f"{control_value:06x}",
            "recovered_hex": f"{control_recovered:06x}",
        },
        "target_compressed_public_key": TARGET_COMPRESSED.hex(),
        "matches": matches,
        "scope_note": (
            "This exhausts every contiguous three-byte insertion into the verified 29-byte operand, "
            "in both byte orientations and both scalar signs. It does not cover three bytes inserted "
            "at noncontiguous positions or transformations involving the 35 following blocks."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
