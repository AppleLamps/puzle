"""Test the seven passport-derived diagonal components against Chain 4.

The family is fixed by exact dimensions rather than plaintext plausibility:
seven diagonal components, 35 = C(7,3) = C(7,4) aligned 32-byte blocks, and
the visible ``+-`` operand.  Every result is accepted only by the complete
prize point and uncompressed address.
"""

from __future__ import annotations

from functools import reduce
import hashlib
import itertools
import json
from operator import xor

from Crypto.Cipher import AES
from coincurve import PublicKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .passport_prime_playfair_audit import _folded_middle, _matrix
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "passport_intertwined_chain4_audit.json"
MASK_BITS = "10111100111110110110011"
CORRECTED_COLORS = MASK_BITS.translate(str.maketrans("10", "BY"))
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")
SEPARATORS = {"empty": b"", "nul": b"\0", "colon": b":", "newline": b"\n"}


def _target_gate(value: int) -> dict[str, object] | None:
    scalar = value % N
    if not scalar:
        return None
    private = scalar.to_bytes(32, "big")
    public = PublicKey.from_valid_secret(private)
    if public.format(compressed=True) != TARGET_COMPRESSED:
        return None
    address = base58check(b"\0" + hash160(public.format(compressed=False)))
    if address != TARGET_ADDRESS:
        raise AssertionError("point matched but address did not")
    return {"private_hex": private.hex(), "address": address, "accepted": True}


def _apex(values: list[int]) -> int:
    """Apex of the adjacent-XOR triangle without materializing all rows."""

    degree = len(values) - 1
    return reduce(xor, (value for index, value in enumerate(values) if index & ~degree == 0), 0)


def _password_sets() -> dict[str, tuple[bytes, ...]]:
    matrix = _matrix(_folded_middle(), CORRECTED_COLORS)
    assert matrix.diagonal_texts == ("M", "FK", "_NP", "CFWQ", "YJT", "JL", "X")
    assert matrix.diagonal_letters == "MPCTAUX"
    assert matrix.hill_three == "KTGFAIR"
    raw = matrix.diagonal_texts
    sets = {
        "diagonals-drop-blank": tuple(value.replace("_", "").encode() for value in raw),
        "diagonals-A0-blank": tuple(value.replace("_", "A").encode() for value in raw),
        "diagonals-playfair-null": tuple(value.replace("_", "X").encode() for value in raw),
        "diagonal-A0-sums": tuple(value.encode() for value in matrix.diagonal_letters),
        "diagonal-hill-three": tuple(value.encode() for value in matrix.hill_three),
        "direct-mask-seven-A0": tuple(value.encode() for value in "ACGSYMD"),
        "direct-mask-seven-X": tuple(value.encode() for value in "XCGSYMD"),
        "direct-mask-seven-hill": tuple(value.encode() for value in "AGSCUKJ"),
    }
    assert all(len(values) == 7 for values in sets.values())
    return sets


def _key_models(elements: tuple[bytes, ...], subset_size: int) -> list[dict[str, object]]:
    combinations = list(itertools.combinations(range(7), subset_size))
    records: list[dict[str, object]] = []
    for order in itertools.permutations(range(subset_size)):
        for separator_name, separator in SEPARATORS.items():
            joined = [separator.join(elements[combo[index]] for index in order) for combo in combinations]
            records.extend((
                {
                    "name": f"sha256/order-{''.join(map(str, order))}/{separator_name}",
                    "keys": [hashlib.sha256(value).digest() for value in joined],
                },
                {
                    "name": f"md5/order-{''.join(map(str, order))}/{separator_name}",
                    "keys": [hashlib.md5(value).digest() for value in joined],
                },
            ))

    individual = [int.from_bytes(hashlib.sha256(value).digest(), "big") for value in elements]
    records.extend((
        {
            "name": "xor-individual-sha256",
            "keys": [reduce(xor, (individual[index] for index in combo)).to_bytes(32, "big") for combo in combinations],
        },
        {
            "name": "sum-individual-sha256",
            "keys": [(sum(individual[index] for index in combo) % (1 << 256)).to_bytes(32, "big") for combo in combinations],
        },
    ))
    return records


def run() -> dict[str, object]:
    chain4 = reconstruct_chain4(reconstruct(extract_all(), derive_tokens()))
    blocks = list(chain4.blocks)
    assert len(blocks) == 35 and all(len(block) == 32 for block in blocks)
    operand = int.from_bytes(chain4.opcode_operand, "big")
    ivs = {
        "zero": bytes(16),
        "prefix-head": chain4.structured_prefix[:16],
        "prefix-tail": chain4.structured_prefix[-16:],
    }

    matches: list[dict[str, object]] = []
    candidate_count = 0
    cipher_operations = 0
    model_count = 0
    stream = hashlib.sha256()

    def submit(value: int, provenance: dict[str, object]) -> None:
        nonlocal candidate_count
        candidate_count += 1
        scalar = value % N
        stream.update(json.dumps(provenance, sort_keys=True).encode() + b"\0" + scalar.to_bytes(32, "big"))
        hit = _target_gate(value)
        if hit:
            matches.append({**provenance, **hit})

    for set_name, elements in _password_sets().items():
        for subset_size in (3, 4):
            for model in _key_models(elements, subset_size):
                model_count += 1
                keys = model["keys"]
                assert isinstance(keys, list) and len(keys) == 35
                for block_order, ordered_blocks in (("forward", blocks), ("reverse", list(reversed(blocks)))):
                    for direction in ("decrypt", "encrypt"):
                        for mode_name in ("ecb", *ivs):
                            outputs: list[int] = []
                            for index, (key, block) in enumerate(zip(keys, ordered_blocks)):
                                assert isinstance(key, bytes) and len(key) in (16, 32)
                                if mode_name == "ecb":
                                    cipher = AES.new(key, AES.MODE_ECB)
                                else:
                                    cipher = AES.new(key, AES.MODE_CBC, ivs[mode_name])
                                transformed = cipher.decrypt(block) if direction == "decrypt" else cipher.encrypt(block)
                                cipher_operations += 1
                                value = int.from_bytes(transformed, "big")
                                outputs.append(value)
                                base = {
                                    "password_set": set_name,
                                    "subset_size": subset_size,
                                    "key_model": model["name"],
                                    "block_order": block_order,
                                    "direction": direction,
                                    "mode": mode_name,
                                    "block": index,
                                }
                                submit(value, {**base, "reduction": "direct"})
                                submit(value + operand, {**base, "reduction": "plus-operand"})
                                submit(value - operand, {**base, "reduction": "minus-operand"})
                                submit(value ^ operand, {**base, "reduction": "xor-operand"})

                            aggregates = {
                                "xor-all": reduce(xor, outputs),
                                "sum-all": sum(outputs),
                                "adjacent-xor-apex": _apex(outputs),
                                "xor-even-one-based": reduce(xor, outputs[1::2]),
                                "xor-odd-one-based": reduce(xor, outputs[0::2]),
                            }
                            model_base = {
                                "password_set": set_name,
                                "subset_size": subset_size,
                                "key_model": model["name"],
                                "block_order": block_order,
                                "direction": direction,
                                "mode": mode_name,
                            }
                            for aggregate_name, value in aggregates.items():
                                submit(value, {**model_base, "reduction": aggregate_name})
                                submit(value + operand, {**model_base, "reduction": f"{aggregate_name}+operand"})
                                submit(value - operand, {**model_base, "reduction": f"{aggregate_name}-operand"})
                                submit(value ^ operand, {**model_base, "reduction": f"{aggregate_name}-xor-operand"})

    result: dict[str, object] = {
        "status": "MATCH" if matches else "COMPLETE_NO_MATCH",
        "source": {
            "passport_mask": MASK_BITS,
            "password_sets": {name: [value.decode() for value in values] for name, values in _password_sets().items()},
            "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
            "block_count": len(blocks),
            "identity": "35 = C(7,3) = C(7,4)",
        },
        "counts": {
            "models": model_count,
            "cipher_operations": cipher_operations,
            "point_gated_candidates": candidate_count,
        },
        "candidate_stream_sha256": stream.hexdigest(),
        "accepted_matches": matches,
        "acceptance_rule": "complete target point and uncompressed target address",
        "scope": "No plaintext scoring; only the eight literal seven-component readings, C(7,3)/C(7,4), AES, XOR-triangle/even reductions, and the visible Chain 4 operand.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"],
        "counts": output["counts"],
        "candidate_stream_sha256": output["candidate_stream_sha256"],
        "accepted_matches": output["accepted_matches"],
    }, indent=2))
