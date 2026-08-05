"""Test the literal Passport -> Hill -> Playfair -> EVEN Chain-4 route.

The clue-ordered path fixes the two Playfair outputs before this audit starts:
the corrected 4x4 component matrix, conventional X null, key ``KTG``, and
both encryption/decryption direction readings.  Both outputs begin ``EVEN``.
This audit therefore tests only even/odd and visible ``+-`` reductions of the
35 aligned Chain-4 blocks after AES-128 transformation by those two keys.
Candidates are accepted solely by either authentic funded prize address.
"""

from __future__ import annotations

from functools import reduce
import hashlib
import json
from operator import xor

from coincurve import PrivateKey
from Crypto.Cipher import AES

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .passport_prime_playfair_audit import _folded_middle, _matrix, _playfair
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "passport_even_chain4_audit.json"
HALF_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER_HALF_ADDRESS = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
MASK_BITS = "10111100111110110110011"
COLORS = MASK_BITS.translate(str.maketrans("10", "BY"))


def _addresses(value: int) -> dict[str, str]:
    scalar = value % N
    if not scalar:
        return {}
    public = PrivateKey.from_int(scalar).public_key
    return {
        "compressed": base58check(b"\0" + hash160(public.format(compressed=True))),
        "uncompressed": base58check(b"\0" + hash160(public.format(compressed=False))),
    }


def _xor(values: list[int]) -> int:
    return reduce(xor, values, 0)


def _apex(values: list[int]) -> int:
    degree = len(values) - 1
    return _xor([value for index, value in enumerate(values) if index & ~degree == 0])


def _reductions(values: list[int]) -> dict[str, int]:
    odd_one_based = values[0::2]
    even_one_based = values[1::2]
    return {
        "xor-all": _xor(values),
        "sum-all": sum(values),
        "xor-odd-one-based": _xor(odd_one_based),
        "xor-even-one-based": _xor(even_one_based),
        "sum-odd-one-based": sum(odd_one_based),
        "sum-even-one-based": sum(even_one_based),
        "sum-odd-minus-even": sum(odd_one_based) - sum(even_one_based),
        "sum-even-minus-odd": sum(even_one_based) - sum(odd_one_based),
        "alternating-plus-minus": sum(value if index % 2 == 0 else -value for index, value in enumerate(values)),
        "alternating-minus-plus": sum(-value if index % 2 == 0 else value for index, value in enumerate(values)),
        "adjacent-xor-apex": _apex(values),
    }


def run() -> dict[str, object]:
    matrix = _matrix(_folded_middle(), COLORS)
    assert matrix.text == "C_FMYFNKJJWPXLTQ"
    source = matrix.text.replace("_", "X")
    playfair_keys = {
        "playfair-encrypt": _playfair(source, "KTG", decrypt=False).encode("ascii"),
        "playfair-decrypt": _playfair(source, "KTG", decrypt=True).encode("ascii"),
    }
    assert playfair_keys == {
        "playfair-encrypt": b"EVENANIALLVQWMDW",
        "playfair-decrypt": b"EVENSAIAOOVQWMWL",
    }

    chain4 = reconstruct_chain4(reconstruct(extract_all(), derive_tokens()))
    body = b"".join(chain4.blocks)
    operand = int.from_bytes(chain4.opcode_operand, "big")
    ivs = {
        "ecb": None,
        "cbc-zero": bytes(16),
        "cbc-prefix-head": chain4.structured_prefix[:16],
        "cbc-prefix-tail": chain4.structured_prefix[-16:],
    }
    targets = {HALF_ADDRESS: "Half", BETTER_HALF_ADDRESS: "Better_Half"}
    matches: list[dict[str, object]] = []
    tested = 0
    stream = hashlib.sha256()

    def submit(value: int, provenance: dict[str, object]) -> None:
        nonlocal tested
        tested += 1
        scalar = value % N
        stream.update(json.dumps(provenance, sort_keys=True).encode() + b"\0" + scalar.to_bytes(32, "big"))
        addresses = _addresses(value)
        for serialization, address in addresses.items():
            if address in targets:
                matches.append({
                    **provenance,
                    "private_hex": f"{scalar:064x}",
                    "serialization": serialization,
                    "address": address,
                    "role": targets[address],
                    "accepted": True,
                })

    for key_name, key in playfair_keys.items():
        for block_order, ordered_body in (("forward", body), ("reverse", b"".join(reversed(chain4.blocks)))):
            for mode_name, iv in ivs.items():
                for direction in ("decrypt", "encrypt"):
                    if iv is None:
                        cipher = AES.new(key, AES.MODE_ECB)
                    else:
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                    transformed = cipher.decrypt(ordered_body) if direction == "decrypt" else cipher.encrypt(ordered_body)
                    values = [int.from_bytes(transformed[index:index + 32], "big") for index in range(0, len(transformed), 32)]
                    assert len(values) == 35
                    base = {"key": key_name, "block_order": block_order, "mode": mode_name, "direction": direction}
                    for reduction, value in _reductions(values).items():
                        for operand_operation, candidate in (
                            ("none", value),
                            ("plus", value + operand),
                            ("minus", value - operand),
                            ("xor", value ^ operand),
                        ):
                            submit(candidate, {**base, "reduction": reduction, "operand": operand_operation})

    result: dict[str, object] = {
        "schema": "passport-even-chain4-audit-v1",
        "status": "MATCH" if matches else "COMPLETE_NO_MATCH",
        "source": {
            "mask": MASK_BITS,
            "matrix": matrix.text,
            "playfair_input": source,
            "playfair_key": "KTG",
            "aes128_keys": {name: key.decode() for name, key in playfair_keys.items()},
            "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        },
        "candidate_count": tested,
        "candidate_stream_sha256": stream.hexdigest(),
        "accepted_matches": matches,
        "scope": "Exact EVEN/odd, alternating +-, XOR-apex, and operand reductions only; no plaintext scoring.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
