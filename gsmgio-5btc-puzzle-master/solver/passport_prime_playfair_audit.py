"""Audit the passport-prime 23/16/7 split and its direct Playfair route.

This experiment is deliberately clue-bounded:

* 11 SEP 01 is read as DDMMYYYY = 11092001.
* The date prime is XORed with the authenticated 24-bit F73D92 color stream.
* Its significant bits provide the exact 23-bit, 16/7 control described by
  the Architect clue.
* The control is applied to the already authenticated S570 matrix-sum-list
  construction.  Its seven diagonal controls produce KTGFAIR after HILL ONE.
* FAIR authorizes Playfair; KTG (and only closely literal key readings) are
  applied to the corresponding sixteen matrix cells.
* Sixteen-letter Playfair results are tested as AES-128 keys on Chain 4.  A
  candidate is accepted only if it recreates the full prize public key and
  uncompressed P2PKH address.

There is no language scoring and no general password enumeration here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from itertools import product
from math import isqrt

from Crypto.Cipher import AES
from coincurve import PublicKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .salphaseion_raw import extract_raw
from .secp256k1_verify import N, p2pkh_address, public_key
from .witteveen_identity_audit import is_prime, t23_components, unique_color_parse


RESULT_PATH = ROOT / "passport_prime_playfair_audit.json"
GENESIS_VALUE = 0xF73D92
PASSPORT_DATE = 11092001
PASSPORT_HEX = 0xA94021
XOR_VALUE = GENESIS_VALUE ^ PASSPORT_DATE
TARGET_PUBLIC_KEY = b"\x04" + TARGET_X.to_bytes(32, "big") + TARGET_Y.to_bytes(32, "big")
OLD_COLORS = "BBBBYBBBYYBBBBYBBYYBBYY"


def a0(value: int) -> str:
    return chr(ord("A") + value % 26)


def _primality_certificate(value: int) -> dict[str, object]:
    limit = isqrt(value)
    smallest_divisor = next((d for d in range(2, limit + 1) if value % d == 0), None)
    return {
        "value": value,
        "trial_division_through": limit,
        "smallest_divisor": smallest_divisor,
        "is_prime": smallest_divisor is None,
    }


def _folded_middle() -> list[int]:
    raw = extract_raw()
    parsed = unique_color_parse(raw.s91)
    assert parsed == OLD_COLORS
    primes = [number for number in range(1, 84) if is_prime(number)]
    sums = {
        color: sum(number for number, actual in zip(primes, parsed) if actual == color)
        for color in "BY"
    }
    assert sums == {"B": 474, "Y": 400}
    values = [ord(symbol) - ord("a") for symbol in raw.s570]
    for index in sums.values():
        values[index] = 0
    combined = [left + right for left, right in zip(values[:285], reversed(values[285:]))]
    assert "".join(a0(value) for value in combined[:7]) == "HILLONE"
    assert "".join(a0(value) for value in combined[-2:]) == "KG"
    return combined[7:-2]


@dataclass(frozen=True)
class MatrixResult:
    pairs: tuple[tuple[int, int], ...]
    grid: tuple[tuple[int, ...], ...]
    text: str
    diagonal_texts: tuple[str, ...]
    diagonal_sums: tuple[int, ...]
    diagonal_letters: str
    hill_three: str


def _matrix(middle: list[int], colors: str) -> MatrixResult:
    _rendered, components = t23_components(middle, colors)
    retained_columns = list(range(19, 15, -1)) + list(range(10, -1, -1))
    composite_ids = [4, 6, 8, 9, 10, 12, 14, 15]
    selected_columns = [retained_columns[index - 1] for index in composite_ids]
    pairs = tuple(tuple(components[column]) for column in selected_columns)
    flat = [0 if value == 0 else (value - 1) % 26 for pair in pairs for value in pair]
    grid = tuple(tuple(flat[offset:offset + 4]) for offset in range(0, 16, 4))

    diagonals: list[tuple[int, ...]] = []
    for start_column in range(3, -1, -1):
        diagonals.append(tuple(grid[row][start_column + row] for row in range(4 - start_column)))
    for start_row in range(1, 4):
        diagonals.append(tuple(grid[start_row + column][column] for column in range(4 - start_row)))
    diagonal_sums = tuple(sum(diagonal) for diagonal in diagonals)
    diagonal_letters = "".join(a0(value) for value in diagonal_sums)
    hill_three = "".join(a0(3 * (ord(char) - ord("A"))) for char in diagonal_letters)
    return MatrixResult(
        pairs=pairs,
        grid=grid,
        text="".join("_" if value == 0 else a0(value) for value in flat),
        diagonal_texts=tuple("".join("_" if value == 0 else a0(value) for value in diagonal) for diagonal in diagonals),
        diagonal_sums=diagonal_sums,
        diagonal_letters=diagonal_letters,
        hill_three=hill_three,
    )


def _key_square(key: str) -> str:
    sequence = "".join(char for char in key.upper() if char.isalpha()).replace("J", "I") + "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    return "".join(dict.fromkeys(sequence))


def _playfair(text: str, key: str, decrypt: bool) -> str:
    square = _key_square(key)
    positions = {char: divmod(index, 5) for index, char in enumerate(square)}
    direction = -1 if decrypt else 1
    normalized = text.replace("J", "I")
    if len(normalized) % 2:
        raise ValueError("Playfair input must contain complete digraphs")
    output: list[str] = []
    for first, second in zip(normalized[::2], normalized[1::2]):
        r1, c1 = positions[first]
        r2, c2 = positions[second]
        if r1 == r2:
            output.extend((square[5 * r1 + (c1 + direction) % 5], square[5 * r2 + (c2 + direction) % 5]))
        elif c1 == c2:
            output.extend((square[5 * ((r1 + direction) % 5) + c1], square[5 * ((r2 + direction) % 5) + c2]))
        else:
            output.extend((square[5 * r1 + c2], square[5 * r2 + c1]))
    return "".join(output)


def _d4_reads(grid: tuple[tuple[int, ...], ...]) -> dict[str, str]:
    size = 4

    def text_for(coords: list[tuple[int, int]]) -> str:
        return "".join("_" if grid[row][column] == 0 else a0(grid[row][column]) for row, column in coords)

    transforms = {
        "identity": lambda r, c: (r, c),
        "rot90": lambda r, c: (size - 1 - c, r),
        "rot180": lambda r, c: (size - 1 - r, size - 1 - c),
        "rot270": lambda r, c: (c, size - 1 - r),
        "mirror_lr": lambda r, c: (r, size - 1 - c),
        "mirror_tb": lambda r, c: (size - 1 - r, c),
        "transpose": lambda r, c: (c, r),
        "anti_transpose": lambda r, c: (size - 1 - c, size - 1 - r),
    }
    base = [(r, c) for r in range(size) for c in range(size)]
    reads = {name: text_for([transform(r, c) for r, c in base]) for name, transform in transforms.items()}

    # The seven matrix diagonals are literally the previously derived list.
    diagonal_coords: list[tuple[int, int]] = []
    for start_column in range(3, -1, -1):
        diagonal_coords.extend((row, start_column + row) for row in range(4 - start_column))
    for start_row in range(1, 4):
        diagonal_coords.extend((start_row + column, column) for column in range(4 - start_row))
    reads["seven_diagonals"] = text_for(diagonal_coords)
    reads["seven_diagonals_reverse"] = reads["seven_diagonals"][::-1]
    for name, transform in transforms.items():
        reads[f"seven_diagonals_{name}"] = text_for([transform(r, c) for r, c in diagonal_coords])

    # Original puzzle convention: upper-left, down first, counterclockwise.
    spiral: list[tuple[int, int]] = []
    top = left = 0
    bottom = right = 3
    while left <= right and top <= bottom:
        spiral.extend((row, left) for row in range(top, bottom + 1))
        left += 1
        spiral.extend((bottom, column) for column in range(left, right + 1))
        bottom -= 1
        if left <= right:
            spiral.extend((row, right) for row in range(bottom, top - 1, -1))
            right -= 1
        if top <= bottom:
            spiral.extend((top, column) for column in range(right, left - 1, -1))
            top += 1
    reads["puzzle_spiral"] = text_for(spiral)
    reads["puzzle_spiral_reverse"] = reads["puzzle_spiral"][::-1]
    return reads


def _point_gate(candidate: bytes) -> dict[str, object] | None:
    if len(candidate) != 32:
        return None
    scalar = int.from_bytes(candidate, "big")
    if not 1 <= scalar < N:
        return None
    actual_public = PublicKey.from_valid_secret(candidate).format(compressed=False)
    if actual_public != TARGET_PUBLIC_KEY:
        return None
    address = p2pkh_address(candidate, compressed=False)
    if address != TARGET_ADDRESS:
        raise AssertionError("target point matched but address cross-check failed")
    return {
        "private_hex": candidate.hex(),
        "public_key": actual_public.hex(),
        "uncompressed_address": address,
        "accepted": True,
    }


def run() -> dict[str, object]:
    certificate = _primality_certificate(PASSPORT_DATE)
    assert certificate["is_prime"]
    assert PASSPORT_DATE == PASSPORT_HEX
    passport_bits = format(PASSPORT_DATE, "024b")
    xor_bits_padded = format(XOR_VALUE, "024b")
    xor_bits = format(XOR_VALUE, "b")
    assert passport_bits == "101010010100000000100001"
    assert passport_bits.count("1") == 7
    assert XOR_VALUE == 0x5E7DB3
    assert xor_bits_padded == "010111100111110110110011"
    assert xor_bits == "10111100111110110110011"
    assert len(xor_bits) == 23 and xor_bits.count("1") == 16 and xor_bits.count("0") == 7
    corrected_colors = xor_bits.translate(str.maketrans("10", "BY"))
    assert corrected_colors == "BYBBBBYYBBBBBYBBYBBYYBB"

    middle = _folded_middle()
    old_matrix = _matrix(middle, OLD_COLORS)
    new_matrix = _matrix(middle, corrected_colors)
    assert old_matrix.text == "C_VWWHKNJJCJNVZK"
    assert new_matrix.pairs == ((3, 0), (32, 13), (25, 6), (14, 37), (10, 10), (23, 16), (24, 38), (72, 17))
    assert new_matrix.text == "C_FMYFNKJJWPXLTQ"
    assert new_matrix.diagonal_texts == ("M", "FK", "_NP", "CFWQ", "YJT", "JL", "X")
    assert new_matrix.diagonal_sums == (12, 15, 28, 45, 52, 20, 23)
    assert new_matrix.diagonal_letters == "MPCTAUX"
    assert new_matrix.hill_three == "KTGFAIR"

    # FAIR identifies the cipher.  KTG is the immediately preceding key-sized
    # segment; KG is retained because it is the independently derived S570
    # trailer, and KTGFAIR is the one literal unsplit keyword alternative.
    # ``K T G FAIR`` can also be read as "key to [Play]fair: G"; the
    # independently folded trailer ``KG`` reinforces that literal one-letter
    # key, so G is the primary reading rather than an unconstrained addition.
    key_readings = ("G", "KTG", "KG", "KTGFAIR")
    fillers = ("A", "X", "O", "G")  # A0, conventional null, zeroed O, and key-note G.
    playfair_records: list[dict[str, object]] = []
    playfair_keys: dict[bytes, list[dict[str, str]]] = {}
    for matrix_name, matrix in (("corrected", new_matrix), ("authenticated", old_matrix)):
        for traversal, raw_text in _d4_reads(matrix.grid).items():
            for filler, key, operation in product(fillers, key_readings, ("decrypt", "encrypt")):
                source = raw_text.replace("_", filler)
                output = _playfair(source, key, decrypt=operation == "decrypt")
                metadata = {
                    "matrix": matrix_name,
                    "traversal": traversal,
                    "blank": filler,
                    "key": key,
                    "operation": operation,
                    "input": source,
                    "output": output,
                }
                playfair_records.append(metadata)
                playfair_keys.setdefault(output.encode("ascii"), []).append(metadata)

    # The most literal Architect-count reading applies the mask to the fixed
    # 23-column control itself: sixteen 1-slots are the encrypted payload and
    # seven 0-slots are the intertwined password material.
    t23_text, _ = t23_components(middle, OLD_COLORS)
    direct_sixteen = "".join(char for char, bit in zip(t23_text, xor_bits) if bit == "1")
    direct_seven = "".join(char for char, bit in zip(t23_text, xor_bits) if bit == "0")
    assert direct_sixteen == "__OHIFASKHKETFJK"
    assert direct_seven == "_CGSYMD"
    direct_key_readings = ("G", direct_seven.replace("_", ""), direct_seven.replace("_", "A"), direct_seven.replace("_", "X"))
    for filler, key, operation in product(fillers, direct_key_readings, ("decrypt", "encrypt")):
        source = direct_sixteen.replace("_", filler)
        output = _playfair(source, key, decrypt=operation == "decrypt")
        metadata = {
            "matrix": "direct_23_mask_split",
            "traversal": "significant_bit_order",
            "blank": filler,
            "key": key,
            "operation": operation,
            "input": source,
            "output": output,
        }
        playfair_records.append(metadata)
        playfair_keys.setdefault(output.encode("ascii"), []).append(metadata)

    chain4 = reconstruct_chain4(reconstruct(extract_all(), derive_tokens()))
    body = b"".join(chain4.blocks)
    ivs = {
        "zero": bytes(16),
        "prefix_head": chain4.structured_prefix[:16],
        "prefix_tail": chain4.structured_prefix[-16:],
    }
    operand_values = {
        "none": 0,
        "magnitude29": int.from_bytes(chain4.operand, "big"),
        "signed30": int.from_bytes(chain4.opcode_operand, "big"),
    }
    matches: list[dict[str, object]] = []
    gate_count = 0
    duplicate_candidates = 0
    seen_candidates: set[bytes] = set()
    candidate_stream = hashlib.sha256()

    def gate(candidate: bytes, record: dict[str, object]) -> None:
        nonlocal gate_count, duplicate_candidates
        if candidate in seen_candidates:
            duplicate_candidates += 1
            return
        seen_candidates.add(candidate)
        gate_count += 1
        stream_record = {key: value for key, value in record.items() if key != "sources"}
        candidate_stream.update(json.dumps(stream_record, sort_keys=True).encode("utf-8") + b"\0" + candidate)
        hit = _point_gate(candidate)
        if hit:
            matches.append({**record, **hit})

    # Direct, deterministic 32-byte serializations of each Playfair output.
    unique_outputs = sorted(playfair_keys)
    for output in unique_outputs:
        sources = playfair_keys[output]
        gate(hashlib.sha256(output).digest(), {"family": "sha256_playfair", "output": output.decode(), "sources": sources})
        for source in sorted({entry["input"] for entry in sources}):
            source_bytes = source.encode("ascii")
            gate(output + source_bytes, {"family": "playfair_plus_input", "output": output.decode(), "input": source})
            gate(source_bytes + output, {"family": "input_plus_playfair", "output": output.decode(), "input": source})

    # The 16-letter result is an exact AES-128 key length.  Chain 4 is the
    # only remaining layer with an explicitly aligned 32-byte block region.
    aes_operations = 0
    for key in unique_outputs:
        source_records = playfair_keys[key]
        ecb = AES.new(key, AES.MODE_ECB)
        for block_index, block in enumerate(chain4.blocks):
            for direction, transformed in (("decrypt", ecb.decrypt(block)), ("encrypt", ecb.encrypt(block))):
                aes_operations += 1
                for operand_name, operand in operand_values.items():
                    operations = (("direct", 0),) if operand_name == "none" else (("plus", operand), ("minus", -operand))
                    for arithmetic, delta in operations:
                        scalar = (int.from_bytes(transformed, "big") + delta) % (1 << 256)
                        gate(scalar.to_bytes(32, "big"), {
                            "family": "chain4_aes128_ecb",
                            "aes_key": key.decode(),
                            "sources": source_records,
                            "direction": direction,
                            "block": block_index,
                            "operand": operand_name,
                            "arithmetic": arithmetic,
                        })
        for iv_name, iv in ivs.items():
            for direction in ("decrypt", "encrypt"):
                cipher = AES.new(key, AES.MODE_CBC, iv)
                transformed_body = cipher.decrypt(body) if direction == "decrypt" else cipher.encrypt(body)
                aes_operations += 1
                for chunk_index in range(35):
                    chunk = transformed_body[32 * chunk_index:32 * (chunk_index + 1)]
                    for operand_name, operand in operand_values.items():
                        operations = (("direct", 0),) if operand_name == "none" else (("plus", operand), ("minus", -operand))
                        for arithmetic, delta in operations:
                            scalar = (int.from_bytes(chunk, "big") + delta) % (1 << 256)
                            gate(scalar.to_bytes(32, "big"), {
                                "family": "chain4_aes128_cbc",
                                "aes_key": key.decode(),
                                "sources": source_records,
                                "direction": direction,
                                "iv": iv_name,
                                "chunk": chunk_index,
                                "operand": operand_name,
                                "arithmetic": arithmetic,
                            })

    # Positive control for the exact full-point and address gate.
    known_scalar = (1).to_bytes(32, "big")
    assert public_key(known_scalar, compressed=False).hex().startswith("0479be667e")
    assert p2pkh_address(known_scalar, compressed=False) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"

    result: dict[str, object] = {
        "status": "MATCH" if matches else "COMPLETE_NO_MATCH",
        "passport": {
            "display": "11 SEP 01",
            "ddmmyyyy": PASSPORT_DATE,
            "hex": f"{PASSPORT_DATE:06X}",
            "binary_24": passport_bits,
            "popcount": passport_bits.count("1"),
            "primality_certificate": certificate,
        },
        "genesis_hex": f"{GENESIS_VALUE:06X}",
        "xor": {
            "hex": f"{XOR_VALUE:06X}",
            "binary_24": xor_bits_padded,
            "significant_binary": xor_bits,
            "length": len(xor_bits),
            "ones": xor_bits.count("1"),
            "zeros": xor_bits.count("0"),
            "colors": corrected_colors,
        },
        "corrected_matrix": {
            "pairs": new_matrix.pairs,
            "text": new_matrix.text,
            "diagonals": new_matrix.diagonal_texts,
            "diagonal_sums": new_matrix.diagonal_sums,
            "a0": new_matrix.diagonal_letters,
            "hill_three": new_matrix.hill_three,
        },
        "direct_23_mask_split": {
            "source": t23_text,
            "sixteen_one_slots": direct_sixteen,
            "seven_zero_slots": direct_seven,
            "playfair_key_readings": direct_key_readings,
        },
        "authenticated_matrix_control": {
            "text": old_matrix.text,
            "diagonal_sums": old_matrix.diagonal_sums,
            "a0": old_matrix.diagonal_letters,
        },
        "playfair": {
            "record_count": len(playfair_records),
            "unique_aes128_keys": len(unique_outputs),
            "key_readings": key_readings,
            "fillers": fillers,
            "records": playfair_records,
        },
        "gate_counts": {
            "aes_operations": aes_operations,
            "unique_private_scalar_candidates": gate_count,
            "duplicate_candidates_skipped": duplicate_candidates,
        },
        "candidate_stream_sha256": candidate_stream.hexdigest(),
        "accepted_matches": matches,
        "acceptance_rule": "complete uncompressed target public key plus target P2PKH address",
        "scope": "No plaintext scoring or free password search; only the passport XOR, matrix, Playfair, and Chain 4 operations above.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"],
        "passport": output["passport"],
        "xor": output["xor"],
        "corrected_matrix": output["corrected_matrix"],
        "gate_counts": output["gate_counts"],
        "candidate_stream_sha256": output["candidate_stream_sha256"],
        "accepted_matches": output["accepted_matches"],
    }, indent=2))
