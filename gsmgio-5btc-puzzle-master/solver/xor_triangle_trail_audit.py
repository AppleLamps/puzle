"""Audit clue-bounded XOR-triangle interpretations around Chain 4 and Cosmic.

This does not trust the unreproduced Issue #88 ``cosmic_A`` bytes.  It only
uses locally reproduced Chain 4 blocks, the 103x103 Cosmic interpretation, and
the authenticated trail1 suffix ``fc0c1b02``.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections import defaultdict
from dataclasses import dataclass

from coincurve import PrivateKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160, wif
from .witteveen_identity_audit import derive as derive_witteveen


RESULT_PATH = ROOT / "xor_triangle_trail_audit.json"

PRIZE_ADDRESSES = {
    "Half": "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "Better_Half": "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa",
}

TRAIL_SIGNED = (-4, 12, 27, 2)
FORMULA_BASE = (-4, 2, 32, 12, 4, 27, 0, 2, -16, 15)

WITTEVEEN_SOURCES: dict[str, tuple[bytes, ...]] = {
    "diagonal-strings-with-blank": (b"W", b"VN", b"_KJ", b"CHCK", b"WJZ", b"JV", b"N"),
    "diagonal-strings-zero-omitted": (b"W", b"VN", b"KJ", b"CHCK", b"WJZ", b"JV", b"N"),
    "diagonal-sum-letters": tuple(bytes([byte]) for byte in b"WITVEEN"),
    "diagonal-sum-decimals": tuple(str(value).encode("ascii") for value in (22, 34, 19, 21, 56, 30, 13)),
}


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _xor_bytes(*values: bytes) -> bytes:
    output = bytearray(32)
    for value in values:
        if len(value) != 32:
            raise ValueError("XOR inputs must be 32 bytes")
        for index, byte in enumerate(value):
            output[index] ^= byte
    return bytes(output)


def _sum_mod_n(*values: bytes) -> bytes:
    total = sum(int.from_bytes(value, "big") for value in values) % N
    return total.to_bytes(32, "big")


def _int32(value: int) -> bytes:
    return (value % N).to_bytes(32, "big")


def _repeat_to_32(value: bytes) -> bytes:
    if not value:
        return bytes(32)
    return (value * ((32 // len(value)) + 1))[:32]


def _bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) != 256:
        raise ValueError("expected exactly 256 bits")
    output = bytearray()
    for offset in range(0, 256, 8):
        byte = 0
        for bit in bits[offset : offset + 8]:
            byte = (byte << 1) | bit
        output.append(byte)
    return bytes(output)


def _candidate_addresses(candidate: bytes) -> dict[str, str]:
    scalar = int.from_bytes(candidate, "big") % N
    if not scalar:
        return {}
    public = PrivateKey(scalar.to_bytes(32, "big")).public_key
    return {
        "uncompressed": base58check(b"\0" + hash160(public.format(compressed=False))),
        "compressed": base58check(b"\0" + hash160(public.format(compressed=True))),
    }


@dataclass
class CandidateGate:
    generated: int = 0
    unique_nonzero: int = 0
    duplicate_or_zero: int = 0
    seen: set[int] | None = None
    family_generated: dict[str, int] | None = None
    family_unique: dict[str, int] | None = None
    matches: list[dict[str, object]] | None = None

    def __post_init__(self) -> None:
        self.seen = set()
        self.family_generated = defaultdict(int)
        self.family_unique = defaultdict(int)
        self.matches = []

    def submit(self, family: str, label: str, candidate: bytes) -> None:
        if len(candidate) != 32:
            raise ValueError(f"{label} produced {len(candidate)} bytes, not 32")
        assert self.seen is not None
        assert self.family_generated is not None
        assert self.family_unique is not None
        assert self.matches is not None

        self.generated += 1
        self.family_generated[family] += 1
        scalar = int.from_bytes(candidate, "big") % N
        if not scalar or scalar in self.seen:
            self.duplicate_or_zero += 1
            return
        self.seen.add(scalar)
        self.unique_nonzero += 1
        self.family_unique[family] += 1
        normalized = scalar.to_bytes(32, "big")
        addresses = _candidate_addresses(normalized)
        for serialization, address in addresses.items():
            for role, target in PRIZE_ADDRESSES.items():
                if address == target:
                    self.matches.append(
                        {
                            "family": family,
                            "label": label,
                            "private_hex": normalized.hex(),
                            "wif_uncompressed": wif(normalized, compressed=False),
                            "wif_compressed": wif(normalized, compressed=True),
                            "serialization": serialization,
                            "address": address,
                            "prize_role": role,
                        }
                    )


def _element_vectors(elements: tuple[bytes, ...]) -> dict[str, tuple[bytes, ...]]:
    return {
        "sha256": tuple(_sha256(element) for element in elements),
        "repeat": tuple(_repeat_to_32(element) for element in elements),
        "leftpad": tuple(element[-32:].rjust(32, b"\0") for element in elements),
    }


def _submit_pascal_witteveen(gate: CandidateGate, blocks: list[bytes]) -> dict[str, object]:
    family = "pascal_witteveen_c73"
    triples = list(itertools.combinations(range(7), 3))
    block_orders = {"chain4-natural": blocks, "chain4-reversed": list(reversed(blocks))}
    combo_orders = {
        "c73-lex": triples,
        "c73-reversed": list(reversed(triples)),
        "c74-complement-lex": [tuple(index for index in range(7) if index not in triple) for triple in triples],
        "c74-complement-reversed": list(
            reversed([tuple(index for index in range(7) if index not in triple) for triple in triples])
        ),
    }
    models = 0

    for source_name, elements in WITTEVEEN_SOURCES.items():
        for case_name, routed in (("source-case", elements), ("lowercase", tuple(value.lower() for value in elements))):
            vectors_by_model = _element_vectors(routed)
            for vector_model, vectors in vectors_by_model.items():
                for block_order_name, ordered_blocks in block_orders.items():
                    for combo_order_name, combos in combo_orders.items():
                        models += 1
                        residuals: list[bytes] = []
                        for block_index, (block, combo) in enumerate(zip(ordered_blocks, combos)):
                            mask = _xor_bytes(*(vectors[index] for index in combo))
                            residual = _xor_bytes(block, mask)
                            residuals.append(residual)
                            gate.submit(
                                family,
                                f"{source_name}/{case_name}/{vector_model}/{block_order_name}/{combo_order_name}/"
                                f"block{block_index}/residual",
                                residual,
                            )
                            gate.submit(
                                family,
                                f"{source_name}/{case_name}/{vector_model}/{block_order_name}/{combo_order_name}/"
                                f"block{block_index}/block+mask",
                                _sum_mod_n(block, mask),
                            )
                        gate.submit(
                            family,
                            f"{source_name}/{case_name}/{vector_model}/{block_order_name}/{combo_order_name}/"
                            "xor-all-residuals",
                            _xor_bytes(*residuals),
                        )
                        gate.submit(
                            family,
                            f"{source_name}/{case_name}/{vector_model}/{block_order_name}/{combo_order_name}/"
                            "sha256-residual-stream",
                            _sha256(b"".join(residuals)),
                        )
                        for diagonal_index in range(7):
                            selected_blocks = [
                                ordered_blocks[index] for index, combo in enumerate(combos) if diagonal_index in combo
                            ]
                            selected_residuals = [
                                residuals[index] for index, combo in enumerate(combos) if diagonal_index in combo
                            ]
                            gate.submit(
                                family,
                                f"{source_name}/{case_name}/{vector_model}/{block_order_name}/{combo_order_name}/"
                                f"diag{diagonal_index}/xor-containing-blocks",
                                _xor_bytes(*selected_blocks),
                            )
                            gate.submit(
                                family,
                                f"{source_name}/{case_name}/{vector_model}/{block_order_name}/{combo_order_name}/"
                                f"diag{diagonal_index}/xor-containing-residuals",
                                _xor_bytes(*selected_residuals),
                            )
    return {
        "models": models,
        "source_count": len(WITTEVEEN_SOURCES),
        "combination": "35 Chain4 blocks mapped to C(7,3) triples and C(7,4) complements",
    }


def _triangle_rows(nodes: list[bytes], sizes: tuple[int, ...]) -> list[list[bytes]]:
    rows: list[list[bytes]] = []
    cursor = 0
    for size in sizes:
        rows.append(nodes[cursor : cursor + size])
        cursor += size
    return rows


def _submit_t5_hillone(gate: CandidateGate, blocks: list[bytes], trail: bytes) -> dict[str, object]:
    family = "t5_hillone_askhskey"
    witteveen = derive_witteveen()
    controls = {
        "hillone-askhskey": b"HILLONEASKHSKEY",
        "askhskey-hillone": b"ASKHSKEYHILLONE",
        "t5-qvygvcemufpkjbe": b"QVYGVCEMUFPKJBE",
        "t5-comps-rowsums": b"16,45,29,41,39",
        "t5-comps": b"COMPS",
        "witteveen-t5-controls": (
            "HILLONE|___OHICGFASKHSKEYTFMDJK|QVYGVCEMUFPKJBE|COMPS|WITVEEN".encode("ascii")
        ),
    }
    if witteveen["s570_controls"][0] != "HILLONE" or "ASKHSKEY" not in witteveen["s570_controls"][1]:
        raise AssertionError("unexpected WITTEVEEN control values")

    selected_indices = sorted(set(_triangular_indices(TRAIL_SIGNED + tuple(trail))))
    selected_blocks = [blocks[index] for index in selected_indices[:15]]
    while len(selected_blocks) < 15:
        selected_blocks.append(blocks[len(selected_blocks)])
    block_sets = {
        "chain4-first15": blocks[:15],
        "chain4-last15": blocks[-15:],
        "chain4-trail-triangular15": selected_blocks,
    }
    row_orders = {"rows1to5": (1, 2, 3, 4, 5), "rows5to1": (5, 4, 3, 2, 1)}
    models = 0

    for control_name, text in controls.items():
        expanded = text if len(text) >= 15 else _repeat_to_32(text)[:15]
        symbols = [bytes([byte]) for byte in expanded[:15]]
        vector_sets = _element_vectors(tuple(symbols))
        vector_sets["sha256-row-salted"] = tuple(
            _sha256(control_name.encode("ascii") + b":" + str(index).encode("ascii") + b":" + symbol)
            for index, symbol in enumerate(symbols)
        )
        for vector_model, nodes in vector_sets.items():
            gate.submit(family, f"{control_name}/{vector_model}/sha256-control", _sha256(text))
            for row_order_name, sizes in row_orders.items():
                rows = _triangle_rows(list(nodes), sizes)
                if row_order_name == "rows5to1":
                    rows = list(reversed(rows))
                models += 1
                for row_index, row in enumerate(rows):
                    gate.submit(
                        family,
                        f"{control_name}/{vector_model}/{row_order_name}/row{row_index}/xor",
                        _xor_bytes(*row),
                    )
                    gate.submit(
                        family,
                        f"{control_name}/{vector_model}/{row_order_name}/row{row_index}/sha256",
                        _sha256(b"".join(row)),
                    )
                residuals: list[bytes] = []
                for upper, lower in zip(rows, rows[1:]):
                    if len(lower) != len(upper) + 1:
                        continue
                    for index, parent in enumerate(upper):
                        residuals.append(_xor_bytes(parent, lower[index], lower[index + 1]))
                if residuals:
                    gate.submit(
                        family,
                        f"{control_name}/{vector_model}/{row_order_name}/xor-residuals",
                        _xor_bytes(*residuals),
                    )
                    gate.submit(
                        family,
                        f"{control_name}/{vector_model}/{row_order_name}/sha256-residuals",
                        _sha256(b"".join(residuals)),
                    )
                node_list = [node for row in rows for node in row]
                for block_set_name, selected in block_sets.items():
                    for index, (block, node) in enumerate(zip(selected, node_list)):
                        gate.submit(
                            family,
                            f"{control_name}/{vector_model}/{row_order_name}/{block_set_name}/node{index}/block^node",
                            _xor_bytes(block, node),
                        )
                    gate.submit(
                        family,
                        f"{control_name}/{vector_model}/{row_order_name}/{block_set_name}/xor-block-node-stream",
                        _xor_bytes(*(_xor_bytes(block, node) for block, node in zip(selected, node_list))),
                    )
    return {
        "models": models,
        "controls": list(controls),
        "block_sets": list(block_sets),
        "source": "HILLONE + ASKHSKEY controls from solver.witteveen_identity_audit",
    }


def _triangular_number(value: int) -> int:
    return value * (value + 1) // 2


def _triangular_indices(values: tuple[int, ...], modulo: int = 35) -> list[int]:
    indices: list[int] = []
    for value in values:
        variants = (
            value,
            abs(value),
            _triangular_number(value),
            _triangular_number(abs(value)),
            _triangular_number(value % modulo),
        )
        indices.extend(variant % modulo for variant in variants)
    for left, right in zip(values, values[1:]):
        indices.extend(
            (
                (_triangular_number(left) + right) % modulo,
                (_triangular_number(abs(left)) + abs(right)) % modulo,
                (_triangular_number(left % modulo) + right) % modulo,
            )
        )
    return indices


def _submit_trail_pairings(
    gate: CandidateGate, blocks: list[bytes], half: bytes, better: bytes, trail: bytes
) -> dict[str, object]:
    family = "trail_triangular_half_better_chain4"
    seeds = {
        "trail-signed": TRAIL_SIGNED,
        "trail-unsigned-bytes": tuple(trail),
        "formula-base": FORMULA_BASE,
        "formula-h42": (-4, 2, 32, 42, 4, 27, 0, 2, -16, 15),
        "formula-q82": (-4, 2, 32, 12, 4, 27, 0, 82, -16, 15),
        "formula-h42-q82": (-4, 2, 32, 42, 4, 27, 0, 82, -16, 15),
    }
    share_vectors = {
        "half": half,
        "better": better,
        "half^better": _xor_bytes(half, better),
        "trail-repeat": _repeat_to_32(trail),
        "sha256-trail": _sha256(trail),
    }
    unique_indices: dict[str, list[int]] = {}
    for seed_name, values in seeds.items():
        indices = _triangular_indices(values)
        deduped = list(dict.fromkeys(indices))
        unique_indices[seed_name] = deduped
        for index in deduped:
            block = blocks[index]
            gate.submit(family, f"{seed_name}/c4[{index}]", block)
            for share_name, share in share_vectors.items():
                gate.submit(family, f"{seed_name}/c4[{index}]^{share_name}", _xor_bytes(block, share))
                gate.submit(family, f"{seed_name}/c4[{index}]+{share_name}", _sum_mod_n(block, share))
                gate.submit(
                    family,
                    f"{seed_name}/sha256(c4[{index}]||{share_name})",
                    _sha256(block + share),
                )
                gate.submit(
                    family,
                    f"{seed_name}/sha256({share_name}||c4[{index}])",
                    _sha256(share + block),
                )
        for left, right in zip(deduped, deduped[1:]):
            pair_xor = _xor_bytes(blocks[left], blocks[right])
            pair_sum = _sum_mod_n(blocks[left], blocks[right])
            gate.submit(family, f"{seed_name}/c4[{left}]^c4[{right}]", pair_xor)
            gate.submit(family, f"{seed_name}/c4[{left}]+c4[{right}]", pair_sum)
            for share_name, share in share_vectors.items():
                gate.submit(family, f"{seed_name}/c4[{left}]^c4[{right}]^{share_name}", _xor_bytes(pair_xor, share))
                gate.submit(family, f"{seed_name}/c4[{left}]+c4[{right}]+{share_name}", _sum_mod_n(pair_sum, share))
    return {
        "seed_index_counts": {name: len(indices) for name, indices in unique_indices.items()},
        "seed_indices": unique_indices,
        "index_rule": "value, abs(value), T(value), T(abs(value)), T(value mod 35), and adjacent T+offset variants mod 35",
    }


def _formula_variants() -> dict[str, tuple[int, ...]]:
    return {
        "base": FORMULA_BASE,
        "h42": (-4, 2, 32, 42, 4, 27, 0, 2, -16, 15),
        "q82": (-4, 2, 32, 12, 4, 27, 0, 82, -16, 15),
        "h42-q82": (-4, 2, 32, 42, 4, 27, 0, 82, -16, 15),
    }


def _walk_bytes(data: bytes, start: int, strides: tuple[int, ...], count: int = 32) -> bytes:
    position = start % len(data)
    output = bytearray()
    for index in range(count):
        output.append(data[position])
        step = strides[index % len(strides)]
        position = (position + step) % len(data)
    return bytes(output)


def _edge_fold_bytes(data: bytes, start: int, edges: tuple[int, ...]) -> bytes:
    position = start % len(data)
    output = bytearray(32)
    for edge_index, edge in enumerate(edges):
        width = abs(edge) or 1
        chunk = bytearray()
        for offset in range(width):
            chunk.append(data[(position + offset) % len(data)])
        digest = _sha256(bytes(chunk))
        for index, byte in enumerate(digest):
            output[index] ^= byte
        position = (position + edge) % len(data)
        output[edge_index % 32] ^= width & 0xFF
    return bytes(output)


def _walk_matrix_bits(bits: tuple[int, ...], start: int, strides: tuple[int, ...]) -> bytes:
    row = (start // 103) % 103
    col = start % 103
    output: list[int] = []
    pairs = list(zip(strides[::2], strides[1::2]))
    if len(strides) % 2:
        pairs.append((strides[-1], strides[0]))
    for index in range(256):
        output.append(bits[row * 103 + col])
        dr, dc = pairs[index % len(pairs)]
        row = (row + dr) % 103
        col = (col + dc) % 103
    return _bits_to_bytes(output)


def _submit_cosmic_stride_edges(
    gate: CandidateGate, cosmic: bytes, matrix_bits: tuple[int, ...], trail: bytes
) -> dict[str, object]:
    family = "cosmic_formula_triangle_strides"
    starts = sorted(
        {
            0,
            31,
            32,
            35,
            68,
            103,
            158,
            246,
            833,
            865,
            103 * 103 // 8,
            int.from_bytes(trail, "big") % len(cosmic),
            int.from_bytes(trail, "little") % len(cosmic),
            *[value % len(cosmic) for value in trail],
            *[abs(value) % len(cosmic) for value in TRAIL_SIGNED],
            *[_triangular_number(abs(value)) % len(cosmic) for value in FORMULA_BASE],
        }
    )
    models = 0
    for variant_name, strides in _formula_variants().items():
        for direction_name, directed in (("forward", strides), ("reverse", tuple(reversed(strides)))):
            for start in starts:
                models += 1
                gate.submit(
                    family,
                    f"{variant_name}/{direction_name}/start{start}/byte-walk",
                    _walk_bytes(cosmic, start, directed),
                )
                gate.submit(
                    family,
                    f"{variant_name}/{direction_name}/start{start}/byte-walk-doubled",
                    _walk_bytes(cosmic, start, tuple(value * 2 if value else 1 for value in directed)),
                )
                gate.submit(
                    family,
                    f"{variant_name}/{direction_name}/start{start}/edge-fold",
                    _edge_fold_bytes(cosmic, start, directed),
                )
                gate.submit(
                    family,
                    f"{variant_name}/{direction_name}/start{start}/matrix-bit-walk",
                    _walk_matrix_bits(matrix_bits, start % (103 * 103), directed),
                )
    return {
        "models": models,
        "starts": starts,
        "sequence_variants": list(_formula_variants()),
        "sequence_note": "base sequence plus H=42 and/or Q=82 replacements",
    }


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)
    blocks = list(chain4.blocks)
    if matrix.trail1.hex() != "fc0c1b02":
        raise AssertionError(f"unexpected trail1 {matrix.trail1.hex()}")

    gate = CandidateGate()
    families = {
        "pascal_witteveen_c73": _submit_pascal_witteveen(gate, blocks),
        "t5_hillone_askhskey": _submit_t5_hillone(gate, blocks, matrix.trail1),
        "trail_triangular_half_better_chain4": _submit_trail_pairings(
            gate, blocks, matrix.half, matrix.better_half, matrix.trail1
        ),
        "cosmic_formula_triangle_strides": _submit_cosmic_stride_edges(
            gate, chains.cosmic_decryption.plaintext, matrix.matrix_bits, matrix.trail1
        ),
    }

    assert gate.family_generated is not None
    assert gate.family_unique is not None
    assert gate.matches is not None
    family_counts = {
        name: {
            "generated_candidates": gate.family_generated.get(name, 0),
            "unique_nonzero_candidates": gate.family_unique.get(name, 0),
            "metadata": metadata,
        }
        for name, metadata in families.items()
    }
    result: dict[str, object] = {
        "schema": "xor-triangle-trail-audit-v1",
        "status": "MATCH" if gate.matches else "NO_MATCH",
        "source": {
            "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
            "cosmic_sha256": hashlib.sha256(chains.cosmic_decryption.plaintext).hexdigest(),
            "trail1_hex": matrix.trail1.hex(),
            "trail1_signed": list(TRAIL_SIGNED),
            "formula_base": list(FORMULA_BASE),
            "formula_alternates": {"H": [12, 42], "Q": [2, 82], "S": 32, "B": -16},
        },
        "prize_addresses": PRIZE_ADDRESSES,
        "address_gate": "Every unique nonzero scalar is checked against both prize P2PKH addresses using compressed and uncompressed public keys.",
        "candidate_counts": {
            "generated": gate.generated,
            "unique_nonzero": gate.unique_nonzero,
            "duplicate_or_zero": gate.duplicate_or_zero,
        },
        "families": family_counts,
        "matches": gate.matches,
        "scope": (
            "Bounded XOR/triangular interpretations over reproduced Chain4/Cosmic data only; "
            "does not test unreproduced cosmic_A/row1-4/K_I1 claims."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(
        json.dumps(
            {
                "status": output["status"],
                "candidate_counts": output["candidate_counts"],
                "families": {
                    name: {
                        "generated_candidates": details["generated_candidates"],
                        "unique_nonzero_candidates": details["unique_nonzero_candidates"],
                    }
                    for name, details in output["families"].items()
                },
                "matches": output["matches"],
            },
            indent=2,
        )
    )
