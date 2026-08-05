"""Falsify the published missing-node eight-row XOR-triangle interpretation."""

from __future__ import annotations

import hashlib
import itertools
import json

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .salphaseion import derive_tokens


RESULT_PATH = ROOT / "xor_triangle_audit.json"
ZERO = bytes(32)


def bxor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def solve(rows: list[list[tuple[bytes, int]]]) -> tuple[bytes | None, bool]:
    unknown = None
    for upper, lower in zip(rows, rows[1:]):
        for index, node in enumerate(upper):
            constant = bxor(node[0], bxor(lower[index][0], lower[index + 1][0]))
            coefficient = node[1] ^ lower[index][1] ^ lower[index + 1][1]
            if coefficient:
                if unknown is None:
                    unknown = constant
                elif unknown != constant:
                    return None, False
            elif constant != ZERO:
                return None, False
    return unknown, True


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    blocks = list(chain4.blocks)
    attempted = 0
    survivors = []
    for serialized_lengths in (tuple(range(1, 9)), tuple(range(8, 0, -1))):
        for insertion in range(36):
            nodes: list[tuple[bytes, int]] = [(block, 0) for block in blocks]
            nodes.insert(insertion, (ZERO, 1))
            split = []
            offset = 0
            for length in serialized_lengths:
                split.append(nodes[offset : offset + length])
                offset += length
            if serialized_lengths[0] == 8:
                split.reverse()
            for reversals in itertools.product((False, True), repeat=8):
                attempted += 1
                rows = [row[::-1] if reverse else row for row, reverse in zip(split, reversals)]
                missing, consistent = solve(rows)
                if consistent and missing is not None:
                    survivors.append(
                        {
                            "serialized_lengths": serialized_lengths,
                            "insertion": insertion,
                            "row_reversals": tuple(int(value) for value in reversals),
                            "missing_hex": missing.hex(),
                        }
                    )
    result: dict[str, object] = {
        "status": "NO_EXACT_SURVIVOR" if not survivors else "SURVIVORS_FOUND",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "attempted_layouts": attempted,
        "recurrence": "parent[j] = child[j] XOR child[j+1]",
        "serialized_row_orders": [list(range(1, 9)), list(range(8, 0, -1))],
        "insertion_positions": 36,
        "independent_row_reversals": 256,
        "exact_triangle_survivors": survivors,
        "scope_note": "This falsifies only the exact serialized T8 missing-node family, not every possible XOR triangle.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))

