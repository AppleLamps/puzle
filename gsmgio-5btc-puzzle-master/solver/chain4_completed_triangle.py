"""Test the exact 36-word XOR triangle formed by completing Chain 4's 31-byte prefix."""

from __future__ import annotations

import hashlib
import itertools
import json

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .frontier_experiment import _target_match
from .salphaseion import derive_tokens
from .xor_triangle_audit import ZERO, bxor


RESULT_PATH = ROOT / "chain4_completed_triangle.json"


def _residuals(rows: list[list[bytes]]) -> list[bytes]:
    residuals: list[bytes] = []
    for parent, child in zip(rows, rows[1:]):
        for index, node in enumerate(parent):
            residuals.append(bxor(node, bxor(child[index], child[index + 1])))
    return residuals


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)
    prefix = chain4.structured_prefix
    completions: dict[str, bytes] = {}
    for index, value in enumerate(matrix.trail1):
        byte = bytes([value])
        completions[f"trail1[{index}] || prefix31"] = byte + prefix
        completions[f"prefix31 || trail1[{index}]"] = prefix + byte
    if len(completions) != 8 or any(len(word) != 32 for word in completions.values()):
        raise AssertionError("expected eight distinct 32-byte prefix completions")

    attempted = 0
    exact_layouts: list[dict[str, object]] = []
    target_words: list[dict[str, object]] = []
    minimum_nonzero_residuals = 36
    closest_layout_count = 0
    closest_layouts: list[dict[str, object]] = []

    for completion_label, completion in completions.items():
        serialized = [completion, *chain4.blocks]
        for serialized_lengths in (tuple(range(1, 9)), tuple(range(8, 0, -1))):
            split: list[list[bytes]] = []
            offset = 0
            for length in serialized_lengths:
                split.append(serialized[offset : offset + length])
                offset += length
            if serialized_lengths[0] == 8:
                split.reverse()
            for reversals in itertools.product((False, True), repeat=8):
                attempted += 1
                rows = [row[::-1] if reverse else row for row, reverse in zip(split, reversals)]
                residuals = _residuals(rows)
                nonzero = sum(value != ZERO for value in residuals)
                descriptor = {
                    "completion": completion_label,
                    "serialized_lengths": list(serialized_lengths),
                    "row_reversals": [int(value) for value in reversals],
                    "nonzero_residuals": nonzero,
                }
                if nonzero < minimum_nonzero_residuals:
                    minimum_nonzero_residuals = nonzero
                    closest_layout_count = 1
                    closest_layouts = [descriptor]
                elif nonzero == minimum_nonzero_residuals:
                    closest_layout_count += 1
                    if len(closest_layouts) < 8:
                        closest_layouts.append(descriptor)
                if nonzero == 0:
                    exact_layouts.append(descriptor)

        for position, word in enumerate(serialized):
            if _target_match(int.from_bytes(word, "big")):
                target_words.append(
                    {"completion": completion_label, "serialized_position": position, "private_hex": word.hex()}
                )

    result: dict[str, object] = {
        "status": "EXACT_LAYOUT_FOUND" if exact_layouts else "NO_EXACT_LAYOUT",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "trail1_hex": matrix.trail1.hex(),
        "completion_count": len(completions),
        "attempted_layouts": attempted,
        "recurrence": "parent[j] = child[j] XOR child[j+1]",
        "serialized_row_orders": [list(range(1, 9)), list(range(8, 0, -1))],
        "independent_row_reversals": 256,
        "completions": {label: word.hex() for label, word in completions.items()},
        "minimum_nonzero_residuals": minimum_nonzero_residuals,
        "closest_layout_count": closest_layout_count,
        "closest_layout_examples": closest_layouts,
        "exact_layouts": exact_layouts,
        "target_words": target_words,
        "scope_note": "This exhausts the direct one-byte trail1 completion of the 31-byte prefix as a serialized T8 XOR triangle.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
