"""Test all ordered, non-repeating trail1 byte selections as Chain 4 prefix completions."""

from __future__ import annotations

import hashlib
import itertools
import json

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .frontier_experiment import TARGET_X, TARGET_Y, _target_match
from .salphaseion import derive_tokens
from .secp256k1_verify import N, p2pkh_address


RESULT_PATH = ROOT / "trail1_permutation_experiment.json"
TARGET_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)
    trail = matrix.trail1

    words: dict[str, bytes] = {}
    for selection_length, operand_name, operand in (
        (2, "opcode_operand30", chain4.opcode_operand),
        (3, "marker_operand29", chain4.operand),
    ):
        for indexes in itertools.permutations(range(len(trail)), selection_length):
            fragment = bytes(trail[index] for index in indexes)
            index_label = ",".join(map(str, indexes))
            words[f"trail1[{index_label}] || {operand_name}"] = fragment + operand
            words[f"{operand_name} || trail1[{index_label}]"] = operand + fragment
    if len(words) != 72 or any(len(word) != 32 for word in words.values()):
        raise AssertionError("the permutation family must contain 72 distinct 32-byte words")

    seen: set[int] = set()
    matches: list[dict[str, object]] = []
    generated = 0

    def submit(value: int, word_label: str, operation: str, block_index: int | None) -> None:
        nonlocal generated
        generated += 1
        value %= N
        if not value or value in seen:
            return
        seen.add(value)
        if not _target_match(value):
            return
        private_key = value.to_bytes(32, "big")
        addresses = {
            "uncompressed": p2pkh_address(private_key, False),
            "compressed": p2pkh_address(private_key, True),
        }
        if TARGET_ADDRESS not in addresses.values():
            raise AssertionError("full target point matched but target address did not")
        matches.append(
            {
                "word": word_label,
                "operation": operation,
                "block_index": block_index,
                "private_hex": private_key.hex(),
                "addresses": addresses,
            }
        )

    for word_label, word in words.items():
        word_int = int.from_bytes(word, "big")
        submit(word_int, word_label, "word", None)
        for block_index, block in enumerate(chain4.blocks):
            block_int = int.from_bytes(block, "big")
            submit(word_int + block_int, word_label, "word + block", block_index)
            submit(word_int - block_int, word_label, "word - block", block_index)
            submit(block_int - word_int, word_label, "block - word", block_index)
            submit(int.from_bytes(_xor(word, block), "big"), word_label, "word XOR block", block_index)

    result: dict[str, object] = {
        "status": "MATCH" if matches else "NO_MATCH_IN_BOUNDED_FAMILY",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "trail1_hex": trail.hex(),
        "selection_rule": "ordered byte selections without replacement",
        "word_count": len(words),
        "block_count": len(chain4.blocks),
        "generated_candidates": generated,
        "unique_nonzero_scalars": len(seen),
        "words": {label: word.hex() for label, word in words.items()},
        "operations": ["word", "word + block", "word - block", "block - word", "word XOR block"],
        "target": {
            "x": f"{TARGET_X:064x}",
            "y": f"{TARGET_Y:064x}",
            "address": TARGET_ADDRESS,
        },
        "matches": matches,
        "scope_note": "This falsifies only the exact ordered non-repeating trail1 completion family documented in VERIFICATION_REPORT.md.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
