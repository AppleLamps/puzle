"""Test the public L4 plaintext cribs as repeating-key XOR constraints."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .frontier_experiment import _target_match
from .salphaseion import derive_tokens


RESULT_PATH = ROOT / "l4_crib_audit.json"
CRIBS = {
    "prime_basics": b"REINSERTING THE PRIME BASICS",
    "private_key": b"please take the private key",
    "ciao_bella": b"CIAO BELLA O",
}
MIN_SHARED_CONSTRAINTS = 4
PRINTABLE_THRESHOLD = 0.85


def _constraints(ciphertext: bytes, crib: bytes, offset: int, period: int) -> dict[int, int] | None:
    result: dict[int, int] = {}
    for index, plain in enumerate(crib):
        key_index = (offset + index) % period
        value = ciphertext[offset + index] ^ plain
        if key_index in result and result[key_index] != value:
            return None
        result[key_index] = value
    return result


def _merge(left: dict[int, int], right: dict[int, int]) -> dict[int, int] | None:
    overlap = left.keys() & right.keys()
    if any(left[index] != right[index] for index in overlap):
        return None
    return left | right


def _printable_ratio(data: bytes) -> float:
    return sum(value in (9, 10, 13) or 32 <= value < 127 for value in data) / len(data)


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    ciphertext = chain4.decryption.plaintext
    consistent_pairs = 0
    full_period_keys: dict[bytes, dict[str, object]] = {}

    for period in range(1, 65):
        candidates: dict[str, list[tuple[int, dict[int, int]]]] = {}
        for name, crib in CRIBS.items():
            candidates[name] = [
                (offset, mapping)
                for offset in range(len(ciphertext) - len(crib) + 1)
                if (mapping := _constraints(ciphertext, crib, offset, period)) is not None
            ]

        names = list(CRIBS)
        for left_index, left_name in enumerate(names):
            for right_name in names[left_index + 1 :]:
                left_by_residue: dict[int, list[tuple[int, dict[int, int]]]] = defaultdict(list)
                right_by_residue: dict[int, list[tuple[int, dict[int, int]]]] = defaultdict(list)
                for offset, mapping in candidates[left_name]:
                    left_by_residue[offset % period].append((offset, mapping))
                for offset, mapping in candidates[right_name]:
                    right_by_residue[offset % period].append((offset, mapping))
                for left_candidates in left_by_residue.values():
                    for right_candidates in right_by_residue.values():
                        overlap_indexes = left_candidates[0][1].keys() & right_candidates[0][1].keys()
                        if len(overlap_indexes) < MIN_SHARED_CONSTRAINTS:
                            continue
                        signature = tuple(sorted(overlap_indexes))
                        right_index: dict[tuple[int, ...], list[tuple[int, dict[int, int]]]] = defaultdict(list)
                        for right_offset, right_map in right_candidates:
                            right_index[tuple(right_map[index] for index in signature)].append((right_offset, right_map))
                        for left_offset, left_map in left_candidates:
                            left_values = tuple(left_map[index] for index in signature)
                            for right_offset, right_map in right_index.get(left_values, ()):
                                merged = _merge(left_map, right_map)
                                assert merged is not None
                                consistent_pairs += 1
                                placements = {left_name: left_offset, right_name: right_offset}
                                merged_variants = [(merged, placements)]
                                if len(merged) < period:
                                    third_name = next(name for name in names if name not in placements)
                                    merged_variants = []
                                    for third_offset, third_map in candidates[third_name]:
                                        extended = _merge(merged, third_map)
                                        if extended is not None:
                                            merged_variants.append((extended, placements | {third_name: third_offset}))
                                for complete, complete_placements in merged_variants:
                                    if len(complete) != period:
                                        continue
                                    key = bytes(complete[index] for index in range(period))
                                    decrypted = bytes(value ^ key[index % period] for index, value in enumerate(ciphertext))
                                    ratio = _printable_ratio(decrypted)
                                    entry = full_period_keys.setdefault(
                                        key,
                                        {
                                            "period": period,
                                            "key_hex": key.hex(),
                                            "key_sha256": hashlib.sha256(key).hexdigest(),
                                            "placements": [],
                                            "printable_ratio": ratio,
                                            "plaintext_sha256": hashlib.sha256(decrypted).hexdigest(),
                                            "passes_language_gate": ratio >= PRINTABLE_THRESHOLD,
                                            "exact_target_if_32_bytes": period == 32 and _target_match(int.from_bytes(key, "big")),
                                        },
                                    )
                                    if len(entry["placements"]) < 8:
                                        entry["placements"].append(complete_placements)

    recovered = list(full_period_keys.values())
    language_survivors = [entry for entry in recovered if entry["passes_language_gate"]]
    target_matches = [entry for entry in recovered if entry["exact_target_if_32_bytes"]]
    result: dict[str, object] = {
        "status": "SURVIVOR" if language_survivors or target_matches else "NO_REPEATING_XOR_CRIB_SURVIVOR",
        "chain4_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "periods_tested": [1, 64],
        "cribs": {name: crib.decode("ascii") for name, crib in CRIBS.items()},
        "minimum_shared_key_constraints": MIN_SHARED_CONSTRAINTS,
        "printable_threshold": PRINTABLE_THRESHOLD,
        "consistent_crib_pairs": consistent_pairs,
        "unique_full_period_keys": len(recovered),
        "language_survivors": language_survivors,
        "target_matches": target_matches,
        "scope_note": "This tests exact-case quoted cribs under repeating-byte XOR only. It does not test Beaufort, VIC, transposition, or approximate plaintext variants.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
