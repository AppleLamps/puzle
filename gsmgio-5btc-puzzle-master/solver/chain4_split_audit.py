"""Test whether the reported Chain 4 byte-246 entropy boundary is exceptional."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import random

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .salphaseion import derive_tokens


RESULT_PATH = ROOT / "chain4_split_audit.json"
SPLIT = 246
PERMUTATIONS = 10_000
SEED = 0x47534D47


def _entropy(data: bytes | list[int]) -> float:
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    plaintext = chain4.decryption.plaintext
    head = plaintext[:SPLIT]
    tail = plaintext[SPLIT:]
    head_entropy = _entropy(head)
    tail_entropy = _entropy(tail)
    observed_delta = tail_entropy - head_entropy

    rng = random.Random(SEED)
    shuffled = list(plaintext)
    greater_or_equal = 0
    simulated_sum = 0.0
    for _ in range(PERMUTATIONS):
        rng.shuffle(shuffled)
        delta = _entropy(shuffled[SPLIT:]) - _entropy(shuffled[:SPLIT])
        simulated_sum += delta
        if delta >= observed_delta:
            greater_or_equal += 1
    p_value = (greater_or_equal + 1) / (PERMUTATIONS + 1)

    result: dict[str, object] = {
        "status": "NO_FIXED_SPLIT_ENTROPY_EVIDENCE" if p_value >= 0.05 else "ENTROPY_DIFFERENCE_DETECTED",
        "chain4_sha256": hashlib.sha256(plaintext).hexdigest(),
        "split_offset": SPLIT,
        "head_length": len(head),
        "tail_length": len(tail),
        "head_sha256": hashlib.sha256(head).hexdigest(),
        "tail_sha256": hashlib.sha256(tail).hexdigest(),
        "head_plugin_entropy_bits_per_byte": head_entropy,
        "tail_plugin_entropy_bits_per_byte": tail_entropy,
        "observed_entropy_delta": observed_delta,
        "permutation_count": PERMUTATIONS,
        "permutation_seed": SEED,
        "permutation_mean_delta": simulated_sum / PERMUTATIONS,
        "permutations_at_least_observed": greater_or_equal,
        "one_sided_permutation_p_value": p_value,
        "block_alignment_remainder": (SPLIT - 31) % 32,
        "scope_note": "The fixed-size permutation test preserves the complete byte multiset. It tests only the reported Shannon-entropy contrast, not every possible structure at byte 246.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
