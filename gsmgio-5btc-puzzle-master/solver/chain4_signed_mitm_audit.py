"""Exhaust the literal +/- interpretation of the 35 Chain 4 blocks.

For signs s_i in {-1,+1}, write A for the indices assigned +1.  Then

    constant + sum(s_i * block_i)
      = constant - sum(block_i) + 2 * sum(block_i for i in A).

This turns the complete 2^35 sign space into an ordinary subset-sum search
over doubled block scalars, allowing the checkpointed point-space MITM engine
to test the full family without enumerating every scalar explicitly.
"""

from __future__ import annotations

import json
import hashlib

from coincurve import PrivateKey

from .chain4 import reconstruct_chain4
from .chain4_mitm_audit import (
    TARGET_ADDRESS,
    TARGET_COMPRESSED,
    _point_from_scalar,
    _point_from_compressed,
    _point_key,
    _shifted_target,
    run_family,
)
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .salphaseion import derive_tokens
from .secp256k1_verify import N


RESULT_PATH = ROOT / "chain4_signed_mitm_audit.json"


def _signed_targets(target, block_total: int, constants: dict[str, int]):
    """Build subset targets for k = constant + sum(+/- block_i)."""
    targets = {}
    for label, constant in constants.items():
        adjustment = (constant - block_total) % N
        targets[label] = (_shifted_target(target, adjustment), adjustment)
    return targets


def run(*, force: bool = False) -> dict[str, object]:
    sal = derive_tokens()
    chains = reconstruct(extract_all(), sal)
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)

    blocks = [int.from_bytes(block, "big") % N for block in chain4.blocks]
    doubled = [(2 * value) % N for value in blocks]
    labels = [f"2*block_{index:02d}" for index in range(len(blocks))]
    block_total = sum(blocks) % N
    target = _point_from_compressed(TARGET_COMPRESSED)

    operand = int.from_bytes(chain4.opcode_operand, "big") % N
    magnitude = int.from_bytes(chain4.operand, "big") % N
    prefix = int.from_bytes(chain4.structured_prefix, "big") % N
    half = int.from_bytes(matrix.half, "big") % N
    better = int.from_bytes(matrix.better_half, "big") % N

    literal_constants = {
        "c=0": 0,
        "c=+operand30": operand,
        "c=-operand30": -operand,
        "c=+magnitude29": magnitude,
        "c=-magnitude29": -magnitude,
        "c=+prefix31": prefix,
        "c=-prefix31": -prefix,
    }
    cross_branch_constants = {
        "c=+Half": half,
        "c=-Half": -half,
        "c=+Better": better,
        "c=-Better": -better,
        "c=+Half+Better": half + better,
        "c=+Half-Better": half - better,
        "c=-Half+Better": -half + better,
        "c=-Half-Better": -half - better,
    }

    # Positive control for the signed reduction itself, separate from the
    # generic subset control in solver.chain4_mitm_audit.
    control_blocks = [1 << index for index in range(12)]
    control_plus = [0, 3, 7, 11]
    control_constant = 19
    control_total = sum(control_blocks) % N
    control_scalar = (
        control_constant
        + sum(control_blocks[index] for index in control_plus)
        - sum(control_blocks[index] for index in range(12) if index not in control_plus)
    ) % N
    control_point = _point_from_scalar(control_scalar)
    if control_point is None:
        raise ValueError("signed MITM control unexpectedly produced zero")
    control = run_family(
        "signed_synthetic_positive_control",
        [(2 * value) % N for value in control_blocks],
        [f"2*power2_{index}" for index in range(12)],
        {
            "known_sign_pattern": (
                _shifted_target(control_point, (control_constant - control_total) % N),
                (control_constant - control_total) % N,
            )
        },
        expected_point=_point_key(control_point),
        expected_address=None,
        checkpoint_interval=64,
        force=force,
    )
    control_matches = [match for match in control["matches"] if match["accepted"]]
    if not control_matches or control_matches[0]["selected_indices"] != control_plus:
        raise ValueError("signed MITM positive control failed")

    literal = run_family(
        "S1_signed_blocks35_literal_constants",
        doubled,
        labels,
        _signed_targets(target, block_total, literal_constants),
        force=force,
    )
    cross_branch = run_family(
        "S2_signed_blocks35_half_better_constants",
        doubled,
        labels,
        _signed_targets(target, block_total, cross_branch_constants),
        force=force,
    )

    accepted = []
    for family_name, manifest in (("S1", literal), ("S2", cross_branch)):
        for match in manifest["matches"]:
            if match["accepted"]:
                plus = list(match["selected_indices"])
                plus_set = set(plus)
                accepted.append(
                    {
                        "family": family_name,
                        **match,
                        "plus_block_indices": plus,
                        "minus_block_indices": [index for index in range(35) if index not in plus_set],
                    }
                )

    result: dict[str, object] = {
        "status": "MATCH" if accepted else "COMPLETE_NO_MATCH",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "identity": "c + sum(s_i*b_i) = c - sum(b_i) + sum_{i in A}(2*b_i)",
        "block_count": len(blocks),
        "logical_sign_patterns_per_constant": str(1 << len(blocks)),
        "literal_constant_count": len(literal_constants),
        "cross_branch_constant_count": len(cross_branch_constants),
        "literal_constants_hex": {label: f"{value % N:064x}" for label, value in literal_constants.items()},
        "cross_branch_constants_hex": {
            label: f"{value % N:064x}" for label, value in cross_branch_constants.items()
        },
        "families": {"S1_literal": literal, "S2_cross_branch": cross_branch},
        "positive_control": {
            "plus_indices": control_plus,
            "recovered": True,
            "private_hex": f"{control_scalar:064x}",
            "compressed_point": PrivateKey.from_int(control_scalar).public_key.format(compressed=True).hex(),
        },
        "accepted_matches": accepted,
        "target": {"compressed_point": TARGET_COMPRESSED.hex(), "address": TARGET_ADDRESS},
        "scope_note": (
            "This exhausts every +/- assignment of all 35 aligned Chain 4 blocks with the listed constants. "
            "It does not cover omission of blocks, nonlinear operations, or unlisted external operands."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
