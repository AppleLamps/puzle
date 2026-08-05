"""Audit Chain 4 blocks as secp256k1 x-coordinates, with exact point gates."""

from __future__ import annotations

import hashlib
import itertools
import json

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import P, point_add, scalar_multiply


RESULT_PATH = ROOT / "chain4_xcoordinate_audit.json"
TARGET_POINT = (TARGET_X, TARGET_Y)


def _negate(point: tuple[int, int] | None) -> tuple[int, int] | None:
    return None if point is None else (point[0], (-point[1]) % P)


def _lift_x(x: int) -> tuple[tuple[int, int], tuple[int, int]] | None:
    if not 0 <= x < P:
        return None
    square = (pow(x, 3, P) + 7) % P
    y = pow(square, (P + 1) // 4, P)
    if y * y % P != square:
        return None
    return (x, y), (x, (-y) % P)


def _sum_points(points: tuple[tuple[int, int], ...]) -> tuple[int, int] | None:
    total = None
    for point in points:
        total = point_add(total, point)
    return total


def _enumerate_relations(
    lifts: list[dict[str, object]],
    shifts: dict[str, tuple[int, int] | None],
    target: tuple[int, int],
    maximum_terms: int = 3,
) -> tuple[dict[str, int], list[dict[str, object]]]:
    counts: dict[str, int] = {}
    matches: list[dict[str, object]] = []
    for term_count in range(1, maximum_terms + 1):
        tested = 0
        for selected in itertools.combinations(lifts, term_count):
            # Select block indices first and then signs. This intentionally
            # excludes the historical script's P + (-P) use of one block.
            for signs in itertools.product((1, -1), repeat=term_count):
                signed_points = tuple(
                    item["positive"] if sign == 1 else item["negative"]
                    for item, sign in zip(selected, signs)
                )
                base = _sum_points(signed_points)
                for shift_name, shift in shifts.items():
                    tested += 1
                    if point_add(base, shift) == target:
                        matches.append({
                            "term_count": term_count,
                            "block_indices": [item["index"] for item in selected],
                            "signs": ["+" if sign == 1 else "-" for sign in signs],
                            "shift": shift_name,
                        })
        counts[str(term_count)] = tested
    return counts, matches


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)

    lifts: list[dict[str, object]] = []
    invalid_indices: list[int] = []
    for index, block in enumerate(chain4.blocks):
        lifted = _lift_x(int.from_bytes(block, "big"))
        if lifted is None:
            invalid_indices.append(index)
            continue
        positive, negative = lifted
        if point_add(positive, negative) is not None:
            raise ValueError("x-coordinate lift inverse control failed")
        lifts.append({
            "index": index,
            "x_hex": block.hex(),
            "positive_y_hex": f"{positive[1]:064x}",
            "negative_y_hex": f"{negative[1]:064x}",
            "positive": positive,
            "negative": negative,
        })

    scalar_shifts = {
        "operand": int.from_bytes(chain4.opcode_operand, "big"),
        "magnitude": int.from_bytes(chain4.operand, "big"),
        "prefix": int.from_bytes(chain4.structured_prefix, "big"),
        "Half": int.from_bytes(matrix.half, "big"),
        "Better_Half": int.from_bytes(matrix.better_half, "big"),
    }
    shifts: dict[str, tuple[int, int] | None] = {"none": None}
    for name, scalar in scalar_shifts.items():
        point = scalar_multiply(scalar)
        shifts[f"+{name}"] = point
        shifts[f"-{name}"] = _negate(point)

    counts, matches = _enumerate_relations(lifts, shifts, TARGET_POINT)

    if len(lifts) < 3:
        raise ValueError("not enough valid block x-coordinates for positive control")
    control_selection = (lifts[0], lifts[1], lifts[2])
    control_target = point_add(
        _sum_points((control_selection[0]["positive"], control_selection[1]["negative"], control_selection[2]["positive"])),
        shifts["+Half"],
    )
    if control_target is None:
        raise ValueError("synthetic x-coordinate control unexpectedly reached infinity")
    control_counts, control_matches = _enumerate_relations(lifts[:3], shifts, control_target)
    expected_control = {
        "term_count": 3,
        "block_indices": [item["index"] for item in control_selection],
        "signs": ["+", "-", "+"],
        "shift": "+Half",
    }
    if expected_control not in control_matches:
        raise ValueError("synthetic x-coordinate positive control was not recovered")

    serializable_lifts = [
        {key: value for key, value in item.items() if key not in {"positive", "negative"}}
        for item in lifts
    ]
    result: dict[str, object] = {
        "status": "POINT_RELATION_FOUND" if matches else "COMPLETE_NO_POINT_RELATION",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "interpretation": "each aligned 32-byte Chain 4 block is tested as a field x-coordinate, not as a private scalar",
        "valid_x_coordinate_count": len(lifts),
        "invalid_x_coordinate_count": len(invalid_indices),
        "invalid_block_indices": invalid_indices,
        "valid_lifts": serializable_lifts,
        "shift_scalars_hex": {name: f"{value:064x}" for name, value in scalar_shifts.items()},
        "shift_count": len(shifts),
        "candidate_counts_by_term_count": counts,
        "total_candidate_relations": sum(counts.values()),
        "point_relation_matches": matches,
        "synthetic_positive_control": {
            "candidate_counts_by_term_count": control_counts,
            "expected_match": expected_control,
            "recovered": True,
        },
        "accepted_private_scalars": [],
        "evidence_limit": "A point relation would not reveal the discrete logarithms of lifted x-coordinate points and therefore would not by itself recover the prize private scalar.",
        "historical_correction": "Combinations are over distinct block indices before sign assignment; this excludes selecting both y lifts of the same block as separate terms.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"],
        "valid_x_coordinate_count": output["valid_x_coordinate_count"],
        "candidate_counts_by_term_count": output["candidate_counts_by_term_count"],
        "total_candidate_relations": output["total_candidate_relations"],
        "point_relation_matches": output["point_relation_matches"],
    }, indent=2))
