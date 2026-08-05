"""Checkpointed point-space MITM closure for additive Chain 4 selections."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time

from coincurve import PrivateKey, PublicKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160, public_key


RESULT_PATH = ROOT / "chain4_mitm_audit.json"
CHECKPOINTS = ROOT / "artifacts" / "mitm_checkpoints"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")
INF_KEY = b"\0"
ENGINE_VERSION = 1


def _point_from_scalar(scalar: int) -> PublicKey | None:
    scalar %= N
    return None if scalar == 0 else PrivateKey.from_int(scalar).public_key


def _point_from_compressed(encoded: bytes) -> PublicKey:
    return PublicKey(encoded)


def _negate(point: PublicKey | None) -> PublicKey | None:
    if point is None:
        return None
    encoded = point.format(compressed=True)
    return PublicKey(bytes([5 - encoded[0]]) + encoded[1:])


def _add(left: PublicKey | None, right: PublicKey | None) -> PublicKey | None:
    if left is None:
        return right
    if right is None:
        return left
    try:
        return PublicKey.combine_keys((left, right))
    except ValueError:
        return None


def _point_key(point: PublicKey | None) -> bytes:
    return INF_KEY if point is None else point.format(compressed=True)


def _point_for_mask(points: list[PublicKey], mask: int) -> PublicKey | None:
    selected = [point for index, point in enumerate(points) if (mask >> index) & 1]
    if not selected:
        return None
    if len(selected) == 1:
        return selected[0]
    return PublicKey.combine_keys(selected)


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _input_digest(
    family: str,
    scalars: list[int],
    scalar_labels: list[str],
    targets: dict[str, tuple[PublicKey, int]],
    expected_point: bytes,
) -> str:
    record = {
        "engine_version": ENGINE_VERSION,
        "family": family,
        "scalars": [f"{value % N:064x}" for value in scalars],
        "scalar_labels": scalar_labels,
        "targets": {
            label: {
                "point": _point_key(point).hex(),
                "full_scalar_adjustment": f"{adjustment % N:064x}",
            }
            for label, (point, adjustment) in targets.items()
        },
        "expected_point": expected_point.hex(),
    }
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def _build_half_table(points: list[PublicKey]) -> tuple[dict[bytes, int], int]:
    table: dict[bytes, int] = {INF_KEY: 0}
    collisions = 0
    current: PublicKey | None = None
    previous_gray = 0
    for sequence in range(1, 1 << len(points)):
        gray = sequence ^ (sequence >> 1)
        changed = gray ^ previous_gray
        bit = changed.bit_length() - 1
        current = _add(current, points[bit] if (gray >> bit) & 1 else _negate(points[bit]))
        key = _point_key(current)
        if key in table:
            collisions += 1
        else:
            table[key] = gray
        previous_gray = gray
    return table, collisions


def _verify_collision(
    scalars: list[int],
    scalar_labels: list[str],
    left_mask: int,
    right_mask: int,
    left_size: int,
    target_label: str,
    adjustment: int,
    target_point: PublicKey,
    expected_point: bytes,
    expected_address: str | None,
) -> dict[str, object]:
    selected_indices = [index for index in range(left_size) if (left_mask >> index) & 1]
    selected_indices.extend(
        left_size + index
        for index in range(len(scalars) - left_size)
        if (right_mask >> index) & 1
    )
    subset_scalar = sum(scalars[index] for index in selected_indices) % N
    subset_point = _point_from_scalar(subset_scalar)
    shifted_point_verified = _point_key(subset_point) == _point_key(target_point)
    full_scalar = (subset_scalar + adjustment) % N
    full_point = _point_from_scalar(full_scalar)
    full_point_verified = _point_key(full_point) == expected_point
    address: str | None = None
    address_verified: bool | None = None
    if full_scalar:
        uncompressed = PrivateKey.from_int(full_scalar).public_key.format(compressed=False)
        address = base58check(b"\0" + hash160(uncompressed))
        address_verified = None if expected_address is None else address == expected_address
    return {
        "target_shift": target_label,
        "selected_indices": selected_indices,
        "selected_labels": [scalar_labels[index] for index in selected_indices],
        "subset_size": len(selected_indices),
        "subset_scalar_hex": f"{subset_scalar:064x}",
        "full_scalar_adjustment_hex": f"{adjustment % N:064x}",
        "full_private_hex": f"{full_scalar:064x}",
        "shifted_point_verified": shifted_point_verified,
        "full_point_verified": full_point_verified,
        "address": address,
        "address_verified": address_verified,
        "accepted": shifted_point_verified and full_point_verified and (expected_address is None or address_verified is True),
    }


def _validate_complete_manifest(
    manifest: dict[str, object],
    scalars: list[int],
    scalar_labels: list[str],
    targets: dict[str, tuple[PublicKey, int]],
    expected_point: bytes,
    expected_address: str | None,
) -> None:
    left_size = len(scalars) // 2
    expected_left = 1 << left_size
    expected_right = 1 << (len(scalars) - left_size)
    expected_space = (1 << len(scalars)) * len(targets)
    invariants = {
        "scalar_count": len(scalars),
        "scalar_labels": scalar_labels,
        "left_subset_count": expected_left,
        "right_subset_count": expected_right,
        "target_count": len(targets),
        "logical_candidate_space": str(expected_space),
        "next_right_subset": expected_right,
    }
    for field, expected in invariants.items():
        if manifest.get(field) != expected:
            raise ValueError(f"completed MITM manifest has invalid {field}: {manifest.get(field)!r} != {expected!r}")
    matches = list(manifest.get("matches", []))
    accepted = 0
    for stored in matches:
        indices = list(stored["selected_indices"])
        if indices != sorted(set(indices)) or any(not 0 <= index < len(scalars) for index in indices):
            raise ValueError("completed MITM manifest contains invalid subset indices")
        target_label = str(stored["target_shift"])
        if target_label not in targets:
            raise ValueError("completed MITM manifest references an unknown target shift")
        target_point, adjustment = targets[target_label]
        subset_scalar = sum(scalars[index] for index in indices) % N
        full_scalar = (subset_scalar + adjustment) % N
        shifted_ok = _point_key(_point_from_scalar(subset_scalar)) == _point_key(target_point)
        full_ok = _point_key(_point_from_scalar(full_scalar)) == expected_point
        address_ok: bool | None = None
        if full_scalar:
            uncompressed = PrivateKey.from_int(full_scalar).public_key.format(compressed=False)
            address = base58check(b"\0" + hash160(uncompressed))
            address_ok = None if expected_address is None else address == expected_address
        accepted_now = shifted_ok and full_ok and (expected_address is None or address_ok is True)
        if stored.get("subset_scalar_hex") != f"{subset_scalar:064x}" or stored.get("full_private_hex") != f"{full_scalar:064x}":
            raise ValueError("completed MITM manifest collision scalar does not rederive")
        if bool(stored.get("accepted")) != accepted_now:
            raise ValueError("completed MITM manifest collision acceptance does not reverify")
        accepted += int(accepted_now)
    if manifest.get("accepted_matches") != accepted:
        raise ValueError("completed MITM manifest accepted-match count is inconsistent")


def run_family(
    family: str,
    scalars: list[int],
    scalar_labels: list[str],
    targets: dict[str, tuple[PublicKey, int]],
    *,
    expected_point: bytes = TARGET_COMPRESSED,
    expected_address: str | None = TARGET_ADDRESS,
    checkpoint_interval: int = 1 << 17,
    force: bool = False,
) -> dict[str, object]:
    if len(scalars) != len(scalar_labels) or any(value % N == 0 for value in scalars):
        raise ValueError("MITM scalar inputs must be labeled, nonzero curve scalars")
    checkpoint = CHECKPOINTS / f"{family}.json"
    digest = _input_digest(family, scalars, scalar_labels, targets, expected_point)
    existing: dict[str, object] = {}
    if checkpoint.exists() and not force:
        existing = json.loads(checkpoint.read_text(encoding="utf-8"))
        if existing.get("input_sha256") != digest:
            raise ValueError(f"checkpoint input mismatch for {family}")
        if existing.get("status") == "COMPLETE":
            _validate_complete_manifest(existing, scalars, scalar_labels, targets, expected_point, expected_address)
            return existing

    started = time.perf_counter()
    points = [_point_from_scalar(value) for value in scalars]
    assert all(point is not None for point in points)
    concrete_points = [point for point in points if point is not None]
    left_size = len(scalars) // 2
    left_points = concrete_points[:left_size]
    right_points = concrete_points[left_size:]
    left_table, left_collisions = _build_half_table(left_points)

    next_right = int(existing.get("next_right_subset", 0))
    matches = list(existing.get("matches", []))
    previous_seconds = float(existing.get("elapsed_seconds", 0.0))
    if next_right:
        previous_gray = next_right ^ (next_right >> 1)
        current = _point_for_mask(right_points, previous_gray)
    else:
        previous_gray = 0
        current = None

    right_count = 1 << len(right_points)
    target_count = len(targets)
    manifest: dict[str, object] = {
        "schema_version": 1,
        "engine": "coincurve/libsecp256k1 Gray-code point-space MITM",
        "engine_version": ENGINE_VERSION,
        "family": family,
        "input_sha256": digest,
        "status": "RUNNING",
        "scalar_count": len(scalars),
        "scalar_labels": scalar_labels,
        "left_subset_count": 1 << left_size,
        "right_subset_count": right_count,
        "target_count": target_count,
        "logical_candidate_space": str((1 << len(scalars)) * target_count),
        "left_point_collisions": left_collisions,
        "next_right_subset": next_right,
        "matches": matches,
        "elapsed_seconds": previous_seconds,
    }

    for sequence in range(next_right, right_count):
        gray = sequence ^ (sequence >> 1)
        if sequence != next_right or next_right == 0:
            if sequence:
                changed = gray ^ previous_gray
                bit = changed.bit_length() - 1
                current = _add(current, right_points[bit] if (gray >> bit) & 1 else _negate(right_points[bit]))
        negative_current = _negate(current)
        for target_label, (target_point, adjustment) in targets.items():
            needed = _add(target_point, negative_current)
            left_mask = left_table.get(_point_key(needed))
            if left_mask is not None:
                collision = _verify_collision(
                    scalars, scalar_labels, left_mask, gray, left_size,
                    target_label, adjustment, target_point, expected_point, expected_address,
                )
                if collision not in matches:
                    matches.append(collision)
        previous_gray = gray
        completed = sequence + 1
        if completed % checkpoint_interval == 0 or completed == right_count:
            manifest.update({
                "next_right_subset": completed,
                "matches": matches,
                "elapsed_seconds": previous_seconds + time.perf_counter() - started,
            })
            _write_json(checkpoint, manifest)
            print(
                f"{family}: right {completed}/{right_count}; "
                f"targets={target_count}; matches={len(matches)}",
                flush=True,
            )

    manifest.update({
        "status": "COMPLETE",
        "next_right_subset": right_count,
        "matches": matches,
        "accepted_matches": sum(bool(match.get("accepted")) for match in matches),
        "elapsed_seconds": previous_seconds + time.perf_counter() - started,
    })
    _write_json(checkpoint, manifest)
    return manifest


def _shifted_target(target: PublicKey, adjustment: int) -> PublicKey:
    # Search subset point = target - adjustment*G, so adding adjustment to
    # the recovered subset scalar reconstructs the expected target point.
    shifted = _add(target, _negate(_point_from_scalar(adjustment)))
    if shifted is None:
        raise ValueError("target shift produced the point at infinity")
    return shifted


def run(*, force: bool = False) -> dict[str, object]:
    sal = derive_tokens()
    chains = reconstruct(extract_all(), sal)
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)
    block_scalars = [int.from_bytes(block, "big") % N for block in chain4.blocks]
    block_labels = [f"block_{index:02d}" for index in range(35)]
    operand = int.from_bytes(chain4.opcode_operand, "big") % N
    magnitude = int.from_bytes(chain4.operand, "big") % N
    prefix = int.from_bytes(chain4.structured_prefix, "big") % N
    recovered_k_bytes = [
        chains.chain1.key1, chains.chain1.key2,
        chains.chain2.key1, chains.chain2.key2,
        chains.cosmic_b.key1, chains.cosmic_b.key2,
        chains.cosmic_h.key1, chains.cosmic_h.key2,
    ]
    recovered_k = [int.from_bytes(value, "big") % N for value in recovered_k_bytes]
    recovered_k_labels = ["K_C1", "K_C2", "K_S1", "K_S2", "K_B1", "K_B2", "K_H1", "K_H2"]
    target = _point_from_compressed(TARGET_COMPRESSED)

    # Independent engine controls against the package's pure-Python curve
    # implementation, followed by an exhaustive synthetic known-subset test.
    point_controls = []
    for label, scalar in (("one", 1), ("block_00", block_scalars[0]), ("operand", operand), ("block_sum", sum(block_scalars) % N)):
        libsecp = _point_key(_point_from_scalar(scalar))
        independent = public_key((scalar % N).to_bytes(32, "big"), True)
        point_controls.append({"label": label, "match": libsecp == independent, "compressed": libsecp.hex()})
    if not all(control["match"] for control in point_controls):
        raise ValueError("libsecp256k1 point control disagrees with independent scalar multiplication")

    synthetic_scalars = [1 << index for index in range(12)]
    synthetic_indices = [0, 3, 7, 11]
    synthetic_total = sum(synthetic_scalars[index] for index in synthetic_indices)
    synthetic_point = _point_from_scalar(synthetic_total)
    assert synthetic_point is not None
    synthetic = run_family(
        "synthetic_positive_control",
        synthetic_scalars,
        [f"power2_{index}" for index in range(12)],
        {"known_subset": (synthetic_point, 0)},
        expected_point=_point_key(synthetic_point),
        expected_address=None,
        checkpoint_interval=64,
        force=force,
    )
    accepted_synthetic = [match for match in synthetic["matches"] if match["accepted"]]
    if not accepted_synthetic or accepted_synthetic[0]["selected_indices"] != synthetic_indices:
        raise ValueError("synthetic MITM positive control failed to recover the known subset")

    m1_adjustments = {
        "T": 0,
        "T-minus-operand": operand,
        "T-plus-operand": -operand,
        "T-minus-magnitude": magnitude,
        "T-plus-magnitude": -magnitude,
        "T-minus-prefix": prefix,
        "T-plus-prefix": -prefix,
    }
    m1_targets = {
        label: (_shifted_target(target, adjustment), adjustment)
        for label, adjustment in m1_adjustments.items()
    }

    half = int.from_bytes(matrix.half, "big") % N
    better = int.from_bytes(matrix.better_half, "big") % N
    component_adjustments = {
        "T": 0,
        "T-minus-half": half,
        "T-plus-half": -half,
        "T-minus-better": better,
        "T-plus-better": -better,
        "T-minus-half-minus-better": half + better,
        "T-plus-half-plus-better": -half - better,
        "T-minus-half-plus-better": half - better,
        "T-plus-half-minus-better": -half + better,
    }
    component_targets = {
        label: (_shifted_target(target, adjustment), adjustment)
        for label, adjustment in component_adjustments.items()
    }

    families = {
        "M1_blocks35_prefix_shifts": run_family(
            "M1_blocks35_prefix_shifts", block_scalars, block_labels, m1_targets, force=force
        ),
        "M2_blocks35_plus_operand": run_family(
            "M2_blocks35_plus_operand",
            block_scalars + [operand], block_labels + ["operand30"], {"T": (target, 0)}, force=force,
        ),
        "M3_blocks35_plus_magnitude": run_family(
            "M3_blocks35_plus_magnitude",
            block_scalars + [magnitude], block_labels + ["magnitude29"], {"T": (target, 0)}, force=force,
        ),
        "M4_blocks35_plus_K8": run_family(
            "M4_blocks35_plus_K8",
            block_scalars + recovered_k, block_labels + recovered_k_labels, {"T": (target, 0)},
            checkpoint_interval=1 << 18, force=force,
        ),
        "M5_blocks35_component_shifts": run_family(
            "M5_blocks35_component_shifts", block_scalars, block_labels, component_targets, force=force
        ),
    }
    accepted_matches = [
        {"family": family, **match}
        for family, manifest in families.items()
        for match in manifest["matches"]
        if match["accepted"]
    ]
    result: dict[str, object] = {
        "status": "MATCH" if accepted_matches else "COMPLETE_NO_MATCH",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "engine": {
            "name": "coincurve/libsecp256k1 Gray-code point-space MITM",
            "version": ENGINE_VERSION,
            "point_controls": point_controls,
            "synthetic_positive_control": synthetic,
        },
        "families": families,
        "total_logical_candidate_space": str(sum(int(manifest["logical_candidate_space"]) for manifest in families.values())),
        "accepted_matches": accepted_matches,
        "target": {"compressed_point": TARGET_COMPRESSED.hex(), "address": TARGET_ADDRESS},
        "scope_note": "Each family exhausts every subset of its explicitly listed scalars in point space. This closes additive selection for those sets and shifts, not arbitrary non-additive operations.",
    }
    _write_json(RESULT_PATH, result)
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"],
        "total_logical_candidate_space": output["total_logical_candidate_space"],
        "accepted_matches": output["accepted_matches"],
        "families": {
            name: {
                "status": value["status"],
                "logical_candidate_space": value["logical_candidate_space"],
                "elapsed_seconds": value["elapsed_seconds"],
                "matches": len(value["matches"]),
            }
            for name, value in output["families"].items()
        },
    }, indent=2))
