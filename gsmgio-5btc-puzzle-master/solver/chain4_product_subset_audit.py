"""Checkpointed exact-point audit of bounded Chain 4 product families."""

from __future__ import annotations

import concurrent.futures
import hashlib
import itertools
import json
import os
from pathlib import Path

from coincurve import PublicKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "chain4_product_subset_audit.json"
CHECKPOINTS = ROOT / "artifacts" / "product_subset_checkpoints"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")
FAMILIES = {
    "Q3": {"subset_size": 3, "operations": ("product", "multiply_operand", "divide_operand", "add_operand", "subtract_operand")},
    "Q4": {"subset_size": 4, "operations": ("product", "multiply_operand", "divide_operand", "add_operand", "subtract_operand")},
    "Q7": {"subset_size": 7, "operations": ("product", "multiply_operand")},
}


def _combination_count(n: int, r: int) -> int:
    if r < 0 or n < r:
        return 0
    numerator = denominator = 1
    for value in range(1, r + 1):
        numerator *= n - r + value
        denominator *= value
    return numerator // denominator


def _candidate_values(product: int, operand: int, inverse_operand: int, operations: tuple[str, ...]) -> tuple[int, ...]:
    values = {
        "product": product,
        "multiply_operand": product * operand,
        "divide_operand": product * inverse_operand,
        "add_operand": product + operand,
        "subtract_operand": product - operand,
    }
    return tuple(values[name] % N for name in operations)


def _partition_worker(arguments: tuple[object, ...]) -> dict[str, object]:
    family, subset_size, operations, first, blocks, operand, input_sha256 = arguments
    family = str(family)
    subset_size = int(subset_size)
    operations = tuple(operations)
    first = int(first)
    blocks = tuple(int(value) for value in blocks)
    operand = int(operand)
    inverse_operand = pow(operand, -1, N)
    expected_combinations = _combination_count(len(blocks) - first - 1, subset_size - 1)
    stream = hashlib.sha256()
    combination_count = candidate_count = zero_scalar_count = 0
    matches: list[dict[str, object]] = []
    for tail in itertools.combinations(range(first + 1, len(blocks)), subset_size - 1):
        combo = (first, *tail)
        product = 1
        for index in combo:
            product = product * blocks[index] % N
        stream.update(bytes(combo))
        candidates = _candidate_values(product, operand, inverse_operand, operations)
        for operation_index, (operation, scalar) in enumerate(zip(operations, candidates)):
            candidate_count += 1
            scalar_bytes = scalar.to_bytes(32, "big")
            stream.update(bytes([operation_index]))
            stream.update(scalar_bytes)
            if scalar == 0:
                zero_scalar_count += 1
                continue
            public = PublicKey.from_valid_secret(scalar_bytes)
            if public.format(compressed=True) != TARGET_COMPRESSED:
                continue
            address = base58check(b"\0" + hash160(public.format(compressed=False)))
            matches.append({
                "block_indices": list(combo),
                "operation": operation,
                "private_hex": scalar_bytes.hex(),
                "prize_point_match": True,
                "address": address,
                "prize_address_match": address == TARGET_ADDRESS,
                "accepted": address == TARGET_ADDRESS,
            })
        combination_count += 1
    if combination_count != expected_combinations:
        raise ValueError("product partition combination count is inconsistent")
    return {
        "status": "COMPLETE",
        "family": family,
        "subset_size": subset_size,
        "operations": list(operations),
        "first_block_index": first,
        "input_sha256": input_sha256,
        "combination_count": combination_count,
        "candidate_count": candidate_count,
        "zero_scalar_count": zero_scalar_count,
        "candidate_stream_sha256": stream.hexdigest(),
        "matches": matches,
        "accepted_matches": sum(bool(match["accepted"]) for match in matches),
    }


def _manifest_path(family: str, first: int) -> Path:
    return CHECKPOINTS / f"{family}_first_{first:02d}.json"


def _validated_cached_manifest(
    path: Path,
    family: str,
    subset_size: int,
    operations: tuple[str, ...],
    first: int,
    input_sha256: str,
    block_count: int,
) -> dict[str, object] | None:
    if not path.exists():
        return None
    manifest = json.loads(path.read_text(encoding="utf-8"))
    expected_combinations = _combination_count(block_count - first - 1, subset_size - 1)
    expected = {
        "status": "COMPLETE",
        "family": family,
        "subset_size": subset_size,
        "operations": list(operations),
        "first_block_index": first,
        "input_sha256": input_sha256,
        "combination_count": expected_combinations,
        "candidate_count": expected_combinations * len(operations),
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            return None
    if not isinstance(manifest.get("candidate_stream_sha256"), str) or len(manifest["candidate_stream_sha256"]) != 64:
        return None
    if manifest.get("accepted_matches") != sum(bool(item.get("accepted")) for item in manifest.get("matches", [])):
        return None
    return manifest


def run(*, max_workers: int | None = None) -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    blocks = tuple(int.from_bytes(block, "big") % N for block in chain4.blocks)
    if any(block == 0 for block in blocks):
        raise ValueError("zero Chain 4 block prevents the recorded product family")
    operand = int.from_bytes(chain4.opcode_operand, "big") % N
    if operand == 0:
        raise ValueError("zero operand prevents multiplicative inverse variants")
    inverse_operand = pow(operand, -1, N)
    input_bytes = b"".join(chain4.blocks) + chain4.opcode_operand
    input_sha256 = hashlib.sha256(input_bytes).hexdigest()
    CHECKPOINTS.mkdir(parents=True, exist_ok=True)
    worker_count = max_workers or min(8, os.cpu_count() or 1)

    manifests_by_family: dict[str, list[dict[str, object]]] = {}
    for family, definition in FAMILIES.items():
        subset_size = int(definition["subset_size"])
        operations = tuple(definition["operations"])
        manifests: dict[int, dict[str, object]] = {}
        pending: list[tuple[object, ...]] = []
        for first in range(len(blocks) - subset_size + 1):
            path = _manifest_path(family, first)
            cached = _validated_cached_manifest(path, family, subset_size, operations, first, input_sha256, len(blocks))
            if cached is None:
                pending.append((family, subset_size, operations, first, blocks, operand, input_sha256))
            else:
                manifests[first] = cached
        if pending:
            print(f"{family}: running {len(pending)} missing partitions with {worker_count} workers", flush=True)
            with concurrent.futures.ProcessPoolExecutor(max_workers=worker_count) as executor:
                futures = {executor.submit(_partition_worker, arguments): int(arguments[3]) for arguments in pending}
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    first = futures[future]
                    manifest = future.result()
                    _manifest_path(family, first).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
                    manifests[first] = manifest
                    completed += 1
                    if completed % 5 == 0 or completed == len(pending):
                        print(f"{family}: checkpointed {completed}/{len(pending)} missing partitions", flush=True)
        manifests_by_family[family] = [manifests[first] for first in sorted(manifests)]

    planted_combo = (0, 1, 2)
    planted_product = blocks[0] * blocks[1] % N * blocks[2] % N
    planted_scalar = _candidate_values(planted_product, operand, inverse_operand, FAMILIES["Q3"]["operations"])[2]
    planted_public = PublicKey.from_valid_secret(planted_scalar.to_bytes(32, "big"))
    planted_compressed = planted_public.format(compressed=True)
    planted_address = base58check(b"\0" + hash160(planted_public.format(compressed=False)))
    control_matches: list[dict[str, object]] = []
    control_candidates = 0
    for combo in itertools.combinations(range(6), 3):
        product = blocks[combo[0]] * blocks[combo[1]] % N * blocks[combo[2]] % N
        candidates = _candidate_values(product, operand, inverse_operand, FAMILIES["Q3"]["operations"])
        for operation, scalar in zip(FAMILIES["Q3"]["operations"], candidates):
            control_candidates += 1
            if not scalar:
                continue
            public = PublicKey.from_valid_secret(scalar.to_bytes(32, "big"))
            if public.format(compressed=True) == planted_compressed:
                address = base58check(b"\0" + hash160(public.format(compressed=False)))
                control_matches.append({
                    "block_indices": list(combo), "operation": operation,
                    "private_hex": f"{scalar:064x}", "point_match": True,
                    "address": address, "address_match": address == planted_address,
                })
    expected_control = {
        "block_indices": list(planted_combo), "operation": "divide_operand",
        "private_hex": f"{planted_scalar:064x}", "point_match": True,
        "address": planted_address, "address_match": True,
    }
    positive_control = {
        "family": "Q3", "fixture_block_count": 6, "candidate_count": control_candidates,
        "expected_match": expected_control, "matches": control_matches,
        "compressed_public_key": planted_compressed.hex(), "uncompressed_address": planted_address,
        "recovered": expected_control in control_matches,
    }
    if not positive_control["recovered"]:
        raise ValueError("product audit positive control failed")

    family_summaries: dict[str, dict[str, object]] = {}
    all_matches: list[dict[str, object]] = []
    for family, manifests in manifests_by_family.items():
        definition = FAMILIES[family]
        subset_size = int(definition["subset_size"])
        expected_combinations = _combination_count(len(blocks), subset_size)
        combination_count = sum(int(item["combination_count"]) for item in manifests)
        candidate_count = sum(int(item["candidate_count"]) for item in manifests)
        if combination_count != expected_combinations:
            raise ValueError(f"{family} aggregate combination count is inconsistent")
        matches = [dict(item, family=family) for manifest in manifests for item in manifest["matches"]]
        all_matches.extend(matches)
        family_summaries[family] = {
            "subset_size": subset_size,
            "operations": list(definition["operations"]),
            "partition_count": len(manifests),
            "combination_count": combination_count,
            "candidate_count": candidate_count,
            "zero_scalar_count": sum(int(item["zero_scalar_count"]) for item in manifests),
            "partition_stream_digest_sha256": hashlib.sha256(
                "".join(str(item["candidate_stream_sha256"]) for item in manifests).encode("ascii")
            ).hexdigest(),
            "matches": matches,
            "accepted_matches": sum(bool(item["accepted"]) for item in matches),
            "partitions": manifests,
        }

    result: dict[str, object] = {
        "status": "MATCH" if any(item["accepted"] for item in all_matches) else "COMPLETE_NO_MATCH",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "input_sha256": input_sha256,
        "block_count": len(blocks),
        "operand_hex": f"{operand:064x}",
        "inverse_operand_hex": f"{inverse_operand:064x}",
        "engine": {
            "name": "partitioned coincurve/libsecp256k1 exact public-key gate",
            "worker_count": worker_count,
            "positive_control": positive_control,
        },
        "families": family_summaries,
        "total_combinations": sum(int(item["combination_count"]) for item in family_summaries.values()),
        "total_candidate_scalars": sum(int(item["candidate_count"]) for item in family_summaries.values()),
        "accepted_matches": [item for item in all_matches if item["accepted"]],
        "scope_note": "This is exhaustive only for product subset sizes 3, 4, and 7 and the explicitly listed field operations.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"],
        "families": {
            name: {key: value for key, value in family.items() if key in {"combination_count", "candidate_count", "accepted_matches"}}
            for name, family in output["families"].items()
        },
        "total_candidate_scalars": output["total_candidate_scalars"],
        "accepted_matches": output["accepted_matches"],
    }, indent=2))
