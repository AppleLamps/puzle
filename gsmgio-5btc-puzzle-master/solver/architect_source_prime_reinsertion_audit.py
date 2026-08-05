"""Preregistered source-code / prime-basics experiment after the 479 hit.

This tests only the family sealed in
``architect_source_prime_reinsertion_preregistered.json``. It deliberately
excludes Cosmic, Chain 4, Witteveen material, and community-only operands.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from coincurve import PrivateKey

from .extract import ROOT
from .phase32_symbol_recovery import _raw_symbol_record
from .secp256k1_verify import N, hash160


MANIFEST_PATH = ROOT / "architect_source_prime_reinsertion_preregistered.json"
RECOVERY_PATH = ROOT / "phase32_symbol_recovery.json"
RESULT_PATH = ROOT / "architect_source_prime_reinsertion_audit.json"

RAW_SHA256 = "bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b"
TRANSLITERATION_SHA256 = "6d66e0e0e2dfdb812d5ecee2be6f54c1f3b8c84b0d74580686cf2053d76a200e"
PHASE32_PASSWORD = b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
BEAUFORT_KEY = b"THEMATRIXHASYOU"
COLORS = "BBBBYBBBYYBBBBYBBYYBYYBY"
PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89)
HALF_PUBLIC = bytes.fromhex(
    "04"
    "f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)
BETTER_H160 = bytes.fromhex("4bc468447fe1b048ad030a2f9a125478eabc4ed6")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_inputs() -> dict[str, bytes]:
    raw = _raw_symbol_record()
    if len(raw) != 1539 or _sha(raw) != RAW_SHA256:
        raise ValueError("authenticated raw source record changed")

    recovery = json.loads(RECOVERY_PATH.read_text(encoding="utf-8"))
    mapping = {int(key, 16): value for key, value in recovery["recovered_mapping"].items()}
    transliteration = "".join(mapping[value] for value in raw).encode("ascii")
    if len(transliteration) != 1539 or _sha(transliteration) != TRANSLITERATION_SHA256:
        raise ValueError("authenticated transliteration changed")
    return {"raw": raw, "transliteration": transliteration}


def _prime_operation(layer: bytes, base: int, operation: str) -> bytes:
    indices = [prime - 1 if base == 1 else prime for prime in PRIMES]
    if operation == "select":
        return bytes(layer[index] for index in indices)
    if operation == "select-zero-5":
        return bytes(layer[index] for prime, index in zip(PRIMES, indices) if prime != 5)

    output = bytearray(layer)
    if operation == "xor-prime":
        for prime, index in zip(PRIMES, indices):
            output[index] ^= prime
    elif operation == "color-lsb":
        for color, index in zip(COLORS, indices):
            if color == "B":
                output[index] |= 1
            else:
                output[index] &= 0xFE
    else:
        raise ValueError(f"unknown prime operation: {operation}")
    return bytes(output)


def _disseminate(value: bytes, mode: str) -> bytes:
    if mode == "identity":
        return value
    if mode == "xor-phase32-password":
        code = PHASE32_PASSWORD
    elif mode == "xor-beaufort-key-digest":
        code = hashlib.sha256(BEAUFORT_KEY).digest()
    else:
        raise ValueError(f"unknown dissemination mode: {mode}")
    return bytes(byte ^ code[index % len(code)] for index, byte in enumerate(value))


def _extract_scalars(value: bytes) -> dict[str, bytes]:
    extracted = {"sha256": hashlib.sha256(value).digest()}
    if len(value) >= 32:
        extracted.update(
            {
                "first-32": value[:32],
                "last-32": value[-32:],
                "offset-479": value[479:511],
            }
        )
    else:
        extracted.update(
            {
                "left-zero-pad": value.rjust(32, b"\0"),
                "right-zero-pad": value.ljust(32, b"\0"),
            }
        )
    if any(len(candidate) != 32 for candidate in extracted.values()):
        raise ValueError("scalar extractor did not produce 32 bytes")
    return extracted


def _gate(candidate: bytes) -> dict[str, object]:
    scalar = int.from_bytes(candidate, "big")
    if not 1 <= scalar < N:
        return {"valid_scalar": False, "match": False}
    public = PrivateKey(candidate).public_key
    compressed = public.format(compressed=True)
    uncompressed = public.format(compressed=False)
    half = uncompressed == HALF_PUBLIC
    better_compressed = hash160(compressed) == BETTER_H160
    better_uncompressed = hash160(uncompressed) == BETTER_H160
    return {
        "valid_scalar": True,
        "match": half or better_compressed or better_uncompressed,
        "half_exact_public_key": half,
        "better_hash160_compressed": better_compressed,
        "better_hash160_uncompressed": better_uncompressed,
    }


def run() -> dict[str, object]:
    manifest_bytes = MANIFEST_PATH.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest["schema"] != "architect-source-prime-reinsertion-v1":
        raise ValueError("unexpected preregistration schema")
    if manifest["expected_candidate_records"] != 168:
        raise ValueError("preregistered candidate count changed")
    if tuple(manifest["frozen_inputs"]["first_24_primes"]) != PRIMES:
        raise ValueError("preregistered prime list changed")
    if manifest["frozen_inputs"]["poster_marker_colors"] != COLORS:
        raise ValueError("preregistered marker colors changed")

    layers = _load_inputs()
    operations = ("select", "select-zero-5", "xor-prime", "color-lsb")
    dissemination_modes = ("identity", "xor-phase32-password", "xor-beaufort-key-digest")
    records: list[dict[str, object]] = []
    stream = hashlib.sha256()

    for layer_name, layer in layers.items():
        for base in (0, 1):
            for operation in operations:
                operated = _prime_operation(layer, base, operation)
                for dissemination in dissemination_modes:
                    output = _disseminate(operated, dissemination)
                    for extractor, candidate in _extract_scalars(output).items():
                        label = (
                            f"{layer_name}/base-{base}/{operation}/"
                            f"{dissemination}/{extractor}"
                        )
                        gate = _gate(candidate)
                        stream.update(label.encode("ascii") + b"\0" + candidate)
                        records.append(
                            {
                                "label": label,
                                "output_length": len(output),
                                "output_sha256": _sha(output),
                                "scalar_hex": candidate.hex(),
                                **gate,
                            }
                        )

    if len(records) != manifest["expected_candidate_records"]:
        raise ValueError(f"candidate drift: expected 168, got {len(records)}")
    matches = [record for record in records if record["match"]]
    valid = [record for record in records if record["valid_scalar"]]
    result: dict[str, object] = {
        "status": "PRIZE_MATCH" if matches else "COMPLETE_NO_MATCH",
        "schema": manifest["schema"],
        "manifest_sha256": _sha(manifest_bytes),
        "inputs": {
            name: {"length": len(value), "sha256": _sha(value)}
            for name, value in layers.items()
        },
        "candidate_records": len(records),
        "valid_scalar_records": len(valid),
        "unique_valid_scalars": len({record["scalar_hex"] for record in valid}),
        "candidate_stream_sha256": stream.hexdigest(),
        "matches": matches,
        "family_counts": {
            "layers": len(layers),
            "index_bases": 2,
            "prime_operations": len(operations),
            "dissemination_modes": len(dissemination_modes),
            "short_extractors": 3,
            "full_extractors": 4,
        },
        "scope_note": manifest["scope_note"],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
