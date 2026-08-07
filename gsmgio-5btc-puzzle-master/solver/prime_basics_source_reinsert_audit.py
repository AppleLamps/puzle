"""Evaluate the sealed v55 prime-basics → source-codes reinsertion family.

Verifies the seal, reloads authenticated Architect layers, fails on drift,
runs a planted positive control through :mod:`solver.targets`, then gates
every sealed candidate.

Run ``python -m solver.prime_basics_source_reinsert_preregister`` first, then
``python -m solver.prime_basics_source_reinsert_audit``.
"""

from __future__ import annotations

import hashlib
import json

from . import targets
from .phase32_symbol_recovery import _raw_symbol_record
from .secp256k1_verify import N
from .prime_basics_source_reinsert_preregister import (
    BEAUFORT_KEY,
    CONTROL_SCALAR_HEX,
    DISSEMINATIONS,
    EXTRACTORS,
    INSERT_MODES,
    LAYERS,
    MANIFEST_PATH,
    PAYLOAD_LISTS,
    PHASE32_PASSWORD,
    PLAINTEXT_SHA256,
    RAW_SHA256,
    RESULT_PATH,
    SCHEMA,
    SEAL_PATH,
    SERIALIZATIONS,
    TRANSLITERATION_SHA256,
    build_manifest,
    expected_candidate_count,
)
from .extract import ROOT
from .yinyang_prime_dual_preregister import prime_lists


RECOVERY_PATH = ROOT / "phase32_symbol_recovery.json"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_layers() -> dict[str, bytes]:
    raw = _raw_symbol_record()
    if len(raw) != 1539 or _sha(raw) != RAW_SHA256:
        raise ValueError("authenticated raw source record changed")

    recovery = json.loads(RECOVERY_PATH.read_text(encoding="utf-8"))
    mapping = {int(key, 16): value for key, value in recovery["recovered_mapping"].items()}
    transliteration = "".join(mapping[value] for value in raw).encode("ascii")
    if len(transliteration) != 1539 or _sha(transliteration) != TRANSLITERATION_SHA256:
        raise ValueError("authenticated transliteration changed")

    plaintext = recovery["plaintext"].encode("ascii")
    if len(plaintext) != 1539 or _sha(plaintext) != PLAINTEXT_SHA256:
        raise ValueError("authenticated Architect plaintext changed")

    return {
        "raw": raw,
        "transliteration": transliteration,
        "plaintext": plaintext,
    }


def _serialize(values: list[int], name: str) -> bytes:
    if name == "raw_value_bytes":
        return bytes(value % 256 for value in values)
    if name == "ascii_decimal_concat":
        return "".join(str(value) for value in values).encode("ascii")
    if name == "mod26_A0_ascii":
        return "".join(chr(65 + value % 26) for value in values).encode("ascii")
    raise ValueError(f"unsealed serialization: {name}")


def _disseminate(layer: bytes, mode: str) -> bytes:
    if mode == "identity":
        return layer
    if mode == "xor-beaufort-key-ascii":
        code = BEAUFORT_KEY
    elif mode == "xor-beaufort-key-digest":
        code = hashlib.sha256(BEAUFORT_KEY).digest()
    elif mode == "xor-phase32-password":
        code = PHASE32_PASSWORD
    else:
        raise ValueError(f"unsealed dissemination: {mode}")
    return bytes(byte ^ code[index % len(code)] for index, byte in enumerate(layer))


def _reinsert(layer: bytes, payload: bytes, mode: str) -> bytes:
    if mode == "append":
        return layer + payload
    if mode.startswith("overwrite@"):
        offset = int(mode.split("@", 1)[1])
        output = bytearray(layer)
        end = offset + len(payload)
        if end > len(output):
            # Truncate payload to the remaining source — still a sealed mode.
            payload = payload[: len(output) - offset]
            end = offset + len(payload)
        output[offset:end] = payload
        return bytes(output)
    if mode.startswith("xor@"):
        offset = int(mode.split("@", 1)[1])
        output = bytearray(layer)
        for index, byte in enumerate(payload):
            position = offset + index
            if position >= len(output):
                break
            output[position] ^= byte
        return bytes(output)
    raise ValueError(f"unsealed insert mode: {mode}")


def _extract(value: bytes, name: str) -> bytes:
    if name == "sha256":
        return hashlib.sha256(value).digest()
    if name == "first-32":
        if len(value) >= 32:
            return value[:32]
        return value.ljust(32, b"\0")
    if name == "last-32":
        if len(value) >= 32:
            return value[-32:]
        return value.rjust(32, b"\0")
    if name == "window-479-32":
        if len(value) >= 511:
            return value[479:511]
        # Short only for append-less edge cases; left-pad to keep width.
        window = value[479:] if len(value) > 479 else b""
        return window.ljust(32, b"\0")[:32]
    raise ValueError(f"unsealed extractor: {name}")


def _control() -> dict[str, object]:
    scalar = int(CONTROL_SCALAR_HEX, 16)
    x, y = targets._public_point(scalar)
    planted_half = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    planted = targets.gate_point(x, y, half_public=planted_half)
    production = targets.gate_scalar_bytes(bytes.fromhex(CONTROL_SCALAR_HEX))
    return {
        "planted_target_accepted": planted is not None,
        "production_targets_reject_control": production is None,
        "control_scalar": CONTROL_SCALAR_HEX,
    }


def run() -> dict[str, object]:
    sealed = SEAL_PATH.read_text(encoding="ascii").strip()
    manifest_bytes = MANIFEST_PATH.read_bytes()
    if _sha(manifest_bytes) != sealed:
        raise ValueError("manifest seal mismatch")
    manifest = json.loads(manifest_bytes)
    rederived = build_manifest()
    if rederived != manifest:
        raise ValueError("manifest drifted from build_manifest()")
    if manifest["schema"] != SCHEMA:
        raise ValueError("unexpected schema")
    if manifest["expansion"]["expected_candidate_records"] != expected_candidate_count():
        raise ValueError("candidate count drift")

    layers = _load_layers()
    lists = prime_lists()
    control = _control()
    if not control["planted_target_accepted"] or not control["production_targets_reject_control"]:
        raise ValueError(f"gate control failed: {control}")

    records: list[dict[str, object]] = []
    stream = hashlib.sha256()
    matches: list[dict[str, object]] = []

    for layer_name in LAYERS:
        layer = layers[layer_name]
        for dissemination in DISSEMINATIONS:
            disseminated = _disseminate(layer, dissemination)
            for list_name in PAYLOAD_LISTS:
                values = lists[list_name]
                for serialization in SERIALIZATIONS:
                    payload = _serialize(values, serialization)
                    for insert_mode in INSERT_MODES:
                        reinserted = _reinsert(disseminated, payload, insert_mode)
                        for extractor in EXTRACTORS:
                            candidate = _extract(reinserted, extractor)
                            label = (
                                f"{layer_name}/{dissemination}/{list_name}/"
                                f"{serialization}/{insert_mode}/{extractor}"
                            )
                            gate = targets.gate_scalar_bytes(candidate)
                            stream.update(label.encode("ascii") + b"\0" + candidate)
                            record = {
                                "label": label,
                                "output_length": len(reinserted),
                                "output_sha256": _sha(reinserted),
                                "scalar_hex": candidate.hex(),
                                "valid_scalar": (
                                    1 <= int.from_bytes(candidate, "big") % N < N
                                    and int.from_bytes(candidate, "big") % N != 0
                                ),
                                "match": gate is not None,
                                "gate": gate,
                            }
                            records.append(record)
                            if gate is not None:
                                matches.append(record)

    if len(records) != expected_candidate_count():
        raise ValueError(f"candidate drift: expected {expected_candidate_count()}, got {len(records)}")

    valid = [record for record in records if record["valid_scalar"]]
    result: dict[str, object] = {
        "status": "PRIZE_MATCH" if matches else "COMPLETE_NO_MATCH",
        "schema": SCHEMA,
        "manifest_sha256": sealed,
        "control": control,
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
            "layers": len(LAYERS),
            "disseminations": len(DISSEMINATIONS),
            "payload_lists": len(PAYLOAD_LISTS),
            "serializations": len(SERIALIZATIONS),
            "insert_modes": len(INSERT_MODES),
            "extractors": len(EXTRACTORS),
        },
        "scope_note": manifest["scope_note"],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
