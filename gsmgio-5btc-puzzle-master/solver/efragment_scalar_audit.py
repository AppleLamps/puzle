"""Audit finite scalar constructions from the four recovered 15-byte E fields."""

from __future__ import annotations

import hashlib
import itertools
import json

from coincurve import PublicKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "efragment_scalar_audit.json"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")


def _addresses(public: PublicKey) -> tuple[str, str]:
    return (
        base58check(b"\0" + hash160(public.format(compressed=True))),
        base58check(b"\0" + hash160(public.format(compressed=False))),
    )


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)
    fragments = {
        "E_C": chains.chain1.extension,
        "E_S": chains.chain2.extension,
        "E_B": chains.cosmic_b.extension,
        "E_H": chains.cosmic_h.extension,
    }
    if any(len(fragment) != 15 for fragment in fragments.values()):
        raise ValueError("recovered E fields are not four 15-byte fragments")
    k_values = {
        "K_C1": chains.chain1.key1, "K_C2": chains.chain1.key2,
        "K_S1": chains.chain2.key1, "K_S2": chains.chain2.key2,
        "K_B1": chains.cosmic_b.key1, "K_B2": chains.cosmic_b.key2,
        "K_H1": chains.cosmic_h.key1, "K_H2": chains.cosmic_h.key2,
    }

    half_public = PublicKey.from_valid_secret(matrix.half)
    better_public = PublicKey.from_valid_secret(matrix.better_half)
    points = {
        "prize": TARGET_COMPRESSED,
        "Half": half_public.format(compressed=True),
        "Better_Half": better_public.format(compressed=True),
    }
    addresses = {
        "prize": (base58check(b"\0" + hash160(TARGET_COMPRESSED)), TARGET_ADDRESS),
        "Half": _addresses(half_public),
        "Better_Half": _addresses(better_public),
    }

    generated: list[tuple[str, str, int]] = []

    def emit(family: str, label: str, value: int) -> None:
        generated.append((family, label, value % N))

    items = list(fragments.items())
    concatenated = b"".join(fragments.values())
    for (first_name, first), (second_name, second) in itertools.permutations(items, 2):
        for window_name, window_fragment in items:
            for offset in range(14):
                blob = first + second + window_fragment[offset : offset + 2]
                label = f"{first_name}+{second_name}+{window_name}[{offset}:{offset + 2}]"
                emit("F1", label, int.from_bytes(blob, "big"))
                emit("F1", f"reverse({label})", int.from_bytes(blob, "little"))
    for (first_name, first), (second_name, second) in itertools.permutations(items, 2):
        for offset in range(len(concatenated) - 1):
            blob = first + second + concatenated[offset : offset + 2]
            emit("F1", f"{first_name}+{second_name}+allE[{offset}:{offset + 2}]", int.from_bytes(blob, "big"))

    for name, fragment in items:
        for form_name, blob in ((name, fragment), (f"{name}_reverse", fragment[::-1])):
            emit("F2", f"{form_name}_leftpad", int.from_bytes(blob.rjust(32, b"\0"), "big"))
            emit("F2", f"{form_name}_rightpad", int.from_bytes(blob.ljust(32, b"\0"), "big"))
            emit("F2", f"{form_name}_integer", int.from_bytes(blob, "big"))
    for (first_name, first), (second_name, second) in itertools.permutations(items, 2):
        blob = first + second
        emit("F2", f"{first_name}+{second_name}_leftpad", int.from_bytes(blob.rjust(32, b"\0"), "big"))
        emit("F2", f"{first_name}+{second_name}_rightpad", int.from_bytes(blob.ljust(32, b"\0"), "big"))
        emit("F2", f"{first_name}+{second_name}_integer", int.from_bytes(blob, "big"))
    emit("F2", "sha256(all_E)", int.from_bytes(hashlib.sha256(concatenated).digest(), "big"))

    for fragment_name, fragment in items:
        fragment_scalar = int.from_bytes(fragment, "big")
        for key_name, key_bytes in k_values.items():
            key_scalar = int.from_bytes(key_bytes, "big")
            emit("F3", f"{fragment_name}+{key_name}", fragment_scalar + key_scalar)
            emit("F3", f"{fragment_name}-{key_name}", fragment_scalar - key_scalar)
            emit("F3", f"{key_name}-{fragment_name}", key_scalar - fragment_scalar)
            emit("F3", f"{fragment_name}*{key_name}", fragment_scalar * key_scalar)
            emit("F3", f"{fragment_name}^{key_name}", fragment_scalar ^ key_scalar)
            emit("F3", f"sha256({fragment_name}+{key_name})", int.from_bytes(hashlib.sha256(fragment + key_bytes).digest(), "big"))
            emit("F3", f"sha256({key_name}+{fragment_name})", int.from_bytes(hashlib.sha256(key_bytes + fragment).digest(), "big"))

    block_sum = sum(int.from_bytes(block, "big") for block in chain4.blocks) % N
    bases = {
        "chain4_password": int.from_bytes(chain4.password, "big"),
        "operand": int.from_bytes(chain4.opcode_operand, "big"),
    }
    for base_name, base in bases.items():
        for key_name, key_bytes in k_values.items():
            key_scalar = int.from_bytes(key_bytes, "big")
            emit("F4", f"{base_name}+{key_name}", base + key_scalar)
            emit("F4", f"{base_name}-{key_name}", base - key_scalar)
            emit("F4", f"{base_name}*{key_name}", base * key_scalar)
            emit("F4", f"{base_name}^{key_name}", base ^ key_scalar)
        emit("F4", f"{base_name}+block_sum", base + block_sum)
        emit("F4", f"{base_name}-block_sum", base - block_sum)
        emit("F4", f"{base_name}*block_sum", base * block_sum)
        emit("F4", f"{base_name}^block_sum", base ^ block_sum)

    raw_counts: dict[str, int] = {}
    for family, _, _ in generated:
        raw_counts[family] = raw_counts.get(family, 0) + 1
    if raw_counts != {"F1": 2052, "F2": 61, "F3": 224, "F4": 72}:
        raise ValueError(f"E-fragment raw family counts changed: {raw_counts}")

    stream = hashlib.sha256()
    seen: set[int] = set()
    unique_by_first_family: dict[str, int] = {family: 0 for family in raw_counts}
    zero_attempts = duplicate_attempts = 0
    point_matches: list[dict[str, object]] = []
    for family, label, scalar in generated:
        stream.update(family.encode("ascii") + b"\0" + label.encode("utf-8") + b"\0" + scalar.to_bytes(32, "big"))
        if scalar == 0:
            zero_attempts += 1
            continue
        if scalar in seen:
            duplicate_attempts += 1
            continue
        seen.add(scalar)
        unique_by_first_family[family] += 1
        public = PublicKey.from_valid_secret(scalar.to_bytes(32, "big"))
        compressed = public.format(compressed=True)
        names = [name for name, point in points.items() if point == compressed]
        if not names:
            continue
        compressed_address, uncompressed_address = _addresses(public)
        for name in names:
            if (compressed_address, uncompressed_address) != addresses[name]:
                raise ValueError("E-fragment point/address cross-check failed")
        prize = "prize" in names
        point_matches.append({
            "family": family, "label": label, "private_hex": f"{scalar:064x}",
            "point_names": names, "compressed_address": compressed_address,
            "uncompressed_address": uncompressed_address, "prize_point_match": prize,
            "prize_address_match": prize and uncompressed_address == TARGET_ADDRESS,
            "accepted": prize and uncompressed_address == TARGET_ADDRESS,
        })

    # Enumerated control: select one actual F2 scalar and scan the complete F2
    # generator output for its exact point and address.
    planted = next(item for item in generated if item[0] == "F2" and item[1] == "E_C_leftpad")
    planted_scalar = planted[2]
    planted_public = PublicKey.from_valid_secret(planted_scalar.to_bytes(32, "big"))
    planted_point = planted_public.format(compressed=True)
    planted_addresses = _addresses(planted_public)
    control_matches = []
    for family, label, scalar in generated:
        if family != "F2" or scalar == 0:
            continue
        public = PublicKey.from_valid_secret(scalar.to_bytes(32, "big"))
        if public.format(compressed=True) == planted_point:
            control_matches.append({"label": label, "private_hex": f"{scalar:064x}", "addresses": list(_addresses(public))})
    expected_control = {"label": planted[1], "private_hex": f"{planted_scalar:064x}", "addresses": list(planted_addresses)}
    positive_control = {
        "family": "F2", "candidate_count": raw_counts["F2"],
        "expected_match": expected_control, "matches": control_matches,
        "recovered": expected_control in control_matches,
    }
    if not positive_control["recovered"]:
        raise ValueError("E-fragment positive control failed")

    accepted = [match for match in point_matches if match["accepted"]]
    result: dict[str, object] = {
        "status": "MATCH" if accepted else "COMPLETE_NO_MATCH",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "fragments_hex": {name: fragment.hex() for name, fragment in fragments.items()},
        "k_values_hex": {name: value.hex() for name, value in k_values.items()},
        "raw_family_counts": raw_counts,
        "raw_attempt_count": len(generated),
        "zero_attempt_count": zero_attempts,
        "duplicate_attempt_count": duplicate_attempts,
        "unique_scalar_count": len(seen),
        "unique_by_first_family": unique_by_first_family,
        "candidate_stream_sha256": stream.hexdigest(),
        "point_matches": point_matches,
        "accepted_prize_matches": accepted,
        "positive_control": positive_control,
        "scope_note": "The audit closes only the explicit fragment serialization and operation family. Duplicate scalars are globally gated once but every raw attempt contributes to the stream digest.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({key: output[key] for key in (
        "status", "raw_family_counts", "raw_attempt_count", "duplicate_attempt_count",
        "unique_scalar_count", "unique_by_first_family", "candidate_stream_sha256",
        "point_matches", "positive_control",
    )}, indent=2))
