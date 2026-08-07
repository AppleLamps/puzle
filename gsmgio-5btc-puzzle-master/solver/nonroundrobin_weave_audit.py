"""Evaluate sealed v68: non-round-robin weaves of the seven passwords."""

from __future__ import annotations

import hashlib
import json

from . import targets
from .extract import extract_all
from .nonroundrobin_weave_preregister import (
    CREATOR_PHRASES,
    ENVELOPES,
    FILL_CHARACTER,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PART_SETS,
    PASSWORD_FORMS,
    RESULT_PATH,
    SALPHASEION_TOKENS,
    SEAL_PATH,
    WEAVE_IDS,
    build_manifest,
    expected_aes_trials,
    expected_scalar_gates,
)
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import PHASE32_PASSWORD
from .pipeline_operand_split_envelope_audit import _gate_plaintext, _password_bytes


def _column_weave_padded(parts: tuple[str, ...]) -> str:
    width = max(len(part) for part in parts)
    padded = [part.ljust(width, FILL_CHARACTER) for part in parts]
    return "".join(row[index] for index in range(width) for row in padded)


def _chunk_weave(parts: tuple[str, ...], size: int) -> str:
    out: list[str] = []
    offset = 0
    while any(offset < len(part) for part in parts):
        for part in parts:
            out.append(part[offset : offset + size])
        offset += size
    return "".join(out)


def _proportional_weave(parts: tuple[str, ...]) -> str:
    shortest = min(len(part) for part in parts)
    out: list[str] = []
    for step in range(shortest):
        for part in parts:
            take = len(part) // shortest
            out.append(part[step * take : (step + 1) * take])
    for part in parts:
        take = len(part) // shortest
        out.append(part[shortest * take :])
    return "".join(out)


def _braid(parts: tuple[str, ...]) -> str:
    out: list[str] = []
    for index in range(max(len(part) for part in parts)):
        for part in parts:
            if index < len(part):
                out.append(part[index])
    return "".join(out)


def _nested_pairwise_braid(parts: tuple[str, ...]) -> str:
    level = list(parts)
    while len(level) > 1:
        nxt: list[str] = []
        for index in range(0, len(level) - 1, 2):
            nxt.append(_braid((level[index], level[index + 1])))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def _mod26_stack(parts: tuple[str, ...], subtract: bool) -> str:
    width = max(len(part) for part in parts)
    out: list[str] = []
    for index in range(width):
        total = 0
        for part in parts:
            value = ord(part[index % len(part)]) - ord("a")
            total = total - value if subtract else total + value
        out.append(chr(ord("a") + total % 26))
    return "".join(out)


def _xor_ascii_stack_hex(parts: tuple[str, ...]) -> str:
    width = max(len(part) for part in parts)
    out = bytearray()
    for index in range(width):
        value = 0
        for part in parts:
            value ^= ord(part[index % len(part)])
        out.append(value)
    return bytes(out).hex()


def _transpose_grid(parts: tuple[str, ...], columns: int) -> str:
    text = "".join(parts)
    rows = [text[offset : offset + columns] for offset in range(0, len(text), columns)]
    return "".join(row[index] for index in range(columns) for row in rows if index < len(row))


def _caesar_chain(parts: tuple[str, ...]) -> str:
    current = parts[0]
    for part in parts[1:]:
        current = "".join(
            chr(ord("a") + (ord(character) - ord("a") + ord(part[index % len(part)]) - ord("a")) % 26)
            for index, character in enumerate(current)
        )
    return current


def _head_tail_alternate(parts: tuple[str, ...]) -> str:
    width = max(len(part) for part in parts)
    out: list[str] = []
    for index in range(width):
        for position, part in enumerate(parts):
            if index >= len(part):
                continue
            out.append(part[index] if position % 2 == 0 else part[len(part) - 1 - index])
    return "".join(out)


def build_weaves() -> dict[tuple[str, str], bytes]:
    sets = {"phrases": CREATOR_PHRASES, "tokens": SALPHASEION_TOKENS}
    weaves: dict[tuple[str, str], bytes] = {}
    for set_name, parts in sets.items():
        reversed_parts = tuple(part[::-1] for part in parts)
        built = {
            "W01_column_weave_padded": _column_weave_padded(parts),
            "W02_chunk2_weave": _chunk_weave(parts, 2),
            "W03_chunk3_weave": _chunk_weave(parts, 3),
            "W04_chunk4_weave": _chunk_weave(parts, 4),
            "W05_proportional_weave": _proportional_weave(parts),
            "W06_nested_pairwise_braid": _nested_pairwise_braid(parts),
            "W07_reverse_each_concat": "".join(reversed_parts),
            "W08_reverse_each_braid": _braid(reversed_parts),
            "W09_mod26_add_stack": _mod26_stack(parts, subtract=False),
            "W10_mod26_sub_stack": _mod26_stack(parts, subtract=True),
            "W11_xor_ascii_stack_hex": _xor_ascii_stack_hex(parts),
            "W12_transpose_grid_7col": _transpose_grid(parts, 7),
            "W13_caesar_chain": _caesar_chain(parts),
            "W14_length_sorted_concat": "".join(sorted(parts, key=len)),
            "W15_head_tail_alternate": _head_tail_alternate(parts),
        }
        for weave_id, text in built.items():
            weaves[(set_name, weave_id)] = text.encode("ascii")
    return weaves


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    inputs = extract_all()
    envelopes = {"chain1": inputs.chain1_envelope, "chain2": inputs.chain2_envelope}
    weaves = build_weaves()

    phase32 = decrypt_salted_aes256_cbc(inputs.phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    scalar = int(manifest["control_scalar_hex"], 16)
    x, y = targets._public_point(scalar)
    planted = targets.gate_point(x, y, half_public=targets.serializations(x, y)["uncompressed"])

    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []
    materials: dict[str, str] = {}

    for set_name in PART_SETS:
        for weave_id in WEAVE_IDS:
            preimage = weaves[(set_name, weave_id)]
            materials[f"{set_name}/{weave_id}"] = hashlib.sha256(preimage).hexdigest()

            for derivation in ("sha256", "double_sha256"):
                digest = hashlib.sha256(preimage).digest()
                if derivation == "double_sha256":
                    digest = hashlib.sha256(digest).digest()
                hit = targets.gate_scalar_bytes(digest)
                scalar_results.append(
                    {
                        "part_set": set_name,
                        "weave_id": weave_id,
                        "derivation": derivation,
                        "prize_match": hit,
                    }
                )
                if hit is not None:
                    prize_matches.append(
                        {"kind": "scalar", "part_set": set_name, "weave_id": weave_id, **hit}
                    )

            for form in PASSWORD_FORMS:
                password = _password_bytes(preimage, form)
                for kdf in KDF_DIGESTS:
                    for envelope_name in ENVELOPES:
                        try:
                            plaintext = decrypt_salted_aes256_cbc(
                                envelopes[envelope_name], password, digest=kdf
                            ).plaintext
                        except ValueError:
                            aes_results.append(
                                {
                                    "part_set": set_name,
                                    "weave_id": weave_id,
                                    "form": form,
                                    "kdf": kdf,
                                    "envelope": envelope_name,
                                    "padding_valid": False,
                                }
                            )
                            continue
                        padding_hits += 1
                        gate = _gate_plaintext(plaintext)
                        record = {
                            "part_set": set_name,
                            "weave_id": weave_id,
                            "form": form,
                            "kdf": kdf,
                            "envelope": envelope_name,
                            "padding_valid": True,
                            **gate,
                        }
                        if gate["legible"]:
                            legible_outputs += 1
                        if gate["prize_matches"]:
                            prize_matches.extend(
                                {
                                    "kind": f"aes_{envelope_name}",
                                    "part_set": set_name,
                                    "weave_id": weave_id,
                                    **match,
                                }
                                for match in gate["prize_matches"]
                            )
                        aes_results.append(record)

    if len(aes_results) != expected_aes_trials():
        raise ValueError(f"aes trial drift: {len(aes_results)} != {expected_aes_trials()}")
    if len(scalar_results) != expected_scalar_gates():
        raise ValueError("scalar gate drift")

    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "controls": {
            "phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you."),
            "planted_scalar_accepted": planted is not None,
            "production_rejects_control_scalar": targets.gate_scalar_bytes(
                bytes.fromhex(manifest["control_scalar_hex"])
            )
            is None,
        },
        "counts": {
            "aes_trials": len(aes_results),
            "scalar_gates": len(scalar_results),
            "padding_hits": padding_hits,
            "legible_outputs": legible_outputs,
            "prize_matches": len(prize_matches),
        },
        "weave_material_sha256": materials,
        "prize_matches": prize_matches,
        "legible_records": [r for r in aes_results if r.get("legible")],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import json as _json

    output = run()
    print(_json.dumps({"status": output["status"], **output["counts"]}, indent=2))
