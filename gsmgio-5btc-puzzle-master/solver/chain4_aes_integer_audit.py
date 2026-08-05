"""Reconstruct the bounded Chain 4 AES-layer and integer-reading probe."""

from __future__ import annotations

import hashlib
import json

from coincurve import PublicKey
from Crypto.Cipher import AES

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "chain4_aes_integer_audit.json"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")


def _addresses(public: PublicKey) -> tuple[str, str]:
    return (
        base58check(b"\0" + hash160(public.format(compressed=True))),
        base58check(b"\0" + hash160(public.format(compressed=False))),
    )


def _point_gate(
    value: int,
    known_points: dict[str, bytes],
    known_addresses: dict[str, tuple[str, str]],
) -> dict[str, object] | None:
    scalar = value % N
    if scalar == 0:
        return None
    public = PublicKey.from_valid_secret(scalar.to_bytes(32, "big"))
    compressed = public.format(compressed=True)
    point_names = [name for name, expected in known_points.items() if compressed == expected]
    if not point_names:
        return None
    compressed_address, uncompressed_address = _addresses(public)
    for name in point_names:
        if (compressed_address, uncompressed_address) != known_addresses[name]:
            raise ValueError(f"point/address cross-check failed for {name}")
    prize = "prize" in point_names
    return {
        "private_hex": f"{scalar:064x}",
        "point_names": point_names,
        "compressed_public_key": compressed.hex(),
        "compressed_address": compressed_address,
        "uncompressed_address": uncompressed_address,
        "prize_point_match": prize,
        "prize_address_match": prize and uncompressed_address == TARGET_ADDRESS,
        "accepted": prize and uncompressed_address == TARGET_ADDRESS,
    }


def run() -> dict[str, object]:
    sal = derive_tokens()
    chains = reconstruct(extract_all(), sal)
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)
    body = b"".join(chain4.blocks)
    prefix = chain4.structured_prefix

    recovered = {
        "K_C1": chains.chain1.key1,
        "K_C2": chains.chain1.key2,
        "K_S1": chains.chain2.key1,
        "K_S2": chains.chain2.key2,
        "K_B1": chains.cosmic_b.key1,
        "K_B2": chains.cosmic_b.key2,
        "K_H1": chains.cosmic_h.key1,
        "K_H2": chains.cosmic_h.key2,
    }
    keys: dict[str, bytes] = dict(recovered)
    for token in dict.fromkeys(sal.tokens):
        keys[f"sha256({token})"] = hashlib.sha256(token.encode("utf-8")).digest()
    keys.update({
        "cosmic_master": sal.xor_password,
        "chain4_password": chain4.password,
        "operand_leftpad": chain4.opcode_operand.rjust(32, b"\0"),
        "operand_rightpad": chain4.opcode_operand.ljust(32, b"\0"),
    })
    if len(keys) != 18 or any(len(key) != 32 for key in keys.values()):
        raise ValueError("AES probe key derivation did not reproduce 18 AES-256 keys")

    half_public = PublicKey.from_valid_secret(matrix.half)
    better_public = PublicKey.from_valid_secret(matrix.better_half)
    known_points = {
        "prize": TARGET_COMPRESSED,
        "Half": half_public.format(compressed=True),
        "Better_Half": better_public.format(compressed=True),
    }
    known_addresses = {
        "prize": (base58check(b"\0" + hash160(TARGET_COMPRESSED)), TARGET_ADDRESS),
        "Half": _addresses(half_public),
        "Better_Half": _addresses(better_public),
    }
    # The prize compressed-address entry is informative only; the prize uses
    # the uncompressed serialization and the full point is the primary gate.

    stream = hashlib.sha256()
    structure_hits: list[dict[str, object]] = []
    point_matches: list[dict[str, object]] = []
    ecb_decryptions = 0
    for key_name, key in keys.items():
        cipher = AES.new(key, AES.MODE_ECB)
        for block_index, block in enumerate(chain4.blocks):
            plaintext = cipher.decrypt(block)
            ecb_decryptions += 1
            stream.update(b"A1\0" + key_name.encode("utf-8") + b"\0" + bytes([block_index]) + plaintext)
            gate = _point_gate(int.from_bytes(plaintext, "big"), known_points, known_addresses)
            if gate:
                point_matches.append({"family": "A1", "key": key_name, "block_index": block_index, **gate})
            printable_count = sum(32 <= byte < 127 for byte in plaintext)
            if plaintext.startswith(b"Salted__") or printable_count >= 29:
                structure_hits.append({
                    "family": "A1", "key": key_name, "block_index": block_index,
                    "plaintext_hex": plaintext.hex(), "printable_count": printable_count,
                    "salted_header": plaintext.startswith(b"Salted__"),
                })

    cbc_decryptions = cbc_chunk_scalar_gates = 0
    ivs = {
        "zero": bytes(16),
        "operand_head": chain4.opcode_operand[:16],
        "operand_tail": chain4.opcode_operand[-16:],
    }
    for key_name, key in keys.items():
        for iv_name, iv in ivs.items():
            plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
            cbc_decryptions += 1
            stream.update(b"A2\0" + key_name.encode("utf-8") + b"\0" + iv_name.encode("ascii") + b"\0" + plaintext)
            for chunk_index in range(35):
                chunk = plaintext[32 * chunk_index : 32 * (chunk_index + 1)]
                cbc_chunk_scalar_gates += 1
                gate = _point_gate(int.from_bytes(chunk, "big"), known_points, known_addresses)
                if gate:
                    point_matches.append({
                        "family": "A2", "key": key_name, "iv": iv_name,
                        "chunk_index": chunk_index, **gate,
                    })
            if plaintext.startswith(b"Salted__"):
                structure_hits.append({"family": "A2", "key": key_name, "iv": iv_name, "salted_header": True})

    integer_readings = (
        ("chain4_big", int.from_bytes(chain4.decryption.plaintext, "big")),
        ("chain4_little", int.from_bytes(chain4.decryption.plaintext, "little")),
        ("body_big", int.from_bytes(body, "big")),
        ("body_little", int.from_bytes(body, "little")),
        ("prefix_big", int.from_bytes(prefix, "big")),
    )
    whole_integer_candidates = 0
    for reading_name, value in integer_readings:
        for sign_name, candidate in (("positive", value), ("negative", -value)):
            whole_integer_candidates += 1
            scalar = candidate % N
            stream.update(b"B1\0" + reading_name.encode("ascii") + b"\0" + sign_name.encode("ascii") + scalar.to_bytes(32, "big"))
            gate = _point_gate(candidate, known_points, known_addresses)
            if gate:
                point_matches.append({"family": "B1", "reading": reading_name, "sign": sign_name, **gate})

    selectors = {
        "operand": int.from_bytes(chain4.opcode_operand, "big"),
        "magnitude": int.from_bytes(chain4.operand, "big"),
        "prefix": int.from_bytes(prefix, "big"),
    }
    selector_candidates = 0
    selector_records: list[dict[str, object]] = []
    for source_name, source in selectors.items():
        index = source % len(chain4.blocks)
        for base in (0, 1):
            block_index = index if base == 0 else (index - 1) % len(chain4.blocks)
            block_value = int.from_bytes(chain4.blocks[block_index], "big")
            for operation, candidate in (
                ("direct", block_value), ("add_source", block_value + source), ("subtract_source", block_value - source)
            ):
                selector_candidates += 1
                scalar = candidate % N
                stream.update(
                    b"B2\0" + source_name.encode("ascii") + bytes([base, block_index])
                    + operation.encode("ascii") + b"\0" + scalar.to_bytes(32, "big")
                )
                selector_records.append({
                    "source": source_name, "source_mod_35": index, "index_base": base,
                    "selected_block_index": block_index, "operation": operation,
                    "candidate_scalar_hex": f"{scalar:064x}",
                })
                gate = _point_gate(candidate, known_points, known_addresses)
                if gate:
                    point_matches.append({
                        "family": "B2", "source": source_name, "index_base": base,
                        "selected_block_index": block_index, "operation": operation, **gate,
                    })

    # Cryptographic and point-gate controls use derived data, not fixtures
    # copied from expected ciphertexts.
    control_plaintext = bytes(range(32))
    control_key = recovered["K_C1"]
    ecb_ciphertext = AES.new(control_key, AES.MODE_ECB).encrypt(control_plaintext)
    cbc_iv = chain4.opcode_operand[:16]
    cbc_ciphertext = AES.new(control_key, AES.MODE_CBC, cbc_iv).encrypt(control_plaintext)
    half_gate = _point_gate(int.from_bytes(matrix.half, "big"), known_points, known_addresses)
    positive_controls = {
        "ecb_roundtrip": AES.new(control_key, AES.MODE_ECB).decrypt(ecb_ciphertext) == control_plaintext,
        "cbc_roundtrip": AES.new(control_key, AES.MODE_CBC, cbc_iv).decrypt(cbc_ciphertext) == control_plaintext,
        "component_point_gate": bool(half_gate and "Half" in half_gate["point_names"]),
    }
    if not all(positive_controls.values()):
        raise ValueError("AES/integer audit positive control failed")

    accepted = [match for match in point_matches if match["accepted"]]
    result: dict[str, object] = {
        "status": "MATCH" if accepted else "COMPLETE_NO_MATCH",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "derived_keys": {name: value.hex() for name, value in keys.items()},
        "derived_key_count": len(keys),
        "iv_hex": {name: value.hex() for name, value in ivs.items()},
        "counts": {
            "A1_ecb_block_decryptions": ecb_decryptions,
            "A2_cbc_body_decryptions": cbc_decryptions,
            "A2_chunk_scalar_gates": cbc_chunk_scalar_gates,
            "B1_whole_integer_candidates": whole_integer_candidates,
            "B2_selector_candidates": selector_candidates,
        },
        "candidate_stream_sha256": stream.hexdigest(),
        "structure_hits": structure_hits,
        "point_matches": point_matches,
        "accepted_prize_matches": accepted,
        "selector_records": selector_records,
        "positive_controls": positive_controls,
        "scope_note": "Printable output is recorded only as structure evidence and is never accepted as a key. Candidate acceptance requires the complete prize point and uncompressed prize address.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"], "derived_key_count": output["derived_key_count"],
        "counts": output["counts"], "candidate_stream_sha256": output["candidate_stream_sha256"],
        "structure_hits": output["structure_hits"], "point_matches": output["point_matches"],
    }, indent=2))
