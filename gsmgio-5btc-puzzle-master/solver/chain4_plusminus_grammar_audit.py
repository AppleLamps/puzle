"""Reproduce the finite '+-' grammar families proposed at the public frontier."""

from __future__ import annotations

import hashlib
import itertools
import json

from Crypto.Cipher import AES
from coincurve import PrivateKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .openssl_compat import evp_bytes_to_key_md5, strict_pkcs7_unpad
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "chain4_plusminus_grammar_audit.json"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _target_gate(value: int) -> dict[str, object] | None:
    value %= N
    if not value:
        return None
    public = PrivateKey.from_int(value).public_key.format(compressed=False)
    target_public = b"\x04" + TARGET_X.to_bytes(32, "big") + TARGET_Y.to_bytes(32, "big")
    uncompressed = base58check(b"\x00" + hash160(public))
    if public != target_public or uncompressed != TARGET_ADDRESS:
        return None
    return {"private_hex": f"{value:064x}", "address": uncompressed}


def _bit_windows(data: bytes, width: int, order: str):
    bits: list[int] = []
    for byte in data:
        positions = range(7, -1, -1) if order == "msb" else range(8)
        bits.extend((byte >> position) & 1 for position in positions)
    for start in range(len(bits) - width + 1):
        yield start, bits[start : start + width]


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    envelope = chain4.embedded_envelope
    salt = envelope[8:16]
    ciphertext = envelope[16:]
    fragments = {
        "E_C": chains.chain1.extension,
        "E_S": chains.chain2.extension,
        "E_B": chains.cosmic_b.extension,
        "E_H": chains.cosmic_h.extension,
    }
    if any(len(fragment) != 15 for fragment in fragments.values()):
        raise ValueError("unexpected E-fragment length")

    valid_padding: list[dict[str, object]] = []
    tested_passwords = 0
    for (name1, fragment1), (name2, fragment2), (name3, fragment3) in itertools.product(
        fragments.items(), repeat=3
    ):
        for offset in range(14):
            password = fragment1 + fragment2 + fragment3[offset : offset + 2]
            tested_passwords += 1
            key, iv = evp_bytes_to_key_md5(password, salt)
            padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
            try:
                body, padding_length = strict_pkcs7_unpad(padded)
            except ValueError:
                continue
            printable64 = sum(
                32 <= value < 127 or value in (9, 10, 13) for value in body[:64]
            ) / max(1, min(64, len(body)))
            canonical_layout = (
                len(body) == 1151
                and body.startswith(b"+-")
                and (len(body) - 31) % 32 == 0
                and (len(body) - 31) // 32 == 35
            )
            valid_padding.append(
                {
                    "slots": [name1, name2, name3, offset],
                    "password_hex": password.hex(),
                    "padding_length": padding_length,
                    "plaintext_length": len(body),
                    "printable64": round(printable64, 6),
                    "head31_hex": body[:31].hex(),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "canonical_plusminus_layout": canonical_layout,
                }
            )
    if tested_passwords != 896:
        raise ValueError("15+15+2 password count changed")
    canonical_hits = [hit for hit in valid_padding if hit["canonical_plusminus_layout"]]
    expected_password = fragments["E_C"] + fragments["E_S"] + fragments["E_B"][:2]
    if len(canonical_hits) != 1 or canonical_hits[0]["password_hex"] != expected_password.hex():
        raise ValueError("canonical Chain 4 password control was not uniquely recovered")

    raw = chain4.decryption.plaintext
    prefix = raw[:31]
    operand30 = prefix[1:31]
    magnitude29 = prefix[2:31]
    blocks = list(chain4.blocks)
    scalars = [int.from_bytes(block, "big") for block in blocks]
    operand_int = int.from_bytes(operand30, "big")
    magnitude_int = int.from_bytes(magnitude29, "big")

    # Family B: ten exact whole-integer readings of the unstripped plaintext.
    key, iv = evp_bytes_to_key_md5(expected_password, salt)
    unstripped = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    if len(unstripped) != 1152 or unstripped[-1] != 1:
        raise ValueError("canonical unstripped Chain 4 control changed")
    blocks36 = [unstripped[index : index + 32] for index in range(0, 1152, 32)]
    blocks35_after_header = [unstripped[index : index + 32] for index in range(32, 1152, 32)]
    xor36 = 0
    for block in blocks36:
        xor36 ^= int.from_bytes(block, "big")
    xor35 = 0
    for block in blocks35_after_header:
        xor35 ^= int.from_bytes(block, "big")
    base_b = {
        "B36_sum": sum(int.from_bytes(block, "big") for block in blocks36),
        "B36_xor": xor36,
        "B35_after_header_sum": sum(int.from_bytes(block, "big") for block in blocks35_after_header),
        "B35_after_header_xor": xor35,
        "B36_sum_times_inv8": sum(int.from_bytes(block, "big") for block in blocks36) * pow(8, -1, N),
    }
    b_candidates: list[dict[str, object]] = []
    matches: list[dict[str, object]] = []
    for name, value in base_b.items():
        for derived_name, candidate in (
            (name, value),
            (f"sha256({name})", int.from_bytes(_sha256((value % N).to_bytes(32, "big")), "big")),
        ):
            gate = _target_gate(candidate)
            b_candidates.append({"name": derived_name, "scalar_hex": f"{candidate % N:064x}"})
            if gate:
                matches.append({"family": "B", "name": derived_name, **gate})

    # Family C: sign selectors from every 35-bit prefix/operand window.
    c_stream = hashlib.sha256()
    tested_c = 0
    for source, data in (("prefix31", prefix), ("operand30", operand30), ("magnitude29", magnitude29)):
        for order in ("msb", "lsb"):
            for start, signs in _bit_windows(data, 35, order):
                for plus_on_one in (True, False):
                    coefficients = [1 if (bit == 1) == plus_on_one else -1 for bit in signs]
                    folded = sum(coefficient * scalar for coefficient, scalar in zip(coefficients, scalars))
                    for operation, extra in (
                        ("none", 0),
                        ("+operand", operand_int),
                        ("-operand", -operand_int),
                        ("+magnitude", magnitude_int),
                        ("-magnitude", -magnitude_int),
                    ):
                        candidate = (folded + extra) % N
                        tested_c += 1
                        c_stream.update(candidate.to_bytes(32, "big"))
                        gate = _target_gate(candidate)
                        if gate:
                            matches.append(
                                {
                                    "family": "C",
                                    "source": source,
                                    "order": order,
                                    "start": start,
                                    "plus_on_one": plus_on_one,
                                    "operation": operation,
                                    **gate,
                                }
                            )
    if tested_c != 12360:
        raise ValueError("sign-window candidate count changed")

    # Family D: the recorded natural sign and selected-XOR folds.
    token_hashes = [
        _sha256(token.encode("ascii"))
        for token in (
            "matrixsumlist",
            "enter",
            "lastwordsbeforearchichoice",
            "thispassword",
            "matrixsumlist",
            "yourlastcommand",
            "secondanswer",
        )
    ]
    patterns: dict[str, list[int]] = {
        "index_parity": [1 if index % 2 == 0 else -1 for index in range(35)],
        "msb_set": [1 if blocks[index][0] & 0x80 else -1 for index in range(35)],
        "lsb_set": [1 if blocks[index][-1] & 1 else -1 for index in range(35)],
        "block_sum_parity": [1 if sum(blocks[index]) % 2 == 0 else -1 for index in range(35)],
    }
    for marker in (0x2D, 0x77, 0xEF):
        patterns[f"marker_{marker:02x}"] = [1 if marker in blocks[index] else -1 for index in range(35)]
    token_bits = [digest[0] & 1 for digest in token_hashes]
    patterns["token_parity_rows"] = [1 if token_bits[index % 7] == 0 else -1 for index in range(35)]
    # Preserve the historical ninth base pattern explicitly.
    patterns["index_parity_reverse"] = [-value for value in patterns["index_parity"]]

    tested_d = 0
    d_stream = hashlib.sha256()
    for name, coefficients in patterns.items():
        for orientation, oriented in (("as_is", coefficients), ("negated", [-value for value in coefficients])):
            signed_sum = sum(coefficient * scalar for coefficient, scalar in zip(oriented, scalars))
            xor_selected = 0
            for coefficient, block in zip(oriented, blocks):
                if coefficient == 1:
                    xor_selected ^= int.from_bytes(block, "big")
            for operation, candidate in (
                ("signed_sum", signed_sum),
                ("xor_selected", xor_selected),
                ("signed_sum+operand", signed_sum + operand_int),
                ("signed_sum-operand", signed_sum - operand_int),
            ):
                candidate %= N
                tested_d += 1
                d_stream.update(candidate.to_bytes(32, "big"))
                gate = _target_gate(candidate)
                if gate:
                    matches.append(
                        {"family": "D", "pattern": name, "orientation": orientation, "operation": operation, **gate}
                    )
    if tested_d != 72:
        raise ValueError("natural sign-pattern count changed")

    result: dict[str, object] = {
        "status": "MATCH" if matches else "COMPLETE_NO_MATCH",
        "chain4_sha256": hashlib.sha256(raw).hexdigest(),
        "A_fragment_passwords": {
            "tested": tested_passwords,
            "strict_padding_hits": len(valid_padding),
            "canonical_structure_hits": len(canonical_hits),
            "valid_padding_records": valid_padding,
        },
        "B_unstripped_integer_readings": {
            "unstripped_length": len(unstripped),
            "candidate_count": len(b_candidates),
            "candidates": b_candidates,
        },
        "C_sign_windows": {"candidate_count": tested_c, "candidate_stream_sha256": c_stream.hexdigest()},
        "D_natural_sign_patterns": {
            "base_pattern_count": len(patterns),
            "candidate_count": tested_d,
            "candidate_stream_sha256": d_stream.hexdigest(),
        },
        "matches": matches,
        "positive_controls": {
            "canonical_password_recovered_uniquely": True,
            "canonical_password_hex": expected_password.hex(),
            "canonical_chain4_sha256": canonical_hits[0]["sha256"],
        },
        "scope_note": (
            "Strict padding hits are recorded but are not treated as evidence. Only the known password yields the exact '+-' "
            "plus 31+35x32 layout. Families C and D are also contained within the complete all-sign MITM audit."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
