"""Evaluate sealed v70: extended yinyang seven-operand compositions."""

from __future__ import annotations

import hashlib
import json
import math
import re

from Crypto.Cipher import AES

from . import targets
from .extract import extract_all, README
from .openssl_compat import decrypt_salted_aes256_cbc, evp_bytes_to_key, strict_pkcs7_unpad
from .phase32_classical import BEAUFORT_KEY, PHASE32_PASSWORD, _beaufort
from .poster_resistor_split_envelope_audit import _poster_grid, _row_sums
from .salphaseion import derive_tokens
from .salphaseion_split_envelope_preregister import split_envelope
from .yinyang_composition_extended_preregister import (
    AES_TARGETS,
    COMPOSITIONS,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    RESULT_PATH,
    SEAL_PATH,
    STEP_OPERAND_IDS,
    build_manifest,
    expected_aes_trials,
    expected_scalar_gates,
)
from .yinyang_prime_dual_preregister import prime_lists
from .yinyang_rot180_partition_preregister import partition
from .youwon_middle_block_preregister import difference_state


ENGLISH_RUN = re.compile(rb"[A-Za-z]{6,}")


def _architect_plaintext() -> str:
    readme = README.read_text(encoding="utf-8-sig")
    match = re.search(
        r"- phase 3\.2\.1\s+The first blob.*?converted to letters:\s*\n\s*([a-z]+)",
        readme,
        re.DOTALL,
    )
    if match is None:
        raise ValueError("published Phase 3.2.1 ciphertext not found")
    return _beaufort(match.group(1), BEAUFORT_KEY)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in b"\t\n\r" or 32 <= b <= 126 for b in data) / len(data)


def _legible(data: bytes) -> bool:
    if _printable_ratio(data) < 0.85:
        return False
    return _entropy(data) <= 5.9 or bool(ENGLISH_RUN.search(data))


def _password_bytes(preimage: bytes, form: str) -> bytes:
    if form == "literal":
        return preimage
    digest = hashlib.sha256(preimage).digest()
    if form == "sha256_hex_lower":
        return digest.hex().encode("ascii")
    if form == "sha256_raw32":
        return digest
    raise ValueError(form)


def _pack_bits(bits: str) -> bytes:
    usable = len(bits) // 8 * 8
    return bytes(int(bits[i : i + 8], 2) for i in range(0, usable, 8))


def _xor_extend(left: bytes, right: bytes) -> bytes:
    length = max(len(left), len(right))
    return bytes(left[i % len(left)] ^ right[i % len(right)] for i in range(length))


def _add_mod256(left: bytes, right: bytes) -> bytes:
    length = max(len(left), len(right))
    return bytes((left[i % len(left)] + right[i % len(right)]) % 256 for i in range(length))


def _interleave_bytes(parts: tuple[bytes, ...]) -> bytes:
    length = max(len(part) for part in parts)
    out = bytearray()
    for index in range(length):
        for part in parts:
            if index < len(part):
                out.append(part[index])
    return bytes(out)


def _step_operands() -> dict[str, bytes]:
    tokens = derive_tokens()
    p3 = tokens.directly_decoded[2]
    lists = prime_lists()
    part = partition()
    diff = difference_state()
    architect = _architect_plaintext()
    row_mod10 = "".join(str(v % 10) for v in _row_sums(_poster_grid(), zero_eye=False)).encode("ascii")
    return {
        "step1_yellowblueprimes_blue_zero5_decimal": "".join(str(v) for v in lists["blue15_zero5"]).encode("ascii"),
        "step2_matrixsumlist_row_mod10": row_mod10,
        "step3_lastwords_decoded": p3.encode("ascii"),
        "step4_yinyang_rot180_mask_packed": _pack_bits(str(part["streams"]["rot180_inversion_mask98"])),
        "step5_wewontgiveaway_architect_479_33": architect[479:512].encode("ascii"),
        "step6_infrontofyoureyes_middle49": diff["middle49"].encode("ascii"),
        "step7_giveaway_yellow9_decimal": "".join(str(v) for v in lists["yellow9"]).encode("ascii"),
    }


def _compose(name: str, operands: list[bytes]) -> bytes:
    if name == "fold_add_mod256":
        acc = operands[0]
        for nxt in operands[1:]:
            acc = _add_mod256(acc, nxt)
        return acc
    if name == "fold_interleave_bytes":
        return _interleave_bytes(tuple(operands))
    if name == "fold_sha256_concat":
        return hashlib.sha256(b"".join(operands)).digest()
    if name == "yinyang_mirror_xor":
        head = operands[0]
        for part in operands[1:3]:
            head = _xor_extend(head, part)
        tail = operands[4]
        for part in operands[5:7]:
            tail = _xor_extend(tail, part)
        mirrored = _xor_extend(head, tail)
        return mirrored + operands[3]
    raise ValueError(name)


def _decrypt_target(
    target: str,
    chain1: bytes,
    env48: bytes,
    raw48: bytes,
    password: bytes,
    digest: str,
) -> bytes | None:
    if target == "chain1":
        try:
            return decrypt_salted_aes256_cbc(chain1, password, digest=digest).plaintext
        except ValueError:
            return None
    if target == "env48":
        try:
            return decrypt_salted_aes256_cbc(env48, password, digest=digest).plaintext
        except ValueError:
            return None
    salt = env48[8:16]
    key, evp_iv = evp_bytes_to_key(password, salt, digest=digest)
    iv = evp_iv if target == "raw48_evp_iv" else env48[32:48]
    try:
        padded = AES.new(key, AES.MODE_CBC, iv).decrypt(raw48)
        plaintext, _ = strict_pkcs7_unpad(padded)
        return plaintext
    except ValueError:
        return None


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    chain1 = extract_all().chain1_envelope
    env48, raw48 = split_envelope()
    steps = _step_operands()
    ordered = [steps[step_id] for step_id in STEP_OPERAND_IDS]

    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for composition in COMPOSITIONS:
        material = _compose(composition, ordered)
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(material).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append(
                {
                    "composition": composition,
                    "derivation": derivation,
                    "material_sha256": hashlib.sha256(material).hexdigest(),
                    "prize_match": hit,
                }
            )
            if hit is not None:
                prize_matches.append({"kind": "scalar", "composition": composition, **hit})

        for form in PASSWORD_FORMS:
            password = _password_bytes(material, form)
            for digest in KDF_DIGESTS:
                for target in AES_TARGETS:
                    plaintext = _decrypt_target(target, chain1, env48, raw48, password, digest)
                    record: dict[str, object] = {
                        "composition": composition,
                        "form": form,
                        "kdf": digest,
                        "target": target,
                        "padding_valid": plaintext is not None,
                    }
                    if plaintext is None:
                        aes_results.append(record)
                        continue
                    padding_hits += 1
                    leg = _legible(plaintext)
                    record["legible"] = leg
                    record["printable_ratio"] = round(_printable_ratio(plaintext), 4)
                    record["entropy"] = round(_entropy(plaintext), 4)
                    if leg:
                        legible_outputs += 1
                    aes_results.append(record)

    if len(aes_results) != expected_aes_trials():
        raise ValueError("aes trial count drift")
    if len(scalar_results) != expected_scalar_gates():
        raise ValueError("scalar gate count drift")

    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "controls": {"phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you.")},
        "counts": {
            "aes_trials": len(aes_results),
            "scalar_gates": len(scalar_results),
            "padding_hits": padding_hits,
            "legible_outputs": legible_outputs,
            "prize_matches": len(prize_matches),
        },
        "prize_matches": prize_matches,
        "legible_records": [r for r in aes_results if r.get("legible")],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import json as _json

    print(_json.dumps(run()["counts"], indent=2))
