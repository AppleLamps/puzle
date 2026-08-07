"""Evaluate sealed v58: pipeline-operand split-envelope legibility audit.

Run ``python -m solver.pipeline_operand_split_envelope_preregister`` then
``python -m solver.pipeline_operand_split_envelope_audit``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re

from Crypto.Cipher import AES

from . import targets
from .openssl_compat import decrypt_salted_aes256_cbc, evp_bytes_to_key, strict_pkcs7_unpad
from .extract import README, extract_all
from .phase32_classical import BEAUFORT_KEY, PHASE32_PASSWORD, _beaufort, _vic_decode
from .poster_resistor_split_envelope_audit import _col_sums, _poster_grid, _row_sums
from .pipeline_operand_split_envelope_preregister import (
    ENV48_OPERAND_IDS,
    ENV48_SHA256,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    RAW48_IV_MODES,
    RAW48_OPERAND_IDS,
    RAW48_SHA256,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_aes_trials,
    expected_scalar_gates,
)
from .salphaseion import derive_tokens
from .salphaseion_raw import extract_raw, sha256_hex
from .salphaseion_split_envelope_preregister import split_envelope
from .yinyang_prime_dual_preregister import prime_lists
from .yinyang_rot180_partition_preregister import partition
from .youwon_middle_block_preregister import difference_state


ROOT = MANIFEST_PATH.parent
PHASE32_PATH = ROOT / "phase32_classical.json"
VIC_ALPHABET = "FUBCDORA.LETHINGKYMVPS.JQZXW"

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


def _ai_to_letters(field: str) -> str:
    return "".join(ch.upper() for ch in field if "a" <= ch <= "i")


def _ai_to_digits(field: str) -> str:
    return "".join(str(ord(ch) - ord("a") + 1) for ch in field if "a" <= ch <= "i")


def _serialize_primes(values: list[int], mode: str) -> bytes:
    if mode == "decimal":
        return "".join(str(v) for v in values).encode("ascii")
    if mode == "two_digit":
        return "".join(f"{v:02d}" for v in values).encode("ascii")
    raise ValueError(mode)


def _build_operands() -> dict[str, bytes]:
    parts = extract_raw()
    tokens = derive_tokens()
    p3, p4 = tokens.directly_decoded[2], tokens.directly_decoded[3]
    grid = _poster_grid()
    sums = {
        "row_eye9": _row_sums(grid, zero_eye=False),
        "col_eye9": _col_sums(grid, zero_eye=False),
        "row_eye0": _row_sums(grid, zero_eye=True),
        "col_eye0": _col_sums(grid, zero_eye=True),
    }
    lists = prime_lists()
    part = partition()
    diff = difference_state()
    phase32 = json.loads(PHASE32_PATH.read_text(encoding="utf-8"))
    architect_text = _architect_plaintext()
    if len(architect_text) != 1539:
        raise ValueError("architect plaintext length drift")
    vic_digits = phase32["vic"]["digit_count"]
    opened = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    numeric = re.search(rb"\r\n\r\n(\d+)\r\n\r\nRaising the stakes", opened.plaintext)
    if numeric is None:
        raise ValueError("phase32 VIC digits missing")
    vic_digit_str = numeric.group(1).decode("ascii")
    if len(vic_digit_str) != vic_digits:
        raise ValueError("VIC digit length drift")

    blue_zero5 = lists["blue15_zero5"]
    yellow9 = lists["yellow9"]
    all24 = lists["all24"]

    return {
        "E01_s91_letters": _ai_to_letters(parts.s91).encode("ascii"),
        "E02_s91_digits_a1_i9": _ai_to_digits(parts.s91).encode("ascii"),
        "E03_s570_letters": _ai_to_letters(parts.s570).encode("ascii"),
        "E04_lastwords_decoded": p3.encode("ascii"),
        "E05_thispassword_decoded": p4.encode("ascii"),
        "E06_resistor_row_eye9_raw": bytes(sums["row_eye9"]),
        "E07_resistor_col_eye9_raw": bytes(sums["col_eye9"]),
        "E08_resistor_row_eye0_raw": bytes(sums["row_eye0"]),
        "E09_resistor_col_eye0_raw": bytes(sums["col_eye0"]),
        "E10_resistor_row_eye9_mod10": "".join(str(v % 10) for v in sums["row_eye9"]).encode("ascii"),
        "E11_resistor_col_eye9_mod10": "".join(str(v % 10) for v in sums["col_eye9"]).encode("ascii"),
        "E12_resistor_row_eye0_mod10": "".join(str(v % 10) for v in sums["row_eye0"]).encode("ascii"),
        "E13_resistor_col_eye0_mod10": "".join(str(v % 10) for v in sums["col_eye0"]).encode("ascii"),
        "E14_prime_blue_zero5_decimal": _serialize_primes(blue_zero5, "decimal"),
        "E15_prime_yellow9_decimal": _serialize_primes(yellow9, "decimal"),
        "E16_prime_all24_two_digit": _serialize_primes(all24, "two_digit"),
        "R01_architect_479_120": architect_text[479:599].encode("ascii"),
        "R02_architect_479_60": architect_text[479:539].encode("ascii"),
        "R03_vic_digits_149": vic_digit_str.encode("ascii"),
        "R04_vic_funds_message": phase32["vic"]["plaintext"].encode("ascii"),
        "R05_rot180_mask_packed": _pack_bits(str(part["streams"]["rot180_inversion_mask98"])),
        "R06_rot180_yin_bits_packed": _pack_bits(str(part["streams"]["yin_bits98"])),
        "R07_difference_middle49": diff["middle49"].encode("ascii"),
        "R08_difference_full91": diff["difference_full"].encode("ascii"),
    }


def _decrypt_env48(env48: bytes, password: bytes, digest: str) -> bytes | None:
    try:
        return decrypt_salted_aes256_cbc(env48, password, digest=digest).plaintext
    except ValueError:
        return None


def _decrypt_raw48(
    raw48: bytes,
    env48: bytes,
    password: bytes,
    digest: str,
    iv_mode: str,
) -> bytes | None:
    salt = env48[8:16]
    if iv_mode == "evp_iv":
        key, iv = evp_bytes_to_key(password, salt, digest=digest)
    elif iv_mode == "continuation_iv":
        key, _ = evp_bytes_to_key(password, salt, digest=digest)
        iv = env48[32:48]
    else:
        raise ValueError(iv_mode)
    try:
        padded = AES.new(key, AES.MODE_CBC, iv).decrypt(raw48)
        plaintext, _ = strict_pkcs7_unpad(padded)
        return plaintext
    except ValueError:
        return None


def _gate_plaintext(plaintext: bytes) -> dict[str, object]:
    result: dict[str, object] = {
        "legible": _legible(plaintext),
        "printable_ratio": round(_printable_ratio(plaintext), 4),
        "entropy": round(_entropy(plaintext), 4),
        "length": len(plaintext),
        "prize_matches": [],
    }
    for candidate in (hashlib.sha256(plaintext).digest(), plaintext[:32] if len(plaintext) >= 32 else b""):
        if len(candidate) != 32:
            continue
        hit = targets.gate_scalar_bytes(candidate)
        if hit is not None:
            result["prize_matches"].append({"scalar_hex": candidate.hex(), **hit})
    return result


def _controls(env48: bytes) -> dict[str, object]:
    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    scalar = int(build_manifest()["control_scalar_hex"], 16)
    x, y = targets._public_point(scalar)
    planted = targets.gate_point(x, y, half_public=targets.serializations(x, y)["uncompressed"])
    return {
        "phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you."),
        "vic_self_check": "THEPRIVATEKEYSBELONGTOHALFANDBETTERHALF"
        in _vic_decode(
            re.search(rb"\r\n\r\n(\d+)\r\n\r\nRaising the stakes", phase32.plaintext).group(1).decode("ascii"),
            VIC_ALPHABET,
            ("1", "4"),
        ),
        "env48_pinned": sha256_hex(env48) == ENV48_SHA256,
        "raw48_pinned": sha256_hex(split_envelope()[1]) == RAW48_SHA256,
        "planted_scalar_accepted": planted is not None,
        "production_rejects_control_scalar": targets.gate_scalar_bytes(bytes.fromhex(build_manifest()["control_scalar_hex"])) is None,
    }


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if manifest["status"] != "SEALED_BEFORE_AES_OR_SCALAR_EVALUATION":
        raise ValueError("manifest is not sealed")
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("re-derived manifest differs from sealed manifest")

    targets.self_check()
    env48, raw48 = split_envelope()
    controls = _controls(env48)
    if not all(
        controls[k]
        for k in (
            "phase32_legible_control",
            "vic_self_check",
            "env48_pinned",
            "raw48_pinned",
            "planted_scalar_accepted",
            "production_rejects_control_scalar",
        )
    ):
        raise ValueError(f"controls failed: {controls}")

    operands = _build_operands()
    operand_digests = {key: sha256_hex(value) for key, value in operands.items()}

    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for operand_id in ENV48_OPERAND_IDS:
        preimage = operands[operand_id]
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(preimage).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append(
                {
                    "operand_id": operand_id,
                    "target": "scalar",
                    "derivation": derivation,
                    "preimage_sha256": operand_digests[operand_id],
                    "prize_match": hit,
                }
            )
            if hit is not None:
                prize_matches.append({"kind": "scalar", "operand_id": operand_id, **hit})

        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for digest in KDF_DIGESTS:
                plaintext = _decrypt_env48(env48, password, digest)
                record: dict[str, object] = {
                    "target": "env48",
                    "operand_id": operand_id,
                    "form": form,
                    "kdf": digest,
                    "password_sha256": sha256_hex(password),
                    "padding_valid": plaintext is not None,
                }
                if plaintext is None:
                    aes_results.append(record)
                    continue
                padding_hits += 1
                gate = _gate_plaintext(plaintext)
                record.update(gate)
                if gate["legible"]:
                    legible_outputs += 1
                if gate["prize_matches"]:
                    prize_matches.extend(
                        {"kind": "aes_env48", "operand_id": operand_id, **m} for m in gate["prize_matches"]
                    )
                aes_results.append(record)

    for operand_id in RAW48_OPERAND_IDS:
        preimage = operands[operand_id]
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(preimage).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append(
                {
                    "operand_id": operand_id,
                    "target": "scalar",
                    "derivation": derivation,
                    "preimage_sha256": operand_digests[operand_id],
                    "prize_match": hit,
                }
            )
            if hit is not None:
                prize_matches.append({"kind": "scalar", "operand_id": operand_id, **hit})

        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for digest in KDF_DIGESTS:
                for iv_mode in RAW48_IV_MODES:
                    plaintext = _decrypt_raw48(raw48, env48, password, digest, iv_mode)
                    record = {
                        "target": "raw48",
                        "operand_id": operand_id,
                        "form": form,
                        "kdf": digest,
                        "iv_mode": iv_mode,
                        "password_sha256": sha256_hex(password),
                        "padding_valid": plaintext is not None,
                    }
                    if plaintext is None:
                        aes_results.append(record)
                        continue
                    padding_hits += 1
                    gate = _gate_plaintext(plaintext)
                    record.update(gate)
                    if gate["legible"]:
                        legible_outputs += 1
                    if gate["prize_matches"]:
                        prize_matches.extend(
                            {"kind": "aes_raw48", "operand_id": operand_id, **m}
                            for m in gate["prize_matches"]
                        )
                    aes_results.append(record)

    aes_trials = len(aes_results)
    if aes_trials != expected_aes_trials():
        raise ValueError(f"aes trial drift: got {aes_trials}, expected {expected_aes_trials()}")
    if len(scalar_results) != expected_scalar_gates():
        raise ValueError("scalar gate count drift")

    stream = hashlib.sha256()
    stream.update(json.dumps(aes_results, sort_keys=True).encode("utf-8"))
    stream.update(json.dumps(scalar_results, sort_keys=True).encode("utf-8"))

    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"

    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "controls": controls,
        "operand_digests": operand_digests,
        "counts": {
            "aes_trials": aes_trials,
            "scalar_gates": len(scalar_results),
            "padding_hits": padding_hits,
            "legible_outputs": legible_outputs,
            "prize_matches": len(prize_matches),
        },
        "prize_matches": prize_matches,
        "legible_records": [r for r in aes_results if r.get("legible")],
        "stream_sha256": stream.hexdigest(),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    outcome = run()
    print(json.dumps(outcome["counts"], indent=2))
