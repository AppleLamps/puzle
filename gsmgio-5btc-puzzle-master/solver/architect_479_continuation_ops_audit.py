"""Evaluate sealed v76: Architect 479 continuation named operations."""

from __future__ import annotations

import hashlib
import json

from . import targets
from .architect_479_continuation_ops_preregister import (
    AES_TARGETS,
    KDF_DIGESTS,
    MANIFEST_PATH,
    OPERATIONS,
    PASSWORD_FORMS,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_aes_trials,
    expected_materials,
    expected_scalar_gates,
)
from .architect_anchor_windows_preregister import ANCHORS
from .creator_pipeline_poster_architect_audit import HOPE_QUOTE, _beaufort
from .envelope_legibility_audit import decrypt_target, legible, password_bytes
from .extract import extract_all
from .intertwined_password_coherence_audit import _architect_plaintext
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import PHASE32_PASSWORD
from .salphaseion import derive_tokens
from .salphaseion_raw import extract_raw
from .salphaseion_split_envelope_preregister import split_envelope
from .yinyang_prime_dual_preregister import prime_lists
from .yinyang_rot180_partition_preregister import partition
from .youwon_middle_block_preregister import difference_state


HASHTHETEXT = b"HASTHETEXT"


def _windows() -> dict[str, bytes]:
    text = _architect_plaintext()
    if len(text) != 1539:
        raise ValueError("architect length drift")
    take = ANCHORS["TAKETHE"]
    pk = ANCHORS["PRIVATEKEY_FIRST"]
    ret = ANCHORS["RETURN"]
    src = ANCHORS["SOURCECODES"]
    reinsert = ANCHORS["REINSERTING"]
    return {
        "W01": text[take:ret].encode("ascii"),
        "W02": text[pk:ret].encode("ascii"),
        "W03": text[pk : pk + 120].encode("ascii"),
        "W04": text[pk : pk + 60].encode("ascii"),
        "W05": text[ret:reinsert].encode("ascii"),
        "W06": text[src:reinsert].encode("ascii"),
        "W07": text[reinsert : reinsert + 120].encode("ascii"),
        "W08": text[reinsert : reinsert + 60].encode("ascii"),
        "W09": text[take:reinsert].encode("ascii"),
    }


def _reinsert_digits(text: bytes, values: list[int]) -> bytes:
    chars = list(text.decode("ascii"))
    for index, value in enumerate(values, start=1):
        if index <= len(chars):
            chars[index - 1] = str(value % 10)
    return "".join(chars).encode("ascii")


def _mod26_add(left: bytes, right: bytes) -> bytes:
    length = min(len(left), len(right))
    out = bytearray()
    for index in range(length):
        if not (65 <= left[index] <= 90 or 97 <= left[index] <= 122):
            out.append(left[index])
            continue
        if not (65 <= right[index] <= 90 or 97 <= right[index] <= 122):
            out.append(left[index])
            continue
        base = 65 if left[index] <= 90 else 97
        rb = 65 if right[index] <= 90 else 97
        out.append(((left[index] - base + right[index] - rb) % 26) + base)
    return bytes(out)


def _materials() -> dict[str, bytes]:
    windows = _windows()
    lists = prime_lists()
    diff = difference_state()
    tokens = derive_tokens()
    lastwords = tokens.directly_decoded[2].encode("ascii")
    architect = _architect_plaintext()
    mask = str(partition()["streams"]["rot180_inversion_mask98"])
    s91 = extract_raw().s91.upper().encode("ascii")
    middle49 = diff["middle49"].encode("ascii")

    materials: dict[str, bytes] = {}
    for index in range(1, 10):
        key = f"W0{index}"
        materials[f"hash_the_text_{key}"] = hashlib.sha256(windows[key]).digest()

    materials["reinsert_yellow9_W02"] = _reinsert_digits(windows["W02"], lists["yellow9"])
    materials["reinsert_blue_zero5_W06"] = _reinsert_digits(windows["W06"], lists["blue15_zero5"])
    suffix = architect[479 : 479 + 98]
    materials["select_rot180_suffix98"] = "".join(
        suffix[index] for index, bit in enumerate(mask) if bit == "1"
    ).encode("ascii")
    materials["xor_middle49_W04"] = bytes(a ^ b for a, b in zip(windows["W04"], middle49.ljust(len(windows["W04"]), b"A")))
    materials["beaufort_hope_W05"] = _beaufort(windows["W05"].decode("ascii"), HOPE_QUOTE[: len(windows["W05"])]).encode(
        "ascii"
    )
    materials["mod26_add_s91_W02"] = _mod26_add(windows["W02"], s91)
    materials["mod26_add_middle49_W04"] = _mod26_add(windows["W04"], middle49)
    materials["concat_enter_lastwords_W02"] = windows["W02"][:120] + b"enter" + lastwords
    for key in ("W01", "W06"):
        materials[f"sha256_chain_hashthetext_{key}"] = hashlib.sha256(
            HASHTHETEXT + hashlib.sha256(windows[key]).digest()
        ).digest()
    return materials


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    materials = _materials()
    if set(materials) != set(OPERATIONS):
        raise ValueError("operation set drift")

    chain1 = extract_all().chain1_envelope
    env48, raw48 = split_envelope()

    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for operation in OPERATIONS:
        material = materials[operation]
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(material).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append(
                {"operation": operation, "derivation": derivation, "prize_match": hit}
            )
            if hit is not None:
                prize_matches.append({"kind": "scalar", "operation": operation, **hit})

        for form in PASSWORD_FORMS:
            password = password_bytes(material, form)
            for kdf in KDF_DIGESTS:
                for target in AES_TARGETS:
                    plaintext = decrypt_target(target, chain1, env48, raw48, password, kdf)
                    record: dict[str, object] = {
                        "operation": operation,
                        "form": form,
                        "kdf": kdf,
                        "target": target,
                        "padding_valid": plaintext is not None,
                    }
                    if plaintext is None:
                        aes_results.append(record)
                        continue
                    padding_hits += 1
                    leg = legible(plaintext)
                    record["legible"] = leg
                    if leg:
                        legible_outputs += 1
                    aes_results.append(record)

    if len(materials) != expected_materials():
        raise ValueError("material count drift")
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
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        "controls": {
            "phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you."),
        },
        "counts": {
            "materials": len(materials),
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
