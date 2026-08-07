"""Evaluate sealed v78: post-479 suffix continuation operations."""

from __future__ import annotations

import hashlib
import json
import re

from . import targets
from .architect_post479_suffix_ops_preregister import (
    AES_TARGETS,
    FRESCO_QUOTE,
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
from .creator_pipeline_poster_architect_audit import _beaufort
from .envelope_legibility_audit import decrypt_target, legible, password_bytes, xor_extend
from .extract import extract_all
from .intertwined_password_coherence_audit import _architect_plaintext
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import PHASE32_PASSWORD
from .phase32_symbol_recovery import _raw_symbol_record
from .poster_resistor_split_envelope_audit import _poster_grid, _row_sums
from .salphaseion import derive_tokens
from .salphaseion_split_envelope_preregister import split_envelope
from .yinyang_prime_dual_preregister import prime_lists


def _suffix140(architect: str) -> str:
    return architect[479:619]


def _reinsert_digits(text: str, values: list[int]) -> bytes:
    chars = list(text)
    for index, value in enumerate(values, start=1):
        if index <= len(chars):
            chars[index - 1] = str(value % 10)
    return "".join(chars).encode("ascii")


def _mod26_add(left: str, right: str) -> bytes:
    length = min(len(left), len(right))
    out = []
    for index in range(length):
        a, b = left[index], right[index]
        if not (a.isalpha() and b.isalpha()):
            out.append(a)
            continue
        base = 65
        out.append(chr((ord(a.upper()) - base + ord(b.upper()) - base) % 26 + base))
    return "".join(out).encode("ascii")


def _matrixsumlist_select(suffix: str, sums: list[int], *, mode: str) -> bytes:
    length = len(suffix)
    chars = []
    cumulative = 0
    for value in sums:
        if mode == "absolute":
            index = value % length
        elif mode == "cumulative":
            cumulative = (cumulative + value) % length
            index = cumulative
        else:
            raise ValueError(mode)
        chars.append(suffix[index])
    return "".join(chars).encode("ascii")


def _source_record() -> tuple[bytes, bytes]:
    raw = _raw_symbol_record()
    recovery = json.loads((MANIFEST_PATH.parent / "phase32_symbol_recovery.json").read_text(encoding="utf-8"))
    mapping = {int(key, 16): value for key, value in recovery["recovered_mapping"].items()}
    transliteration = "".join(mapping[value] for value in raw).encode("ascii")
    return raw, transliteration


def _vic_digits() -> str:
    opened = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256").plaintext
    match = re.search(rb"\r\n\r\n(\d+)\r\n\r\nRaising the stakes", opened)
    if match is None:
        raise ValueError("VIC digits missing")
    return match.group(1).decode("ascii")


def _materials() -> dict[str, bytes]:
    architect = _architect_plaintext()
    if len(architect) != 1539:
        raise ValueError("architect length drift")
    suffix = _suffix140(architect)
    raw, transliteration = _source_record()
    lists = prime_lists()
    row_sums = _row_sums(_poster_grid(), zero_eye=False)
    tokens = derive_tokens()
    fresco = re.sub(r"[^A-Za-z ]", "", FRESCO_QUOTE).replace(" ", "").upper()
    vic = _vic_digits()
    sourcecodes = architect[1021:1089]

    vic_overlay = bytearray(suffix.encode("ascii"))
    for index, digit in enumerate(vic[:140]):
        if suffix[index].isalpha():
            base = 65
            vic_overlay[index] = (ord(suffix[index]) - base + int(digit)) % 26 + base
    token_parts = [hashlib.sha256(token.encode("ascii")).digest() for token in tokens.tokens[:7]]
    token_digest = token_parts[0]
    for part in token_parts[1:]:
        token_digest = xor_extend(token_digest, part)

    pk1 = architect[479:479 + 32].ljust(32, "A")
    pk2 = architect[1238:1238 + 32].ljust(32, "A")

    return {
        "suffix140_hundredforty": suffix.encode("ascii"),
        "suffix_takeheart_wiseman": architect[511:535].encode("ascii"),
        "suffix_479_to_hundredforty_word": architect[479:562].encode("ascii"),
        "matrixsumlist_row_index_suffix140": _matrixsumlist_select(suffix, row_sums, mode="absolute"),
        "matrixsumlist_local_suffix140": _matrixsumlist_select(suffix, row_sums, mode="cumulative"),
        "raw_source_xor_suffix140": bytes(a ^ b for a, b in zip(raw[:140], suffix.encode("ascii"))),
        "transliteration_xor_suffix140": bytes(
            a ^ b for a, b in zip(transliteration[:140], suffix.encode("ascii"))
        ),
        "dual_privatekey_xor_32": bytes(ord(a) ^ ord(b) for a, b in zip(pk1, pk2)),
        "beaufort_fresco_suffix140": _beaufort(suffix, fresco[:140]).encode("ascii"),
        "mod26_fresco_add_suffix140": _mod26_add(suffix, fresco[:140]),
        "disseminate_concat_suffix140_x2": (suffix * 2).encode("ascii"),
        "return_sourcecodes_beaufort_suffix140": _beaufort(suffix, sourcecodes).encode("ascii"),
        "sha256_suffix140_then_sourcecodes": hashlib.sha256(
            suffix.encode("ascii") + sourcecodes.encode("ascii")
        ).digest(),
        "seven_token_xor_fold_suffix140": xor_extend(suffix.encode("ascii"), token_digest),
        "vic_digits_mod10_suffix140": bytes(vic_overlay),
        "prime_reinsert_yellow9_suffix140": _reinsert_digits(suffix, lists["yellow9"]),
        "takeheart_center32": architect[511 - 16 : 511 + 16].ljust(32, "A").encode("ascii"),
    }


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
            scalar_results.append({"operation": operation, "derivation": derivation, "prize_match": hit})
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
