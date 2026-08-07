"""Evaluate sealed v75: second-door poster × 479/484 composition."""

from __future__ import annotations

import hashlib
import json

from . import targets
from .envelope_legibility_audit import (
    add_mod256,
    decrypt_target,
    interleave_bytes,
    legible,
    pack_bits,
    password_bytes,
    xor_extend,
)
from .extract import extract_all
from .intertwined_password_coherence_audit import _architect_plaintext
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import PHASE32_PASSWORD
from .salphaseion_split_envelope_preregister import split_envelope
from .second_door_composition_preregister import (
    AES_TARGETS,
    ANCHOR_OPERANDS,
    COMPOSITIONS,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    POSTER_OPERANDS,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_aes_trials,
    expected_compositions,
    expected_scalar_gates,
)
from .second_door_eye_spiral_preregister import EYE_SPIRAL_INDEX
from .second_door_frontier_derivations import IMPURE_RABBIT_CELLS
from .second_door_yellowblueprimes_audit import (
    BLACK,
    BLUE,
    FALLBACK_IMAGE,
    IMAGE,
    URL,
    _majority_grid,
    _spiral_positions,
)
from .yinyang_prime_dual_preregister import prime_lists
from .yinyang_rot180_partition_preregister import partition


def _body_bits() -> str:
    grid = _majority_grid(IMAGE if IMAGE.exists() else FALLBACK_IMAGE)
    order = _spiral_positions(14)
    colours = [grid[row][col] for row, col in order]
    return "".join("1" if colour in (BLACK, BLUE) else "0" for colour in colours)


def _pack_url(bits: str) -> bytes:
    return bytes(int(bits[:192][offset : offset + 8], 2) for offset in range(0, 192, 8))


def _apply_eye_edit(bits: str, edit: str) -> str:
    chars = list(bits)
    if edit == "flip_bit_163":
        chars[EYE_SPIRAL_INDEX] = "0" if chars[EYE_SPIRAL_INDEX] == "1" else "1"
    elif edit == "force_bit_163_one":
        chars[EYE_SPIRAL_INDEX] = "1"
    else:
        raise ValueError(edit)
    return "".join(chars)


def _triangle91_bits(grid, *, lower: bool) -> bytes:
    order = _spiral_positions(14)
    bits: list[str] = []
    for row, col in order:
        if lower and row > col:
            colour = grid[row][col]
            bits.append("1" if colour in (BLACK, BLUE) else "0")
        if not lower and row < col:
            colour = grid[row][col]
            bits.append("1" if colour in (BLACK, BLUE) else "0")
    return pack_bits("".join(bits))


def _bunny_bits(grid) -> bytes:
    bits = []
    for row, col in IMPURE_RABBIT_CELLS:
        colour = grid[row][col]
        bits.append("1" if colour in (BLACK, BLUE) else "0")
    return pack_bits("".join(bits))


def _poster_operands() -> dict[str, bytes]:
    grid = _majority_grid(IMAGE if IMAGE.exists() else FALLBACK_IMAGE)
    baseline = _body_bits()
    part = partition()
    return {
        "eye_flip_url_packed": _pack_url(_apply_eye_edit(baseline, "flip_bit_163")),
        "eye_force_one_url_packed": _pack_url(_apply_eye_edit(baseline, "force_bit_163_one")),
        "bunny_impure7_packed": _bunny_bits(grid),
        "lower_triangle91_bits_packed": _triangle91_bits(grid, lower=True),
        "upper_triangle91_bits_packed": _triangle91_bits(grid, lower=False),
        "rot180_mask98_packed": pack_bits(str(part["streams"]["rot180_inversion_mask98"])),
    }


def _anchor_operands() -> dict[str, bytes]:
    lists = prime_lists()
    architect = _architect_plaintext()
    return {
        "anchor479_decimal": b"479",
        "anchor484_decimal": b"484",
        "yellow9_primes_decimal": "".join(str(v) for v in lists["yellow9"]).encode("ascii"),
        "architect_privatekey_window33": architect[479:512].encode("ascii"),
    }


def _compose(rule: str, poster: bytes, anchor: bytes) -> bytes:
    if rule == "xor_poster_anchor":
        return xor_extend(poster, anchor)
    if rule == "add_mod256_poster_anchor":
        return add_mod256(poster, anchor)
    if rule == "sha256_concat_poster_anchor":
        return hashlib.sha256(poster + anchor).digest()
    if rule == "interleave_poster_anchor":
        return interleave_bytes(poster, anchor)
    raise ValueError(rule)


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    if _pack_url(_body_bits()) != URL:
        raise ValueError("baseline URL drift")

    poster_ops = _poster_operands()
    anchor_ops = _anchor_operands()
    chain1 = extract_all().chain1_envelope
    env48, raw48 = split_envelope()

    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for poster_id in POSTER_OPERANDS:
        for anchor_id in ANCHOR_OPERANDS:
            for composition in COMPOSITIONS:
                material = _compose(composition, poster_ops[poster_id], anchor_ops[anchor_id])
                comp_id = f"{poster_id}/{anchor_id}/{composition}"
                for derivation in ("sha256", "double_sha256"):
                    digest = hashlib.sha256(material).digest()
                    if derivation == "double_sha256":
                        digest = hashlib.sha256(digest).digest()
                    hit = targets.gate_scalar_bytes(digest)
                    scalar_results.append(
                        {
                            "composition_id": comp_id,
                            "derivation": derivation,
                            "prize_match": hit,
                        }
                    )
                    if hit is not None:
                        prize_matches.append({"kind": "scalar", "composition_id": comp_id, **hit})

                for form in PASSWORD_FORMS:
                    password = password_bytes(material, form)
                    for kdf in KDF_DIGESTS:
                        for target in AES_TARGETS:
                            plaintext = decrypt_target(target, chain1, env48, raw48, password, kdf)
                            record: dict[str, object] = {
                                "composition_id": comp_id,
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

    if len(scalar_results) != expected_scalar_gates():
        raise ValueError("scalar gate count drift")
    if len(aes_results) != expected_aes_trials():
        raise ValueError("aes trial count drift")
    if len({r["composition_id"] for r in scalar_results}) != expected_compositions():
        raise ValueError("composition count drift")

    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        "controls": {
            "baseline_url": True,
            "phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you."),
        },
        "counts": {
            "compositions": expected_compositions(),
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
