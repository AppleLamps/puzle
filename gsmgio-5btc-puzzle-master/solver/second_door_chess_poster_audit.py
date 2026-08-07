"""Evaluate sealed v72: chess/poster second door before chain1."""

from __future__ import annotations

import hashlib
import json
import math
import re

from Crypto.Cipher import AES

from . import targets
from .cipher_catalogue_23_16_7_preregister import CHESS_HINT
from .extract import extract_all
from .openssl_compat import decrypt_salted_aes256_cbc, evp_bytes_to_key, strict_pkcs7_unpad
from .phase32_classical import PHASE32_PASSWORD
from .salphaseion_split_envelope_preregister import split_envelope
from .second_door_chess_poster_preregister import (
    AES_TARGETS,
    CHESS_FEN,
    CHESS_MATERIALS,
    CHESS_MOVE,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    POSTER_MATERIALS,
    RESULT_PATH,
    SCALAR_DERIVATIONS,
    SEAL_PATH,
    build_manifest,
    expected_aes_trials,
    expected_materials,
    expected_scalar_gates,
)
from .second_door_eye_spiral_preregister import EYE_SPIRAL_INDEX, PARTNER_SPIRAL_INDEX
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


ENGLISH_RUN = re.compile(rb"[A-Za-z]{6,}")


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


def _body_bits() -> str:
    grid = _majority_grid(IMAGE if IMAGE.exists() else FALLBACK_IMAGE)
    order = _spiral_positions(14)
    colours = [grid[row][col] for row, col in order]
    return "".join("1" if colour in (BLACK, BLUE) else "0" for colour in colours)


def _apply_eye_edit(bits: str, edit: str) -> str:
    chars = list(bits)
    if edit == "flip_bit_163":
        chars[EYE_SPIRAL_INDEX] = "0" if chars[EYE_SPIRAL_INDEX] == "1" else "1"
    elif edit == "swap_bits_163_173":
        chars[EYE_SPIRAL_INDEX], chars[PARTNER_SPIRAL_INDEX] = (
            chars[PARTNER_SPIRAL_INDEX],
            chars[EYE_SPIRAL_INDEX],
        )
    elif edit == "force_bit_163_one":
        chars[EYE_SPIRAL_INDEX] = "1"
    elif edit == "force_bit_163_zero":
        chars[EYE_SPIRAL_INDEX] = "0"
    elif edit == "xor_bits_163_173_into_163":
        a = chars[EYE_SPIRAL_INDEX] == "1"
        b = chars[PARTNER_SPIRAL_INDEX] == "1"
        chars[EYE_SPIRAL_INDEX] = "1" if a ^ b else "0"
    else:
        raise ValueError(edit)
    return "".join(chars)


def _pack_url(bits: str) -> bytes:
    return bytes(int(bits[:192][offset : offset + 8], 2) for offset in range(0, 192, 8))


def _diagonal_bits(grid, *, main_lower: bool) -> str:
    size = 14
    bits: list[str] = []
    for row in range(size):
        for col in range(size):
            if main_lower and row >= col:
                colour = grid[row][col]
                bits.append("1" if colour in (BLACK, BLUE) else "0")
            if not main_lower and row + col >= size - 1:
                colour = grid[row][col]
                bits.append("1" if colour in (BLACK, BLUE) else "0")
    return "".join(bits)


def _bunny_bits(grid) -> bytes:
    order = _spiral_positions(14)
    bits = []
    for cell in IMPURE_RABBIT_CELLS:
        row, col = cell
        colour = grid[row][col]
        bits.append("1" if colour in (BLACK, BLUE) else "0")
    usable = len(bits) // 8 * 8
    return bytes(int("".join(bits[i : i + 8]), 2) for i in range(0, usable, 8))


def _material(name: str) -> bytes:
    if name == "fen_literal":
        return CHESS_FEN.encode("ascii")
    if name == "fen_lower":
        return CHESS_FEN.lower().encode("ascii")
    if name == "fen_no_spaces":
        return CHESS_FEN.replace(" ", "").encode("ascii")
    if name == "move_rc6_plus":
        return CHESS_MOVE.encode("ascii")
    if name == "move_rc6":
        return b"Rc6"
    if name == "fen_then_move":
        return (CHESS_FEN + CHESS_MOVE).encode("ascii")
    if name == "chess_hint_letters_lower":
        return "".join(ch for ch in CHESS_HINT.lower() if ch.isalpha()).encode("ascii")

    grid = _majority_grid(IMAGE if IMAGE.exists() else FALLBACK_IMAGE)
    baseline = _body_bits()
    if name == "eye_flip_bit_163_url":
        return _pack_url(_apply_eye_edit(baseline, "flip_bit_163"))
    if name == "eye_swap_bits_163_173_url":
        return _pack_url(_apply_eye_edit(baseline, "swap_bits_163_173"))
    if name == "eye_force_bit_163_one_url":
        return _pack_url(_apply_eye_edit(baseline, "force_bit_163_one"))
    if name == "eye_force_bit_163_zero_url":
        return _pack_url(_apply_eye_edit(baseline, "force_bit_163_zero"))
    if name == "eye_xor_bits_163_173_url":
        return _pack_url(_apply_eye_edit(baseline, "xor_bits_163_173_into_163"))
    if name == "bunny_impure7_bits_packed":
        return _bunny_bits(grid)
    if name == "main_diagonal_lower_bits98":
        return _diagonal_bits(grid, main_lower=True).encode("ascii")
    if name == "anti_diagonal_lower_bits98":
        return _diagonal_bits(grid, main_lower=False).encode("ascii")
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
    if _pack_url(_body_bits()) != URL:
        raise ValueError("baseline URL drift")

    chain1 = extract_all().chain1_envelope
    env48, raw48 = split_envelope()
    materials = list(CHESS_MATERIALS) + list(POSTER_MATERIALS)

    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for material_name in materials:
        blob = _material(material_name)
        for derivation in SCALAR_DERIVATIONS:
            digest = hashlib.sha256(blob).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append(
                {"material": material_name, "derivation": derivation, "prize_match": hit}
            )
            if hit is not None:
                prize_matches.append({"kind": "scalar", "material": material_name, **hit})

        for form in PASSWORD_FORMS:
            password = _password_bytes(blob, form)
            for kdf in KDF_DIGESTS:
                for target in AES_TARGETS:
                    plaintext = _decrypt_target(target, chain1, env48, raw48, password, kdf)
                    record: dict[str, object] = {
                        "material": material_name,
                        "form": form,
                        "kdf": kdf,
                        "target": target,
                        "padding_valid": plaintext is not None,
                    }
                    if plaintext is None:
                        aes_results.append(record)
                        continue
                    padding_hits += 1
                    leg = _legible(plaintext)
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
            "baseline_url": _pack_url(_body_bits()) == URL,
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
