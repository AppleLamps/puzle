"""Evaluate sealed v57: creator-named Beaufort/VIC/chess catalogue only.

Run ``python -m solver.cipher_catalogue_23_16_7_preregister`` then
``python -m solver.cipher_catalogue_23_16_7_audit``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re

from Crypto.Cipher import AES

from . import targets
from .cipher_catalogue_23_16_7_preregister import (
    BEAUFORT_KEYS,
    CHAIN1_SALT_HEX,
    CHESS_HINT,
    CIPHERTEXTS,
    CONTROL_SCALAR_HEX,
    COSMIC_SALT_HEX,
    ENVELOPES,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    RAW_SOURCE_SHA256,
    RESIDUAL_CLUES,
    RESULT_PATH,
    SCHEMA,
    SEAL_PATH,
    TRANSLITERATION_SHA256,
    VIC_ALPHABET_DOT,
    VIC_ALPHABET_SLASH,
    VIC_ALPHABETS,
    VIC_DIGIT_MAPS,
    VIC_FIELDS,
    VIC_ROW_DIGITS,
    build_manifest,
    expected_aes_trials,
    expected_catalogue_outputs,
    expected_scalar_gates,
    fresco_key_materials,
)
from .extract import ROOT
from .openssl_compat import decrypt_salted_aes256_cbc, strict_pkcs7_unpad
from .phase32_classical import BEAUFORT_KEY, PHASE32_PASSWORD, _beaufort, _vic_decode
from .phase32_symbol_recovery import _raw_symbol_record
from .salphaseion_raw import extract_raw
from .secp256k1_verify import N


ENGLISH_RUN = re.compile(rb"[A-Za-z]{6,}")
RECOVERY_PATH = ROOT / "phase32_symbol_recovery.json"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def _residual_mask(clue: int) -> bytes:
    if clue <= 255:
        return bytes([clue]) * 32
    mask = bytearray(32)
    mask[-2:] = clue.to_bytes(2, "big")
    return bytes(mask)


def _ai_to_letters(field: str) -> str:
    return "".join(ch.upper() for ch in field if "a" <= ch <= "i")


def _ai_to_digits(field: str, mode: str) -> str:
    digits: list[str] = []
    for ch in field:
        if not ("a" <= ch <= "i"):
            continue
        if mode == "a1_i9":
            digits.append(str(ord(ch) - ord("a") + 1))
        elif mode == "a0_i8":
            digits.append(str(ord(ch) - ord("a")))
        else:
            raise ValueError(mode)
    return "".join(digits)


def _load_ciphertexts() -> dict[str, str]:
    parts = extract_raw()
    raw = _raw_symbol_record()
    if _sha(raw) != RAW_SOURCE_SHA256:
        raise ValueError("raw pre-Beaufort drifted")
    recovery = json.loads(RECOVERY_PATH.read_text(encoding="utf-8"))
    mapping = {int(k, 16): v for k, v in recovery["recovered_mapping"].items()}
    transliteration = "".join(mapping[b] for b in raw)
    if _sha(transliteration.encode("ascii")) != TRANSLITERATION_SHA256:
        raise ValueError("transliteration drifted")
    return {
        "S91_letters": _ai_to_letters(parts.s91),
        "S570_letters": _ai_to_letters(parts.s570),
        "transliteration": transliteration,
        "raw_pre_beaufort_mod26": "".join(chr(65 + (b % 26)) for b in raw),
        "S91": parts.s91,
        "S570": parts.s570,
    }


def _password_bytes(preimage: bytes, form: str) -> bytes:
    if form == "literal":
        return preimage
    digest = hashlib.sha256(preimage).digest()
    if form == "sha256_hex_ascii":
        return digest.hex().encode("ascii")
    if form == "sha256_raw32":
        return digest
    raise ValueError(form)


def _raw_key_decrypt(envelope: bytes, key: bytes) -> bytes | None:
    try:
        iv = hashlib.sha256(envelope[8:16]).digest()[:16]
        padded = AES.new(key, AES.MODE_CBC, iv).decrypt(envelope[16:])
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
    candidates = [hashlib.sha256(plaintext).digest()]
    if len(plaintext) >= 32:
        candidates.extend([plaintext[:32], plaintext[-32:]])
        if len(plaintext) >= 64:
            candidates.append(plaintext[32:64])
    for candidate in candidates:
        hit = targets.gate_scalar_bytes(candidate)
        if hit is not None:
            result["prize_matches"].append({"scalar_hex": candidate.hex(), **hit})
    return result


def _control() -> dict[str, object]:
    phase32 = (ROOT / "artifacts" / "bin" / "phase32_envelope.bin").read_bytes()
    opened = decrypt_salted_aes256_cbc(phase32, PHASE32_PASSWORD, digest="sha256")
    # VIC positive control on the phase-3.2 digit record.
    numeric = re.search(rb"\r\n\r\n(\d+)\r\n\r\nRaising the stakes", opened.plaintext)
    if numeric is None:
        raise ValueError("phase32 VIC digits missing")
    vic_plain = _vic_decode(numeric.group(1).decode("ascii"), VIC_ALPHABET_DOT, ("1", "4"))
    scalar = int(CONTROL_SCALAR_HEX, 16)
    x, y = targets._public_point(scalar)
    planted_half = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    planted = targets.gate_point(x, y, half_public=planted_half)
    production = targets.gate_scalar_bytes(bytes.fromhex(CONTROL_SCALAR_HEX))
    return {
        "phase32_positive_control_opens": opened.plaintext.startswith(
            b"I've been waiting for you."
        ),
        "vic_positive_control": "THEPRIVATEKEYSBELONGTOHALFANDBETTERHALF" in vic_plain,
        "planted_target_accepted": planted is not None,
        "production_targets_reject_control": production is None,
        "beaufort_self_check": _beaufort("vtkv", BEAUFORT_KEY).startswith("Y"),
    }


def _catalogue_outputs(fields: dict[str, str]) -> list[tuple[str, bytes]]:
    keys = fresco_key_materials()
    outputs: list[tuple[str, bytes]] = []

    # Frozen catalogue strings themselves (alphabet / hint / auth key).
    outputs.append(("catalogue/vic_alphabet_dot", VIC_ALPHABET_DOT.encode("ascii")))
    outputs.append(("catalogue/vic_alphabet_slash", VIC_ALPHABET_SLASH.encode("ascii")))
    outputs.append(("catalogue/chess_hint", CHESS_HINT.encode("ascii")))
    outputs.append(("catalogue/beaufort_key_thematrixhasyou", BEAUFORT_KEY.encode("ascii")))

    for ct_name in CIPHERTEXTS:
        ciphertext = fields[ct_name]
        for key_name in BEAUFORT_KEYS:
            key = keys[key_name]
            if not key:
                raise ValueError(f"empty beaufort key {key_name}")
            plain = _beaufort(ciphertext.lower(), key)
            outputs.append((f"beaufort/{ct_name}/{key_name}", plain.encode("ascii")))

    alphabets = {"dot": VIC_ALPHABET_DOT, "slash": VIC_ALPHABET_SLASH}
    for field in VIC_FIELDS:
        for alphabet_name in VIC_ALPHABETS:
            alphabet = alphabets[alphabet_name]
            for row in VIC_ROW_DIGITS:
                for digit_map in VIC_DIGIT_MAPS:
                    digits = _ai_to_digits(fields[field], digit_map)
                    label = f"vic/{field}/{alphabet_name}/rows{''.join(row)}/{digit_map}"
                    try:
                        decoded = _vic_decode(digits, alphabet, row)
                    except ValueError:
                        # Sealed: record failed decode as empty and still hash it.
                        decoded = ""
                    outputs.append((label, decoded.encode("ascii")))

    if len(outputs) != expected_catalogue_outputs():
        raise ValueError(
            f"catalogue output drift: {len(outputs)} != {expected_catalogue_outputs()}"
        )
    return outputs


def run() -> dict[str, object]:
    sealed = SEAL_PATH.read_text(encoding="ascii").strip()
    manifest_bytes = MANIFEST_PATH.read_bytes()
    if _sha(manifest_bytes) != sealed:
        raise ValueError("seal mismatch")
    manifest = json.loads(manifest_bytes)
    if build_manifest() != manifest:
        raise ValueError("manifest drift")
    if manifest["schema"] != SCHEMA:
        raise ValueError("schema drift")

    control = _control()
    if not control["phase32_positive_control_opens"]:
        raise ValueError("AES positive control failed")
    if not control["vic_positive_control"]:
        raise ValueError("VIC positive control failed")
    if not control["planted_target_accepted"] or not control["production_targets_reject_control"]:
        raise ValueError(f"scalar control failed: {control}")

    fields = _load_ciphertexts()
    envelopes = {
        "chain1": (ROOT / "artifacts" / "bin" / "chain1_envelope.bin").read_bytes(),
        "cosmic": (ROOT / "artifacts" / "bin" / "cosmic_envelope.bin").read_bytes(),
    }
    if envelopes["chain1"][8:16].hex() != CHAIN1_SALT_HEX:
        raise ValueError("chain1 salt drift")
    if envelopes["cosmic"][8:16].hex() != COSMIC_SALT_HEX:
        raise ValueError("cosmic salt drift")

    outputs = _catalogue_outputs(fields)
    stream = hashlib.sha256()
    aes_trials = 0
    raw_key_trials = 0
    padding_hits = 0
    scalar_gates = 0
    scalar_valid = 0
    vic_decode_failures = 0
    legible_hits: list[dict[str, object]] = []
    prize_hits: list[dict[str, object]] = []

    for label, preimage in outputs:
        stream.update(label.encode("ascii") + b"\0" + preimage)
        if label.startswith("vic/") and preimage == b"":
            vic_decode_failures += 1

        digest = hashlib.sha256(preimage).digest()
        double = hashlib.sha256(digest).digest()
        for name, candidate in [("sha256", digest), ("double_sha256", double)] + [
            (f"sha256_xor_clue_{clue}", bytes(a ^ b for a, b in zip(digest, _residual_mask(clue))))
            for clue in RESIDUAL_CLUES
        ]:
            scalar_gates += 1
            value = int.from_bytes(candidate, "big") % N
            if 1 <= value < N:
                scalar_valid += 1
            hit = targets.gate_scalar_bytes(candidate)
            if hit is not None:
                prize_hits.append(
                    {
                        "channel": "scalar",
                        "label": label,
                        "extractor": name,
                        "scalar_hex": candidate.hex(),
                        **hit,
                    }
                )

        for form in PASSWORD_FORMS:
            password = _password_bytes(preimage, form)
            for digest_name in KDF_DIGESTS:
                for envelope_name in ENVELOPES:
                    aes_trials += 1
                    try:
                        opened = decrypt_salted_aes256_cbc(
                            envelopes[envelope_name], password, digest=digest_name
                        )
                    except ValueError:
                        continue
                    padding_hits += 1
                    gate = _gate_plaintext(opened.plaintext)
                    if gate["legible"] or gate["prize_matches"]:
                        record = {
                            "channel": "aes",
                            "label": label,
                            "form": form,
                            "kdf": digest_name,
                            "envelope": envelope_name,
                            "plaintext_sha256": _sha(opened.plaintext),
                            **gate,
                        }
                        if gate["legible"]:
                            legible_hits.append(record)
                        if gate["prize_matches"]:
                            prize_hits.append(record)

        key = hashlib.sha256(preimage).digest()
        for envelope_name in ENVELOPES:
            raw_key_trials += 1
            plaintext = _raw_key_decrypt(envelopes[envelope_name], key)
            if plaintext is None:
                continue
            padding_hits += 1
            gate = _gate_plaintext(plaintext)
            if gate["legible"] or gate["prize_matches"]:
                record = {
                    "channel": "raw_aes_key",
                    "label": label,
                    "envelope": envelope_name,
                    "plaintext_sha256": _sha(plaintext),
                    **gate,
                }
                if gate["legible"]:
                    legible_hits.append(record)
                if gate["prize_matches"]:
                    prize_hits.append(record)

    if aes_trials != expected_aes_trials():
        raise ValueError(f"AES drift {aes_trials} != {expected_aes_trials()}")
    if scalar_gates != expected_scalar_gates():
        raise ValueError(f"scalar drift {scalar_gates} != {expected_scalar_gates()}")
    if raw_key_trials != expected_catalogue_outputs() * len(ENVELOPES):
        raise ValueError("raw-key drift")

    status = (
        "PRIZE_MATCH"
        if prize_hits
        else ("LEGIBLE_OPEN" if legible_hits else "COMPLETE_NO_MATCH")
    )
    result: dict[str, object] = {
        "status": status,
        "schema": SCHEMA,
        "manifest_sha256": sealed,
        "control": control,
        "catalogue_outputs": len(outputs),
        "vic_decode_failures": vic_decode_failures,
        "aes_trials": aes_trials,
        "raw_aes_key_trials": raw_key_trials,
        "padding_hits": padding_hits,
        "padding_hit_rate": round(padding_hits / max(1, aes_trials + raw_key_trials), 6),
        "legible_hits": legible_hits,
        "prize_hits": prize_hits,
        "scalar_gates": scalar_gates,
        "scalar_valid": scalar_valid,
        "unique_preimage_stream_sha256": stream.hexdigest(),
        "scope_note": manifest["scope_note"],
        "narrowest_underdetermined_step_if_null": (
            "With the creator-named Beaufort/VIC/chess catalogue frozen and "
            "keyed by Fresco 23/16/7 still null against chain1/cosmic, the "
            "remaining free choice is no longer 'which classical cipher' but "
            "whether 23/16/7 names a different operand entirely (e.g. the "
            "close-friends giveaway text, or an unpublished catalogue). Next "
            "bounded step should not widen the cipher menu."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
