"""Evaluate sealed v56: SalPhaseIon prime-select + 23/16/7 → chain1/cosmic.

Run ``python -m solver.endgame_23_16_7_salphaseion_preregister`` then
``python -m solver.endgame_23_16_7_salphaseion_audit``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

from Crypto.Cipher import AES

from . import targets
from .endgame_23_16_7_salphaseion_preregister import (
    CHAIN1_SALT_HEX,
    CONTROL_SCALAR_HEX,
    COSMIC_SALT_HEX,
    ENVELOPES,
    KEYSPACE_NAMES,
    KDF_DIGESTS,
    LITERALS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    PHASE32_PASSWORD,
    PRIME_SELECT_MODES,
    RAW_SOURCE_SHA256,
    REPORTED_TOKENS,
    RESIDUAL_CLUES,
    RESULT_PATH,
    SCHEMA,
    SEAL_PATH,
    SOURCE_FIELDS,
    build_manifest,
    expected_aes_trials,
    expected_preimage_count,
    expected_scalar_gates,
    fresco_partitions,
    _primes_24,
)
from .extract import ROOT
from .openssl_compat import decrypt_salted_aes256_cbc, strict_pkcs7_unpad
from .phase32_symbol_recovery import _raw_symbol_record
from .salphaseion_raw import extract_raw
from .secp256k1_verify import N


ENGLISH_RUN = re.compile(rb"[A-Za-z]{6,}")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total) for count in counts if count
    )


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(byte in b"\t\n\r" or 32 <= byte <= 126 for byte in data) / len(data)


def _legible(data: bytes) -> bool:
    if _printable_ratio(data) < 0.85:
        return False
    return _entropy(data) <= 5.9 or bool(ENGLISH_RUN.search(data))


def _load_sources() -> dict[str, bytes]:
    parts = extract_raw()
    raw = _raw_symbol_record()
    if len(raw) != 1539 or _sha(raw) != RAW_SOURCE_SHA256:
        raise ValueError("raw pre-Beaufort source drifted")
    return {
        "S91": parts.s91.encode("ascii"),
        "S570": parts.s570.encode("ascii"),
        "raw_pre_beaufort": raw,
        "literals_concat": "".join(LITERALS).encode("ascii"),
        "tokens7_concat": "".join(REPORTED_TOKENS).encode("ascii"),
    }


def _prime_select(source: bytes, mode: str) -> bytes:
    primes = _primes_24()
    if mode.endswith("-drop5"):
        primes = [prime for prime in primes if prime != 5]
    base = 0 if "0based" in mode else 1
    chars: list[int] = []
    for prime in primes:
        index = prime - 1 if base == 1 else prime
        if 0 <= index < len(source):
            chars.append(source[index])
    return bytes(chars)


def _normalize(value: bytes) -> bytes:
    return re.sub(rb"[^0-9A-Za-z]+", b"", value).lower()


def _password_bytes(preimage: bytes, form: str) -> bytes:
    if form == "literal":
        return preimage
    if form == "normalized_lower_alnum":
        return _normalize(preimage)
    digest = hashlib.sha256(preimage).digest()
    if form == "sha256_hex_ascii":
        return digest.hex().encode("ascii")
    if form == "sha256_raw32":
        return digest
    raise ValueError(form)


def _disseminate(value: bytes, code: bytes) -> bytes:
    return bytes(byte ^ code[index % len(code)] for index, byte in enumerate(value))


def _xor_digests(left: bytes, right: bytes) -> bytes:
    a = hashlib.sha256(left).digest()
    b = hashlib.sha256(right).digest()
    return bytes(x ^ y for x, y in zip(a, b))


def _residual_mask(clue: int) -> bytes:
    if clue <= 255:
        return bytes([clue]) * 32
    mask = bytearray(32)
    mask[-2:] = clue.to_bytes(2, "big")
    return bytes(mask)


def _raw_key_decrypt(envelope: bytes, key: bytes) -> bytes | None:
    if len(key) != 32:
        return None
    salt = envelope[8:16]
    iv = hashlib.sha256(salt).digest()[:16]
    ciphertext = envelope[16:]
    try:
        padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
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
    # Gate every aligned 32-byte window and sha256 of the whole plaintext.
    candidates = [hashlib.sha256(plaintext).digest()]
    if len(plaintext) >= 32:
        candidates.append(plaintext[:32])
        candidates.append(plaintext[-32:])
        if len(plaintext) >= 64:
            candidates.append(plaintext[32:64])
        if len(plaintext) == 79:
            candidates.extend([plaintext[:32], plaintext[32:64], plaintext[64:].ljust(32, b"\0")[:32]])
    for candidate in candidates:
        if len(candidate) != 32:
            continue
        hit = targets.gate_scalar_bytes(candidate)
        if hit is not None:
            result["prize_matches"].append({"scalar_hex": candidate.hex(), **hit})
    return result


def _control() -> dict[str, object]:
    phase32 = (ROOT / "artifacts" / "bin" / "phase32_envelope.bin").read_bytes()
    opened = decrypt_salted_aes256_cbc(phase32, PHASE32_PASSWORD, digest="sha256")
    prefix = opened.plaintext.startswith(b"I've been waiting for you.")
    scalar = int(CONTROL_SCALAR_HEX, 16)
    x, y = targets._public_point(scalar)
    planted_half = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    planted = targets.gate_point(x, y, half_public=planted_half)
    production = targets.gate_scalar_bytes(bytes.fromhex(CONTROL_SCALAR_HEX))
    return {
        "phase32_positive_control_opens": prefix,
        "phase32_plaintext_len": len(opened.plaintext),
        "planted_target_accepted": planted is not None,
        "production_targets_reject_control": production is None,
    }


def run() -> dict[str, object]:
    sealed = SEAL_PATH.read_text(encoding="ascii").strip()
    manifest_bytes = MANIFEST_PATH.read_bytes()
    if _sha(manifest_bytes) != sealed:
        raise ValueError("manifest seal mismatch")
    manifest = json.loads(manifest_bytes)
    if build_manifest() != manifest:
        raise ValueError("manifest drifted from build_manifest()")
    if manifest["schema"] != SCHEMA:
        raise ValueError("unexpected schema")

    control = _control()
    if not control["phase32_positive_control_opens"]:
        raise ValueError("AES oracle positive control failed")
    if not control["planted_target_accepted"] or not control["production_targets_reject_control"]:
        raise ValueError(f"scalar gate control failed: {control}")

    sources = _load_sources()
    envelopes = {
        "chain1": (ROOT / "artifacts" / "bin" / "chain1_envelope.bin").read_bytes(),
        "cosmic": (ROOT / "artifacts" / "bin" / "cosmic_envelope.bin").read_bytes(),
    }
    if envelopes["chain1"][8:16].hex() != CHAIN1_SALT_HEX:
        raise ValueError("chain1 salt drifted")
    if envelopes["cosmic"][8:16].hex() != COSMIC_SALT_HEX:
        raise ValueError("cosmic salt drifted")

    # Fix preimage enumeration to match seal arithmetic exactly.
    preimages = _preimages_sealed(sources)
    if len(preimages) != expected_preimage_count():
        raise ValueError(
            f"preimage drift: got {len(preimages)}, sealed {expected_preimage_count()}"
        )

    stream = hashlib.sha256()
    aes_trials = 0
    padding_hits = 0
    legible_hits: list[dict[str, object]] = []
    prize_hits: list[dict[str, object]] = []
    raw_key_trials = 0
    scalar_gates = 0
    scalar_valid = 0

    for label, preimage in preimages:
        stream.update(label.encode("ascii") + b"\0" + preimage)

        # Scalar branch: sha256, double-sha256, residual masks on sha256.
        digest = hashlib.sha256(preimage).digest()
        double = hashlib.sha256(digest).digest()
        scalar_candidates = [("sha256", digest), ("double_sha256", double)]
        for clue in RESIDUAL_CLUES:
            masked = bytes(a ^ b for a, b in zip(digest, _residual_mask(clue)))
            scalar_candidates.append((f"sha256_xor_clue_{clue}", masked))
        for name, candidate in scalar_candidates:
            scalar_gates += 1
            value = int.from_bytes(candidate, "big")
            if 1 <= (value % N) < N and (value % N) != 0:
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

        # AES password branch.
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

        # Raw AES-key branch on sha256(preimage).
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
        raise ValueError(f"AES trial drift: {aes_trials} != {expected_aes_trials()}")
    if scalar_gates != expected_scalar_gates():
        raise ValueError(
            f"scalar gate drift: {scalar_gates} != {expected_scalar_gates()}"
        )
    if raw_key_trials != expected_preimage_count() * len(ENVELOPES):
        raise ValueError("raw-key trial drift")

    status = "PRIZE_MATCH" if prize_hits else (
        "LEGIBLE_OPEN" if legible_hits else "COMPLETE_NO_MATCH"
    )
    result: dict[str, object] = {
        "status": status,
        "schema": SCHEMA,
        "manifest_sha256": sealed,
        "control": control,
        "source_sha256": {name: _sha(value) for name, value in sources.items()},
        "preimages": len(preimages),
        "aes_trials": aes_trials,
        "raw_aes_key_trials": raw_key_trials,
        "padding_hits": padding_hits,
        "padding_hit_rate": round(padding_hits / max(1, aes_trials + raw_key_trials), 6),
        "legible_hits": legible_hits,
        "prize_hits": prize_hits,
        "scalar_gates": scalar_gates,
        "scalar_valid": scalar_valid,
        "unique_preimage_stream_sha256": stream.hexdigest(),
        "residual_truncation": {
            "handoff_suggested": "low 2^20 XOR",
            "sealed_to": list(RESIDUAL_CLUES),
            "reason": "keep residual clue-bound; open 2^20 is unconstrained mutation",
        },
        "scope_note": manifest["scope_note"],
        "narrowest_underdetermined_step_if_null": (
            "Which object the 23/16/7 menu selects *as the cipher list* remains "
            "free once SalPhaseIon prime-select + Fresco/pipeline password "
            "composition against the two envelopes is null. Next bounded "
            "falsifier: freeze one creator-named cipher catalogue (the phase-3.2 "
            "VIC alphabet / chess line / Beaufort-only) as the '23 ciphers' side "
            "without adding a free menu, and retest only that."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def _preimages_sealed(sources: dict[str, bytes]) -> list[tuple[str, bytes]]:
    """Enumerate preimages exactly as the seal's expected_preimage_count counts."""
    keyspace = {name: value.encode("ascii") for name, value in fresco_partitions().items()}
    primes: list[tuple[str, bytes]] = []
    for field in SOURCE_FIELDS:
        for mode in PRIME_SELECT_MODES:
            primes.append((f"{field}/{mode}", _prime_select(sources[field], mode)))

    out: list[tuple[str, bytes]] = []
    for name in KEYSPACE_NAMES:
        out.append((f"keyspace_alone/{name}", keyspace[name]))
    for prime_name, prime_value in primes:
        out.append((f"prime_alone/{prime_name}", prime_value))
    for key_name in KEYSPACE_NAMES:
        key_value = keyspace[key_name]
        for prime_name, prime_value in primes:
            out.append((f"keyspace_plus_prime/{key_name}/{prime_name}", key_value + prime_value))
            out.append((f"prime_plus_keyspace/{prime_name}/{key_name}", prime_value + key_value))
            out.append(
                (
                    f"xor_sha256_digests/{key_name}/{prime_name}",
                    _xor_digests(key_value, prime_value),
                )
            )
            disseminated = _disseminate(prime_value, PHASE32_PASSWORD)
            # Counted once per (key,prime) in seal arithmetic for these two modes.
            out.append(
                (
                    f"disseminate_carried_over_prime/{key_name}/{prime_name}",
                    disseminated,
                )
            )
            out.append(
                (
                    f"disseminate_then_plus_keyspace/{prime_name}/{key_name}",
                    disseminated + key_value,
                )
            )
    return out


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
