"""Evaluate the sealed v46 balanced-prime-pair family.

Verifies the seal, re-derives the 484/479 balance from the pinned marker
string, fails on drift, runs a planted positive control through the production
gate, then gates the sealed family.

Run ``python -m solver.yinyang_prime_dual_audit``.
"""

from __future__ import annotations

import hashlib
import json

from . import targets
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion_raw import extract_raw
from .yinyang_prime_dual_preregister import (
    AES_DIGESTS,
    AES_PASSWORD_FORMS,
    CONTROL_SCALAR_HEX,
    DERIVATIONS,
    MANIFEST_PATH,
    PHRASE,
    PHRASE_FORMS,
    RESULT_PATH,
    SEAL_PATH,
    SERIALIZATIONS,
    build_manifest,
    prime_lists,
)


def _serialize(values: list[int], name: str) -> bytes:
    if name == "raw_value_bytes":
        return bytes(value % 256 for value in values)
    if name == "ascii_decimal_concat":
        return "".join(str(value) for value in values).encode("ascii")
    if name == "ascii_two_digit_concat":
        return "".join(f"{value % 100:02d}" for value in values).encode("ascii")
    if name == "ascii_csv":
        return ",".join(str(value) for value in values).encode("ascii")
    if name == "ascii_space":
        return " ".join(str(value) for value in values).encode("ascii")
    if name == "mod10_ascii":
        return "".join(str(value % 10) for value in values).encode("ascii")
    if name == "mod9_zero_ascii":
        return "".join(str(value % 9) for value in values).encode("ascii")
    if name == "mod9_zero_to9_ascii":
        return "".join(str(value % 9 or 9) for value in values).encode("ascii")
    if name == "mod26_A0_ascii":
        return "".join(chr(65 + value % 26) for value in values).encode("ascii")
    raise ValueError(f"unsealed serialization: {name}")


def _derive(value: bytes, name: str) -> bytes:
    digest = hashlib.sha256(value).digest()
    if name == "sha256":
        return digest
    if name == "double_sha256":
        return hashlib.sha256(digest).digest()
    if name == "sha256^0x7f":
        return bytes(byte ^ 0x7F for byte in digest)
    if name == "sha256_reversed":
        return digest[::-1]
    if name == "phrase_prefix_sha256":
        return hashlib.sha256(PHRASE.encode("ascii") + value).digest()
    if name == "phrase_suffix_sha256":
        return hashlib.sha256(value + PHRASE.encode("ascii")).digest()
    raise ValueError(f"unsealed derivation: {name}")


def _printable_ratio(value: bytes) -> float:
    return sum(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in value) / max(1, len(value))


def _control() -> dict[str, object]:
    scalar = int(CONTROL_SCALAR_HEX, 16)
    x, y = targets._public_point(scalar)
    planted = targets.gate_point(
        x,
        y,
        half_public=targets.serializations(x, y)["uncompressed"],
        half_h160=targets.HALF_H160,
        better_h160=targets.BETTER_H160,
    )
    return {
        "scalar": CONTROL_SCALAR_HEX,
        "accepted_against_planted_target": planted is not None,
        "rejected_against_real_targets": targets.gate_scalar(scalar) is None,
    }


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    actual_seal = hashlib.sha256(encoded).hexdigest()
    if actual_seal != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if manifest["status"] != "SEALED_BEFORE_SCALAR_OR_AES_EVALUATION":
        raise ValueError("manifest is not marked sealed")
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("re-derived manifest differs from the sealed manifest")

    control = _control()
    if not (control["accepted_against_planted_target"] and control["rejected_against_real_targets"]):
        raise ValueError("the gate failed its own control; results would be meaningless")

    lists = prime_lists()
    raw = extract_raw()

    matches: list[dict[str, object]] = []
    seen: set[bytes] = set()

    def gate(value: bytes, provenance: str) -> None:
        if len(value) != 32 or value in seen:
            return
        seen.add(value)
        hit = targets.gate_scalar_bytes(value)
        if hit:
            matches.append({"provenance": provenance, "scalar_hex": value.hex(), "gate": hit})

    serialized: list[tuple[str, bytes]] = []
    for name, values in sorted(lists.items()):
        for serialization in SERIALIZATIONS:
            serialized.append((f"{name}/{serialization}", _serialize(values, serialization)))

    for provenance, value in serialized:
        for derivation in (*DERIVATIONS, *PHRASE_FORMS):
            gate(_derive(value, derivation), f"{provenance}/{derivation}")

    aes_tests = 0
    valid_padding: list[dict[str, object]] = []
    structured: list[dict[str, object]] = []
    passwords: dict[bytes, list[str]] = {}
    for provenance, value in serialized:
        digest = hashlib.sha256(value).digest()
        for form in AES_PASSWORD_FORMS:
            password = value if form == "literal" else digest.hex().encode("ascii")
            passwords.setdefault(password, []).append(f"{provenance}/{form}")

    for password, provenances in passwords.items():
        for kdf in AES_DIGESTS:
            aes_tests += 1
            try:
                decrypted = decrypt_salted_aes256_cbc(raw.short_envelope, password, digest=kdf)
            except ValueError:
                continue
            record = {
                "provenances": provenances[:4],
                "kdf_digest": kdf,
                "plaintext_hex": decrypted.plaintext.hex(),
                "printable_ratio": _printable_ratio(decrypted.plaintext),
                "padding_length": decrypted.padding_length,
            }
            valid_padding.append(record)
            lowered = decrypted.plaintext.lower()
            if record["printable_ratio"] >= 0.85 or any(
                token in lowered for token in (b"private", b"bitcoin", b"matrix", b"key", b"gsmg")
            ):
                structured.append(record)
            for offset in range(max(0, len(decrypted.plaintext) - 31)):
                gate(decrypted.plaintext[offset : offset + 32], f"AES-window/{provenances[0]}/{kdf}/offset-{offset}")

    result = {
        "schema": "yinyang-prime-dual-audit-v46",
        "status": "MATCH" if matches else "NO_PRIZE_MATCH_IN_PREREGISTERED_FAMILY",
        "preregistration_sha256": actual_seal,
        "balance": {
            "blue_sum": 484,
            "yellow_sum": 479,
            "imbalance_is_blue_prime_5": True,
            "balanced_after_zeroing": sum(lists["blue15_zero5"]) == sum(lists["yellow9"]) == 479,
        },
        "lists": {name: values for name, values in sorted(lists.items())},
        "serialized_records": len(serialized),
        "unique_scalar_tests": len(seen),
        "unique_passwords": len(passwords),
        "aes_tests": aes_tests,
        "valid_padding_count": len(valid_padding),
        "valid_padding": valid_padding,
        "structured_plaintexts": structured,
        "control": control,
        "matches": matches,
        "scope_note": (
            "Falsifies only the sealed v46 family: twelve prime lists from the "
            "484/479 balance x nine serialisations x six byte derivations, plus the "
            "listed short-envelope AES trials. It does not show that the 479 "
            "balance is the wrong reading of yinyang, and it does not reach any "
            "construction that combines these lists with another artifact."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    outcome = run()
    print(json.dumps({key: value for key, value in outcome.items() if key not in ("lists", "valid_padding")}, indent=2))
