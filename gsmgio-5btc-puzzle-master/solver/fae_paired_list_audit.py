"""Evaluate the sealed v45 paired-list family (9x63 sums x the F63 field).

Verifies the seal, re-derives both operands, fails on drift, runs a planted
positive control through the production gate, then gates the sealed family.
Elementwise agreement between the two lists is reported for information only:
it is explicitly not an acceptance criterion, and neither is AES padding.

Run ``python -m solver.fae_paired_list_audit``.
"""

from __future__ import annotations

import hashlib
import json

from . import targets
from .fae_paired_list_preregister import (
    AES_DIGESTS,
    AES_PASSWORD_FORMS,
    CONTROL_SCALAR_HEX,
    MANIFEST_PATH,
    PAIR_OPERATIONS,
    RESULT_PATH,
    SEAL_PATH,
    SERIALIZATIONS,
    build_manifest,
    operands,
)
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion_raw import extract_raw


def _pair(sums: list[int], digits: list[int], operation: str) -> list[int]:
    if operation == "sum_plus_digit":
        return [s + d for s, d in zip(sums, digits)]
    if operation == "sum_minus_digit":
        return [s - d for s, d in zip(sums, digits)]
    if operation == "digit_minus_sum":
        return [d - s for s, d in zip(sums, digits)]
    if operation == "sum_xor_digit":
        return [s ^ d for s, d in zip(sums, digits)]
    if operation == "sum_times_digit":
        return [s * d for s, d in zip(sums, digits)]
    if operation == "sum_plus_digit_mod9":
        return [(s + d) % 9 for s, d in zip(sums, digits)]
    if operation == "sum_plus_digit_mod10":
        return [(s + d) % 10 for s, d in zip(sums, digits)]
    if operation == "sum_plus_digit_mod26":
        return [(s + d) % 26 for s, d in zip(sums, digits)]
    if operation == "interleave_sum_first":
        return [value for pair in zip(sums, digits) for value in pair]
    if operation == "interleave_digit_first":
        return [value for pair in zip(digits, sums) for value in pair]
    raise ValueError(f"unsealed operation: {operation}")


def _serialize(values: list[int], name: str) -> bytes:
    if name == "raw_sum_bytes":
        return bytes(value % 256 for value in values)
    if name == "ascii_decimal_concat":
        return "".join(str(value) for value in values).encode("ascii")
    if name == "ascii_two_digit_concat":
        return "".join(f"{abs(value) % 100:02d}" for value in values).encode("ascii")
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
    if build_manifest() != manifest:
        raise ValueError("re-derived manifest differs from the sealed manifest")

    control = _control()
    if not (control["accepted_against_planted_target"] and control["rejected_against_real_targets"]):
        raise ValueError("the gate failed its own control; results would be meaningless")

    derived = operands()
    sums: dict[str, list[int]] = derived["sums"]  # type: ignore[assignment]
    digits: list[int] = derived["digits"]  # type: ignore[assignment]
    raw = extract_raw()

    records: list[tuple[str, bytes]] = []
    for source, values in sorted(sums.items()):
        for operation in PAIR_OPERATIONS:
            paired = _pair(values, digits, operation)
            for serialization in SERIALIZATIONS:
                records.append((f"{source}/{operation}/{serialization}", _serialize(paired, serialization)))

    matches: list[dict[str, object]] = []
    seen: set[bytes] = set()

    def gate(value: bytes, provenance: str) -> None:
        if len(value) != 32 or value in seen:
            return
        seen.add(value)
        hit = targets.gate_scalar_bytes(value)
        if hit:
            matches.append({"provenance": provenance, "scalar_hex": value.hex(), "gate": hit})

    for provenance, value in records:
        digest = hashlib.sha256(value).digest()
        gate(digest, f"SHA256({provenance})")
        gate(hashlib.sha256(digest).digest(), f"double_SHA256({provenance})")

    aes_tests = 0
    valid_padding: list[dict[str, object]] = []
    structured: list[dict[str, object]] = []
    passwords: dict[bytes, list[str]] = {}
    for provenance, value in records:
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
                "provenance_count": len(provenances),
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

    # Information only: how closely does any paired list reproduce the F63 digits?
    agreement = {}
    for source, values in sorted(sums.items()):
        for operation in PAIR_OPERATIONS[:8]:
            paired = _pair(values, digits, operation)
            agreement[f"{source}/{operation}"] = sum(a == b for a, b in zip(paired, digits))

    result = {
        "schema": "fae-paired-list-audit-v45",
        "status": "MATCH" if matches else "NO_PRIZE_MATCH_IN_PREREGISTERED_FAMILY",
        "preregistration_sha256": actual_seal,
        "records": len(records),
        "unique_scalar_tests": len(seen),
        "unique_passwords": len(passwords),
        "aes_tests": aes_tests,
        "valid_padding_count": len(valid_padding),
        "valid_padding": valid_padding,
        "structured_plaintexts": structured,
        "elementwise_agreement_with_f63_of_63": agreement,
        "control": control,
        "matches": matches,
        "scope_note": (
            "Falsifies only the sealed v45 family: four sum lists x ten fixed "
            "pairings with the F63 digits x nine serialisations, hashed and used "
            "as short-envelope AES passwords. It does not refute the F-A-E header "
            "reading, the 9x63 structure, or a sonata-derived mapping of S570, "
            "which needs an external score this audit never loads."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    outcome = run()
    print(json.dumps({key: value for key, value in outcome.items() if key != "valid_padding"}, indent=2))
