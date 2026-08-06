"""Evaluate the sealed v44 ``YOUWON`` difference-block family.

Verifies the seal, re-derives every operand from committed artifacts, fails on
drift, runs a planted positive control through the production gate, and then
gates the sealed family.  Padding and readable text are recorded but never
accepted.

Run ``python -m solver.youwon_middle_block_audit``.
"""

from __future__ import annotations

import hashlib
import json

from . import targets
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion_raw import extract_raw, sha256_hex
from .youwon_middle_block_preregister import (
    AES_DIGESTS,
    AES_PASSWORD_FORMS,
    CASES,
    CONTROL_SCALAR_HEX,
    MANIFEST_PATH,
    ORIENTATIONS,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    difference_state,
)


def _base26(text: str, first_value: int) -> bytes:
    value = 0
    for character in text.upper():
        value = value * 26 + (ord(character) - ord("A") + first_value)
    return (value % (1 << 256)).to_bytes(32, "big")


def _letter_bytes(text: str, first_value: int) -> bytes:
    return bytes((ord(character) - ord("A") + first_value) % 256 for character in text.upper())


def _derive(text: str, name: str) -> bytes:
    encoded = text.encode("ascii")
    digest = hashlib.sha256(encoded).digest()
    if name == "sha256":
        return digest
    if name == "double_sha256":
        return hashlib.sha256(digest).digest()
    if name == "sha256^0x7f":
        return bytes(byte ^ 0x7F for byte in digest)
    if name == "sha256_reversed":
        return digest[::-1]
    if name == "base26_A0_bigendian":
        return _base26(text, 0)
    if name == "base26_A1_bigendian":
        return _base26(text, 1)
    if name == "sha256_of_A0_bytes":
        return hashlib.sha256(_letter_bytes(text, 0)).digest()
    if name == "sha256_of_A1_bytes":
        return hashlib.sha256(_letter_bytes(text, 1)).digest()
    raise ValueError(f"unsealed derivation: {name}")


def _printable_ratio(value: bytes) -> float:
    return sum(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in value) / max(1, len(value))


def _control() -> dict[str, object]:
    """Drive the production gate with a planted target on the audit's own path."""
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

    state = difference_state()
    raw = extract_raw()

    matches: list[dict[str, object]] = []
    seen: set[bytes] = set()
    for source, text in sorted(state.items()):
        for orientation in ORIENTATIONS:
            oriented = text if orientation == "forward" else text[::-1]
            for case in CASES:
                cased = oriented.upper() if case == "upper" else oriented.lower()
                for derivation in manifest["expansion"]["derivations"]:
                    value = _derive(cased, derivation)
                    if value in seen:
                        continue
                    seen.add(value)
                    hit = targets.gate_scalar_bytes(value)
                    if hit:
                        matches.append(
                            {
                                "provenance": f"{source}/{orientation}/{case}/{derivation}",
                                "scalar_hex": value.hex(),
                                "gate": hit,
                            }
                        )

    aes_tests = 0
    valid_padding: list[dict[str, object]] = []
    structured: list[dict[str, object]] = []
    for source, text in sorted(state.items()):
        for case in CASES:
            cased = text.upper() if case == "upper" else text.lower()
            digest = hashlib.sha256(cased.encode("ascii")).digest()
            for form in AES_PASSWORD_FORMS:
                password = cased.encode("ascii") if form == "literal" else digest.hex().encode("ascii")
                for kdf in AES_DIGESTS:
                    aes_tests += 1
                    try:
                        decrypted = decrypt_salted_aes256_cbc(raw.short_envelope, password, digest=kdf)
                    except ValueError:
                        continue
                    record = {
                        "provenance": f"{source}/{case}/{form}/{kdf}",
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
                        window = decrypted.plaintext[offset : offset + 32]
                        if len(window) == 32 and window not in seen:
                            seen.add(window)
                            hit = targets.gate_scalar_bytes(window)
                            if hit:
                                matches.append(
                                    {
                                        "provenance": f"AES-window/{record['provenance']}/offset-{offset}",
                                        "scalar_hex": window.hex(),
                                        "gate": hit,
                                    }
                                )

    result = {
        "schema": "youwon-middle-block-audit-v44",
        "status": "MATCH" if matches else "NO_PRIZE_MATCH_IN_PREREGISTERED_FAMILY",
        "preregistration_sha256": actual_seal,
        "operands": {
            name: {"length": len(text), "sha256": sha256_hex(text.encode("ascii")), "text": text}
            for name, text in sorted(state.items())
        },
        "v42_operand_comparison": {
            "v42_sliced": "S91[21:70] (raw base-9 field)",
            "this_audit_slices": "D[21:70] where D = S91 - VIC (mod 26)",
            "same_operand": False,
            "note": "v42_s91_middle_block.json does not test the block named in ATTEMPT_LOG or the Telegram review.",
        },
        "unique_scalar_tests": len(seen),
        "aes_tests": aes_tests,
        "valid_padding_count": len(valid_padding),
        "valid_padding": valid_padding,
        "structured_plaintexts": structured,
        "control": control,
        "matches": matches,
        "scope_note": (
            "Falsifies only the sealed v44 family: eight difference-derived source "
            "strings x two orientations x two letter cases x eight fixed byte "
            "derivations, plus the listed short-envelope AES trials. It does not "
            "explain the YOUWON alignment and does not reach any construction "
            "needing an operand this audit never builds."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    outcome = run()
    print(json.dumps({key: value for key, value in outcome.items() if key != "operands"}, indent=2))
