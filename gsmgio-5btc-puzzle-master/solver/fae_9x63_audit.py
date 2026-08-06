"""Bounded audit of the ``fae`` + 9x63 SalPhaseIon hypothesis.

The hypothesis and candidate family are sealed in
``fae_9x63_preregistered.json`` before this module is evaluated.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from .extract import ROOT
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion_raw import extract_raw
from .targets import gate_scalar_bytes, self_check

PRE = ROOT / "fae_9x63_preregistered.json"
SEAL = ROOT / "fae_9x63_preregistered.sha256"
RESULT = ROOT / "fae_9x63_audit.json"


def _serializations(sums: list[int]):
    yield "raw_sum_bytes", bytes(sums)
    yield "ascii_decimal_concat", "".join(map(str, sums)).encode("ascii")
    yield "ascii_two_digit_concat", "".join(f"{v:02d}" for v in sums).encode("ascii")
    yield "ascii_csv", ",".join(map(str, sums)).encode("ascii")
    yield "ascii_space", " ".join(map(str, sums)).encode("ascii")
    yield "mod10_ascii", "".join(str(v % 10) for v in sums).encode("ascii")
    yield "mod9_zero_ascii", "".join(str(v % 9) for v in sums).encode("ascii")
    yield "mod9_zero_to9_ascii", "".join(str(v % 9 or 9) for v in sums).encode("ascii")
    yield "mod26_A0_ascii", "".join(chr(65 + v % 26) for v in sums).encode("ascii")


def _printable_ratio(value: bytes) -> float:
    return sum(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in value) / max(1, len(value))


def run() -> dict[str, object]:
    pre_bytes = PRE.read_bytes()
    actual_seal = hashlib.sha256(pre_bytes).hexdigest()
    expected_seal = SEAL.read_text(encoding="ascii").strip()
    if actual_seal != expected_seal:
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(pre_bytes)
    if manifest["status"] != "SEALED_BEFORE_SCALAR_OR_AES_EVALUATION":
        raise ValueError("unexpected preregistration status")

    target_check = self_check()
    raw = extract_raw()
    if not raw.s570.startswith("fae"):
        raise ValueError("S570 no longer starts fae")
    remainder = raw.s570[3:]
    if len(remainder) != 567 or len(set(raw.s570)) != 9 or len(raw.lastwords_numeric) != 63:
        raise ValueError("FAE/9x63 structural observation changed")

    mappings = {
        "one_based": {chr(97+i): i+1 for i in range(9)},
        "zero_based": {chr(97+i): i for i in range(9)},
    }
    lists: dict[str, list[int]] = {}
    for map_name, mapping in mappings.items():
        values = [mapping[c] for c in remainder]
        # Source-order 9 rows of 63; sum each column.
        grid = [values[i*63:(i+1)*63] for i in range(9)]
        lists[f"{map_name}/9x63_column_sums"] = [sum(row[col] for row in grid) for col in range(63)]
        # Source-order 63 rows of 9; sum each row.
        lists[f"{map_name}/63x9_row_sums"] = [sum(values[i*9:(i+1)*9]) for i in range(63)]

    serial_records: list[tuple[str, bytes]] = []
    for source, sums in lists.items():
        for ser_name, value in _serializations(sums):
            serial_records.append((f"{source}/{ser_name}", value))

    scalar_tests = 0
    scalar_matches = []
    seen_scalars: set[bytes] = set()
    def gate(value: bytes, provenance: str):
        nonlocal scalar_tests
        if value in seen_scalars:
            return
        seen_scalars.add(value)
        scalar_tests += 1
        hit = gate_scalar_bytes(value)
        if hit:
            scalar_matches.append({"provenance": provenance, "scalar_hex": value.hex(), "gate": hit})

    for source, value in serial_records:
        d1 = hashlib.sha256(value).digest()
        gate(d1, f"SHA256({source})")
        gate(hashlib.sha256(d1).digest(), f"double_SHA256({source})")

    password_records: dict[bytes, list[str]] = {}
    for source, value in serial_records:
        d = hashlib.sha256(value).digest()
        for suffix, password in (("literal", value), ("sha256_raw", d), ("sha256_hex", d.hex().encode("ascii"))):
            password_records.setdefault(password, []).append(f"{source}/{suffix}")

    aes_tests = 0
    valid_padding = []
    structured = []
    for password, sources in password_records.items():
        for digest in ("md5", "sha256"):
            aes_tests += 1
            try:
                dec = decrypt_salted_aes256_cbc(raw.short_envelope, password, digest=digest)
            except ValueError:
                continue
            record = {
                "sources": sources,
                "password_hex": password.hex(),
                "kdf_digest": digest,
                "plaintext_hex": dec.plaintext.hex(),
                "plaintext_repr": repr(dec.plaintext),
                "printable_ratio": _printable_ratio(dec.plaintext),
                "padding_length": dec.padding_length,
            }
            valid_padding.append(record)
            lower = dec.plaintext.lower()
            if record["printable_ratio"] >= 0.85 or any(token in lower for token in (b"private", b"bitcoin", b"matrix", b"key", b"gsmg")):
                structured.append(record)
            if len(dec.plaintext) == 32:
                gate(dec.plaintext, f"AES-plaintext/{sources}/{digest}")
            elif len(dec.plaintext) > 32:
                for offset in range(len(dec.plaintext)-31):
                    gate(dec.plaintext[offset:offset+32], f"AES-window/{sources}/{digest}/offset-{offset}")

    # Compare the generated list to the immediately following 63 source digits,
    # but do not use comparison score as acceptance.
    digit_map = {**{chr(97+i): i+1 for i in range(9)}, "o": 0}
    target = [digit_map[c] for c in raw.lastwords_numeric]
    comparisons = {}
    for source, sums in lists.items():
        transforms = {
            "mod10": [v % 10 for v in sums],
            "mod9_zero": [v % 9 for v in sums],
            "mod9_zero_to9": [v % 9 or 9 for v in sums],
            "tens": [v // 10 for v in sums],
        }
        comparisons[source] = {name: sum(a == b for a,b in zip(seq,target)) for name,seq in transforms.items()}

    result = {
        "status": "MATCH" if scalar_matches else "NO_PRIZE_MATCH_IN_PREREGISTERED_FAMILY",
        "preregistration_sha256": actual_seal,
        "authenticated_inputs": {
            "s570_sha256": hashlib.sha256(raw.s570.encode("ascii")).hexdigest(),
            "s570_prefix": raw.s570[:3],
            "remainder_length": len(remainder),
            "alphabet": "".join(sorted(set(raw.s570))),
            "following_field_length": len(raw.lastwords_numeric),
            "following_field_decoded": raw.lastwords_marker,
            "short_envelope_sha256": hashlib.sha256(raw.short_envelope).hexdigest(),
        },
        "structural_equalities": ["570-3=567", "567=9*63", "alphabet_size=9", "following_raw_field_length=63"],
        "sum_lists": lists,
        "following_field_comparison_matches_of_63": comparisons,
        "serialization_records": len(serial_records),
        "unique_scalar_tests": scalar_tests,
        "unique_passwords": len(password_records),
        "aes_tests": aes_tests,
        "valid_padding_count": len(valid_padding),
        "valid_padding": valid_padding,
        "structured_plaintexts": structured,
        "target_self_check": target_check,
        "matches": scalar_matches,
        "scope_note": "This tests only the sealed source-order FAE-header 9x63/63x9 sum-list family and its listed serializations. Padding is never acceptance. It does not establish or refute the broader F-A-E Sonata interpretation.",
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
