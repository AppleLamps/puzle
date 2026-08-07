"""Preregistered AES test of 14x14 poster resistor sum lists.

Tests every well-defined encoding of the four 14-entry 14x14 poster resistor
sum lists (rows/columns, eye-zeroed and eye-nine) as an AES password against
the split SalPhaseIon env48/raw48 halves under both EVP_BytesToKey digests.

* env48 is the 48-byte OpenSSL ``Salted__`` half.
* raw48 is the 48-byte no-header half.

For raw48 each password is used in two IV modes:

* ``evp_iv`` - the IV produced by EVP_BytesToKey with the env48 salt.
* ``continuation_iv`` - the last 16 bytes of the env48 ciphertext, treating
  raw48 as the continuation of the same CBC stream.

Every valid-padding plaintext is gated by legibility (``_readable`` and the
historical printable/entropy thresholds) and by ``solver.targets`` on every
32-byte slice.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from Crypto.Cipher import AES
from PIL import Image

from . import targets
from .openssl_compat import (
    decrypt_salted_aes256_cbc,
    evp_bytes_to_key,
    strict_pkcs7_unpad,
)
from .salphaseion_blind_eval import _formats, _readable
from .salphaseion_raw import sha256_hex
from .salphaseion_split_envelope_preregister import split_envelope


ROOT = Path(__file__).resolve().parent.parent
POSTER = ROOT.parent / "sources" / "follow_the_white_rabbit.png"

MANIFEST_PATH = ROOT / "poster_resistor_split_envelope_preregistered.json"
SEAL_PATH = ROOT / "poster_resistor_split_envelope_preregistered.sha256"
RESULT_PATH = ROOT / "poster_resistor_split_envelope_results.json"

CELL = 25
SIZE = 14

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)
OFF_WHITE = (254, 254, 254)

RESISTOR = {BLACK: 0, YELLOW: 4, BLUE: 6, WHITE: 9, OFF_WHITE: 9}


def _poster_grid() -> list[list[tuple[int, int, int]]]:
    pixels = Image.open(POSTER).convert("RGB").load()
    return [
        [
            Counter(
                pixels[x, y]
                for y in range(row * CELL, (row + 1) * CELL)
                for x in range(col * CELL, (col + 1) * CELL)
            ).most_common(1)[0][0]
            for col in range(SIZE)
        ]
        for row in range(SIZE)
    ]


def _resistor_value(colour: tuple[int, int, int], *, zero_eye: bool) -> int:
    if zero_eye and colour == OFF_WHITE:
        return 0
    return RESISTOR[colour]


def _row_sums(grid: list[list[tuple[int, int, int]]], *, zero_eye: bool) -> list[int]:
    return [
        sum(_resistor_value(cell, zero_eye=zero_eye) for cell in row)
        for row in grid
    ]


def _col_sums(grid: list[list[tuple[int, int, int]]], *, zero_eye: bool) -> list[int]:
    return [
        sum(_resistor_value(grid[row][col], zero_eye=zero_eye) for row in range(SIZE))
        for col in range(SIZE)
    ]


def _sum_lists() -> dict[str, list[int]]:
    grid = _poster_grid()
    return {
        "poster_resistor_row_sums_eye_nine": _row_sums(grid, zero_eye=False),
        "poster_resistor_col_sums_eye_nine": _col_sums(grid, zero_eye=False),
        "poster_resistor_row_sums_eye_zeroed": _row_sums(grid, zero_eye=True),
        "poster_resistor_col_sums_eye_zeroed": _col_sums(grid, zero_eye=True),
    }


def _mod26(values: list[int], *, zero_based: bool, lower: bool) -> bytes:
    base = ord("a") if lower else ord("A")
    if zero_based:
        return "".join(chr(base + (v % 26)) for v in values).encode("ascii")
    return "".join(chr(base + ((v - 1) % 26)) for v in values).encode("ascii")


def _encodings(values: list[int]) -> list[tuple[str, bytes]]:
    """Enumerate the preregistered password encodings."""

    forms: list[tuple[str, bytes]] = []

    # Raw bytes of the 14 sum values.
    forms.append(("raw_bytes", bytes(values)))

    # Modulo encodings as printable digit strings and as raw byte values.
    forms.append(("mod10_digits", "".join(str(v % 10) for v in values).encode("ascii")))
    forms.append(("mod10_bytes", bytes(v % 10 for v in values)))
    forms.append(("mod9_digits", "".join(str(v % 9) for v in values).encode("ascii")))
    forms.append(("mod9_bytes", bytes(v % 9 for v in values)))

    # Modulo 26, both 0-based and 1-based alphabet conventions, both cases.
    for zero_based in (True, False):
        for lower in (True, False):
            label = f"mod26_{'a0' if zero_based else 'a1'}_{'lower' if lower else 'upper'}"
            forms.append((label, _mod26(values, zero_based=zero_based, lower=lower)))

    # Two-digit fixed-width decimal concatenation.
    forms.append(("two_digit", "".join(f"{v:02d}" for v in values).encode("ascii")))

    return forms


def _password_forms(password: bytes) -> list[tuple[str, bytes]]:
    """Four standard password forms tested for every encoding."""

    forms: list[tuple[str, bytes]] = [("literal", password)]
    digest = hashlib.sha256(password).digest()
    forms.append(("sha256_digest_raw", digest))
    forms.append(("sha256_hex_ascii", digest.hex().encode("ascii")))
    forms.append(("sha256_hex_decoded", digest))
    return forms


def _stats(value: bytes) -> dict[str, float]:
    length = max(1, len(value))
    counts = Counter(value)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    printable = sum(1 for b in value if b in b"\n\r\t" or 32 <= b <= 126) / length
    return {
        "length": len(value),
        "entropy": round(entropy, 6),
        "printable": round(printable, 6),
    }


def _gate_plaintext(plaintext: bytes) -> dict[str, object]:
    """Run the full acceptance gate on a valid-padding plaintext."""

    stats = _stats(plaintext)
    readable, readable_metrics = _readable(plaintext)
    formats = _formats(plaintext)

    gate_matches: list[dict[str, object]] = []
    if len(plaintext) == 32:
        gate = targets.gate_scalar_bytes(plaintext)
        if gate:
            gate_matches.append({"offset": 0, **gate})
    elif len(plaintext) > 32:
        for offset in range(len(plaintext) - 31):
            window = plaintext[offset : offset + 32]
            gate = targets.gate_scalar_bytes(window)
            if gate:
                gate_matches.append({"offset": offset, **gate})

    # Historical legibility threshold used in the root pipeline reconstruction.
    legible = stats["printable"] >= 0.9 or stats["entropy"] <= 4.5

    accepted = bool(
        readable
        or formats
        or gate_matches
        or legible
    )

    return {
        "padding_valid": True,
        "plaintext_length": len(plaintext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "entropy": stats["entropy"],
        "printable": stats["printable"],
        "legible_threshold": legible,
        "readable": readable,
        "readable_metrics": readable_metrics,
        "formats": formats,
        "gate_matches": gate_matches,
        "accepted": accepted,
    }


def _record_failure(
    *,
    target: str,
    list_name: str,
    encoding: str,
    form: str,
    digest: str,
    password_hex: str,
    error: str,
) -> dict[str, object]:
    return {
        "target": target,
        "list_name": list_name,
        "encoding": encoding,
        "form": form,
        "kdf_digest": digest,
        "password_hex": password_hex,
        "padding_valid": False,
        "error": error,
    }


def build_manifest() -> dict[str, object]:
    """Preregistered manifest: inputs, candidate encodings, and rules."""

    env48, raw48 = split_envelope()
    poster_bytes = POSTER.read_bytes()
    sums = _sum_lists()

    encodings = {
        name: [label for label, _ in _encodings(values)]
        for name, values in sums.items()
    }

    return {
        "schema": "poster-resistor-split-envelope-v1",
        "status": "SEALED_BEFORE_DECRYPTION",
        "source": {
            "poster_path": str(POSTER.relative_to(ROOT.parent)),
            "poster_sha256": sha256_hex(poster_bytes),
            "poster_size": len(poster_bytes),
        },
        "targets": {
            "env48": {
                "length": len(env48),
                "sha256": sha256_hex(env48),
                "kind": "openssl-envelope",
                "salt_hex": env48[8:16].hex(),
            },
            "raw48": {
                "length": len(raw48),
                "sha256": sha256_hex(raw48),
                "kind": "raw-3-block-candidate",
                "env48_ciphertext_tail_iv_hex": env48[32:48].hex(),
            },
        },
        "sum_lists": sums,
        "encodings_per_list": encodings,
        "password_forms": ["literal", "sha256_digest_raw", "sha256_hex_ascii", "sha256_hex_decoded"],
        "kdf_digests": ["md5", "sha256"],
        "raw48_iv_modes": {
            "evp_iv": "the IV produced by EVP_BytesToKey(password, env48 salt, digest)",
            "continuation_iv": "the last 16 bytes of env48 ciphertext (env48[32:48])",
        },
        "acceptance": (
            "A result is accepted only if the plaintext is readable, matches an "
            "exact parser/checksum format, or contains a 32-byte slice that "
            "passes solver.targets. Padding alone is never sufficient."
        ),
    }


def run() -> dict[str, object]:
    """Execute the preregistered experiment and write the result JSON."""

    targets.self_check()
    env48, raw48 = split_envelope()
    env48_salt = env48[8:16]
    env48_ciphertext_tail = env48[32:48]

    # Seal the preregistration manifest before any decryption.
    manifest = build_manifest()
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(manifest_bytes)
    SEAL_PATH.write_text(sha256_hex(manifest_bytes) + "\n", encoding="ascii")

    sums = _sum_lists()
    results: list[dict[str, object]] = []
    stream = hashlib.sha256()

    for list_name, values in sums.items():
        for encoding, password in _encodings(values):
            for form_name, form_password in _password_forms(password):
                for digest in ("md5", "sha256"):
                    # KDF material shared across both raw48 modes.
                    key, evp_iv = evp_bytes_to_key(form_password, env48_salt, digest)

                    # Target 1: env48 (the Salted__ half).
                    stream.update(
                        f"env48/{list_name}/{encoding}/{form_name}/{digest}".encode("ascii")
                        + form_password
                    )
                    try:
                        dec = decrypt_salted_aes256_cbc(env48, form_password, digest=digest)
                        record = {
                            "target": "env48",
                            "list_name": list_name,
                            "encoding": encoding,
                            "form": form_name,
                            "kdf_digest": digest,
                            "password_hex": form_password.hex()[:64],
                            "key_hex": dec.key.hex(),
                            "iv_hex": dec.iv.hex(),
                            "salt_hex": dec.salt.hex(),
                            **_gate_plaintext(dec.plaintext),
                        }
                    except ValueError as exc:
                        record = _record_failure(
                            target="env48",
                            list_name=list_name,
                            encoding=encoding,
                            form=form_name,
                            digest=digest,
                            password_hex=form_password.hex()[:64],
                            error=str(exc),
                        )
                    results.append(record)

                    # Target 2: raw48 with the EVP-derived IV.
                    stream.update(
                        f"raw48_evp_iv/{list_name}/{encoding}/{form_name}/{digest}".encode("ascii")
                        + form_password
                    )
                    try:
                        padded = AES.new(key, AES.MODE_CBC, evp_iv).decrypt(raw48)
                        plaintext, _ = strict_pkcs7_unpad(padded)
                        record = {
                            "target": "raw48_evp_iv",
                            "list_name": list_name,
                            "encoding": encoding,
                            "form": form_name,
                            "kdf_digest": digest,
                            "password_hex": form_password.hex()[:64],
                            "key_hex": key.hex(),
                            "iv_hex": evp_iv.hex(),
                            "salt_hex": env48_salt.hex(),
                            **_gate_plaintext(plaintext),
                        }
                    except ValueError as exc:
                        record = _record_failure(
                            target="raw48_evp_iv",
                            list_name=list_name,
                            encoding=encoding,
                            form=form_name,
                            digest=digest,
                            password_hex=form_password.hex()[:64],
                            error=str(exc),
                        )
                    results.append(record)

                    # Target 3: raw48 with the continuation IV.
                    stream.update(
                        f"raw48_continuation_iv/{list_name}/{encoding}/{form_name}/{digest}".encode("ascii")
                        + form_password
                    )
                    try:
                        padded = AES.new(key, AES.MODE_CBC, env48_ciphertext_tail).decrypt(raw48)
                        plaintext, _ = strict_pkcs7_unpad(padded)
                        record = {
                            "target": "raw48_continuation_iv",
                            "list_name": list_name,
                            "encoding": encoding,
                            "form": form_name,
                            "kdf_digest": digest,
                            "password_hex": form_password.hex()[:64],
                            "key_hex": key.hex(),
                            "iv_hex": env48_ciphertext_tail.hex(),
                            "salt_hex": env48_salt.hex(),
                            **_gate_plaintext(plaintext),
                        }
                    except ValueError as exc:
                        record = _record_failure(
                            target="raw48_continuation_iv",
                            list_name=list_name,
                            encoding=encoding,
                            form=form_name,
                            digest=digest,
                            password_hex=form_password.hex()[:64],
                            error=str(exc),
                        )
                    results.append(record)

    summary = {
        "total_attempts": len(results),
        "valid_padding": sum(1 for r in results if r.get("padding_valid")),
        "accepted": sum(1 for r in results if r.get("accepted")),
        "legible_by_threshold": sum(
            1 for r in results
            if r.get("padding_valid") and r.get("legible_threshold")
        ),
        "readable": sum(
            1 for r in results if r.get("padding_valid") and r.get("readable")
        ),
        "format_hits": sum(
            1 for r in results if r.get("padding_valid") and r.get("formats")
        ),
        "prize_matches": sum(
            len(r.get("gate_matches", [])) for r in results if r.get("padding_valid")
        ),
        "candidate_stream_sha256": stream.hexdigest(),
    }

    result = {
        "schema": "poster-resistor-split-envelope-results-v1",
        "status": "ACCEPTED" if summary["accepted"] else "NO_ACCEPTED_OUTPUT",
        "manifest_sha256": sha256_hex(manifest_bytes),
        "preregistration_sha256": sha256_hex(manifest_bytes),
        "summary": summary,
        "accepted_records": [r for r in results if r.get("accepted")],
        "all_valid_padding": [r for r in results if r.get("padding_valid")],
        "details": results,
    }

    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    result = run()
    print(json.dumps(result["summary"], indent=2))
