"""Reconstruct and test the creator-confirmed pipeline.

YELLOW → BLUE → PRIMES → ZEROED-OUT CHARACTERS → MATRIXSUMLIST →
LAST WORDS BEFORE ARCHITECT CHOICE → AES DECRYPTION → YIN-YANG

This script re-derives every step from the checked-in source image and
SalPhaseIon/Architect plaintext, then tests the most defensible AES
passwords against the original Cosmic envelope.  It is intentionally
self-contained and read-only: it does not modify the repository.

Run from the repository root:
    python reconstruct_pipeline.py
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import math
import sys
from collections import Counter
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent / "gsmgio-5btc-puzzle-master"
if str(PACKAGE) not in sys.path:
    sys.path.insert(0, str(PACKAGE))

from PIL import Image

from solver import targets
from solver.extract import extract_all, extract_cosmic_envelope
from solver.openssl_compat import decrypt_salted_aes256_cbc, evp_bytes_to_key
from solver.phase32_classical import PHASE32_PASSWORD, BEAUFORT_KEY
from solver.salphaseion import derive_tokens

ROOT = Path(__file__).resolve().parent
REPORT_PATH = ROOT / "reconstruct_pipeline_results.json"

SOURCE_IMAGE = ROOT / "sources" / "follow_the_white_rabbit.png"
CELL = 25
SIZE = 14

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)
OFF_WHITE = (254, 254, 254)

RESISTOR = {BLACK: 0, YELLOW: 4, BLUE: 6, WHITE: 9, OFF_WHITE: 9}

ARCHITECT_SHA256 = "56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241"


def _spiral_positions(size: int) -> list[tuple[int, int]]:
    order = []
    top = left = 0
    bottom = right = size - 1
    while top <= bottom and left <= right:
        for row in range(top, bottom + 1):
            order.append((row, left))
        left += 1
        for col in range(left, right + 1):
            order.append((bottom, col))
        bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                order.append((row, right))
            right -= 1
        if top <= bottom:
            for col in range(right, left - 1, -1):
                order.append((top, col))
            top += 1
    return order


def _majority_grid(path: Path) -> list[list[tuple[int, int, int]]]:
    image = Image.open(path).convert("RGB")
    pixels = image.load()
    grid = []
    for row in range(SIZE):
        cells = []
        for col in range(SIZE):
            counts = Counter(
                pixels[x, y]
                for y in range(row * CELL, (row + 1) * CELL)
                for x in range(col * CELL, (col + 1) * CELL)
            )
            cells.append(counts.most_common(1)[0][0])
        grid.append(cells)
    return grid


def _colour_counts(grid: list[list[tuple[int, int, int]]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in grid:
        for cell in row:
            name = {
                BLACK: "black", WHITE: "white", BLUE: "blue",
                YELLOW: "yellow", OFF_WHITE: "off-white",
            }.get(cell, str(cell))
            counts[name] = counts.get(name, 0) + 1
    return counts


def _marker_stream(grid: list[list[tuple[int, int, int]]]) -> dict[str, object]:
    order = _spiral_positions(SIZE)
    colours = [grid[row][col] for row, col in order]
    bits = "".join("1" if colour in (BLACK, BLUE) else "0" for colour in colours)
    body = bits[:192]
    message = "".join(chr(int(body[i : i + 8], 2)) for i in range(0, 192, 8))
    markers = [(i, colour) for i, colour in enumerate(colours) if colour in (BLUE, YELLOW)]
    marker_bits = "".join("1" if colour == BLUE else "0" for _, colour in markers)
    marker_hex = f"{int(marker_bits, 2):06X}"
    off_white = [(row, col) for (row, col), colour in zip(order, colours) if colour == OFF_WHITE]
    return {
        "message": message,
        "padding": bits[192:],
        "marker_count": len(markers),
        "marker_spiral_indices": [i for i, _ in markers],
        "marker_bits": marker_bits,
        "marker_hex": marker_hex,
        "off_white_cells": off_white,
    }


def _primes(limit: int) -> list[int]:
    return [n for n in range(2, limit + 1) if all(n % d for d in range(2, int(n ** 0.5) + 1))]


def _yellow_blue_numbers(grid: list[list[tuple[int, int, int]]]) -> dict[str, object]:
    order = _spiral_positions(SIZE)
    colours = [grid[row][col] for row, col in order]
    marker_colours = [c for c in colours if c in (BLUE, YELLOW)]
    first_24_primes = _primes(89)[:24]
    blue_sum = sum(p for p, c in zip(first_24_primes, marker_colours) if c == BLUE)
    yellow_sum = sum(p for p, c in zip(first_24_primes, marker_colours) if c == YELLOW)
    blue_count = marker_colours.count(BLUE)
    yellow_count = marker_colours.count(YELLOW)
    return {
        "blue_count": blue_count,
        "yellow_count": yellow_count,
        "first_24_primes": first_24_primes,
        "blue_sum": blue_sum,
        "yellow_sum": yellow_sum,
        "difference": blue_sum - yellow_sum,
        "balance_prime": 5,
        "blue_sum_minus_balance": blue_sum - 5,
        "balanced": blue_sum - 5 == yellow_sum,
    }


def _resistor_sums(grid: list[list[tuple[int, int, int]]]) -> dict[str, list[int]]:
    zero_eye = [[RESISTOR.get(c, 0) if c != OFF_WHITE else 0 for c in row] for row in grid]
    eye_nine = [[RESISTOR.get(c, 0) for c in row] for row in grid]
    return {
        "row_sums_eye_zeroed": [sum(row) for row in zero_eye],
        "col_sums_eye_zeroed": [sum(row[i] for row in zero_eye) for i in range(SIZE)],
        "row_sums_eye_nine": [sum(row) for row in eye_nine],
        "col_sums_eye_nine": [sum(row[i] for row in eye_nine) for i in range(SIZE)],
    }


def _load_architect_plaintext() -> str:
    data = json.loads((PACKAGE / "phase32_symbol_recovery.json").read_text())
    plaintext = data["plaintext"]
    if hashlib.sha256(plaintext.encode("ascii")).hexdigest() != ARCHITECT_SHA256:
        raise ValueError("Architect plaintext drifted")
    return plaintext


def _stats(value: bytes) -> dict[str, float]:
    length = max(1, len(value))
    counts = Counter(value)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    printable = sum(1 for b in value if b in b"\n\r\t" or 32 <= b <= 126) / length
    return {"length": len(value), "entropy": round(entropy, 4), "printable": round(printable, 4)}


def _test_aes_forms(password: bytes, envelope: bytes, label: str, results: list[dict]) -> None:
    """Try password in the four explicit forms and two KDF digests."""
    forms: list[tuple[str, bytes]] = [("literal", password)]
    h = hashlib.sha256(password).digest()
    forms.append(("sha256_digest_raw", h))
    forms.append(("sha256_hex_ascii", hashlib.sha256(password).hexdigest().encode("ascii")))
    forms.append(("sha256_hex_decoded", bytes.fromhex(hashlib.sha256(password).hexdigest())))
    for digest in ("md5", "sha256"):
        for form_name, pw in forms:
            try:
                dec = decrypt_salted_aes256_cbc(envelope, pw, digest=digest)
                stats = _stats(dec.plaintext)
                gate = None
                if len(dec.plaintext) == 32:
                    gate = targets.gate_scalar_bytes(dec.plaintext)
                results.append({
                    "label": f"{label}/{form_name}/{digest}",
                    "password_form": form_name,
                    "kdf_digest": digest,
                    "password_bytes": pw.hex()[:64],
                    "padding_valid": True,
                    "plaintext_length": stats["length"],
                    "entropy": stats["entropy"],
                    "printable": stats["printable"],
                    "head": dec.plaintext[:32].hex(),
                    "gate": gate,
                })
            except ValueError as exc:
                results.append({
                    "label": f"{label}/{form_name}/{digest}",
                    "password_form": form_name,
                    "kdf_digest": digest,
                    "password_bytes": pw.hex()[:64],
                    "padding_valid": False,
                    "error": str(exc),
                })


def _raw_key_test(key: bytes, iv: bytes, envelope: bytes, label: str, results: list[dict]) -> None:
    """AES-256-CBC with the given raw key and IV, bypassing EVP."""
    from Crypto.Cipher import AES
    salt = envelope[8:16]
    ciphertext = envelope[16:]
    padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    try:
        from solver.openssl_compat import strict_pkcs7_unpad
        plaintext, _ = strict_pkcs7_unpad(padded)
        stats = _stats(plaintext)
        gate = targets.gate_scalar_bytes(plaintext) if len(plaintext) == 32 else None
        results.append({
            "label": f"{label}/raw_aes_key_iv_from_known_password",
            "password_form": "raw_aes_256_key",
            "kdf_digest": "none",
            "salt": salt.hex(),
            "iv": iv.hex(),
            "key": key.hex(),
            "padding_valid": True,
            "plaintext_length": stats["length"],
            "entropy": stats["entropy"],
            "printable": stats["printable"],
            "head": plaintext[:32].hex(),
            "gate": gate,
        })
    except ValueError as exc:
        results.append({
            "label": f"{label}/raw_aes_key_iv_from_known_password",
            "password_form": "raw_aes_256_key",
            "kdf_digest": "none",
            "padding_valid": False,
            "error": str(exc),
        })


def main() -> None:
    if not SOURCE_IMAGE.exists():
        raise FileNotFoundError(SOURCE_IMAGE)

    report: dict[str, object] = {}

    # 1. First / zero rabbit puzzle artifact.
    grid = _majority_grid(SOURCE_IMAGE)
    marker_info = _marker_stream(grid)
    report["first_artifact"] = {
        "image_path": str(SOURCE_IMAGE),
        "image_size": Image.open(SOURCE_IMAGE).size,
        "grid_cells": SIZE * SIZE,
        "cell_size": CELL,
        "colour_counts": _colour_counts(grid),
        "spiral_message": marker_info["message"],
        "spiral_padding": marker_info["padding"],
        "marker_count": marker_info["marker_count"],
        "marker_spiral_indices": marker_info["marker_spiral_indices"],
        "marker_hex": marker_info["marker_hex"],
        "off_white_cells": marker_info["off_white_cells"],
        "reading_direction": "counter-clockwise inward spiral, down the left column first",
        "bit_assignment": "black/blue = 1, white/yellow = 0; markers restate each byte's LSB",
    }

    # 2. Yellow / blue numbers.
    yb = _yellow_blue_numbers(grid)
    report["yellow_blue"] = yb

    # 3. Resistor sum lists (matrixsumlist candidates).
    sums = _resistor_sums(grid)
    report["poster_resistor_sums"] = sums

    # 4. Architect plaintext and last words.
    architect = _load_architect_plaintext()
    report["architect_plaintext"] = {
        "sha256": ARCHITECT_SHA256,
        "length": len(architect),
        "offset_479_text": architect[479:479 + 40],
        "offset_511_takethistoheart": "TAKETHISTOHEART" in architect,
        "offset_535_wisemanabove": "WISEMANABOVE" in architect,
        "offset_562_hundredfourty": "HUNDREDFOURTY" in architect,
        "offset_1021_sourcecodes": "SOURCECODES" in architect,
        "offset_1103_primebasics": "PRIMEBASICS" in architect,
        "offset_1157_twentythreeciphers": "TWENTYTHREECIPHERS" in architect,
        "offset_1175_sixteenencryptions": "SIXTEENENCRYPTIONS" in architect,
        "offset_1198_sevenintertwinedpasswords": "SEVENINTERTWINEDPASSWORDS" in architect,
        "offset_1529_ciaobellao": "CIAOBELLAO" in architect,
    }

    # 5. AES oracle validation on phase 3.2.
    inputs = extract_all()
    phase32 = decrypt_salted_aes256_cbc(inputs.phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    report["aes_oracle_validation"] = {
        "envelope": "phase32",
        "password_form": "64-ascii-hex",
        "kdf_digest": "sha256",
        "plaintext_sha256": hashlib.sha256(phase32.plaintext).hexdigest(),
        "plaintext_length": len(phase32.plaintext),
        "opening_bytes": phase32.plaintext[:60].decode("ascii", errors="replace"),
        "valid_padding": True,
    }

    # 6. Cosmic AES envelope details.
    cosmic = inputs.cosmic_envelope
    tokens = derive_tokens()
    known_password = tokens.xor_password
    known_dec = decrypt_salted_aes256_cbc(cosmic, known_password, digest="md5")
    report["cosmic_envelope"] = {
        "source_file": str(PACKAGE / "solver" / "data" / "cosmic_duality.txt"),
        "envelope_base64": base64.b64encode(cosmic).decode("ascii"),
        "header": cosmic[:8].decode("ascii", errors="replace"),
        "salt": known_dec.salt.hex(),
        "ciphertext_length": len(known_dec.ciphertext),
        "kdf": "EVP_BytesToKey",
        "kdf_digest": known_dec.kdf_digest,
        "key_length": len(known_dec.key),
        "iv_length": len(known_dec.iv),
        "padding_rule": "PKCS#7",
    }

    # 7. Cosmic decryption with the known 7-token XOR password.
    known_stats = _stats(known_dec.plaintext)
    report["cosmic_known_password"] = {
        "password_form": "7-token sha256-digest XOR (32 raw bytes)",
        "tokens": tokens.tokens,
        "xor_password_hex": known_password.hex(),
        "kdf_digest": "md5",
        "plaintext_length": known_stats["length"],
        "entropy": known_stats["entropy"],
        "printable": known_stats["printable"],
        "plaintext_sha256": hashlib.sha256(known_dec.plaintext).hexdigest(),
        "head": known_dec.plaintext[:32].hex(),
        "legible": known_stats["printable"] >= 0.9 or known_stats["entropy"] <= 4.5,
    }

    # 8. Candidate password tests against Cosmic.
    aes_results: list[dict] = []

    # 8a. The literal ordered pipeline phrases and the full SalPhaseIon token set.
    ordered_phrases = [
        "yellowblueprimes",
        "matrixsumlist",
        "lastwordsbeforearchichoice",
        "yinyang",
    ]
    for parts in (ordered_phrases, list(tokens.tokens)):
        for sep in ("", " "):
            pw = sep.join(parts).encode("ascii")
            _test_aes_forms(pw, cosmic, f"concat/{'+'.join(parts)}/sep={sep!r}", aes_results)

    # 8b. "Last words before architect choice" candidates (Matrix Reloaded film quote).
    quote = "As you adequately put, the problem is choice."
    quote_words = [w.strip(".,") for w in quote.split()]
    last_words = [w for w in quote_words if w.lower() != "choice"]
    for suffix_len in range(1, len(last_words) + 1):
        for sep in ("", " "):
            words = sep.join(last_words[-suffix_len:])
            _test_aes_forms(words.encode("ascii"), cosmic, f"lastwords/suffix_{suffix_len}/sep={sep!r}", aes_results)

    # 8c. The fitted 479-derived string.
    _test_aes_forms(b"asbothbeginningandend", cosmic, "architect_lastwords/beginningandend", aes_results)
    _test_aes_forms(b"beginningandend", cosmic, "architect_lastwords/beginningandend_no_as", aes_results)

    # 8d. Raw AES-256 key using the IV from the known password.
    _raw_key_test(known_dec.key, known_dec.iv, cosmic, "raw_key_known_iv", aes_results)

    report["cosmic_aes_tests"] = aes_results
    report["cosmic_aes_summary"] = {
        "candidates": len(aes_results),
        "valid_padding": sum(1 for r in aes_results if r.get("padding_valid")),
        "legible_printable_90": sum(
            1 for r in aes_results
            if r.get("padding_valid") and r.get("printable", 0) >= 0.9
        ),
        "legible_entropy_4_5": sum(
            1 for r in aes_results
            if r.get("padding_valid") and r.get("entropy", 99) <= 4.5
        ),
        "prize_matches": sum(1 for r in aes_results if r.get("gate")),
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
