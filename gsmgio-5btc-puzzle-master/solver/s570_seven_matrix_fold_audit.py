"""Sealed audit of the S570 seven-9x9-matrix fold construction.

Structure (arithmetic verified against the archived page):

* S570 is the 570-symbol faed run over the page's nine-symbol alphabet a-i.
* S570 = "fae" + 567, and 567 = 7*81 = 7*9*9, so the remainder is exactly
  seven 9x9 matrices.
* Two readings are sealed: SEQUENTIAL blocks of 81, and INTERWOVEN
  (round-robin) blocks, the literal "seven intertwined passwords".
* Summing the seven matrices position-wise gives one 9x9 result.
* Folding that result through its 180-degree rotational opposite ("turning
  inward") leaves 40 mirrored pairs plus the single center cell - the
  Architect's "The One".

Every derived digit/a-i stream is then hashed and gated against both prize
targets (Half exact pubkey + hash160, Better hash160), and every stream and
its hashes are tried as an AES password against the four authenticated
envelopes under a byte-level legibility gate.  Digit streams are also read
with the committed Phase 3.2.2 VIC checkerboard (alphabet
FUBCDORA.LETHINGKYMVPS.JQZXW, row digits 1,4 and 4,1); decoded plaintexts are
sha256-gated as scalars and AES-tested.

The family is sealed here: two block readings x two letter maps x three fold
modes x five output encodings x the fixed VIC parameters.  No result is
accepted on padding, readable fragments, or alphabet-printability alone.
"""

from __future__ import annotations

import hashlib
import json
import math
import re

from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import _vic_decode
from .targets import gate_scalar_bytes
from .unity_of_opposites_audit import _streams_from_html

RESULT_PATH = ROOT / "s570_seven_matrix_fold_audit.json"

VIC_ALPHABET = "FUBCDORA.LETHINGKYMVPS.JQZXW"
ENVELOPES = {}


def _spiral_positions(size: int) -> list[tuple[int, int]]:
    """Counter-clockwise inward spiral from top-left - the poster's own order."""
    top = left = 0
    bottom = right = size - 1
    output: list[tuple[int, int]] = []
    while left <= right and top <= bottom:
        for row in range(top, bottom + 1):
            output.append((row, left))
        left += 1
        for column in range(left, right + 1):
            output.append((bottom, column))
        bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                output.append((row, right))
            right -= 1
        if top <= bottom:
            for column in range(right, left - 1, -1):
                output.append((top, column))
            top += 1
    return output


def _matrices_sequential(body: str) -> list[str]:
    return [body[index * 81 : (index + 1) * 81] for index in range(7)]


def _matrices_intertwined(body: str) -> list[str]:
    """Round-robin weave: symbol k goes to matrix k%7, position k//7."""
    matrices = ["" for _ in range(7)]
    for index, symbol in enumerate(body):
        matrices[index % 7] += symbol
    return matrices


def _sum_matrices(blocks: list[str], mapping: dict[str, int]) -> list[list[int]]:
    sums = [[0 for _ in range(9)] for _ in range(9)]
    for block in blocks:
        for position, symbol in enumerate(block):
            sums[position // 9][position % 9] += mapping[symbol]
    return sums


def _fold180(matrix: list[list[int]], mode: str) -> tuple[list[tuple[int, int]], int]:
    """Return (40 pairs, center) under the 180-degree rotational fold.

    Each orbit {(r,c),(8-r,8-c)} is selected exactly once: rows 0..3 in full,
    plus the four row-4 cells left of the center column.  This covers the 36
    cells above the anti-diagonal and the 4 anti-diagonal pairs, for 40 pairs
    and the single fixed centre (4,4) - "The One".
    """
    pairs: list[tuple[int, int]] = []
    for row in range(9):
        for column in range(9):
            if row < 4 or (row == 4 and column < 4):
                a = matrix[row][column]
                b = matrix[8 - row][8 - column]
                if mode == "sum":
                    pairs.append((a, a + b))
                elif mode == "diff":
                    pairs.append((a, abs(a - b)))
                elif mode == "sum-mod9":
                    pairs.append((a, (a + b) % 9))
                else:  # pragma: no cover
                    raise ValueError(mode)
    if len(pairs) != 40:
        raise ValueError(f"180-degree fold must yield 40 pairs, got {len(pairs)}")
    center = matrix[4][4]
    return pairs, center


def _folded_grid(matrix: list[list[int]], mode: str) -> list[list[int]]:
    grid = [[0 for _ in range(9)] for _ in range(9)]
    for row in range(9):
        for column in range(9):
            a = matrix[row][column]
            b = matrix[8 - row][8 - column]
            if mode == "sum":
                grid[row][column] = a + b
            elif mode == "diff":
                grid[row][column] = abs(a - b)
            else:  # sum-mod9
                grid[row][column] = (a + b) % 9
    return grid


def _encode_pairs(pairs: list[tuple[int, int]], center: int, mode: str) -> str:
    if mode == "sum-mod9":
        return "".join(str(value) for _, value in pairs) + str(center % 9)
    return "".join(f"{value:02d}" for _, value in pairs) + f"{center:02d}"


def _encode_grid(grid: list[list[int]], order: list[tuple[int, int]]) -> str:
    return "".join(f"{grid[row][column]:02d}" for row, column in order)


def _encode_grid_mod9(grid: list[list[int]]) -> str:
    return "".join(
        chr(97 + grid[row][column] % 9) for row in range(9) for column in range(9)
    )


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _gate(value: bytes) -> dict[str, object] | None:
    return gate_scalar_bytes(value)


def _legible_bytes(data: bytes) -> bool:
    if not data:
        return False
    if sum(32 <= b < 127 for b in data) / len(data) < 0.85:
        return False
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )
    if entropy <= 5.9:
        return True
    best = current = 0
    for byte in data:
        if 65 <= byte <= 90:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best >= 6


def run() -> dict[str, object]:
    _, FAED = _streams_from_html()
    if len(FAED) != 570 or FAED[:3] != "fae" or not re.fullmatch(r"[a-i]+", FAED):
        raise ValueError("faed stream changed; construction precondition lost")
    body = FAED[3:]

    inputs = extract_all()
    envelopes = {
        "chain1": inputs.chain1_envelope,
        "chain2": inputs.chain2_envelope,
        "phase32": inputs.phase32_envelope,
        "cosmic": inputs.cosmic_envelope,
    }

    letter_maps = {
        "a1_i9": {chr(97 + value): value + 1 for value in range(9)},
        "a0_i8": {chr(97 + value): value for value in range(9)},
    }
    fold_modes = ("sum", "diff", "sum-mod9")
    spiral_order = _spiral_positions(9)
    row_major_order = [(row, column) for row in range(9) for column in range(9)]

    scalar_attempts = 0
    aes_attempts = 0
    padding_hits = 0
    legible_accepts: list[dict[str, object]] = []
    scalar_hits: list[dict[str, object]] = []
    vic_records: list[dict[str, object]] = []

    construction: dict[str, object] = {}
    for reading_name, blocks_fn in (
        ("sequential", _matrices_sequential),
        ("intertwined", _matrices_intertwined),
    ):
        blocks = blocks_fn(body)
        construction[reading_name] = {"block_lengths": [len(b) for b in blocks]}
        for map_name, mapping in letter_maps.items():
            matrix = _sum_matrices(blocks, mapping)
            for mode in fold_modes:
                pairs, center = _fold180(matrix, mode)
                folded = _folded_grid(matrix, mode)
                label = f"{reading_name}/{map_name}/{mode}"
                encodings: dict[str, str] = {
                    "folded-pairs-digits": _encode_pairs(pairs, center, mode),
                    "grid-row-major-digits": _encode_grid(folded, row_major_order),
                    "grid-spiral-digits": _encode_grid(folded, spiral_order),
                    "grid-row-major-mod9-ai": _encode_grid_mod9(folded),
                    "pre-fold-spiral-digits": _encode_grid(matrix, spiral_order),
                }
                for enc_name, stream in encodings.items():
                    stream_bytes = stream.encode("ascii")
                    for form_name, value in (
                        ("sha256", _sha256(stream_bytes)),
                        ("double-sha256", _sha256(_sha256(stream_bytes))),
                    ):
                        scalar_attempts += 1
                        hit = _gate(value)
                        if hit is not None:
                            scalar_hits.append(
                                {"label": label, "encoding": enc_name, "form": form_name, **hit}
                            )
                    for pw_name, password in (
                        ("raw", stream_bytes),
                        ("sha256-lowerhex", _sha256(stream_bytes).hex().encode("ascii")),
                        ("sha256-digest", _sha256(stream_bytes)),
                    ):
                        for kdf in ("md5", "sha256"):
                            for blob_name, envelope in envelopes.items():
                                aes_attempts += 1
                                try:
                                    plaintext = decrypt_salted_aes256_cbc(
                                        envelope, password, digest=kdf
                                    ).plaintext
                                except ValueError:
                                    continue
                                padding_hits += 1
                                if _legible_bytes(plaintext):
                                    legible_accepts.append({
                                        "label": label,
                                        "encoding": enc_name,
                                        "password_form": pw_name,
                                        "kdf": kdf,
                                        "blob": blob_name,
                                        "plaintext_sha256": _sha256(plaintext).hex(),
                                        "printable_ratio": round(
                                            sum(32 <= b < 127 for b in plaintext)
                                            / len(plaintext),
                                            4,
                                        ),
                                    })
                # VIC read of the digit encodings with the committed alphabet.
                for enc_name in ("folded-pairs-digits", "grid-row-major-digits", "grid-spiral-digits"):
                    digits = encodings[enc_name]
                    for row_digits in (("1", "4"), ("4", "1")):
                        try:
                            decoded = _vic_decode(digits, VIC_ALPHABET, row_digits)
                        except ValueError:
                            continue
                        record: dict[str, object] = {
                            "label": label,
                            "encoding": enc_name,
                            "row_digits": list(row_digits),
                            "plaintext_sha256": _sha256(decoded.encode("ascii")).hex(),
                            "plaintext_length": len(decoded),
                        }
                        decoded_bytes = decoded.encode("ascii")
                        for form_name, value in (
                            ("sha256", _sha256(decoded_bytes)),
                            ("double-sha256", _sha256(_sha256(decoded_bytes))),
                        ):
                            scalar_attempts += 1
                            hit = _gate(value)
                            if hit is not None:
                                scalar_hits.append(
                                    {"label": label, "encoding": enc_name + "/vic", "form": form_name, **hit}
                                )
                                record["scalar_match"] = True
                        for pw_name, password in (
                            ("raw", decoded_bytes),
                            ("sha256-lowerhex", _sha256(decoded_bytes).hex().encode("ascii")),
                            ("sha256-digest", _sha256(decoded_bytes)),
                        ):
                            for kdf in ("md5", "sha256"):
                                for blob_name, envelope in envelopes.items():
                                    aes_attempts += 1
                                    try:
                                        plaintext = decrypt_salted_aes256_cbc(
                                            envelope, password, digest=kdf
                                        ).plaintext
                                    except ValueError:
                                        continue
                                    padding_hits += 1
                                    if _legible_bytes(plaintext):
                                        legible_accepts.append({
                                            "label": label,
                                            "encoding": enc_name + "/vic",
                                            "password_form": pw_name,
                                            "kdf": kdf,
                                            "blob": blob_name,
                                            "plaintext_sha256": _sha256(plaintext).hex(),
                                            "printable_ratio": round(
                                                sum(32 <= b < 127 for b in plaintext)
                                                / len(plaintext),
                                                4,
                                            ),
                                        })
                        vic_records.append(record)

    result = {
        "schema": "s570-seven-9x9-matrix-fold-audit-v1",
        "status": (
            "MATCH"
            if (scalar_hits or legible_accepts)
            else "COMPLETE_NO_ACCEPT"
        ),
        "construction": {
            "faed_length": len(FAED),
            "prefix": FAED[:3],
            "remainder_length": len(body),
            "decomposition": "3 + 7*9*9",
            "fold": "180-degree rotational opposite; 40 pairs + 1 center ('The One')",
            "verified_pair_count": 40,
            "verified_center_cell": (4, 4),
            "readings": construction,
        },
        "sealed_family": {
            "block_readings": ["sequential", "intertwined(round-robin)"],
            "letter_maps": list(letter_maps),
            "fold_modes": list(fold_modes),
            "output_encodings": [
                "folded-pairs-digits",
                "grid-row-major-digits",
                "grid-spiral-digits",
                "grid-row-major-mod9-ai",
                "pre-fold-spiral-digits",
            ],
            "vic_alphabet": VIC_ALPHABET,
            "vic_row_digits": [["1", "4"], ["4", "1"]],
            "aes_password_forms": ["raw", "sha256-lowerhex", "sha256-digest"],
            "aes_kdfs": ["md5", "sha256"],
        },
        "counts": {
            "scalar_attempts": scalar_attempts,
            "scalar_hits": scalar_hits,
            "aes_attempts": aes_attempts,
            "strict_padding_hits": padding_hits,
            "legible_accepts": legible_accepts,
            "vic_decodes": len(vic_records),
        },
        "scope_note": (
            "Bounded to the sealed family above. Does not vary the fold axis, "
            "the pair ordering, the digit width, the spiral starting corner, "
            "non-180 rotations, transpositions, or unauthenticated alphabets. "
            "The intertwined reading is the literal 'seven intertwined' "
            "weave; sequential is the control."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
