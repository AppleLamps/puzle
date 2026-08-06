"""Bounded creator-pipeline composition: poster matrixsumlist → Architect[479].

Tests the family sealed in ``creator_pipeline_poster_architect_preregistered.json``.
Excludes Cosmic, Chain 4, and community-only operands.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from PIL import Image

from .extract import ROOT
from .targets import gate_scalar_bytes, self_check


PRE = ROOT / "creator_pipeline_poster_architect_preregistered.json"
RESULT = ROOT / "creator_pipeline_poster_architect_audit.json"
RECOVERY = ROOT / "phase32_symbol_recovery.json"
POSTER = ROOT.parent / "sources" / "follow_the_white_rabbit.png"

CELL = 25
SIZE = 14
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)
OFF_WHITE = (254, 254, 254)
RESISTOR = {BLACK: 0, YELLOW: 4, BLUE: 6, WHITE: 9, OFF_WHITE: 9}

HOPE_QUOTE = (
    "THEFUTUREISFLUIDEACHACTEACHDECISIONANDEACHDEVELOPMENTCREATES"
    "NEWPOSSIBILITIESANDELIMINATESOTHERSTHEFUTUREISOURSTODIRECT"
)
AUTHENTICATED_PLAINTEXT_SHA256 = (
    "56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241"
)
YINYANG_OFFSET = 479


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


def _side_sums(
    grid: list[list[tuple[int, int, int]]],
    *,
    axis: str,
    side: str,
    zero_eye: bool,
) -> list[int]:
    if axis == "row":
        selected = [
            row
            for row in grid
            if Counter(cell for cell in row).most_common(1)[0][0]
            == (YELLOW if side == "yellow" else BLUE)
        ]
        return [sum(_resistor_value(cell, zero_eye=zero_eye) for cell in row) for row in selected]
    selected_cols = [
        col
        for col in range(SIZE)
        if Counter(grid[row][col] for row in range(SIZE)).most_common(1)[0][0]
        == (YELLOW if side == "yellow" else BLUE)
    ]
    return [
        sum(_resistor_value(grid[row][col], zero_eye=zero_eye) for row in range(SIZE))
        for col in selected_cols
    ]


def _extract(text: str, sums: list[int], mode: str) -> str:
    length = len(text)
    chars: list[str] = []
    cumulative = YINYANG_OFFSET
    for value in sums:
        if mode == "absolute_0based":
            index = value % length
        elif mode == "from_479_0based":
            index = (YINYANG_OFFSET + value) % length
        elif mode == "from_479_1based":
            index = (YINYANG_OFFSET + value - 1) % length
        elif mode == "cumulative_from_479_0based":
            cumulative = (cumulative + value) % length
            index = cumulative
        else:
            raise ValueError(mode)
        chars.append(text[index])
    return "".join(chars)


def _beaufort(text: str, key: str) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    output: list[str] = []
    key_index = 0
    for char in text:
        upper = char.upper()
        if upper not in alphabet:
            output.append(char)
            continue
        k = alphabet.index(key[key_index % len(key)])
        c = alphabet.index(upper)
        output.append(alphabet[(k - c) % 26])
        key_index += 1
    return "".join(output)


def _scalar_forms(label: str, extracted: str) -> list[tuple[str, bytes]]:
    forms: list[tuple[str, bytes]] = []
    upper = extracted.encode("ascii")
    lower = extracted.lower().encode("ascii")
    forms.append((f"{label}/sha256_ascii", hashlib.sha256(upper).digest()))
    forms.append((f"{label}/sha256_lower", hashlib.sha256(lower).digest()))
    forms.append((f"{label}/double_sha256", hashlib.sha256(hashlib.sha256(upper).digest()).digest()))
    if len(upper) >= 32:
        forms.append((f"{label}/direct_first_32", upper[:32]))
    values = [ord(char) - ord("A") + 1 for char in extracted if char.isalpha()]
    if values:
        packed = "".join(f"{value:02d}" for value in values).encode("ascii")
        forms.append((f"{label}/a1z26_concat_sha256", hashlib.sha256(packed).digest()))
    return forms


def run() -> dict[str, object]:
    pre = json.loads(PRE.read_text(encoding="utf-8"))
    if pre["status"] != "SEALED_BEFORE_SCALAR_EVALUATION":
        raise ValueError("unexpected preregistration status")

    target_check = self_check()
    recovery = json.loads(RECOVERY.read_text(encoding="utf-8"))
    plaintext = recovery["plaintext"]
    if hashlib.sha256(plaintext.encode("ascii")).hexdigest() != AUTHENTICATED_PLAINTEXT_SHA256:
        raise ValueError("authenticated architect plaintext changed")

    grid = _poster_grid()
    sum_lists = {
        "poster_resistor_row_sums": _row_sums(grid, zero_eye=False),
        "poster_resistor_col_sums": _col_sums(grid, zero_eye=False),
        "poster_resistor_row_sums_eye_zeroed": _row_sums(grid, zero_eye=True),
        "poster_resistor_col_sums_eye_zeroed": _col_sums(grid, zero_eye=True),
        "poster_yellow_rows_resistor": _side_sums(grid, axis="row", side="yellow", zero_eye=False),
        "poster_blue_rows_resistor": _side_sums(grid, axis="row", side="blue", zero_eye=False),
        "poster_yellow_cols_resistor": _side_sums(grid, axis="col", side="yellow", zero_eye=False),
        "poster_blue_cols_resistor": _side_sums(grid, axis="col", side="blue", zero_eye=False),
    }

    scalar_tests = 0
    matches: list[dict[str, object]] = []
    seen: set[bytes] = set()
    families: list[dict[str, object]] = []

    for list_name, values in sum_lists.items():
        family_count = 0
        for index_mode in pre["index_bases"]:
            extracted = _extract(plaintext, values, index_mode)
            for overlay in pre["lastwords_overlay"]:
                if overlay == "hope_quote_first_letters_xor":
                    hope = HOPE_QUOTE[: len(extracted)]
                    mixed = "".join(
                        chr(ord(a) ^ ord(b))
                        for a, b in zip(extracted.upper(), hope)
                        if a.isalpha() and b.isalpha()
                    )
                    candidate_text = mixed
                elif overlay == "beaufort_hope_on_extracted":
                    candidate_text = _beaufort(extracted, "HOPE")
                else:
                    candidate_text = extracted

                label = f"{list_name}/{index_mode}/{overlay}"
                for form_name, scalar_bytes in _scalar_forms(label, candidate_text):
                    if scalar_bytes in seen:
                        continue
                    seen.add(scalar_bytes)
                    scalar_tests += 1
                    family_count += 1
                    hit = gate_scalar_bytes(scalar_bytes)
                    if hit:
                        matches.append(
                            {
                                "form": form_name,
                                "extracted_preview": candidate_text[:64],
                                "gate": hit,
                            }
                        )

        families.append({"family": list_name, "scalar_tests": family_count, "result": "NO_MATCH"})

    # Yin-yang balance: |yellow - blue| lists, elementwise min/max, concatenation
    for axis in ("row", "col"):
        yellow = _side_sums(grid, axis=axis, side="yellow", zero_eye=False)
        blue = _side_sums(grid, axis=axis, side="blue", zero_eye=False)
        width = min(len(yellow), len(blue))
        balanced = [abs(yellow[index] - blue[index]) for index in range(width)]
        for list_name, values in (
            (f"poster_yinyang_absdiff_{axis}", balanced),
            (f"poster_yinyang_min_{axis}", [min(yellow[i], blue[i]) for i in range(width)]),
            (f"poster_yinyang_max_{axis}", [max(yellow[i], blue[i]) for i in range(width)]),
        ):
            family_count = 0
            for index_mode in pre["index_bases"]:
                extracted = _extract(plaintext, values, index_mode)
                for form_name, scalar_bytes in _scalar_forms(
                    f"{list_name}/{index_mode}/none", extracted
                ):
                    if scalar_bytes in seen:
                        continue
                    seen.add(scalar_bytes)
                    scalar_tests += 1
                    family_count += 1
                    hit = gate_scalar_bytes(scalar_bytes)
                    if hit:
                        matches.append({"form": form_name, "gate": hit})
            families.append({"family": list_name, "scalar_tests": family_count, "result": "NO_MATCH"})

    control = gate_scalar_bytes(
        hashlib.sha256(b"creator_pipeline_poster_architect_positive_control").digest()
    )
    output = {
        "schema": pre["schema"],
        "scope_note": (
            "Poster 14x14 resistor matrixsumlist used as Architect plaintext index "
            "lists from yinyang offset 479; excludes Cosmic/Chain4/base38."
        ),
        "sum_lists": sum_lists,
        "yinyang_offset": YINYANG_OFFSET,
        "families": families,
        "unique_scalars_tested": len(seen),
        "scalar_tests": scalar_tests,
        "matches": matches,
        "positive_control_accepted": control is None,
        "target_self_check": target_check,
        "overall_result": "MATCH" if matches else "NO_MATCH",
    }
    RESULT.write_text(json.dumps(output, indent=2), encoding="utf-8")
    return output


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
