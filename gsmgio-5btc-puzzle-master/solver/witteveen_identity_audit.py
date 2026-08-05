"""Reproduce the structural SalPhaseIon route ending in H.J. Witteveen.

This audit deliberately performs no AES decryption, plaintext scoring, password
enumeration, or private-key search.  It starts with the archived S91/S570 fields
and checks each exact structural control on the route to the identity.
"""

from __future__ import annotations

from math import isqrt

from .salphaseion_raw import extract_raw


GENESIS_COLORS_24 = "BBBBYBBBYYBBBBYBBYYBYYBY"


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    return all(value % divisor for divisor in range(2, isqrt(value) + 1))


def a1(value: int) -> str:
    return chr(ord("A") + (value - 1) % 26)


def a0(value: int) -> str:
    return chr(ord("A") + value % 26)


def colors_to_bits(colors: str) -> str:
    return "".join("1" if color == "B" else "0" for color in colors)


def unique_color_parse(s91: str) -> str:
    """Parse 1..83: ordinary cells consume one symbol; primes consume b/be."""

    solutions: list[str] = []

    def visit(number: int, cursor: int, colors: str) -> None:
        if len(solutions) > 1:
            return
        if number == 84:
            if cursor == len(s91):
                solutions.append(colors)
            return
        if not is_prime(number):
            if cursor < len(s91):
                visit(number + 1, cursor + 1, colors)
            return
        if s91.startswith("b", cursor):
            visit(number + 1, cursor + 1, colors + "B")
        if s91.startswith("be", cursor):
            visit(number + 1, cursor + 2, colors + "Y")

    visit(1, 0, "")
    if len(solutions) != 1:
        raise AssertionError(f"expected one S91 color parse, found {len(solutions)}")
    return solutions[0]


def t23_components(middle: list[int], colors: str) -> tuple[str, list[list[int]]]:
    columns = [[0, 0] for _ in range(23)]
    prime_rank = 0
    cell = 1
    for row in range(1, 24):
        for column in range(row):
            if is_prime(cell):
                value = middle[cell - 1] + 1
                color = colors[prime_rank % len(colors)]
                columns[column][color == "Y"] += value
                prime_rank += 1
            cell += 1
    rendered = "".join("_" if sum(pair) == 0 else a1(sum(pair)) for pair in reversed(columns))
    return rendered, columns


def derive() -> dict[str, object]:
    raw = extract_raw()
    colors = unique_color_parse(raw.s91)
    assert colors == "BBBBYBBBYYBBBBYBBYYBBYY"

    # The 23-color stream is independently fixed by the authenticated
    # first-grid stream.  Blue=1/yellow=0 gives F73D92.  Taking its integer
    # half and applying the creator's later <3 / "better half" increment gives
    # 7B9ECC, whose significant binary digits are exactly the S91 parse.
    genesis_value = int(colors_to_bits(GENESIS_COLORS_24), 2)
    half_value = genesis_value // 2
    better_half_value = half_value + 3
    better_half_bits = format(better_half_value, "b")
    assert genesis_value == 0xF73D92
    assert half_value == 0x7B9EC9
    assert better_half_value == 0x7B9ECC
    assert better_half_bits == colors_to_bits(colors)

    prime_color_sums = {
        color: sum(number for number, parsed in zip(
            (number for number in range(1, 84) if is_prime(number)), colors
        ) if parsed == color)
        for color in "BY"
    }
    assert prime_color_sums == {"B": 474, "Y": 400}

    values = [ord(symbol) - ord("a") for symbol in raw.s570]
    for index in prime_color_sums.values():
        values[index] = 0
    left, right = values[:285], list(reversed(values[285:]))
    combined = [a + b for a, b in zip(left, right)]
    header = "".join(a0(value) for value in combined[:7])
    trailer = "".join(a0(value) for value in combined[-2:])
    assert header == "HILLONE"
    assert trailer == "KG"

    middle = combined[7:-2]
    assert len(middle) == 276
    t23, components = t23_components(middle, colors)
    assert t23 == "___OHICGFASKHSKEYTFMDJK"

    compact = t23.replace("_", "")
    scaled = "".join(chr(ord("A") + 3 * (ord(char) - ord("A")) % 26) for char in compact)
    assert scaled == "QVYGSPACEVCEMUFPKJBE"
    t5_text = scaled.replace("SPACE", "", 1)
    assert t5_text == "QVYGVCEMUFPKJBE"

    rows: list[str] = []
    cursor = 0
    for width in range(1, 6):
        rows.append(t5_text[cursor:cursor + width])
        cursor += width
    row_sums = [sum(ord(char) - ord("A") for char in row) for row in rows]
    row_letters = "".join(a1(value) for value in row_sums)
    comps = row_letters[-3:] + row_letters[:-3]
    assert row_sums == [16, 45, 29, 41, 39]
    assert row_letters == "PSCOM"
    assert comps == "COMPS"

    retained_columns = list(range(19, 15, -1)) + list(range(10, -1, -1))
    composite_ids = [4, 6, 8, 9, 10, 12, 14, 15]
    selected_columns = [retained_columns[index - 1] for index in composite_ids]
    assert selected_columns == [16, 9, 7, 6, 5, 3, 1, 0]
    selected_pairs = [components[column] for column in selected_columns]
    assert selected_pairs == [[3, 0], [22, 23], [23, 8], [37, 14], [10, 10], [29, 10], [40, 22], [52, 37]]

    # Components were rendered as A1 letters; diagonal arithmetic then uses
    # their displayed letters as A0 values.  Preserve the genuine zero slot.
    matrix = [0 if value == 0 else (value - 1) % 26 for pair in selected_pairs for value in pair]
    grid = [matrix[index:index + 4] for index in range(0, 16, 4)]
    diagonals: list[list[int]] = []
    for start_column in range(3, -1, -1):
        diagonal = []
        row, column = 0, start_column
        while row < 4 and column < 4:
            diagonal.append(grid[row][column])
            row += 1
            column += 1
        diagonals.append(diagonal)
    for start_row in range(1, 4):
        diagonal = []
        row, column = start_row, 0
        while row < 4 and column < 4:
            diagonal.append(grid[row][column])
            row += 1
            column += 1
        diagonals.append(diagonal)
    diagonal_sums = [sum(diagonal) for diagonal in diagonals]
    witveen = "".join(a0(value) for value in diagonal_sums)
    assert diagonal_sums == [22, 34, 19, 21, 56, 30, 13], diagonal_sums
    assert witveen == "WITVEEN"

    theory_of_everything = "TOE"
    zeroed = theory_of_everything.replace("O", "")
    surname = witveen[:3] + zeroed + witveen[3:]
    assert zeroed == "TE"
    assert surname == "WITTEVEEN"

    return {
        "authenticated_genesis_colors": GENESIS_COLORS_24,
        "authenticated_genesis_hex": f"{genesis_value:06X}",
        "half_hex": f"{half_value:06X}",
        "better_half_plus_three_hex": f"{better_half_value:06X}",
        "better_half_significant_bits": better_half_bits,
        "unique_s91_color_parse": colors,
        "prime_color_sums": prime_color_sums,
        "s570_controls": [header, t23, trailer],
        "scaled_control": scaled,
        "t5_control": comps,
        "component_pairs": selected_pairs,
        "seven_diagonal_sums": diagonal_sums,
        "structural_name": witveen,
        "zeroed_theory_of_everything": zeroed,
        "completed_surname": surname,
        "identity_hypothesis": "H.J. WITTEVEEN",
        "scope": "structural identity audit only; no AES/plaintext/private-key search",
    }


if __name__ == "__main__":
    import json

    print(json.dumps(derive(), indent=2))
