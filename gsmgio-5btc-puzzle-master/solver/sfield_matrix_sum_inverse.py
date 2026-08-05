"""Invert the S fields as literal lists of 3x3 binary-matrix sums.

The candidate family is fixed independently of decoded output.  Each symbol
``a..i`` means the integer 1..9.  For every clue-supported rectangular layout,
the field is treated as the row-major list of sums of all valid 3x3 windows of
an unknown binary matrix two rows and two columns larger.  SAT and uniqueness
are checked before any byte rendering.  Only fixed row/column and the original
upper-left counterclockwise spiral routes are rendered.
"""

from __future__ import annotations

import hashlib
import json

import z3

from .extract import ROOT
from .salphaseion_raw import extract_raw, sha256_hex


RESULT_PATH = ROOT / "sfield_matrix_sum_inverse.json"


def _spiral_ccw_upper_left(grid: list[list[int]]) -> list[int]:
    # The first-puzzle route: start upper-left, initially travel down.
    rows, columns = len(grid), len(grid[0])
    top, bottom, left, right = 0, rows - 1, 0, columns - 1
    output: list[int] = []
    while top <= bottom and left <= right:
        for row in range(top, bottom + 1):
            output.append(grid[row][left])
        left += 1
        if left > right:
            break
        for column in range(left, right + 1):
            output.append(grid[bottom][column])
        bottom -= 1
        if top > bottom:
            break
        for row in range(bottom, top - 1, -1):
            output.append(grid[row][right])
        right -= 1
        if left > right:
            break
        for column in range(right, left - 1, -1):
            output.append(grid[top][column])
        top += 1
    return output


def _render_routes(grid: list[list[int]]) -> dict[str, list[int]]:
    rows, columns = len(grid), len(grid[0])
    row_major = [value for row in grid for value in row]
    column_major = [grid[row][column] for column in range(columns) for row in range(rows)]
    spiral = _spiral_ccw_upper_left(grid)
    return {
        "row-major": row_major,
        "row-major-reverse": row_major[::-1],
        "column-major": column_major,
        "column-major-reverse": column_major[::-1],
        "ccw-spiral-upper-left": spiral,
        "ccw-spiral-upper-left-reverse": spiral[::-1],
    }


def _bits_to_bytes(bits: list[int], lsb_first: bool) -> bytes | None:
    if len(bits) % 8:
        return None
    output = bytearray()
    for offset in range(0, len(bits), 8):
        group = bits[offset:offset + 8]
        if lsb_first:
            group = group[::-1]
        value = 0
        for bit in group:
            value = value * 2 + bit
        output.append(value)
    return bytes(output)


def _solve(text: str, output_rows: int, output_columns: int) -> dict[str, object]:
    if output_rows * output_columns != len(text):
        raise ValueError("layout does not match field length")
    target = [ord(character) - 96 for character in text]
    rows, columns = output_rows + 2, output_columns + 2
    bits = [[z3.Int(f"b_{row}_{column}") for column in range(columns)] for row in range(rows)]
    solver = z3.Solver()
    for row in bits:
        for bit in row:
            solver.add(bit >= 0, bit <= 1)
    for row in range(output_rows):
        for column in range(output_columns):
            solver.add(
                z3.Sum(bits[r][c] for r in range(row, row + 3) for c in range(column, column + 3))
                == target[row * output_columns + column]
            )

    status = solver.check()
    record: dict[str, object] = {
        "output_layout": [output_rows, output_columns],
        "binary_layout": [rows, columns],
        "binary_bit_count": rows * columns,
        "sat": status == z3.sat,
    }
    if status != z3.sat:
        return record

    model = solver.model()
    solution = [[model.evaluate(bit).as_long() for bit in row] for row in bits]
    solver.push()
    solver.add(z3.Or(
        bit != solution[row][column]
        for row, values in enumerate(bits)
        for column, bit in enumerate(values)
    ))
    record["unique"] = solver.check() == z3.unsat
    solver.pop()
    record["solution_row_major_sha256"] = sha256_hex(
        "".join(str(value) for row in solution for value in row).encode("ascii")
    )

    renderings: list[dict[str, object]] = []
    if record["unique"]:
        for route, routed in _render_routes(solution).items():
            for bit_order in ("msb", "lsb"):
                decoded = _bits_to_bytes(routed, bit_order == "lsb")
                if decoded is None:
                    continue
                printable = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in decoded)
                ratio = printable / len(decoded) if decoded else 0.0
                try:
                    text_value = decoded.decode("utf-8")
                except UnicodeDecodeError:
                    text_value = None
                renderings.append({
                    "route": route,
                    "bit_order": bit_order,
                    "length": len(decoded),
                    "sha256": hashlib.sha256(decoded).hexdigest(),
                    "printable_ratio": ratio,
                    "utf8": text_value,
                    "accepted_readable": text_value is not None and ratio >= 0.85,
                })
    record["renderings"] = renderings
    return record


def run() -> dict[str, object]:
    raw = extract_raw()
    specs = {
        "S91": (raw.s91, [(7, 13), (13, 7)]),
        "S570": (raw.s570, [(15, 38), (38, 15), (19, 30), (30, 19)]),
    }
    records: list[dict[str, object]] = []
    for field, (text, layouts) in specs.items():
        for output_rows, output_columns in layouts:
            record = _solve(text, output_rows, output_columns)
            record["field"] = field
            records.append(record)
    accepted = [
        {"field": record["field"], "layout": record["output_layout"], **rendering}
        for record in records
        for rendering in record.get("renderings", [])
        if rendering["accepted_readable"]
    ]
    result: dict[str, object] = {
        "status": "READABLE_UNIQUE_INVERSE" if accepted else "NO_READABLE_UNIQUE_INVERSE",
        "source": {
            "s91_sha256": sha256_hex(raw.s91.encode("ascii")),
            "s570_sha256": sha256_hex(raw.s570.encode("ascii")),
            "symbol_mapping": "a=1 through i=9",
        },
        "model": "each field value is the inclusive sum of one valid 3x3 window in a binary matrix",
        "layouts_preregistered": {
            "S91": [[7, 13], [13, 7]],
            "S570": [[15, 38], [38, 15], [19, 30], [30, 19]],
        },
        "records": records,
        "accepted": accepted,
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
