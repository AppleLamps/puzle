#!/usr/bin/env python3
"""Read the poster PNG as a 14x14 colour grid and decode the spiral.

The poster is 350x350: a 14x14 grid of 25px cells in five colours. A white
rabbit is drawn across several cells, so each cell is sampled by majority
colour rather than by one pixel.

Reading the grid as a counter-clockwise inward spiral from the top-left gives
196 bits: black and blue are 1, white and yellow are 0. The first 192 bits are
24 ASCII bytes; the remaining 4 are zero.

The 24 blue/yellow cells are not extra payload — they land on the last bit of
every byte, so they delimit bytes and restate that bit (blue = 1, yellow = 0).
The script prints both checks rather than asserting them, so you can see the
structure hold rather than take it on trust.

The output URL is the acceptance test: an arbitrary read order does not produce
readable ASCII.
"""

from __future__ import annotations

from collections import Counter

from _paths import IMAGES
from png import read_rgb

CELL = 25
SIZE = 14

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)

ONE_BITS = {BLACK, BLUE}
MARKERS = {BLUE, YELLOW}


def read_grid(path):
    _, _, rows = read_rgb(path)
    grid = []
    for row in range(SIZE):
        cells = []
        for col in range(SIZE):
            counts = Counter(
                rows[y][x]
                for y in range(row * CELL, (row + 1) * CELL)
                for x in range(col * CELL, (col + 1) * CELL)
            )
            cells.append(counts.most_common(1)[0][0])
        grid.append(cells)
    return grid


def spiral(size):
    """Counter-clockwise inward spiral: down the left column, along the bottom,
    up the right column, back along the top, then inward."""
    order = []
    top, bottom, left, right = 0, size - 1, 0, size - 1
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


def main() -> None:
    grid = read_grid(IMAGES / "poster" / "follow_the_white_rabbit.png")
    colours = [grid[r][c] for r, c in spiral(SIZE)]
    bits = "".join("1" if colour in ONE_BITS else "0" for colour in colours)

    body, padding = bits[:192], bits[192:]
    message = "".join(chr(int(body[i:i + 8], 2)) for i in range(0, 192, 8))

    print(f"distinct cell colours: {sorted(set(colours))}")
    print(f"message: {message}")
    print(f"residual bits: {padding}")

    marks = [(i, colour) for i, colour in enumerate(colours) if colour in MARKERS]
    indices = [i for i, _ in marks]
    print(f"markers: {len(marks)}")
    print(f"markers land on every 8th bit: {indices == list(range(7, 192, 8))}")
    print("marker colour restates that bit: "
          f"{all((colour == BLUE) == (bits[i] == '1') for i, colour in marks)}")

    packed = "".join("1" if colour == BLUE else "0" for _, colour in marks)
    print(f"marker bits packed: {packed} = {int(packed, 2):06X}")


if __name__ == "__main__":
    main()
