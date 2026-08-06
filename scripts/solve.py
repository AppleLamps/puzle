#!/usr/bin/env python3
"""Decode the hidden message in follow_the_white_rabbit.png.

The 350x350 image is a 14x14 grid of 25px cells drawn in five colours:
black, white, blue, yellow, and a single off-white cell. Reading the grid
as a counter-clockwise inward spiral yields 196 bits; the first 192 are
24 ASCII bytes and the last 4 are zero padding.

Black and blue are 1 bits, white and yellow are 0 bits. The blue/yellow
cells are not extra data: they sit on the final bit of every byte, so
they double as byte delimiters that also restate each byte's last bit
(blue = 1, yellow = 0).
"""

from collections import Counter

from PIL import Image

from _paths import SOURCES

CELL = 25
SIZE = 14

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)
OFF_WHITE = (254, 254, 254)

ONE_BITS = {BLACK, BLUE}
MARKERS = {BLUE, YELLOW}


def read_grid(path):
    """Return the 14x14 grid of cell colours.

    The rabbit is drawn across seven cells, so take each cell's dominant
    colour rather than a single sample pixel.
    """
    pixels = Image.open(path).convert("RGB").load()
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


def spiral(size):
    """Counter-clockwise inward spiral from the top-left corner.

    Down the left column, right along the bottom row, up the right
    column, left along the top row, then inward.
    """
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


def main():
    grid = read_grid(SOURCES / "follow_the_white_rabbit.png")
    order = spiral(SIZE)
    colours = [grid[row][col] for row, col in order]
    bits = "".join("1" if colour in ONE_BITS else "0" for colour in colours)

    body, padding = bits[:192], bits[192:]
    message = "".join(chr(int(body[i : i + 8], 2)) for i in range(0, 192, 8))

    print(f"message: {message}")
    print(f"padding: {padding}")

    marks = [(i, colour) for i, colour in enumerate(colours) if colour in MARKERS]
    print(f"markers: {len(marks)} at spiral indices {[i for i, _ in marks]}")
    print(f"markers land on every 8th bit: {[i for i, _ in marks] == list(range(7, 192, 8))}")
    print(
        "marker colour restates that bit: "
        f"{all((colour == BLUE) == (bits[i] == '1') for i, colour in marks)}"
    )

    hidden = [order[i] for i, colour in enumerate(colours) if colour == OFF_WHITE]
    print(f"off-white cell (row, col): {hidden}")


if __name__ == "__main__":
    main()
