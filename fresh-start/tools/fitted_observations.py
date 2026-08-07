#!/usr/bin/env python3
"""Recompute the arithmetic coincidences that are often quoted, and show what each assumes.

Nothing in this file is authenticated. Each result is exact arithmetic, but each
also depends on a convention nobody has shown the creator chose. The point of
recomputing them here is that you can see both the number *and* the assumption,
instead of inheriting the number with the assumption stripped off.

Requires `derived/architect_plaintext.txt` (run `phase32_classical.py` first).
"""

from __future__ import annotations

from _paths import DERIVED, IMAGES
from poster_spiral import BLUE, MARKERS, SIZE, YELLOW, read_grid, spiral


def first_primes(count: int) -> list[int]:
    primes, n = [], 2
    while len(primes) < count:
        if all(n % p for p in primes):
            primes.append(n)
        n += 1
    return primes


def main() -> None:
    grid = read_grid(IMAGES / "poster" / "follow_the_white_rabbit.png")
    colours = [grid[r][c] for r, c in spiral(SIZE)]
    markers = [c for c in colours if c in MARKERS]
    primes = first_primes(len(markers))

    blue = sum(p for p, c in zip(primes, markers) if c == BLUE)
    yellow = sum(p for p, c in zip(primes, markers) if c == YELLOW)

    print("poster marker prime sums")
    print(f"  {len(markers)} markers, first {len(primes)} primes in spiral order")
    print(f"  blue   {blue}")
    print(f"  yellow {yellow}")
    print(f"  blue − 5 = {blue - 5}, which equals yellow: {blue - 5 == yellow}")
    print("  ASSUMES: consecutive primes from 2, assigned in spiral order, and that")
    print("           'zeroing out' means dropping one blue prime rather than something else.")

    path = DERIVED / "architect_plaintext.txt"
    if not path.exists():
        print("\n(run phase32_classical.py to enable the offset check)")
        return

    architect = path.read_text().strip()
    print(f"\nArchitect plaintext at offset {yellow}")
    print(f"  0-based [{yellow}:{yellow + 32}]  {architect[yellow:yellow + 32]}")
    print(f"  1-based [{yellow - 1}:{yellow + 31}]  {architect[yellow - 1:yellow + 31]}")
    print("  ASSUMES: 0-based indexing, and that a milestone computed from the poster")
    print("           indexes this particular text at all.")
    print("\nThis is a landing spot, not a key derivation: nothing above produces a scalar.")


if __name__ == "__main__":
    main()
