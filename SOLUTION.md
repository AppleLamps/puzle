# Solution: `follow_the_white_rabbit.png`

**Answer: `gsmg.io/theseedisplanted`**

Run `python3 solve.py` to reproduce it from the image.

## What the files are

`GSMG _ GSMG.html` is an archived copy of `gsmg.io/Puzzle`. Stripped of the
Internet Archive wrapper it contains nothing but a title, `GSMG MEGANIGMA || 5 BTC`,
and one image tagged `alt="Follow the white rabbit"`. The saved-page asset folder it
references was never captured, so the entire puzzle is the PNG.

The PNG has no metadata, no trailing bytes after `IEND`, and a fully opaque alpha
channel. Everything is in the visible pixels.

## Reading the image

The file is 350x350 but every 5x5 block is a solid colour, so the real bitmap is
70x70 upscaled 5x. The only sub-cell detail at that resolution is the small rabbit
drawing near the centre — decoration, not data.

Above that, the image is a **14x14 grid of 25px cells** in exactly five colours:

| colour | RGB | cells |
| --- | --- | --- |
| black | `0,0,0` | 86 |
| white | `255,255,255` | 85 |
| blue | `63,72,204` | 15 |
| yellow | `255,242,0` | 9 |
| off-white | `254,254,254` | 1 |

14 x 14 = 196 cells. Black and white split evenly at 86 each, which points at a
binary payload; 196 bits is 24 bytes plus 4 bits.

## The clue in the coloured cells

The 24 blue and yellow cells are not scattered at random. Every one of them sits on
a cell where `col - row ≡ 1 (mod 4)` — seven diagonal lines holding 49 cells in
total. Landing 24-for-24 inside a quarter of the grid by chance is a `(1/4)^24`
event, so the placement is deliberate.

That congruence is the fingerprint of *marking every 8th cell along a path that runs
in straight rows and columns*: an 8-step move along a run changes `col - row` by
±8, which is 0 mod 4, so the whole marked set stays on one residue class. The
marks are byte delimiters, and the path is a spiral.

## The decoding

Walk the grid as a **counter-clockwise inward spiral starting at the top-left**:
down the left column, right along the bottom row, up the right column, left along
the top row, then inward. Map **black and blue to `1`**, **white and yellow to `0`**.

The 196 bits split into 24 bytes with 4 bits left over:

```
01100111 01110011 01101101 01100111 00101110 01101001 01101111 00101111
01110100 01101000 01100101 01110011 01100101 01100101 01100100 01101001
01110011 01110000 01101100 01100001 01101110 01110100 01100101 01100100
0000
```

That is `gsmg.io/theseedisplanted`, and the leftover 4 bits are `0000` padding.

## Why the answer is certainly right

The coloured cells confirm the reading rather than contributing to it:

- Their spiral indices are exactly `7, 15, 23, ..., 191` — the **last bit of each of
  the 24 bytes**, one per byte, in order. This fixes the spiral, its start corner,
  its direction, and the 8-bit grouping.
- Each marker's colour restates the bit it covers: **blue = 1, yellow = 0**. All 24
  agree.
- The 15 blue / 9 yellow counts match the message independently: of the 24
  characters in `gsmg.io/theseedisplanted`, exactly 15 have odd character codes
  (`gsmgio/eseeisae`) and 9 have even ones (`.thdplntd`).

Four independent facts (clean ASCII, a valid URL on the puzzle's own domain, a
meaningful phrase, and zero padding) plus a 24-of-24 marker cross-check leave no
ambiguity.

## The off-white cell

The single `254,254,254` cell is at row 7, column 4 — spiral index 163, which is
not a byte boundary, so it carries no payload bit. It sits in the left-hand column
of an inner ring, on the same row as and just left of the rabbit drawing.

It is the white rabbit: a white cell that is not quite white, invisible unless you
sample the pixels, placed on the leg of the spiral that runs *down the left side* —
the one non-obvious choice in the reading order.
