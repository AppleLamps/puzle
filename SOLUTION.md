# GSMG puzzle solutions

| stage | source | answer |
| --- | --- | --- |
| `gsmg.io/Puzzle` | `follow_the_white_rabbit.png` | `gsmg.io/theseedisplanted` |
| `gsmg.io/theseedisplanted` | eight rebus tiles | `cryptologicwarningcanyoudigit` |

Run `python3 solve.py` for stage one and `python3 solve_rebus.py` for stage two.

# Stage one: `follow_the_white_rabbit.png`

**Answer: `gsmg.io/theseedisplanted`**

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

# Stage two: `gsmg.io/theseedisplanted`

**Answer: `cryptologicwarningcanyoudigit`** — "cryptologic warning, can you dig it".

Run `python3 solve_rebus.py` to reproduce the pairing from the images.

## What the page is

`GSMG Puzzle2.html` is an archived copy of `gsmg.io/theseedisplanted`, the URL
stage one decoded. Its body is eight `<img>` tags and nothing else visible. The
one other element is a form hidden with `display: none`:

```html
<form method="POST" action="https://gsmg.io/phase1verification">
<input type="password" name="password">
```

So the eight images have to spell a password. None of the PNGs carries metadata
or trailing bytes, so the answer is in the pixels.

## The tiles

Each image is a ~70x70 block of flat colour, 70px tall, holding up to two
elements stacked vertically — pictograms and letter fragments:

| file | pictogram / symbol | letters (top, bottom) |
| --- | --- | --- |
| `black_banking - war` | bank ($ in a building) | —, `war` |
| `blue_ca` | — | `CA`, — |
| `blue_dig_i` | plus sign | `dig i`, — |
| `blue_lock_lo` | closed padlock | —, `lo` |
| `red_crypto_gic` | — | `crypto`, `gic` |
| `red_n_you` | — | `n you`, — |
| `red_open_lock_n_ing` | open padlock | —, `n ing` |
| `red_t` | minus sign | `t`, — |

## How they pair up

The padding gives the layout away. On the black and blue tiles the colour block
is flush against the **left** edge with white left over on the right; on the red
tiles it is the mirror image, flush **right** with white on the left. That is
what you get by cutting a `[blue-or-black block][gutter][red block]` line
through the middle of its gutter, so the original image was four such lines and
each line is one blue-or-black tile plus one red tile.

Reading a pair's letters in normal order — top line left to right, then bottom
line left to right — gives one word per pair, and **only one of the 24 possible
pairings spells a word every time**:

```
blue_ca              + red_n_you             ->  CA  + n you           = CAN YOU
blue_dig_i           + red_t                 ->  dig i + t             = DIG IT
blue_lock_lo         + red_crypto_gic        ->  crypto + lo + gic     = CRYPTOLOGIC
black_banking - war  + red_open_lock_n_ing   ->  war + n + ing         = WARNING
```

The pictograms and symbols are illustrations of the word on their own line, not
letters: a closed padlock for CRYPTOLOGIC, a bank beside a sprung padlock for
WARNING, and plus/minus signs for DIG IT. Every letter fragment is consumed
exactly once, and the count of `n` fragments (two, one in `n you` and one in
`n ing`) is exactly what CAN and WARNING need between them — which is what
forces this partition and rules out readings like `unlocking` or `warn you`.

## The one judgement call

The four words are forced, but nothing in the tiles fixes which line came first,
since the crops carry no vertical ordering information. Read as English the
natural sentence is a header followed by a taunt:

> cryptologic warning — can you dig it?

giving `cryptologicwarningcanyoudigit`. The alternative ordering,
`canyoudigitcryptologicwarning`, uses the same four words and reads less
naturally; `canyoudigit` on its own is a third possibility if only the question
is wanted.

Note the continuity with stage one: `the seed is planted`, and now `can you dig
it` — the same gardening pun, which is a good sign the words are right.
