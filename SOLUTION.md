# GSMG puzzle solutions

| stage | source | answer |
| --- | --- | --- |
| `gsmg.io/Puzzle` | `follow_the_white_rabbit.png` | `gsmg.io/theseedisplanted` |
| `gsmg.io/theseedisplanted` | eight rebus tiles | `cryptologicwarningcanyoudigit` |
| phase 2 | `gsmg.io/choiceisanillusion…iwroteitmyself` | sha-256 = `89727c59…52f6a32` |
| phase 3 | `gsmg.io/89727c59…52f6a32` (SalPhaseIon) | open |

Run `python3 solve.py` for stage one, `python3 solve_rebus.py` for stage two,
`python3 inspect_bundle.py` for the phase1verification 404, and
`python3 phase23.py` for phases two and three.

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

## Two independent confirmations

The pairing does not rest on the word list alone. The PNG headers group the
tiles the same way, because tiles saved in the same pass share an encoder
fingerprint — the `pHYs` pixels-per-metre value, the colour type, and whether an
`sRGB` chunk is present:

| fingerprint | tiles | line |
| --- | --- | --- |
| 3779, RGB, no sRGB | `blue_ca`, `red_n_you` | CAN YOU |
| 3780, RGBA | `black_banking - war`, `red_open_lock_n_ing` | WARNING |
| 3778, RGBA, sRGB | `blue_dig_i`, `red_t`, `blue_lock_lo`, `red_crypto_gic` | DIG IT and CRYPTOLOGIC |

Two of the four lines are pinned exactly by that grouping and the other two are
confined to the remaining four tiles, which is the same answer the word list
gives.

The two padlocks are also a deliberate matched pair rather than two drawings:
aligned on their bounding boxes they are pixel-identical except for 25 pixels
forming the left leg of the shackle, so one is literally the other unlocked.

Nothing else is hidden in the tiles. Every pixel is opaque, none of the eight
PNGs has metadata or bytes after `IEND`, the white padding is pure white, and
there is no off-by-one colour marker of the kind stage one used.

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

# Phase 2: `gsmg.io/choiceisanillusion...iwroteitmyself`

The chain does not end at the rebus. Two more puzzle pages survive in the
Wayback Machine, found by enumerating archived `gsmg.io/*` URLs. Both are
server-rendered Blade pages titled "GSMG Puzzle", exactly like
`theseedisplanted`, and both were captured while the puzzle was live.

**Phase 2** is at

    gsmg.io/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself

captured 2020-11-12, the same day as `theseedisplanted`. The slug is two
Merovingian lines from *The Matrix Reloaded*. The page carries two AES blobs and
a set of riddles whose answers are "parts 1..7"; concatenated and hashed they
give the phase 3 password.

    Ciphered with aes-256-cbc /w base64 sha-256(password)
    --> parts 1..7 --> sha-256 -> dgst is the password to enter Phase 3.

The riddles decode as follows.

**The keymaker (part 1).** "1... are you looking for the private keymaker? You
come to me, without it. Come to me with it and you'll have the power to
continue. It'll grant the first part." Gates the first 672-byte blob.

**The Norton chain (a later part).** "A guy who theorised ... equivalent current
source Ino in parallel with an equivalent resistance Rno" is Norton's theorem,
so **Norton** — "he might have been insecure" is the antivirus pun, and "his
competition" is **McAfee**. "After enough belikins" is Belize's national beer,
where John McAfee lived, and he ran to rule "the technically poorest" country on
the planet, the most indebted one. Four US presidents share his first name
**John** (Adams, Quincy Adams, Tyler, Kennedy) and two carry it inside their
surname (**Johnson** twice). The ruler resembling "Carrey, James Gates, also
Simulacra and Simulation" is the simulation-hypothesis cluster pointing at
**Truman**. The closing moral — "never execute an order that revokes the highest
power or you might suddenly get killed" — is Kennedy and **Executive Order
11110**, and "the 5binary code" is that number read as five binary digits.

**The genesis block (a later part).** "The idea of this _green_ came _back_" is
the greenback; "a chancellor awaiting banks to be bailed out decided to write an
anarchist digital answer" is the Bitcoin genesis block's coinbase message, *The
Times 03/Jan/2009 Chancellor on brink of second bailout for banks*. "Its raw
data after 4 on row 1616" indexes into that block's raw hex.

**The chess position (a later part).**

    B5KR/1r5B/6R1/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 w - - 0 1

"And now a buddhist is forced to move. What will be the next situation?" — a
zugzwang whose answer is the resulting position.

The three `/(aaa, connected enf)`, `/(aBa, connected enf)` and `/(aBa, connected
not enf)` markers appear to specify how each part is cased and whether it is
concatenated without separators when the seven are joined.

# Phase 3: SalPhaseIon

Phase 2's answer is already recoverable without solving those riddles, because
the phase 3 page is archived under its own password:

    gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32

captured 2023-06-01. A 64-hex slug is precisely the "sha-256 -> dgst" the page
above describes, so **sha256(parts 1..7) = 89727c598b9c…52f6a32**. It serves a
page headed **SalPhaseIon** and **Cosmic Duality**, with two more textareas.

`python3 phase23.py` extracts everything and decodes the readable parts. The
SalPhaseIon textarea is a 1075-character stream that is not one encoding but
three interleaved:

- Letters `a`..`i` are digits 1..9 and `o` is 0, with `z` acting as a separator,
  giving three digit segments of 765, 63 and 29 digits.
- Buried at offset 91 is a 104-character run of nothing but `a` and `b`. Read as
  bits with `a` = 0 it spells **`matrixsumlist`**.
- The tail turns into plain text: `shabefour`, then the instruction
  **`firsthintisyourlastcommand`**, then a 96-byte `Salted__` blob whose base64
  is split in two by another `a`/`b` run — which decodes the same way to the word
  **`enter`**, i.e. the line break between the blob's two base64 lines. It closes
  with `shabefanstoo`.

## State of play

Four ciphertexts are in hand and none has yielded yet:

| blob | source | size | salt |
| --- | --- | --- | --- |
| keymaker | phase 2, first textarea | 656 B | `06286612d43ed7ed` |
| phase 3 | phase 2, second textarea | 4096 B | `9fbc451d13d071f4` |
| cosmic duality | phase 3, second textarea | 1328 B | `2d3f6fe06dc950e6` |
| embedded | inside the SalPhaseIon stream | 80 B | `3ab585348552415d` |

The sweep in `phase23.py` tries each candidate raw, as its sha-256 hex digest and
as its raw digest, under md5, sha1 and sha256 key derivation, and reports no hit
for the obvious candidates including the phase 2 digest itself and
`matrixsumlist`. Notably the phase 3 blob on the phase 2 page does *not* open
with the digest that the phase 3 URL exposes, so the passphrase is some further
transformation of the seven parts rather than the digest verbatim.

# The `phase1verification` capture: a real 404, not a clue

`GSMG _ GSMG.html` is a capture of `https://gsmg.io/phase1verification` and it
renders "Oops! Page Not Found". That is a genuine error, not part of the puzzle.
Run `python3 inspect_bundle.py` for the evidence, which is fivefold.

**It is the trading app, not a puzzle page.** The capture ships the site's full
Vue bundle (`app.js`, 2.3 MB). Pulling the router table out of it gives 22
client-side routes — `/dashboard`, `/markets`, `/login`, `/puzzle`, `/terms` and
so on — plus a catch-all `path: "*"`. `/phase1verification` is not among them,
so it falls to the catch-all.

**The message is the catch-all's own text.** The catch-all points at module
`Dp46`, whose template `zDQp` renders exactly `Oops! {{ $t('page_not_found') }}`
above a `go_home` link, and the page's inline config defines `page_not_found` as
"Page Not Found" and `go_home` as "Go Home". Any unrecognised URL on the site
produces this identical page; there is nothing puzzle-specific in it.

**A GET was never going to work.** `/phase1verification` is the POST target of
the hidden form on the `theseedisplanted` page. The Wayback crawler only issues
GETs, so even while the puzzle was live this URL could not have returned the
next stage to an archiver.

**The capture is three years too late.** It is dated 2023-09-08, against a
puzzle that was live in November 2020, and the footer reads "© 2023 - GSMG …
Official Partner of Bittrex Global". The toolbar reports only **2 captures, 8
Sep 2023 – 2 Mar 2026** — this URL has no 2020-era capture at all, unlike
`/Puzzle` (8 captures from 9 Nov 2020) and `/theseedisplanted` (7 captures from
12 Nov 2020).

**Nothing of the later stages survives in the bundle.** `app.js` contains zero
occurrences of `phase1verification`, `theseedisplanted` or `cryptologic`. The one
puzzle artefact left is the `/puzzle` route itself: component `t5W0`, template
`oQ7m`, which still renders "GSMG MEGANIGMA || 5 BTC" over
`/img/follow_the_white_rabbit.png` — stage one, unchanged. The only new image in
this capture is an Intercom chat-widget launcher icon, and the SVGs are menu
chrome.

That last point also explains the shape of the whole chain: the puzzle stages
were server-rendered routes sitting outside the Vue router. The
`theseedisplanted` capture is a bare Blade page — `<title>GSMG Puzzle</title>`, a
CSRF meta tag, raw `<img>` tags and a form, no `app.js`. Once those server
routes were retired, the SPA's catch-all began answering for them.

## Where this stops

Stage three is whatever the server returned when the correct password was POSTed
to `/phase1verification`, and no GET-based archive can hold it.

The way the chain has worked so far suggests where it will be instead: stage
one's answer *was* a URL, and `/theseedisplanted` was archived on 12 Nov 2020,
three days after `/Puzzle` — someone was capturing each page as they solved it.
So the next stage very likely sits in the archive under its own slug rather than
behind the POST. Enumerating archived `gsmg.io/*` URLs from late 2020 (the
Wayback CDX index will list them) should surface it, exactly the way
`theseedisplanted` surfaced.

The local material is otherwise exhausted. Every HTML capture holds only its
Wayback wrapper plus page content, the `.js`/`.css` assets are stock Internet
Archive replay scripts or the site's own app code, `GSMG Puzzle_files` and
`GSMG Puzzle2_files` are byte-identical, and every image has been checked for
metadata, appended data, alpha channels and near-background colour markers.
