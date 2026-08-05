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

## The `11092001` XOR construction: verified, and a real improvement

The transcript's newest step is `F73D92 XOR 11092001 = 5E7DB3`, whose 23
significant bits hold 16 ones and 7 zeros. Every part of that checks out:

- `11092001` is **prime**, is exactly **24 bits** (`0xA94021`), and has popcount 7.
- `0xF73D92 ^ 0xA94021 = 0x5E7DB3`, binary `10111100111110110110011`.
- That is 23 bits with **16 ones and 7 zeros**, matching the Architect's literal
  line: "you will select from the Matrix 23 individuals, 16 female, 7 male".
- Jacque Fresco's quote is exactly **23 words** and exactly **140 characters**
  without punctuation, and the seven zero-bit positions select
  `future / each / decision / possibilities / others / is / ours`.

**This fixes my objection to the earlier `÷2 + 3` claim.** That move had to flip
marker 21 and discard marker 24 to reach a 23-symbol stream. This one discards
nothing: all 24 markers are used, and the 23-bit width falls out naturally
because the XOR clears the top bit. The operand is externally motivated by film
trivia rather than fitted, and the 16/7 split answers to an actual line of
dialogue. It is a materially better construction.

**It is also selective.** Across 15 plausible encodings of 11 September 2001
(`ddmmyyyy`, `mmddyyyy`, `yyyymmdd`, two-digit years, unix time, and so on)
crossed with five operations (xor, and, or, add, sub) — 75 combinations —
**exactly one** lands on 23 bits with 16 ones, and it is also the only encoding
that is simultaneously prime and exactly 24 bits wide.

**One calibration, though.** `F73D92` has popcount 15, which is just the 15 blue
cells, and the operand has popcount 7, so the XOR popcount is `22 - 2*overlap`
and reaching 16 needs overlap exactly 3. For a random 24-bit operand of weight 7
that happens with probability `C(15,3)*C(9,4)/C(24,7)` ≈ **0.17, about one in
six**. So the "16 ones" test on its own is a weak filter; the weight of the
evidence is the conjunction — prime, 24 bits, the European date order a Dutch
creator would write, the Architect's line, and the quote's 23/140 coincidence.

## Where the freedom re-enters

The step after it is softer. Selecting words at the **zero** bits rather than the
one bits is a free binary choice, and it is exactly that choice which produces a
"seven-password set" instead of a sixteen-word one.

I tested it. From those seven words I built 372 candidates — each word alone, all
35 lexicographic triples under three joiners, the full set in four orderings
under three joiners, plus upper and capitalised variants — and ran them against
all four ciphertexts in three passphrase forms under two key-derivation digests,
**and** against the phase 2 hash oracle. No blob opens, and nothing hashes to
`89727c59…52f6a32`.

Worth noting which oracle is stronger here. For phase 2 material the digest is a
hard, instant test that needs no address derivation at all, and three of the
seven parts are now fixed.

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

## Cross-check against the second agent's transcript

The transcript in `rollout-2026-08-04T21-14-50-*.jsonl` is a separate agent
working the same puzzle from a community repo. Two of its claims are checkable
against the raw files here, and both hold:

**The colour markers spell `F73D92`.** Reading the 24 blue/yellow cells in the
same counter-clockwise spiral that spells the stage one URL, with blue = 1 and
yellow = 0, gives `111101110011110110010010` = `F73D92`. That agent reached the
same conclusion this write-up did independently — the markers are not a separate
pink RGB clue but the least-significant bit of each of the 24 URL bytes. Its
note that they fall at spiral positions 8, 16, 24 … 192 is the same fact as the
byte-delimiter finding above, one-indexed. Row-major ordering would give
`BE2B9B`, which is why the value was previously dismissed.

**24 colour markers ↔ 24 primes.** There are exactly 24 primes in 1..91, and
exactly 24 colour markers, so the stage one bits index the prime positions of
S91. `solve_rebus.py` and `phase23.py` both confirm the counts.

Worth noting the transcript also opens from a *wrong* stage one reading — a
12x12 grid solved as a rabbit maze with yellow breadcrumbs and blue decoys. The
grid is 14x14, the colours are byte delimiters, and the answer is the spiral.
That agent later corrected itself to the same spiral result.

The creator hint it quotes, `yellow blue primes -> matrix sum list -> last words
before archi choice -> yin yang`, matches the field structure: `matrixsumlist`
is 13 characters and S91 is 7 x 13, while `lastwordsbeforearchichoice` +
`thispassword` is 38 characters and S570 is 15 x 38. Its downstream reading
(`AFFECT THIS B`, `COMPS`, a Witteveen identification) is speculative and not
reproducible from these files.

## Two fields the transcript does not mention

Splitting the stream on `z` shows the head is not two fields but four, and the
last two are absent from the other agent's analysis entirely:

    S91 (91) || bits("matrixsumlist") (104) || S570 (570) || z || F63 (63) || z || F29 (29) || z || literal

with `91 + 104 + 570 = 765`, exactly the offset of the first `z`. The two
trailing fields use a **different alphabet**: S91 and S570 draw only on `a`..`i`
(digits 1..9, no zero), whereas F63 and F29 also contain `o`, which is 0 under
the same mapping. As decimal digits they are

    F63  174161018595377387932283725836301293648834223172419022725145445
    F29  36026487402470099740341006948

Whatever transformation the pipeline describes, it has to account for these, and
for the fact that they are drawn from a ten-symbol alphabet while the two large
fields are drawn from nine.

## Testing the transcript's newest lead

The later transcript proposes `F73D92 / 2 = 7B9EC9`, then a `<3` / "better half"
step giving `7B9ECC`, whose 23 significant bits are `BBBBYBBBYYBBBBYBBYYBBYY` —
offered as justification for a 23-colour stream with "the omitted prime-89
colour" and a `YYB -> BYY` tail change.

**The arithmetic is exactly right.** `0xF73D92 / 2 = 0x7B9EC9`, `+3 = 0x7B9ECC`,
and its 23 significant bits do spell that string. `pipeline.py` verifies each
step.

**But look at what the two operations do to the marker stream.** Dividing by two
is just dropping the final bit, and adding three flips the tail:

    true 24 markers   BBBBYBBBYYBBBBYBBYYBYYBY
    claimed 23        BBBBYBBBYYBBBBYBBYYBBYY

They agree for 20 positions, then need two edits: **flip marker 21 from Y to B,
and discard marker 24.** Those two markers are not free variables. Every marker
is the least-significant bit of one URL byte, so marker 21 is the LSB of byte 21
of `gsmg.io/theseedisplanted`, which is `n` = 110, even, therefore yellow; and
marker 24 is the LSB of `d` = 100, also even. Flipping one asserts that `n` is
odd, and dropping the other throws away a byte of a string that decodes
perfectly. "÷2 then +3" is two free parameters chosen to land on a wanted
23-symbol target.

It also undercuts the bridge it is meant to support. The 24 markers ↔ 24 primes
in 1..91 correspondence is one-to-one with nothing left over, so there is no
"omitted prime-89 colour" to explain — discarding a marker is what creates the
gap, not what resolves it.

## The pipeline as stated does not open any blob

`pipeline.py` turns the hint into candidates instead of argument. It builds the
24 marker bits into the 24 prime slots of S91 under both polarities and both
"zero the other 67" and "keep the original digits" readings, takes 7 x 13 column
sums row-major and column-major, renders each sum list six ways, applies the
yin/yang step as the list added to and subtracted from S570 modulo 10, and adds
the Architect phrases and every `F73D92` variant including `7B9EC9` and
`7B9ECC`. That is 86 candidates, each tried raw, as sha-256 hex and as raw
digest, under md5 and sha256 derivation, against all four ciphertexts:
**2064 trial decryptions, no hit.** A further 21 candidates from the on-chain
`for ying yang thank you!` / `it myself 140 investment` / `invisible` lead, plus
`unaware`, `witteveen` and the claimed `AFFECT THIS B` / `COMPS` outputs, also
produce nothing.

That negative is worth something: it is evidence for the other agent's own later
pivot, that `matrixsumlist` names a straddling-checkerboard over-encryption step
rather than an AES passphrase. No arrangement of the sum list is a password.

# BREAKTHROUGH: phase 2 part 1 decrypted

The first phase 2 blob — the one the page says "will grant the first part" —
opens with the password **`causality`**, via `sha-256("causality")` as the
OpenSSL passphrase with sha256 key derivation:

    openssl enc -aes-256-cbc -a -d -md sha256 -k $(printf causality | sha256sum | cut -d" " -f1)

`attack_keymaker.py` finds it; `phase2_part1_plaintext.txt` holds the result.
The word comes straight from the puzzle's own vocabulary — the Merovingian's
"causality" speech in *The Matrix Reloaded*, the same scene the phase 2 URL
quotes. It is also one of the on-chain OP_RETURN messages, as
`Causality Transcended`.

The plaintext is a fresh sub-puzzle:

    The ironic 2name of the keymakers trying to protect the current digital
    powers which are still in severe danger due to the keymaker's way of
    security by hiding, nearly unprotected, in plain sight.
    {eps3.4_[in one of the valleys of Phillip]runtime-error.r00., where
    daughters hit magic keypads} When this fails.. Crypto finally to the latin
    3Moon? Tell me, 4How so mate?

    # X 2 S H 4 Y 0 Q B 15 #

    Q -> extend the name of a hackers' swordless fish, the I and W are below.
    B -> ((BV80605001911AP)- (sqrt(-1)))^2
    H -> (Answer to only this puzzle but nothing else) * -1
    S -> cha' + (vagh * jav)

    Ok kid, on the highway, let put it in the worst gear.

## Two of the four substitutions solve cleanly

**B = 49.** `BV80605001911AP` is Intel's spec code for the Core **i7**-860, and
`sqrt(-1)` is **i**. So `(i7 - i)^2 = 7^2 = 49`.

**S = 32.** The operands are Klingon numerals: `cha'` = 2, `vagh` = 5, `jav` = 6.
So `2 + (5 x 6) = 32`.

That leaves `H`, `Q`, and the two bare variables `X` and `Y`. `H` is
"(Answer to only this puzzle but nothing else) * -1" — a play on 42 being the
answer to everything, so this wants the answer to *only* this puzzle. `Q` is
"extend the name of a hackers' swordless fish": the fish ciphers run Blowfish →
Twofish → Threefish, and dropping the sword from Swordfish leaves the fish.

The closing line, "on the highway, let put it in the worst gear", reads as an
instruction on the assembled string — reverse, or first gear.

The prose carries superscript-style markers `2name`, `3Moon`, `4How`, and the
page itself opens `"1... are you looking for the private keymaker?"`, so clues
1-4 are numbered. `eps3.4_runtime-error.r00` is a *Mr. Robot* episode title and
Phillip Price is that show's E Corp CEO. "Crypto finally to the latin 3Moon"
wants **luna**.

## The seven parts are numbered in the text

Phase 2 ends "--> parts 1..7 --> sha-256 -> dgst", and the creator marks each one
with a digit glued to the front of a word. Scanning the page plus the decrypted
part 1 for that pattern finds exactly five, and the two remaining requests follow
the last of them:

| part | marker | what it asks for |
| --- | --- | --- |
| 1 | `"1... are you looking for the private keymaker?"` | granted by the blob `causality` opens |
| 2 | `The ironic 2name of the keymakers` | the ironic **name** of the keymakers |
| 3 | `Crypto finally to the latin 3Moon?` | latin for **moon**, so `luna` |
| 4 | `Tell me, 4How so mate?` | **how** so, mate |
| 5 | `The 5binary code is a part of the piece` | the **binary** code, Executive Order **11110** |
| 6 | (no marker) | genesis "raw data after 4 on row 1616" |
| 7 | (no marker) | the chess "next situation" |

That accounts for all seven, and it explains the odd typography: `2name`,
`3Moon`, `4How`, `5binary` are not typos but indices. Parts 2-5 all live inside
the part 1 plaintext, which is why the keymaker blob had to be opened first.

Three of the seven are effectively settled — part 3 is `luna`, part 5 is `11110`,
and part 1 is whatever `# X 2 S H 4 Y 0 Q B 15 #` resolves to with `S = 32` and
`B = 49`. The two section markers are consistent with this: `/(aaa, connected
enf)` describes part 1 as lower case and written without separators, while
`/(aBa, connected enf)` and `/(aBa, connected not enf)` describe the mixed-case
parts and the chess answer, where a FEN's spaces need not be stripped.

Because the phase 3 URL exposes `sha256(parts 1..7)` =
`89727c59…52f6a32`, any candidate assembly can be checked instantly. That turns
the rest of phase 2 into a search with a hard test at the end rather than a
guess.

Note the genesis block's raw serialisation is 285 bytes, i.e. **570 hex
characters** — the exact length of phase 3's S570 field.

## Part 6 solved: "raw data after 4 on row 1616"

The clue is self-describing once you take `1616` as **row 16, sixteen hex
characters per row**. Laying the Bitcoin genesis block's raw serialisation out
that way puts the coinbase push at the exact start of row 16:

    row 15: ffff4d04ffff001d
    row 16: 0104455468652054     <- "01 04" pushes the number 4, then the message
    row 17: 696d65732030332f

`01 04` is Satoshi's `CBigNum(4)` in the coinbase scriptSig, and the raw data
**after that 4** is nothing but the headline:

    The Times 03/Jan/2009 Chancellor on brink of second bailout for banks

Under the section's `/(aBa, connected enf)` marker — mixed case, no separators —
part 6 is

    TheTimes03/Jan/2009Chancelloronbrinkofsecondbailoutforbanks

The offset is exact: the push begins at hex offset 256, which is row 16 only
under a 16-hex-character layout (a 16-*byte* layout puts it in row 8). That is
what makes `1616` a single instruction rather than two numbers.

## Part 7 solved: the forced bishop move

"And now a buddhist is forced to move. What will be the next situation?"

A buddhist is a monk, and the monk on a chessboard is the **bishop**. In

    B5KR/1r5B/6R1/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 w - - 0 1

White has fourteen legal moves, of which **exactly one is a bishop move**:
`Bxb7#`. The a8 bishop's only free square is b7, and the h7 bishop is walled in
by its own king and rook. So a bishop move really is *forced* — the word is
doing precise work, not decoration. It is also mate, which is consistent with a
position where thirteen of White's fourteen moves mate.

The next situation is therefore

    6KR/1B5B/6R1/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1

and the section marker fits it exactly: `/(aBa, connected not enf)` says mixed
case with connection *not* enforced — which is precisely how you would describe
a FEN, whose spaces and slashes must survive.

That earlier reading of mine — Black to move, all nine of whose legal moves are
bishop moves — is the wrong one. It leaves nine candidates, so nothing is
forced, and it contradicts the `w` in the FEN.

## Part 1 is letters, not digits

The section marker `/(aaa, connected enf)` says part 1 is **lower case**. That is
vacuous for a digit string, so the template's tokens must resolve to letters.
Mapping them A=1:

    2 -> b    S = 32 -> f    H = -42 -> j    4 -> d    B = 49 -> w    15 -> o

and that immediately explains the odd trailing hint on `Q`:

> Q -> extend the name of a hackers' swordless fish, **the I and W are below**.

Under A=1, `B = 49` gives **w**, and `Q` gives **i** if `Q ≡ 9 (mod 26)`. Both
`Q` and `B` are defined in the lines *below* that sentence — so "the I and W are
below" is naming the two letters those two clues produce. It is a check digit on
the mapping, and it confirms A=1 rather than A=0 (which would send 49 to `x`).

`Q = 9` also fits its own clue two ways: drop the sword from *Swordfish* and
extend the name back out and you have nine characters, and the hacker fish
ciphers run Blowfish → Twofish → **Threefish**, which is nine letters.

That leaves `X` and `Y`, which have no clue at all, and the closing instruction
"on the highway, let put it in the worst gear" — reverse, or first.

## Part 1's H is -42

The other agent's reading of `H -> (Answer to only this puzzle but nothing else)
* -1` is the Hitchhiker's 42 negated, so **H = -42**. With `S = 32` and
`B = 49` that leaves only `Q`, `X` and `Y` unresolved in
`# X 2 S H 4 Y 0 Q B 15 #`.

## The ECDSA nonce route is closed

The transcript proposes auditing the prize address's signatures for a
reproducible nonce relation, on the basis that "the target address has spent
on-chain, so its full public key and signatures are available". `ecdsa_audit.py`
settles it:

| | signatures published | distinct r | reused r |
| --- | --- | --- | --- |
| Half `1GSMG…` | 6 | 6 | 0 |
| Better Half `17ucy…` | 0 | — | — |

Half has published only **six** signatures, every one with a distinct `r`, and
none with an `r` shorter than 250 bits. No nonce reuse, and six samples is far
too few for a lattice attack on biased nonces even if a bias existed.

More importantly, **Better Half has never spent an output**, so it has published
no signature *and no public key at all*. There is nothing there to audit. That
also constrains how candidates can be tested against it: only by deriving the
address hash, never by comparing public points — so any gate written against a
"public key" for `17ucy…` is testing something that does not exist on chain.

## What the breakthrough rules out for the other blobs

`causality` is an ordinary English word taken from the film the puzzle quotes,
so a full wordlist is worth running against the three blobs still closed.
`bigattack.py` does that, using a CBC trick to keep it cheap: the final
plaintext block is `D(C_n) XOR C_(n-1)`, so a single AES block decrypt checks the
padding and rejects about 99.6% of candidates before any full decrypt, giving
roughly 8,800 words/second across all three targets at once.

**All 370,105 words of `words_alpha` fail** against the phase 3, Cosmic Duality
and embedded blobs, in each of three passphrase forms under two key-derivation
digests. A further 360 candidates drawn from the part 1 plaintext's own
vocabulary — `luna`, `threefish`, `twofish`, `blowfish`, `zugzwang`, `keymaker`,
the template string and its reversal — also fail.

So those three are not single-word passphrases. Phase 3's is stated outright as
the sha-256 of parts 1..7, and the remaining two belong to the SalPhaseIon
puzzle rather than to phase 2.

## The chess position

`B5KR/1r5B/6R1/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 w - - 0 1` is a composition
where **13 of White's 14 legal moves are checkmate**. The sole exception is
`Rc6+`, and after it Black has exactly one legal reply, `Rxh7`.

"A buddhist is forced to move" does not fit that line, though — `Rxh7` is a rook.
It fits the position with Black to move, where **all nine of Black's legal moves
are bishop moves**: the bishop is the only black piece that can move at all.
A bishop is the chess piece that is a monk, and the position is a zugzwang. Nine
candidate moves means the "next situation" is not yet pinned down.

# The prize on-chain: Half and Better Half verified

The latest transcript proposes adding `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` as a
second address oracle, on the report that the creator "moved half the original
5 BTC" after solvers decoded phase 3.2.2. `onchain.py` checks that against the
chain, and the move is real and unmistakably deliberate — but the story around
it needs correcting.

| | address | txs | balance |
| --- | --- | --- | --- |
| Half | `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` | 125 | 1.25634510 BTC |
| Better Half | `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` | 44 | 3.75055310 BTC |

Only two transfers ever ran between them, and both land on a Bitcoin halving:

    2020-05-11   2.50000000 BTC   block 630001   halving at block 630000, +1 block
    2024-04-24   1.25000000 BTC   block 840725   halving at block 840000, +725 blocks

**The creator halves the remaining prize at every Bitcoin halving and sends the
half to the second address.** 5 becomes 2.5 + 2.5 one block after the 2020
halving; the 2.5 left behind becomes 1.25 + 1.25 after the 2024 halving. That is
what "HALF AND BETTER HALF" names, and it is why both "need funds to live". A
separate 2020-05-11 message on the address reads simply `Halving`.

Two consequences matter for the search.

**The prize is intact and untouched.** The two balances total 5.0067 BTC, and
Better Half has *never spent an output* — `spent 0.00000000`. Nobody has swept
either key. The next halving, block 1050000, would presumably move another 0.625.

**The transcript's "component addresses" are not these.** It reports that the two
addresses derived from its recovered Half/Better Half scalars "first appeared in
February 2026" with "91/90-spend histories". Better Half first appeared
2020-05-11, funded straight from the prize address one block after the halving.
So whatever those February 2026 addresses are, they are solver artifacts, and
treating their funding as confirmation that "need funds to live" is satisfied is
circular — solvers funded them *because* the derived keys had been published. The
proposal to gate candidates against `17ucy…` is right; the scalars it plans to
gate are not validated by that 2026 activity.

## The on-chain phrase corpus is solver noise

Both addresses carry 41 distinct OP_RETURN messages. Apart from `Halving` in
2020 they are all 2025-2026 and read as solvers writing at the puzzle: `redpill`,
`iamtheone`, `leavethematrix`, `There is no spoon`, `THEMATRIXHASYOU`,
`SalPhaseIon`, `hereismysecret`, `#SOLUTION`, `Causality Transcended`.

Three are worth naming. `itisonlywiththeheartthatoneseesrightlywhatisessentialis
invisibletotheeye` is Saint-Exupéry, and it accounts for both the `<3` hint and
the `invisible` message the transcript is chasing — that OP_RETURN is a solver
quoting *Le Petit Prince*, not a creator key. And
`matrixsumlistenterlastwordsbeforearchichoicethispassword` is exactly the
concatenation of the SalPhaseIon literal instructions, which someone had clearly
already assembled.

All 41 messages, cased and stripped, plus hex payloads decoded, give 88
candidates. Against the four ciphertexts under three passphrase forms and two
digests — **2112 trial decryptions, no hit.** The corpus is saved as
`opreturn_corpus.txt`.

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
