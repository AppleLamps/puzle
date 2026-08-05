# Rebuilding the puzzle from creator-sourced material only

Everything below is separated by provenance. The distinction matters because the
public corpus mixes creator artifacts with solver interpretation, and several
widely repeated "facts" turn out to be the latter.

## What counts as creator-sourced

1. The images and pages the creator published on `gsmg.io`, as archived.
2. Any plaintext that **decrypts** from a creator-published ciphertext. A correct
   AES password is self-authenticating when the output is coherent.
3. Messages posted by the admin account `Jrk Bgrt` in the project Telegram.

Everything else — labels, byte-slicing conventions, masks, matrix
interpretations, the token readings for the later SalPhaseIon fields — is solver
work and is treated here as hypothesis, however often it is repeated.

## The creator's statements, in order

| date | creator statement (Jrk Bgrt) |
| --- | --- |
| 2020-01-14 | "Roses are White but often Red. **Yellow has a number and so does Blue.** Go back to the first puzzle piece without further ado. It might have shown you only one door, beware that **the rabbits nest may contain a whole lot more.**" |
| 2020-05-11 | "who knows what you'll find after opening the **2nd door**. The price is in half, but what does it mean" |
| 2020-08-02 | "Really **nobody managed to find the extra door**, didn't expect that after the earlier pace of cracking things." |
| 2021-01-21 | "a few might **not require the internet** anymore." |
| 2021-03-01 | "You are at the **prime part** already??? … shouldn't have said that. That might have been a hint." |
| 2021-03-14 | "Breaking salphation should be **giving the feeling of the phase's name**." |
| 2021-12-02 | "There is / Another / D O O R" |
| 2021-12-25 | "The previous 'there is another door hint' is still a thing. We're not sure if anyone has found another door so far … **prime numbers** … that is definitely an aspect which is required to proceed. Furthermore, along the way, **some characters need to be 'zeroed out'**." |
| 2023-01-09 | "At least **prime number is very important** to get any further." |
| 2023-02-23 | an encoded image decoding to the pipeline below |
| 2023-08-03 | "Are you really looking for just the btc…?" and "Actually, **the hardest part is done**." |

The 2023-02-23 post is the single most valuable creator artifact, because it is
the creator describing his own construction:

    yellowblueprimes
    matrixsumlist
    lastwordsbeforearchichoice
    yinyang
    wewontgiveawaythepassword
    itsinfrontofyoureyesbutyourenotseeingit
    verylaststepisatruegiveawaypromised

## What follows, and what has to be fixed

**1. There is a second door, it branches from the first image, and the entire
public effort is on the other branch.** The creator says so five separate times
across four years, in 2020-01-14, 2020-05-11, 2020-08-02, 2021-12-02 and
2021-12-25, and as late as December 2021 says nobody had found it. Every line of
published work — the repository, and both AI agents working this problem — is
pushing down SalPhaseIon → Cosmic → base-38. The creator points backwards, at
`follow_the_white_rabbit.png`.

**2. The creator's own four-part recipe does not match the solver chain.** His
list is `yellowblueprimes`, `matrixsumlist`, `lastwordsbeforearchichoice`,
`yinyang`. The working chain 1 password is
`matrixsumlist` + `enter` + `lastwordsbeforearchichoice` + `thispassword` +
`matrixsumlist`. Two of the creator's four components — **`yellowblueprimes` and
`yinyang`** — appear nowhere in the solver chain, and the two that do appear are
joined by words the creator never lists.

**3. "Yin yang" is Cosmic Duality.** The SalPhaseIon page carries exactly two
textareas, headed `SalPhaseIon` and `Cosmic Duality`. A yin-yang is a duality.
The creator's recipe therefore looks like the route into the Cosmic blob, and the
7-token XOR the repository uses for that blob is a solver construction that
appears in no creator source.

**4. The chain 1 password reveals the creator's joke, and it should recur.** The
raw stream reads as an instruction — *matrixsumlist, **enter**,
lastwordsbeforearchichoice, **this password*** — and the solvers used the
instruction's own words as the password. That is exactly
"itsinfrontofyoureyesbutyourenotseeingit". Any remaining lock should be expected
to work the same way. I tested the 2023 message and all 144 of its segment,
hash and digest spellings against all three envelopes: 8 padding hits against a
chance expectation of 3.4, none readable. So the joke does not repeat *literally*
on these three blobs.

**5. The Cosmic decryption is weaker evidence than it is presented as.** The
repository's own audit reports 1,154 Cosmic padding hits from 281,816 trial
decryptions, so valid padding is worthless as proof at that scale, and the
resulting 1327 bytes are high-entropy. The often-cited supporting structure —
that its first 158 bytes are two `32+32+15` records — is not evidence, because
*any* 79 bytes can be sliced 32+32+15; the pattern is imposed, not detected. The
real support is that Chain 4 emerges from the remainder, but that step needs an
8-byte mask which is itself fitted to make `Salted__` appear. Chain 4's
subsequent clean decrypt to 1151 bytes beginning `+-` is a genuine coincidence
worth something, but the whole branch rests on it.

**6. `THE_HALF` / `THE_BETTER_HALF` are not creator-sourced labels.** The words
come from the authenticated Architect line "the private keys belong to Half and
Better Half". Attaching them to `base38_output[0:32]` and `[32:64]` is shape
matching by solvers. Those two scalars produce ten addresses across every
standard script type, none of which is a prize address, and all of which hold
zero.

## The first image, re-examined under the creator's hints

Facts established directly from the file:

- It contains exactly **five** distinct RGB values across 122,500 pixels:
  black 54,675, white 52,200, blue 9,375, yellow 5,625, and **(254,254,254) at
  exactly 625 pixels — one whole cell**, at grid position **(7,4)**.
- The alpha channel is uniformly 255, there are no trailing bytes after `IEND`,
  every chunk CRC is valid, and the scanline filters are the encoder's ordinary
  choice, filter 1 on each of the 14 cell-row boundaries and filter 2 elsewhere.
  There is no conventional steganography.
- That off-white cell is invisible to the eye at one unit of difference, which is
  a precise match for "its in front of your eyes but youre not seeing it".
- It sits at spiral index 163, which is bit 3 of **byte 20**, the character `n`
  of `gsmg.io/theseedisplanted`.
- The published row-sum total of 102 for this grid is wrong. Centre-pixel
  sampling reads a rabbit line crossing cell (7,6); majority sampling gives
  **101**.

Under the resistor colour code that "Yellow has a number and so does Blue"
implies — black 0, red 2, yellow 4, blue 6, white 9 — the grid's row and column
sums each total 900, and 891 with the off-white cell zeroed.

Searched and excluded: all eight spiral variants, row-major, column-major and
both boustrophedon orders, each forwards and reversed, under all fifteen
non-empty colour-to-bit assignments. Exactly one produces readable text, the
known `gsmg.io/theseedisplanted`. The second door is not another plain reading of
these 196 cells.
