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

## The door cannot be fetched, only derived

The creator's pages live at paths you compute: `/theseedisplanted`,
`/choiceisanillusion…iwroteitmyself`, and
`/89727c59…` which is `sha256` of the first page's own text. A second door should
therefore be another computed path. Two routes to it are now closed:

**The live site is gone.** `gsmg.io` today answers every path — real or invented —
with a fingerprinting redirect into a parked advertising page. `/theseedisplanted`
and `/definitelynotarealpage12345` return byte-comparable ad pages with no
textarea. There is nothing left to probe.

**The archive never saw a second door.** Filtering the Wayback CDX index to
creator-era captures leaves 82 distinct non-asset paths, and only four are puzzle
pages: `/Puzzle`, `/theseedisplanted`, `/choiceisanillusion…`, and `/89727c59…`.
Everything else is `/shared/…` referral redirects and site plumbing. Every
64-hex-character path in the index was captured in 2025 or 2026, and all of them
return the identical 36,627-byte single-page-app shell — solver probes that
missed. `/TheArchitectChoice`, which looks promising next to
`lastwordsbeforearchichoice`, is the same 404 shell.

This is a real constraint on the whole endeavour, and it cuts both ways. If the
second door is a page, its contents died with the site, because nobody ever
visited it to get it archived. What survives is only what can be *derived*. That
may be the point: the creator's 2021-01-21 note that "a few might not require the
internet anymore" suggests the later steps were meant to be computed offline
rather than fetched.

## The Decentraland puzzle piece, and what the audio actually says

The photograph in the corpus is not a book cover or a screenshot of the website.
It is a Decentraland client capture: the minimap reads **"GSMG.io Puzzle piece"**
at parcel **-41,-17**, with a giant white question-mark sculpture and the words
`GSMG.IO 5 BTC PUZZLE CHALLENGE` floating in-world.

That parcel resolves on Decentraland's own content server to a scene entity owned
by `0x5D801b2B0B216790A49898b322246282547b546b`, published at timestamp
1582211536189 — **20 February 2020** — titled `GSMG.io Puzzle piece`. It carries
three files: `scene.json`, `bin/game.js`, and **`sounds/puzzlepiece.mp3`**. This is
creator-published material, addressed by content hash, and it is the earliest
creator artifact in the whole corpus.

The audio is 5.198 seconds of 44.1 kHz stereo at 320 kbps, encoder tag
`Logic Pro X 10.4.1`. Its two channels are **99.43% correlated**, so subtracting
them cancels the music and leaves a 1.5% residual — and that residual is a
picture. Rendering the L−R difference as a spectrogram over 0-8 kHz shows eleven
two-digit numbers drawn in the time-frequency plane:

    48 41 53 48 54 48 45 54 45 58 54

Read as hex ASCII that is `H A S H T H E T E X T` — **`HASHTHETEXT`**. I decoded
this independently from the MP3 rather than accepting the published reading, and
the detail that the published account misses is the *encoding*: the creator did
not draw the letters. He drew **hexadecimal byte values as decimal digit pairs**.
That is a real signal about how this author thinks, and it is worth carrying into
every other undecoded artifact.

I also checked the rest of the file for further payloads and there are none. Above
16 kHz the difference channel is noise at −69.6 dB. The sum channel and each
individual channel are flat at 9-15 dB with variance 38 across the whole band, and
their spectrograms show only the two loop-point transients. The one message is all
there is.

## What HASHTHETEXT explains, and what it does not

It closes a loop that was previously unexplained. The SalPhaseIon stream ends with
`shabefourfirsthintisyourlastcommand` — "sha256, **our first hint is your last
command**". The first hint, from February 2020, is `HASHTHETEXT`. The last command
a solver ran to arrive at that page was `sha256` of the first page's text. The
creator is confirming his own mechanism, not issuing a new instruction.

Taking it as a *final* instruction does not work. I hashed every authenticated
creator text — both phase 3 plaintexts, the first page text, the VIC message, the
recovered Architect speech with and without spacing, the raw SalPhaseIon stream,
the 2023 pipeline message, both solved URLs and the literal string `HASHTHETEXT` —
across seven spellings each and under sha256, double-sha256, sha256-of-hex-digest,
blake2s and first-32-bytes. That is 170 distinct valid scalars, checked against
both prize addresses in compressed and uncompressed form. **Zero matches.**

## Newer creator hints (decoded)

**2024-04-19 (halving day):** "There are few prizes to win besides the banter in
this chat: A private key, some 'obscure' intel, or what I hope most of you have
discovered by now, the most obvious reason to make sure you hold on to Bitcoin."
So the puzzle has multiple intended payoffs, not only the key.

**2026-01-01 New Year binary message**, decoded independently:

    Happy new year! Make the best of everything. Oh, and here's a "tiny hint" <3.

The tiny hint is the literal ASCII `<3`. That is the same heart mark the
Architect's "take this to heart" and the Half/Better-Half language have been
pointing at. Combined with Cosmic Duality / yin-yang, it is a creator-authored
emphasis, not solver ornament.

**2023-08-06:** "Once you hit a ying yang, you'll be able to solve it the same
day." Cosmic Duality is that milestone. The final step after decrypting Cosmic
is supposed to be short — "a true giveaway."

## SalPhaseIon structural identity: Witteveen

I reproduced the repository's structural SalPhaseIon chain from the raw fields
without taking it on faith:

```
F73D92  (yellow/blue spiral markers, blue=1)
  // 2     -> 7B9EC9     ("Half")
  + 3      -> 7B9ECC     ("Better Half", using the creator's <3)
  23 bits  -> BBBBYBBBYYBBBBYBBYYBBYY
```

That 23-bit colour string is **independently** the unique parse of S91 under the
rule "non-primes consume one symbol; primes consume `b`=Blue or `be`=Yellow."
So the `<3` / better-half increment is not an arbitrary edit of verified data —
it is the exact bridge from the first image's 24 marker bits to S91's 23-colour
cycle, including why prime 89 has no colour.

Continuing the chain on S570 (zero cells at the blue/yellow prime-colour sums
474 and 400, fold, Hill-order-one, T5, diagonals) yields the incomplete surname
`WITVEEN`. The creator's "theory of everything" → `TOE`, "zeroed out" → drop
`O` → `TE`, reinserted into `WITVEEN` → **`WITTEVEEN`**. That matches
H.J. Witteveen, editor of *The Heart of Sufism* (400 pages — the yellow sum)
and author whose themes (harmony, heart, finance, duality) sit in the Architect
prose. This is an identity result. It is not yet the private key: direct
brainwallets of the name, Sufi name, page-140 word `unaware`, and HMAC/XOR
combinations with the Cosmic bytes all miss both prize addresses.

## What was tested this round and closed

- Yin-yang dual of the Cosmic matrix (yang rows + yin cols, shift 18) also hits
  exact 80..117 and decodes to a different 68-byte string; neither it nor
  arithmetic combinations with the published base-38 output produce the prize.
- Cosmic halves as sum/difference of the prize scalars: fail against the known
  Half pubkey.
- Cosmic keys as 2-of-2 multisig: produce `3…` addresses, not the P2PKH prize.
- Witteveen / Karimbakhsh / unaware / HILLONE / ASKHSKEY / COMPS / `<3` as
  brainwallets, Cosmic passwords, 7-token XOR substitutions, and HMAC/XOR
  against Cosmic and Chain 4: no prize match.
