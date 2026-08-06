# Rebuilding the puzzle from creator-sourced material only

> Navigation: [repository index](README.md) ·
> [solution walkthrough](SOLUTION.md) ·
> [running attempt log](docs/ATTEMPT_LOG.md) ·
> [transcript index](docs/TRANSCRIPTS.md)

Everything below is separated by provenance. The distinction matters because the
public corpus mixes creator artifacts with solver interpretation, and several
widely repeated "facts" turn out to be the latter.

> **This file is mixed-provenance; the title names its subject, not its
> authority.** Only [The creator's statements, in order](#the-creators-statements-in-order)
> and [Newer creator hints (decoded)](#newer-creator-hints-decoded) are primary.
> Every other section — "re-examined", "missed construction", "continuation
> audit", "poster re-exam", and all of the closed/open notes — is solver
> analysis, and is hypothesis under the rule stated immediately below, however
> confidently it is written. Do not cite those sections as creator evidence.
> This warning exists because an agent did exactly that.

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
| 2020-01-04 | (image) a still of the Merovingian's cake from *The Matrix Reloaded* — the **causality** scene, ten days before the poem below. `causality` is the authenticated phase-two part-one password |
| 2020-01-14 | "Roses are White but often Red. **Yellow has a number and so does Blue.** Go back to the first puzzle piece without further ado. It might have shown you only one door, beware that **the rabbits nest may contain a whole lot more.**" |
| 2020-02-20 | (image) a Decentraland screenshot captioned 😎, parcel label **"GSMG.io Puzzle piece, -41,-17"** — creator provenance for the Decentraland stage whose audio difference channel decodes `HASHTHETEXT` |
| 2020-05-11 | "who knows what you'll find after opening the **2nd door**. The price is in half, but what does it mean" |
| 2020-08-02 | "Really **nobody managed to find the extra door**, didn't expect that after the earlier pace of cracking things." |
| 2021-01-21 | "a few might **not require the internet** anymore." |
| 2021-03-01 | "You are at the **prime part** already??? … shouldn't have said that. That might have been a hint." |
| 2021-03-14 | "Breaking salphation should be **giving the feeling of the phase's name**." |
| 2021-12-02 | "There is / Another / D O O R" |
| 2021-12-25 | "The previous 'there is another door hint' is still a thing. We're not sure if anyone has found another door so far … **prime numbers** … that is definitely an aspect which is required to proceed. Furthermore, along the way, **some characters need to be 'zeroed out'**." |
| 2021-12-31 | "The only date I give away is the **expiry date of Neo's passport**." (`11-09-2001`) |
| 2023-01-09 | "At least **prime number is very important** to get any further." |
| 2023-02-23 | an encoded image decoding to the pipeline below |
| 2023-05-02 | "Still remarkable that scene. Especially the **expiration date of his passport**." |
| 2023-08-03 | "Are you really looking for just the btc…?" and "Actually, **the hardest part is done**." |
| 2023-08-06 | "Once you hit a **ying yang**, you'll be able to solve it the same day." |
| 2025-04-28 | "Did anyone found yingyang? I don't think so … when yingyang is reached, **2 hours max**." / "It's the next phase." |
| 2026-03-03 | "**I only need to look at the address. If any of you reaches the next phase, the price is taken in no-time.**" (answering a claimed prime-index extraction of "ying yang"/"salvation") |
| 2026-03-03 | "No hints, only free will." / "Jacque was quite an inspiring lad I'd say." / "I'm going to rewatch episode 3.5 with **the better half**." |
| 2026-05-28 | "Ah, ofcourse. **The puzzle is still valid!**" |
| 2026-07-12 | "Most of you know the puzzle WAAAY better than me at this point. **I have a hidden laptop which I haven't touched in years. On that thing… is the actual answer.**" |
| 2026-07-12 | "**My close friends have the best chance of solving it** (a few tried). But they don't have the skills some of you do." immediately followed by "**NOTE: that is a hint.**" |
| 2026-07-12 | "I held quite a secret in my head which I seriously wanted to share with the planet… for those who can understand what I meant" / "**The '5' btc was never the actual prize. That was only a tiny fraction.**" / "(And yes, **the btc is still available** before you fire any questions)." |
| 2026-07-12 | asked "salphaseion is 100% solveable?" he answered "**Yes**", then: "And **IIFF I'm somehow still wrong, which I'm most likely not as I've verified many times back then after some sad rushed mistakes**, it's all still solvable with a few stable qubits.", then "But... Bip360 anyone. Thoughts?" (messages 66587-66590; full quote verified against export bytes 2026-08-06) |
| 2026-07-12 | (to a sceptic) "**Some already found it. And understood not to risk it…** 🤐" |
| 2026-07-16 | "Lately, I'm working with many **NOTES**." (in a thread about the 2026-07-12 "NOTE: that is a hint") / "Give yourself yourself and yourself will be given yourself." |

The 2023-02-23 post is the single most valuable creator artifact, because it is
the creator describing his own construction:

    yellowblueprimes
    matrixsumlist
    lastwordsbeforearchichoice
    yinyang
    wewontgiveawaythepassword
    itsinfrontofyoureyesbutyourenotseeingit
    verylaststepisatruegiveawaypromised

### Contested readings of the table above

These are **interpretations, not creator statements**, and they are kept out of
the table so that a reader cannot mistake one for the other.

- *"still solvable with a few stable qubits"* (2026-07-12). **SETTLED
  2026-08-06 against the primary bytes.** The full exchange (table above) shows
  the clause governed by an explicit double conditional: "IIFF I'm somehow
  still wrong, which I'm most likely not as I've verified many times back then
  after some sad rushed mistakes". The creator's primary claim is that
  SalPhaseIon is 100% solvable ("Yes", direct answer) and classically verified;
  the qubits line is a fallback in case of residual authoring error, uttered
  next to BIP 360 quantum-migration chatter. The earlier ECDLP annotation was
  an artifact of quoting the clause without its conditional. Do not plan around
  quantum hardware, and do not treat the remaining gap as discrete-log-hard on
  this evidence: every other statement supports a finite chain of ordinary
  operations, verified end-to-end by the author.
- The 2023-02-23 pipeline is creator-authored and its **order** is the strongest
  structural constraint available. Which object each of its seven phrases acts
  on — the 196-cell poster grid, the 24 markers, the S91 field, the Architect
  plaintext — is *not* stated by the creator and is solver inference every time.

## The 2026 statements, read carefully

Source: the 2026-08-05 Telegram export (see
[transcript index](docs/TRANSCRIPTS.md)). The creator appeared four times after
the previous table entry — 2026-03-03, 2026-05-28, 2026-07-12 and 2026-07-16 —
and has not posted since 2026-07-16. He was self-declaredly drunk on 07-12 and
07-16, which is a reason to weigh the statements carefully, not to discard them:
the same condition preceded the 2025-04-28 remarks that turned out to be
accurate.

What actually constrains the search:

- **Reaching yin-yang means the prize is already gone.** 2026-03-03: "I only
  need to look at the address. If any of you reaches the next phase, the price
  is taken in no-time." Combined with 2023-08-06 ("once you hit a ying yang,
  you'll be able to solve it the same day") and 2025-04-28 ("2 hours max"), the
  creator has now said three times that yin-yang is the last conceptual step and
  that everything after it is mechanical. There is no phase after yin-yang to
  plan for.
- **Yin-yang is still unreached as of 2026-03-03.** He did not accept the
  claimed prime-index extraction of "ying yang"/"salvation"; his answer was that
  the funded address is his only oracle, and it has not moved.
- **The puzzle is still live and the coins are still there** (2026-05-28,
  2026-07-12). Confirmed independently by the address history.
- **The puzzle is classically solvable, author-verified.** Asked directly
  whether SalPhaseIon is 100% solvable, he answered "Yes", and framed the
  qubits scenario as conditional on "IIFF I'm somehow still wrong, which I'm
  most likely not as I've verified many times back then after some sad rushed
  mistakes". (SUPERSEDED reading, kept for the record: this bullet previously
  asserted the creator believes the remaining obstacle is discrete-log hard;
  that came from the truncated quote and is withdrawn.) The "sad rushed
  mistakes" he verified against are the known published-artifact fixes of the
  "givetit" class, which is a reason to keep checking artifact provenance
  across creator edits.
- **"The '5' btc was never the actual prize. That was only a tiny fraction."**
  Read against 2023-08-03 ("are you really looking for just the btc…?"), this is
  most plausibly about the "secret in my head" he wanted to publish, not about
  additional unlisted funds. No second funded address is known.
- **The one self-declared hint** is 2026-07-12: "My close friends have the best
  chance of solving it (a few tried). But they don't have the skills some of you
  do. NOTE: that is a hint." Taken at face value it says the final step depends
  on personal knowledge of the creator rather than on cryptanalytic skill — the
  same shape as the already-confirmed "Half and Better Half" being his partner
  rather than two derivable keys. It is not actionable on its own, and no
  bounded family has been built from it.
- **`NOTES` (2026-07-16)** is the only genuinely open new lead: a capitalised
  callback to "NOTE: that is a hint", left unexplained. Recorded as open, not
  interpreted.

What does **not** constrain the search, and should not be mined:

- "You have to be in your prime for that" (2026-07-16) is a pun inside a
  conversation about whether 2 should count as prime. It is not a prime hint.
- "It's hidden in a room with a hidden door" (2026-07-16) answers someone joking
  about searching Ibiza for his physical laptop. It is about the laptop, not
  about a second door in the poster.
- The drug and drinking material, the BIP 360 explanation he pasted from an AI,
  and the Ibiza logistics carry no puzzle content.

## Where we went wrong (forensic)

The self-authenticating trail is real through stage 1 → rebus → phase 2/3 →
SalPhaseIon field tokens. The fitted five-token password and first-record WIF
produce a reproducible one-way Chain‑1→Chain‑2 decryption, not a demonstrated
mutual unlock. Prize keys were never produced after that. The wrong turn is not
“SalPhaseIon was fake.” It is that
**the next lock was replaced by a community story.**

```
Creator trail (named):
  first image ──2nd door──► yellowblueprimes ──► matrixsumlist
       ──► lastwordsbeforearchichoice ──► yinyang ──► short giveaway

Community trail (followed):
  first image ──door 1 only──► phases ──► SalPhaseIon
       ──► “Cosmic Duality” AES ──► base38 / THE_HALF / Chain4 ──► ∞
```

**Damaging fork #1 — left the first image.** From 2020-01-14 the creator says
go back to the first piece; the nest holds more than one door. He repeats
“2nd / extra / another door” through 2021-12-25 and still calls **yingyang
unfound** on 2025-04-28. Public work treated door‑1 (`theseedisplanted`) as
done and moved forward forever.

**Damaging fork #2 — Cosmic Duality ≠ yinyang.** The HTML heading is the only
creator use of those words. Solvers glued it to his `ying yang` language and
built the 7‑XOR. Proof that equation is false: if Cosmic decrypt *were*
yinyang, he would not say in 2025 that nobody has found it. The Dec 2022
“scary specific” reply was to a **yin‑yang image** a solver googled — that
endorses yin‑yang as a concept, not “AES‑decrypt the Cosmic textarea.”

**Damaging fork #3 — Chain‑1 password ≠ his 2023 recipe.** Working password:
`matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist`.
His construction words: `yellowblueprimes`, `matrixsumlist`,
`lastwordsbeforearchichoice`, `yinyang`. Missing from the password: the first
and fourth. Added by solvers: `enter`, `thispassword`. Chain‑1 is a real joke
unlock; it is **not** the pipeline he published.

**What we (this effort) specifically repeated:** Cosmic password / matrix /
base38 / half‑arithmetic loops after already knowing Cosmic was unauthenticated;
underweighting red/roses, primes+zeroing, off‑white `(7,4)`, 86=86 dual, and
alternate spiral readings on the poster.

**Corrected surface, now an exact but fitted structural hit:** assigning the 24
direct poster colours to the first 24 primes gives Blue = 484 and Yellow = 479.
Their imbalance is the blue prime 5. Zeroing 5 gives **479 = 479**, a literal
balance. Zero-based offset 479 of the authenticated A–Z Architect plaintext is
exactly the `P` of `PRIVATEKEY...`; ordinary one-based position 479 is the
preceding `E`. The arithmetic is exact, while consecutive-prime assignment,
zeroing semantics, and zero-based indexing remain clue-driven conventions.
Cosmic AES / Chain4 / base38 are not needed for this structural hit.

## The missed construction

The creator's words now have one compact, reproducible reading:

```
yellow / blue / primes:
  BBBBYBBBYYBBBBYBBYYBYYBY
  consecutive primes 2..89

matrix sum list:
  Blue   = 2+3+5+7+13+17+19+31+37+41+43+53+59+71+83 = 484
  Yellow = 11+23+29+47+61+67+73+79+89                = 479

zero out:
  484 - 479 = 5
  5 is itself a blue-list prime
  zero it: Blue = 484 - 5 = 479

yinyang:
  479 = 479

giveaway in front of our eyes:
  authenticated Architect plaintext[479:] =
  PRIVATEKEYYOUVEEARNEDITBUTPLEASE...
```

This is not a scored near-match. All operands are direct artifact values, the
zero is uniquely supplied by the imbalance, and the resulting index lands on
the exact phrase promised by the creator. It explains why broad first-grid
duality and yellow-bit-flip searches failed: yin-yang is the **balanced prime
sum**, not a black/white pixel transform.

The continuation also authenticates two more old clues. The Jacque Fresco quote
immediately above the Architect record has exactly **23 words** and exactly
**140 characters** after punctuation is removed while spaces remain, explaining
`WISEMAN ABOVE` and `HUNDRED FOURTY`. The creator-emphasised passport date is
prime and, as the 24-bit integer `0xA94021`, gives:

```
F73D92 XOR A94021 = 5E7DB3
5E7DB3 = 10111100111110110110011  (23 bits: 16 ones, 7 zeroes)
```

That matches the authenticated `TWENTYTHREE CIPHERS / SIXTEEN ENCRYPTIONS /
SEVEN INTERTWINED PASSWORDS` language and partitions the 23-word quote. It does
not yet specify the final cipher/key operation uniquely.

## What follows, and what has to be fixed

**1. There is a second door, it branches from the first image, and the entire
public effort is on the other branch.** The creator says so five separate times
across four years, in 2020-01-14, 2020-05-11, 2020-08-02, 2021-12-02 and
2021-12-25, and as late as December 2021 says nobody had found it. Every line of
published work — the repository, and both AI agents working this problem — is
pushing down SalPhaseIon → Cosmic → base-38. The creator points backwards, at
`sources/follow_the_white_rabbit.png`.

**2. The creator's own four-part recipe does not match the solver chain.** His
list is `yellowblueprimes`, `matrixsumlist`, `lastwordsbeforearchichoice`,
`yinyang`. The working chain 1 password is
`matrixsumlist` + `enter` + `lastwordsbeforearchichoice` + `thispassword` +
`matrixsumlist`. Two of the creator's four components — **`yellowblueprimes` and
`yinyang`** — appear nowhere in the solver chain, and the two that do appear are
joined by words the creator never lists.

**3. "Cosmic Duality" is a page label, not a creator instruction.** The
SalPhaseIon HTML has a second textarea headed `Cosmic Duality`. That is the
**only** creator-published use of those words. The Telegram corpus never says
"Cosmic", "Duality", or "decrypt the second blob." The creator *does* say
`ying yang` / `yingyang` and lists `yinyang` in the 2023 pipeline — solvers
**equated** that with the Cosmic textarea and built the 7-XOR decrypt. That
equation is not creator-sourced. Treating Cosmic AES as the mandatory next
lock is community gravity, not his hint trail.

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
pointing at. That is creator-authored emphasis on duality / better-half
language — not a warrant to AES-decrypt the page label "Cosmic Duality."

**2023-08-06:** "Once you hit a ying yang, you'll be able to solve it the same
day." He names **yingyang**, not Cosmic. Whether that milestone is on the first
image (e.g. the 86=86 dual), elsewhere in SalPhaseIon, or something not yet
reached is open — it is **not** established that it means "AES-decrypt the
Cosmic textarea."

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

## Continuation audit (creator-sourced only)

### Closed readings of Cosmic / Chain 4

- Cosmic base-38 as `04 || x || y` is **not** the Half prize pubkey. Only the
  leading `0x04` matches; the point is not on secp256k1. Same for alternate
  bases 39–41 and for “zero primes then re-base-38” variants that happen to
  start with `02`/`03` — those prefixes do not decompress to curve points, and
  no 33/65-byte window hits either prize hash160.
- Elliptic-curve combinations of the Cosmic Half/Better scalars and points
  (`P_h±P_b`, `2P_h±P_b`, products, inverses, XOR-as-int, `±trail1`, and
  SHA-256 of every creator pipeline phrase as a third operand): zero prize
  matches. Best public-x nibble LCP observed was 2 (noise).
- BIP32 (`Bitcoin seed` HMAC-SHA512) from Cosmic halves, their XOR/concat,
  `F73D92`/`7B9ECC`, Witteveen/`unaware`/`yinyang` digests, and common paths
  including `m/44'/0'/0'/0/0`: zero matches.
- Chain 4 `C(7,3)=35` star-selections, 35-bit control masks from
  `F73D92`/`7B9ECC`/`trail1`/Cosmic XOR key, and 8+7+…+2 pyramid XOR
  reductions: zero matches.
- Creator-pipeline and instruction-joke passwords against the Cosmic envelope
  under both MD5 and SHA-256 `EVP_BytesToKey`: the **only** hit remains the
  published seven-digest XOR. That, plus Chain 4’s `+-` / 31+35×32 layout
  after the mask forced by `rem[:8] XOR Salted__`, is still the structural
  authentication for this branch — not padding alone.

### First-image second-door notes

- Majority vs centre-pixel sampling differs at exactly one cell, `(7,6)`, a
  rabbit stroke. That flips only padding bit 193, so residuals are `0000`
  (majority, 101 ones) vs `0100` (centre, 102 ones). Marker stream `F73D92`
  is identical under both.
- Forcing the off-white cell `(7,4)` to a 1-bit flips the URL’s `n` to `~`
  (`gsmg.io/theseedispla~ted`). Treating it as white leaves the known URL.
  Neither reading, nor rabbit-nest bitmaps, nor resistor-digit concatenations
  of the 24 markers, unlock Cosmic or either prize address.
- The 2021-04-01 hint `another door might be found on {1},{4},{21}` is
  followed the same day by the creator asking what usually happens on April
  1st. Treat it as April Fools, not a coordinate. The 2026-07-13 community
  reading takes the three numbers as row indices into a 21-row decomposition of
  the SalPhaseIon plaintext — row 1 = `dbbi`/S91, row 21 = `anstoo`, row 4 =
  `faed[94:201]` — so that the line reads "two doors you've got, one you don't".
  Its author retracted the rigor when asked for the boundaries: the split is
  "as-transcribed from the soup layout" and "the 21 boundaries were NOT fixed
  independently before applying {1,4,21}". The canonical `textarea1` has no line
  breaks, so there is no 21-row structure to recover. Only the ~107-character
  S570 slice survives as an untested operand.

### Cosmic matrix authentication is weaker than claimed

The unique exact secondary range `80..117` at shift 7 is **not rare**: about
**18%** of random 1327-byte strings have at least one shift with that exact
min/max (200-trial Monte Carlo). Combined with the Chain-4 mask being fitted
to force a `Salted__` header, the public Cosmic 7-XOR branch remains
*structurally used* by solvers but is **not** strong proof that yin-yang has
been reached — consistent with the creator’s 2025-04-28 remark that it had
not.

Issue #82’s matrix invariants reproduce on the public Cosmic plaintext:
`S=5193`, `Wr=268603`, `Wc=268828`, and `p_big=58` equals the count of
secondary values `≥ 100`. Its claimed 79-byte SalPhaseIon SHA `e2590f15…` does
**not** match chain1/2 or either Cosmic 79-byte triplet and was not reproduced
from public envelopes (`salphaseion_79_anchor_hunt.json`).

### Closed this session (still no prize key)

- **Better-Half-aware giveaway audit** (`creator_frontier_giveaway_audit`):
  HASHTHETEXT-style digit-pair decode over S91/S570 variants; Cosmic base-38
  XOR/sub delta vs the known Half pubkey; Witteveen/page-140 Chain4 selectors;
  creator-pipeline XOR + instruction-substitution Cosmic passwords; halving
  arithmetic on Cosmic halves. **36,419** scalar tests, **0** prize matches.
  Cosmic `Dy` begins ASCII-ish `P544…` — treated as noise unless a second
  confirmation appears.
- **SalPhaseIon selector frontier** (`salphaseion_selector_frontier_audit`):
  S570 Vigenere/Beaufort/Playfair with creator keys; phase-3.2 “one for one,
  four for one” number-line material; alternate passwords on the 80-byte
  SalPhaseIon envelope. **59,644** scalar tests, **0** matches. Best vanity
  was only a 4-nibble hash160 prefix (noise at that scale).
- **XOR-triangle / trail1 formula** (`xor_triangle_trail_audit`): Pascal /
  WITVEEN C(7,3) folds, T5 HILLONE+ASKHSKEY, trail1 pairings, and
  `[-4,2,32,12,4,27,0,2,-16,15]` Cosmic strides. **8,771** unique scalars,
  **0** matches. Issue #88 `cosmic_A` / `cd3fea3d…` / `ca[280:312]` remain
  unreproduced; `cc[833:865] XOR` over all Cosmic/Chain4 windows never
  reaches a reproducible LCP≥5 against Half’s public x.
- **Yin dual secondaries**: only `yangR+yangC@7` and `yangR+yinC@18` hit
  exact 80..117; full yinR/yinC span-37 family (38 decodes) plus arithmetic /
  EC combinations of their halves — **0** prize matches. Flip-prime matrix
  duals at shifts 14 and 66 also decode to 68 bytes and miss.
- **Near-key search**: Half pubkey − Cosmic/chain scalars within
  `|Δ|≤50_000` (BSGS) and Better hash160 within `|Δ|≤2_000` of those bases —
  empty. Multiplicative `k∈[1..256]` near-keys empty. EC successive
  halvings of the Half point (`Half/2^n`) do not yield Better’s hash160.
- Rabbit-nest impure cells (7 cells, black counts
  `100,225,150,75,225,100,50`) and packed bitmaps do not open Cosmic or
  match either address.
- **Second-door frontier** (`second_door_frontier_derivations`): all-196
  resistor + prime-zeroing, half-image splits, 14×14 matrix
  sum/product/det, off-white mask, sub-cell rabbit morphology, and
  URL-prime Y/B insert → HASHTHETEXT. **102,093** unique scalars and
  **41,660** AES trials → **0** prize matches / no new structured Cosmic
  plaintext.
- `p_big`/`p_little` selection masks into digits/Cosmic/Chain4, embedded
  WIF scan, and `+-` control folds from `F73D92`/`trail1` — **0** matches.

### Still open (authenticated material only)

**Hard rule:** do not attack Cosmic AES / Chain 4 / base-38 as the next
mandatory lock. The creator never named those. Closed Cosmic trials stay in
the audit above as negatives only.

1. The **second door** from `sources/follow_the_white_rabbit.png` / `puzzle.png` under
   `yellowblueprimes` + primes + zeroing + the unused red resistor line.
   Creator 2025-04-28 still says **yinyang not found** (“2 hours max” once
   reached). That milestone is whatever *he* named `yinyang` — not the HTML
   heading on the SalPhaseIon page.
2. The **giveaway after yin-yang**: once that milestone is hit, the last step
   is supposed to be short (`verylaststepisatruegiveawaypromised`). Do not
   fill the gap with unreproduced solver labels (`cosmic_A` / `row1-4` /
   `K_I1`) or Issue #82’s unreproduced `e2590f15…` SHA.
3. Witteveen / *Heart of Sufism* as the “obscure intel” prize versus a still-
   unknown transform into the BTC scalar.

## Independent re-parse (avoiding public Cosmic / Chain4 lore)

Rebuilt the SalPhaseIon textarea from the archived HTML only. All 1075 tokens
are single characters. The mechanical fields are:

```
S91 | AB1→"matrixsumlist" | S570
| z + ai/o → "lastwordsbeforearchichoice"
| z + ai/o → "thispassword"
| z + "shabefourfirsthintisyourlastcommand"
| b64 #1 → OpenSSL env48 (Salted__, salt 3ab585348552415d)
| AB2→"enter"
| b64 #2 → raw 48 bytes (no Salted__ header)
| "shabefanstoo"
```

The community `extract` path **deletes** the middle `enter` marker and glues the
two base64 runs into one 96-byte envelope. That glued blob *does* open with the
instruction-joke password

`matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist`

to a 79-byte record whose first-32 WIF opens the phase-3.2 trailing blob — so
the glue path is self-consistent. Separately, **env48 alone does not** open with
that same password. Treating env48 and raw48 as two locks (“sha256 answer too”)
has not yet yielded an authenticated second plaintext. Padding hits on env48
(`hashthetext`, etc.) sit inside the ~0.4% MD5-EVP false-positive rate and do
not unlock raw48 or Cosmic under sha256 of the candidate plaintext.

### Cosmic without semantic tokens

The public Cosmic password XOR uses `yourlastcommand` and `secondanswer`, which
are **not** alphabet-decoded from the page. Replacing them with literal fields
(`hashthetext` / `HASHTHETEXT` / `sha256answertoo` / `SalPhaseIon` /
`shabefanstoo`) and with the creator’s seven pipeline words produces no new
authenticated Cosmic plaintext beyond the known 7-XOR and chance-level padding
hits. In particular `sha256("yin") XOR sha256("yang")` opens Cosmic under MD5
EVP, but random two-word XOR pairs hit at ~0.6% on the same blob — same class of
evidence as other padding luck. Cosmic sha256-EVP false positives are rarer
(~0.26%); `SalPhaseIon` as a raw sha256-EVP password is one such hit and is
**not** treated as yin-yang.

### First-image yin-yang that public Cosmic work skipped

On `sources/follow_the_white_rabbit.png`, majority-colour sampling gives **exactly 86
black cells and 86 white/off-white cells**. Blue=15, yellow=9. That equal black/
white split is a literal duality on the artifact the creator keeps pointing at,
and it does not depend on Cosmic or Chain 4. The off-white cell remains at
grid `(7,4)`, spiral index 163 (0-based), still the only near-invisible anomaly.
Seven rabbit-nest cells are impure (two colours only). Geometric dual hashes,
Half-point tweaks by image scalars (86, F73D92, spiral index, …), and
pipeline-suffix brainwallets still miss both prize addresses.

Door-1 spiral still reads `gsmg.io/theseedisplanted` with off-white as white;
forcing it as 1 yields `…pla~ted`. Reverse-spiral / prime-zeroed bitstreams do
not produce a second URL or prize key in the trials run here.

### X2SH endgame (from causality plaintext, not Cosmic)

The keymaker block `# X 2 S H 4 Y 0 Q B 15 #` is **not** required to open phase 3
(the SafenetLunaHSM concatenation already does). Chat-era claims that solving it
*is* solving the puzzle remain plausible as an endgame. Independently:

| var | reading | value |
| --- | --- | --- |
| S | Klingon `cha'+(vagh*jav)` | 32 |
| B | `(5i - i)^2` from the serial/`sqrt(-1)` clue | −16 |
| Q | Mr Robot fish `qwerty` → `qwertyuiop`; numbers above I,W | 82 or 28 |
| H | “Answer to only this puzzle but nothing else” × −1 | **unsolved** (not 42 by the wording) |
| Y | no direct clue (keyboard-above-Y = 6 is a guess) | **unsolved** |

“Worst gear on the highway” = reverse. Large concatenations / polynomials /
sha256 of filled templates over the plausible (H,Y,Q) grid — **0** prize matches.
H = −86 (from the B/W balance) was included; still nothing.

### Prize addresses (still funded)

Half `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` ≈ 1.256 BTC remaining (pubkey known).
Better `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` ≈ 3.751 BTC, never spent.
No candidate from this re-parse hits either address.

## Poster re-exam: QR + bunny (what keeps pulling us back)

The checked-in `puzzle.png` (1048×1556) is the full first puzzle piece. It is
**not** just the 14×14 grid. Top-to-bottom:

1. **Bunny grid** — exact 3× nearest-neighbor of `sources/follow_the_white_rabbit.png`
   (byte-identical when cropped to 1047×1047). Door-1 spiral still reads
   `gsmg.io/theseedisplanted`.
2. **Red divider** — solid `#ED1C24`, **15 px** thick. This is the only red in
   the poster. Creator 2020-01-14: *“Roses are White but often Red. Yellow has
   a number and so does Blue.”* Resistor red = **2**; white = 9. The red line
   has been treated as decoration and barely used.
3. **Footer** — hexagonal **G** logo (not a rabbit), title
   `GSMG.IO 5 BTC PUZZLE CHALLENGE`, a real **QR version 4 (33×33)** that
   decodes (zxing) to
   `https://www.blockchain.com/btc/address/1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`,
   and the same address in text.

### What is *not* the second door (closed this pass)

- **QR “merlon” gray texture** in the finder rings is anti-aliasing (identical
  35-pixel column of 234/236 in all three finders). Not an independent
  bitstream. Dirty modules exist only on finders.
- **Tiny second rabbit in the footer** — not present (BR corner is empty gray).
- **Bunny grid as a scannable QR** (pad to v1–v4 / Micro sizes, with or without
  synthetic finders) — no decode.
- Nest 5×5 downsamples of the seven impure cells only redraw the rabbit
  silhouette; black counts `/25 = 4,9,6,3,9,4,2`.

### Alternate spiral readings that *do* look door-shaped

Door 1 uses black/blue = 1, white/yellow = 0 (yellow/blue sit on each byte’s
LSB). Two deliberate reassignments produce fully printable 24-byte strings:

| rule | result |
| --- | --- |
| yellow forced to 1 (color-as-black) | `gsmg/io/uieseeeisqmaouee` |
| color LSBs zeroed / yellow→white | `frlf.hn.thdrdddhrpl\`ntdd` |
| off-white forced to 1 | `gsmg.io/theseedispla~ted` |
| prime spiral indices zeroed | `\x05SMe&Ig\x07ThEseEdiSPdaLtEd` (high printable) |

The yellow-LSB-flip string is the striking one: it is still `gsmg/io/…` shaped
(`.`→`/` on byte 4, and every yellow-marked LSB flips). No Wayback hit under
`gsmg.io/uieseeeisqmaouee`. It is the clearest *second reading* of the same
spiral that public door-1 work leaves on the table — pursue as second-door
material, not as a Cosmic password.

### Yellow-flip + red audit (this pass) — closed negative

Script: `scripts/second_door_yellow_red_audit.py` (+ follow-up JSON). Scope: first image
spiral variants, poster red divider facts (15 px `#ED1C24`, resistor **2**),
prime-index / char-prime zeroing, roses/red tokens, `{1},{4},{21}` hint
concat, HASHTHETEXT-style sha256 expansions. Gates: Half pubkey + Better
hash160; AES only on **chain1 / chain2 / phase32** (Cosmic excluded).

| check | result |
| --- | --- |
| door1 control | `gsmg.io/theseedisplanted` |
| yellow forced 1 | `gsmg/io/uieseeeisqmaouee` |
| unique scalars | ~2.9k (main) + 292 (follow-up) |
| prize matches | **0** |
| structured AES on auth envelopes | **0** |
| MD5/SHA padding hits | a few (incl. 79-byte chain1 under char-prime-zero) — same class as EVP false positives; not readable |

Also closed as passwords/scalars: `eqoe-km-wkgqgggkqsocmwgg` (yflip⊕2),
dot-fix `gsmg.io/uieseeeisqmaouee`, path `uieseeeisqmaouee`, yflip+`ED1C24`/
`15`/`2`/`8686`/`1421`, `yellowblueprimes‖yflip`, resistor digit stream
concat. **Next:** do not widen into Cosmic. Prefer a single joint rule that
earns the name `yinyang` (86=86 dual / off-white / red+yellow+blue together),
not more path-string brainwallets.

### Yin-yang joint-rule audit (this pass) — structural hit, key miss

Script: `scripts/second_door_yinyang_joint_audit.py`. The grid **does** carry
creator-shaped duality; none of the joint rules hit the prize keys.

**Structural facts (authenticated from the PNG):**

| fact | value |
| --- | --- |
| black / white+off | **86 / 86** |
| L/R black-white | **44/42** vs **42/44** (swap) |
| main diagonal | **7 black + 7 white** |
| off-white eye | `(7,4)`; rot180 dual `(6,9)` = **black** |
| resistor Y/B/(poster R) | 4 / 6 / 2 |
| row & col resistor sums | each total **900** (891 if eye zeroed) |

**Families gated (Half pubkey + Better hash160; AES on chain1/2/phase32 only):**
color-invert spirals; L⊕R / T⊕B / interleave halves; diagonal halves; yin/yang
coordinate & index paths (86 vs 86); `sha256(yin)⊕sha256(yang)` duals; eye +
RYB + `8686` joints; marker digit streams + red `2`; matrixsumlist row/col
CSV; rot180 / reverse spirals. **~2.4k unique scalars, ~8k AES trials → 0
prize matches, 0 structured AES.**

So `yinyang` is visible as **balance on the artifact**, but the transform that
turns that balance into a door/scalar is still missing. Do not fall back to
Cosmic. Next pressure should be on how `yellowblueprimes` + `matrixsumlist` +
this dual compose — not on hashing the word `yinyang`.

### Still the best “in front of your eyes” anomalies

- Off-white cell `(7,4)` = `(254,254,254)`, spiral index 163 — invisible at a
  glance; only difference from white in the whole grid.
- Black count = white/off-white count = **86** (yin-yang on the artifact the
  creator keeps naming).
- Red divider (resistor 2) + yellow/blue numbers — the January 2020 hint names
  three resistor colours; solvers used two.
