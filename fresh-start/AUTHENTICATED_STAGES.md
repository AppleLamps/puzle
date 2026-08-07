# Authenticated stages

"Authenticated" means an exact hash, a decryption to readable text, or an
independent source fixes the result. Everything in the first three sections is
reproduced by `tools/verify_all.py` from the files committed in this folder.
The last two sections are explicitly *not* authenticated and say why.

## Stage map

| Stage | Input | Authenticated output |
| --- | --- | --- |
| Poster | `images/poster/follow_the_white_rabbit.png` | `gsmg.io/theseedisplanted`, residual bits `0000` |
| Poster markers | the same 24 blue/yellow cells | every 8th spiral bit; packed → `F73D92` |
| Rebus | `images/rebus/*.png` | `theflowerblossomsthroughwhatseemstobeaconcretesurface` — a *visual* reading, see below |
| Phase 2 | `ciphertexts/phase2_keymaker.b64` | English keymaker text; password `sha256("causality")` |
| Phase 2 answer | seven-part concatenation | SHA-256 `1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5` |
| Phase 3 | `ciphertexts/phase3_riddles.b64` | English riddle text; password = the digest above |
| Phase 3 URL slug | first page's own visible text | `sha256("GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")` → `89727c59…52f6a32` |
| Phase 3.2 | `ciphertexts/phase32.b64` | Architect payload; password `sha256("jacquefresco…principle")` |
| Symbol record | 1,539 bytes inside phase 3.2 | SHA-256 `bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b` |
| EBCDIC map | those 1,539 bytes | a bijection onto exactly 26 lowercase letters |
| Beaufort | key `THEMATRIXHASYOU`, P = K − C mod 26 | Architect plaintext, SHA-256 `56c43a30…c94b2241` |
| VIC checkerboard | 149 digits inside phase 3.2 | the Half / Better Half funds message |
| SalPhaseIon literals | `archives/salphaseion_phase3.html` | `matrixsumlist`, `enter`, and two page literals |
| Blockchain | Half's spending transaction | Half's uncompressed public key |

## Poster

- 350×350 PNG; a 14×14 grid of 25px cells in five colours. The rabbit drawing
  crosses several cells, so each cell is read by majority colour.
- Counter-clockwise inward spiral from the top-left: down the left column, along
  the bottom, up the right, back along the top, then inward.
- Black and blue are 1, white and yellow are 0. 192 bits → 24 ASCII bytes, then
  4 residual zero bits.
- The 24 blue/yellow cells sit on the last bit of every byte, so they delimit
  bytes *and* restate that bit (blue = 1, yellow = 0). Packed: `F73D92`.

The URL is the acceptance test. An arbitrary read order does not produce
readable ASCII, does not leave a zero residual, and does not put the 24 markers
on a regular stride.

## Phase 3.2 payload structure

After decryption the 2,422-byte payload is, in order:

1. English preamble, ending `One for one, four for one.`
2. 1,539-byte record over 26 high-bit symbols
3. 149-digit line
4. One sentence naming a checkerboard alphabet
5. An 80-byte OpenSSL envelope

The preamble writes its own instructions. "One for one, four for one" reads as
1141 — IBM EBCDIC code page 1141 — and decoding each symbol byte as EBCDIC gives
a bijection onto 26 lowercase letters, which is the check that the reading is
right. "I've designed you a beautiful strategic position" reads as Beaufort; the
key `THEMATRIXHASYOU` is "the matrix has you" with Neo replaced by *you*, as
elsewhere in this puzzle. The checkerboard alphabet is spelled out by the
sentence "A fubcd-king & oracle-queen, thingky mvps, on a sad board…".

Python has no `cp1141`; `tools/phase32_classical.py` uses `cp273`, which is
EBCDIC 1141 without the euro sign and agrees on every byte in this record.

### A defect in the checkerboard alphabet

`FUBCDORA.LETHINGKYMVPS.JQZXW` is 28 positions but only 27 distinct characters:
`.` appears twice. Neither `.` cell is selected by this ciphertext, so the
decode above is unaffected — `phase32_classical.py` prints that check. Any
future decode reaching one of those cells would be reading an unresolved
character.

## Architect plaintext — named substrings

Offsets are 0-based into the authenticated 1,539-letter A–Z stream. These are
observations about where words sit, nothing more: no indexing convention is
creator-stated.

| Offset | Substring |
| ---: | --- |
| 479 | `PRIVATEKEY` |
| 511 | `TAKETHISTOHEART` |
| 535 | `WISEMANABOVE` |
| 562 | `HUNDREDFOURTY` |
| 1021 | `SOURCECODES` |
| 1103 | `PRIMEBASICS` |
| 1157 | `TWENTYTHREECIPHERS` |
| 1175 | `SIXTEENENCRYPTIONS` |
| 1198 | `SEVENINTERTWINEDPASSWORDS` |
| 1238 | `PRIVATEKEY` (second occurrence) |
| 1529 | `CIAOBELLAO` |

## SalPhaseIon page — what actually decodes

From `archives/salphaseion_phase3.html`, reproduced by `tools/salphaseion_fields.py`:

| Field | Position | Decodes to |
| --- | --- | --- |
| a/b binary run | offset 91, 104 bits | `matrixsumlist` |
| a/b binary run | offset 959, 40 bits | `enter` |
| plain page text | before the envelope | `shabefourfirsthintisyourlastcommand` |
| plain page text | after the envelope | `shabefanstoo` |

The stream's structure: a 91-character field over `a`–`i`, the `matrixsumlist`
binary run, a 570-character field over `a`–`i`, then two shorter `z`-separated
fields, then the literals and a split Base64 envelope.

**Not reproduced here.** Other write-ups list `lastwordsbeforearchichoice` and
`thispassword` among this page's decoded fields. They do not decode from the
copy committed here: the two `z`-separated digit fields resolve to nothing
readable under digits→hex or digits→decimal. Both strings do appear in the
creator's seven phrases, so they are not fabricated — but this folder cannot
show them coming off this page and does not claim they do.

## Not authenticated

- **The rebus.** The eight tiles are committed and the pairing into "cryptologic
  warning, can you dig it?" is a visual reading of pictograms and letter
  fragments, not a computation. It is persuasive, and it is not a hash.
- **The SalPhaseIon envelopes.** The Cosmic textarea blob and the 80-byte
  envelope decrypt to high-entropy output under many passwords. One such
  password unpads cleanly and yields 60 bytes of noise — a live demonstration
  that clean padding is not evidence. No decrypt of these has produced anything
  a reader would call plaintext, and the creator's stated criterion is that
  breaking this phase should "give the feeling of the phase's name".

## Fitted, not authenticated

Exact arithmetic that rests on a convention nobody has shown the creator chose.
`tools/fitted_observations.py` recomputes both and prints the assumption with
each, so the number never travels without its caveat.

- **479.** Assigning the first 24 primes to the 24 poster markers in spiral
  order gives blue 484, yellow 479. Dropping the blue prime 5 leaves 479 = 479.
  Assumes consecutive primes from 2, spiral-order assignment, and that "zeroing
  out" means dropping a prime.
- **Offset 479.** Under 0-based indexing, `architect[479:]` begins
  `PRIVATEKEYYOUVEEARNEDITBUTPLEASE`. Under 1-based it starts one letter earlier.
  Assumes 0-based indexing and that a poster-derived number indexes this text.

The hit is exact and it is the strongest structural result here. It is also not
a key derivation: nothing in it produces a scalar.
