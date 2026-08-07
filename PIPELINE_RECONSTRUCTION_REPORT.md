# GSMG.IO 5 BTC puzzle — creator-confirmed pipeline reconstruction and Cosmic AES test

Date: 2026-08-06 (split-envelope poster-sum AES test added 2026-08-07)
Status: **underdetermined at one microstep** — the available artifacts fix every stage up to the operation immediately after the 479 yin-yang balance, but do not determine that operation.

This report is the result of a deterministic re-derivation of the first-image / zero-piece rabbit artifact, the `yellowblueprimes` balance, the `matrixsumlist` reading, the "last words before Architect choice" candidates, and targeted AES tests against the original Cosmic `Salted__` envelope. All key material was tested only against the public prize gates; no funds were moved.

Reproducible artifacts from this run:
- `reconstruct_pipeline.py` — the self-contained reconstruction/test script.
- `reconstruct_pipeline_results.json` — machine-readable first-artifact data, yellow/blue numbers, matrixsumlist list, Architect offsets, AES oracle validation, and every Cosmic AES candidate.
- `solver/poster_resistor_split_envelope_audit.py` — preregistered AES test of the 14×14 poster resistor sum lists against the SalPhaseIon `env48`/`raw48` split halves.
- `poster_resistor_split_envelope_preregistered.json` and its `.sha256` seal — the frozen candidate manifest.
- `poster_resistor_split_envelope_results.json` — the machine-readable result, including the single chance padding hit and the gate/legibility gating.

Commands executed:
```text
python scripts/solve.py
python -m solver.creator_pipeline_poster_architect_audit
python -m solver.second_door_yellowblueprimes_audit
python -m solver.matrixsumlist_instruction_audit
python reconstruct_pipeline.py
python -m solver.poster_resistor_split_envelope_audit
python -m solver.preregistration_integrity_audit
```

---

## 1. The exact reconstructed first / zero rabbit puzzle artifact

**File:** `sources/follow_the_white_rabbit.png` <ref_file file="C:\Users\lucas\github-repos\puzle\sources\follow_the_white_rabbit.png" />

| Property | Value | Source / method |
| --- | --- | --- |
| File | `sources/follow_the_white_rabbit.png` | archived creator image |
| Bitmap dimensions | 350 × 350 pixels | PIL `Image.open(...).size` |
| Cell size | 25 × 25 pixels | `CELL = 25` in `scripts/solve.py` <ref_file file="C:\Users\lucas\github-repos\puzle\scripts\solve.py" /> |
| Grid | 14 × 14 = 196 cells | derived from image / cell size |
| Black cells | 86 | majority-colour sampling |
| White cells | 85 | majority-colour sampling |
| Blue cells | 15 | majority-colour sampling |
| Yellow cells | 9 | majority-colour sampling |
| Off-white cell | 1 at (row 7, col 4) zero-based | majority-colour sampling |

**Reading convention.** The 196 cells are read in a down-first counter-clockwise inward spiral starting at the top-left corner:
- down the left column,
- right along the bottom row,
- up the right column,
- left along the top row,
- repeat inward.

**Bit / colour assignment.**
- Black and blue encode `1`.
- White and yellow encode `0`.
- Blue and yellow are the 24 *marker* cells; each marker sits on the final bit of a byte (spiral indices 7, 15, 23, …, 191 — every 8th bit).
- The marker colour restates that byte's LSB: blue = `1`, yellow = `0`.

**Decoded output.**
```text
Spiral body bits:     192 bits = 24 ASCII bytes
Spiral message:       gsmg.io/theseedisplanted
Padding bits 193-196: 0000
Marker stream bits:   111101111011110010010010
Marker stream packed: F73D92
```

This is the first / zero puzzle piece the creator's 2020-01-14 hint tells the solver to "go back to": *"Go back to the first puzzle piece without further ado. It might have shown you only one door, beware that the rabbits nest may contain a whole lot more."* <ref_file file="C:\Users\lucas\github-repos\puzle\CREATOR_SOURCED.md" />

**Resistor colour code mapping** (implied by "Yellow has a number and so does Blue" and the authenticated 24 marker bits):
- black = 0
- yellow = 4
- blue = 6
- white = 9
- off-white (the "eye") = 9 normally, 0 when zeroed

---

## 2. Inventory of yellow and blue elements and candidate numbers

### 2.1 Yellow and blue elements

The 24 markers are the only yellow and blue cells. Their spiral indices are:

```text
[7, 15, 23, 31, 39, 47, 55, 63, 71, 79, 87, 95,
 103, 111, 119, 127, 135, 143, 151, 159, 167, 175, 183, 191]
```

Every marker is the final bit of a byte. Counting markers by colour:
- Blue markers: 15
- Yellow markers: 9

### 2.2 Candidate numbers for "yellow" and "blue"

The only candidate numbers with direct provenance from the artifact and the creator's prime hint are the sums of the first 24 consecutive primes assigned to the marker positions, treating the marker stream as ordered.

```text
First 24 primes: 2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
                 73, 79, 83, 89

Blue markers  (15 positions): sum = 484
Yellow markers (9 positions): sum = 479
Difference: 484 - 479 = 5
```

The creator said "some characters need to be 'zeroed out'" and that the route "reveals another door". The balancing interpretation is: the blue prime 5 is the difference; zero it from the blue side; then `484 - 5 = 479 = 479`.

| Interpretation | Blue | Yellow | Zeroed | Result | Status |
| --- | --- | --- | --- | --- | --- |
| Consecutive primes, no zeroing | 484 | 479 | — | 479 vs 484 | creator-sourced prime requirement satisfied; not a key |
| Consecutive primes, zero the blue balancing prime 5 | 484 - 5 = 479 | 479 | blue prime 5 removed | 479 = 479 | **fitted structural hit**; zeroing semantics are solver-inferred but strongly clue-driven |
| Resistor-code totals (black=0, yellow=4, blue=6, white=9, eye=0/9) | full grid row sums 900 or 891 | — | — | structural count | tested, no key (<ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\second_door_yellowblueprimes_audit.json" />) |

**Provenance note.** The *assignment* of consecutive primes 2..89 to the 24 marker positions is not independently authenticated by the creator. The creator only stated that yellow and blue "have a number" and that "prime numbers … are required" and that some characters must be "zeroed out". The 479/484 balance is therefore the strongest *fitted* structural result, not a cryptographically authenticated key derivation. <ref_file file="C:\Users\lucas\github-repos\puzle\docs\ATTEMPT_LOG.md" />

---

## 3. Creator-supported prime and zeroing interpretations tested

### 3.1 Definitions

- **Prime position set `primes24`:** positions 2, 3, 5, 7, 11, 13, 17, 19, 23 in the 24-character marker/URL streams.
- **Prime position set `primes91`:** all primes ≤ 91, for the 91-character S91 field.
- **Zeroing modes:** `omit` (delete the character), `ascii-zero` (replace with `0`), `nul` (replace with `\x00`).

### 3.2 Tested families

All of these were executed by the committed audit `solver.second_door_yellowblueprimes_audit` <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\solver\second_door_yellowblueprimes_audit.py" />:

| Family | Input | Zeroing / prime operation | Result |
| --- | --- | --- | --- |
| Resistor digit streams | `6`/`4` marker sequence | raw, packed nibbles, yellow-then-blue, blue-then-yellow | NO_MATCH |
| URL / S91 character zeroing | `gsmg.io/theseedisplanted` and S91 | zero at `primes24` / `primes91` in all 3 modes | NO_MATCH |
| Prime-slot reinsertion | resistor digits / URL characters | insert blue/yellow prime values into non-prime slots of S91 | NO_MATCH |
| Four-token XOR | `yellowblueprimes` / `matrixsumlist` / `lastwords...` / `yinyang` | token XORs and concatenations | NO_MATCH |
| Witteveen bridge | `F73D92 // 2 + 3 = 7B9ECC` | red-line / eye / `8686` joints | NO_MATCH |
| 101/102 and off-white literals | (7,4) coordinate; spiral index 163 | row-major vs spiral index, prime tests | NO_MATCH |
| Full-grid resistor sums | row and column sums with eye=0/9 | 900 / 891 totals | NO_MATCH |

**Result summary** (`second_door_yellowblueprimes_audit.json`):
- 134 unique preimages
- 4,020 AES attempts
- 11 valid PKCS#7 padding hits (all high-entropy, none legible)
- 678 unique scalar attempts
- **0 prize matches**

Scope note: *"Finite creator-motivated family only. Does not re-enumerate plain spiral bit orders, the published 15/9 color-count reinsertion, or unconstrained password search."* <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\second_door_yellowblueprimes_audit.json" />

---

## 4. The precise meaning and remaining ambiguity of `matrixsumlist`

### 4.1 Authenticated facts

`matrixsumlist` is a *literal* in the SalPhaseIon source: the 104-symbol `a`/`b` block in the first textarea decodes to it exactly. It is also **phrase 2** of the creator's ordered 2023-02-23 pipeline <ref_file file="C:\Users\lucas\github-repos\puzle\CREATOR_SOURCED.md" />:

```text
1. yellowblueprimes
2. matrixsumlist
3. lastwordsbeforearchichoice
4. yinyang
5. wewontgiveawaythepassword
6. itsinfrontofyoureyesbutyourenotseeingit
7. verylaststepisatruegiveawaypromised
```

The tension: `matrixsumlist` is both a literal token and an instruction. If it is an instruction, the creator never stated which object it operates on.

### 4.2 Tested `matrixsumlist` interpretations

#### A. S91 and S570 as the matrix

`solver.matrixsumlist_instruction_audit` <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\solver\matrixsumlist_instruction_audit.py" /> preregistered and tested every rectangular factorisation of 91, 570, and 567 (S570 after the `fae` header):
- 102 sum lists
- two mappings: `a=1..i=9,o=0` and `a=0..i=8,o=0`
- both axes: row sums and column sums
- 9 serialisations and 4 derivations per list
- 3,672 logical scalar candidates
- tests against `solver.targets.gate_scalar_bytes` and AES on the authenticated SalPhaseIon short envelope

**Dimensional census:** only four sum lists have a length matching another authenticated field:
- `s570_after_fae/one_based/63x9/rowsums` → length 63
- `s570_after_fae/one_based/9x63/colsums` → length 63
- `s570_after_fae/zero_based/63x9/rowsums` → length 63
- `s570_after_fae/zero_based/9x63/colsums` → length 63

All four point at the 63-symbol `lastwords` field (`lastwordsbeforearchichoice` decoded from the SalPhaseIon numeric segment). No list addresses the 29-symbol password field or S91.

**Self-labelling test:** S91 as 7×13 has 13 columns, matching the 13 letters of `MATRIXSUMLIST`. The column sums do **not** spell `MATRIXSUMLIST` under either mapping or any of the three mod-26 reductions; the best match is 1/13.

**Result:** `NO_PRIZE_MATCH_IN_PREREGISTERED_FAMILY` — 0 prize matches, 0 legible AES breaks.

#### B. The 14×14 poster grid as the matrix

`solver.creator_pipeline_poster_architect_audit` <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\solver\creator_pipeline_poster_architect_audit.py" /> treated the poster resistor values as the matrix and the resulting row/column sums as index lists into the Architect plaintext starting at offset 479. Separately, `solver.second_door_yellowblueprimes_audit` <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\solver\second_door_yellowblueprimes_audit.py" /> tested the same poster sums, in decimal concatenation and CSV, as AES passwords against the Cosmic, Chain-4-embedded, and SalPhaseIon-short envelopes.

Poster resistor row sums (eye treated as 9):
```text
[73, 48, 60, 69, 73, 62, 82, 91, 57, 46, 58, 60, 64, 57]
```

Poster resistor column sums (eye treated as 9):
```text
[60, 48, 72, 42, 60, 75, 89, 73, 69, 71, 52, 67, 67, 55]
```

With the off-white eye zeroed, the row-8 sum drops from 91 to 82 and the col-5 sum drops from 60 to 51.

The audit extracted letters from the 1,539-character Architect plaintext using these sums under four index modes (`absolute_0based`, `from_479_0based`, `from_479_1based`, `cumulative_from_479_0based`) and three overlays (`none`, `hope_quote_first_letters_xor`, `beaufort_hope_on_extracted`).

**Result:** 162 unique scalar tests, **NO_MATCH**.

### 4.3 Remaining ambiguity

`matrixsumlist` is underdetermined at the **object and encoding** level:
- The S91/S570 instruction reading is falsified for every rectangular layout under the bounded v48 serialisation/derivation family.
- The 14×14 poster grid as a `matrixsumlist` object produces well-defined sums but does not reach either prize target when used as an Architect index list, and its decimal-concat/CSV AES forms already failed against the Cosmic, Chain-4-embedded, and SalPhaseIon-short envelopes.
- The literal token `matrixsumlist` is confirmed as part of the Chain-1/Chain-2 password `matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist`, but that decrypt is high-entropy and not legible.

The creator never stated which object `matrixsumlist` operates on or how the resulting list is encoded. Any further step must either (a) find a composition rule that uses the poster/S91/S570 sums in an encoding not yet tested (e.g. raw bytes, mod-26, two-digit, against the split `env48`/`raw48` envelopes), or (b) accept that the literal is the intended reading and that the next operation is elsewhere.

---

## 5. The exact Architect passage and candidate "last words"

### 5.1 Authenticated Architect plaintext

The 1,539-letter Architect plaintext is the Beaufort decryption of the phase-3.2 symbol record with key `THEMATRIXHASYOU`. Its SHA-256 is `56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241` <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\ARCHITECT_479_CONTINUATION.md" />.

At zero-based offset 479 it begins:

```text
PRIVATEKEYYOUVEEARNEDITBUTPLEASETAKETHIS...
```

Other key word offsets:

| Offset (0-based) | Text |
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
| 1529 | `CIAOBELLAO` |

The continuation text near 1021 is a deliberate rewrite of the Architect's Matrix Reloaded speech, with the film's "23 individuals / 16 female / 7 male" counts preserved as "over twenty-three ciphers / sixteen encryptions / seven intertwined passwords". <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\ARCHITECT_479_CONTINUATION.md" />

### 5.2 Source text containing the Architect's choice

The field name `lastwordsbeforearchichoice` points at the Matrix Reloaded line:

> "As you adequately put, the problem is choice."

The words immediately before `choice` are:

```text
As you adequately put the problem is
```

The `SALPHASEION_PREREGISTRATION.md` preregistered every suffix of these seven words, compact and space-separated, as candidate passwords <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\SALPHASEION_PREREGISTRATION.md" />.

### 5.3 Candidates tested

In this run, every suffix of the seven words before `choice` was tested in four password forms and two KDFs against the Cosmic envelope. The family is 7 suffixes × 2 separators × 4 forms × 2 KDFs = 112 tests. Additionally:
- the fitted Architect string `asbothbeginningandend` (4 forms × 2 KDFs = 8 tests)
- the variant `beginningandend` (8 tests)
- ordered concatenations of the four creator pipeline phrases and the seven SalPhaseIon tokens (4 forms × 2 KDFs)

Full machine-readable results: `reconstruct_pipeline_results.json`.

---

## 6. AES candidate passwords tested

### 6.1 Decryption oracle validation

Before testing Cosmic, the AES helper was validated on the **known-good Phase 3.2 envelope**.

| Property | Value |
| --- | --- |
| Envelope | Phase 3.2 `Salted__` envelope (base64 in `gsmgio-5btc-puzzle-master/README.md`) |
| Password form | 64-character lowercase hex string used as **ASCII** bytes: `250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c` |
| KDF | OpenSSL `EVP_BytesToKey` with **SHA-256** |
| Cipher | AES-256-CBC |
| Padding | strict PKCS#7 |
| Plaintext SHA-256 | `b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34` |
| Plaintext length | 2,422 bytes |
| Opening bytes | `I've been waiting for you. You have many questions, and alth...` |

This confirms the implementation matches the earlier puzzle ciphertext and plaintext. The same helper is then applied to the Cosmic envelope.

### 6.2 Cosmic envelope parameters

| Property | Value |
| --- | --- |
| Source | `gsmgio-5btc-puzzle-master/solver/data/cosmic_duality.txt` <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\solver\data\cosmic_duality.txt" /> |
| Encoding | base64 OpenSSL `Salted__` envelope |
| Header | `Salted__` |
| Salt | `2d3f6fe06dc950e6` (8 bytes) |
| Ciphertext length | 1,328 bytes (83 AES blocks) |
| KDF | `EVP_BytesToKey` |
| Key length | 32 bytes |
| IV length | 16 bytes |
| Padding rule | PKCS#7 |

### 6.3 Candidate password classes

For each class, the script tested four explicit forms and two KDF digests (`md5`, `sha256`):

1. **Literal password bytes** — the ASCII string itself (e.g. `b"yellowblueprimes"`).
2. **SHA-256 digest raw** — the 32 raw bytes `SHA256(password)`.
3. **SHA-256 hex as ASCII** — the 64-character lowercase hex string of `SHA256(password)`, used as 64 ASCII bytes.
4. **SHA-256 hex decoded** — the 64-character hex string decoded to the same 32 raw bytes as (2).

This collapses (2) and (4) to the same 32 bytes, but the script enumerates them explicitly to avoid silently treating the hex string as equivalent to the raw digest. The 64-ASCII-hex case is kept distinct because Phase 3.2's authenticated password is exactly that form.

Additionally, a **raw AES-256 key** test was run with the IV derived from the known 7-token-XOR password, bypassing `EVP_BytesToKey`.

### 6.4 Candidates enumerated in this run

| Candidate family | # variants | Notes |
| --- | ---: | --- |
| Known 7-token XOR password | 1 | `matrixsumlist`, `enter`, `lastwordsbeforearchichoice`, `thispassword`, `matrixsumlist`, `yourlastcommand`, `secondanswer` — XOR of their SHA-256 digests |
| Raw AES-256 key with known IV | 1 | key = `EVP_BytesToKey(7-token-XOR, salt, md5)`; IV from same derivation |
| Creator 4-phrase concatenation | 8 × 2 KDF = 16 | `yellowblueprimes`, `matrixsumlist`, `lastwordsbeforearchichoice`, `yinyang` |
| Full 7 SalPhaseIon tokens concatenation | 8 × 2 KDF = 16 | the tokens used for the known XOR password |
| "Last words" suffixes | 7 suffixes × 2 separators × 4 forms × 2 KDF = 112 | e.g. `As you adequately put the problem is`, `you adequately put the problem is`, …, `is` |
| `asbothbeginningandend` | 4 forms × 2 KDF = 8 | fitted 479-derived string <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\architect_lastwords_yinyang_audit.json" /> |
| `beginningandend` | 4 forms × 2 KDF = 8 | variant without `as` |

Total distinct decryption attempts in the machine-readable output: **161**.

---

## 7. Decryption oracle result for each candidate

### 7.1 The only candidate that decrypts to the *known* Cosmic plaintext

| Label | 7-token SHA256-digest XOR (raw 32 bytes) |
| --- | --- |
| Password bytes (hex) | `a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735` |
| KDF digest | `md5` |
| Salt | `2d3f6fe06dc950e6` |
| Key (hex) | `6ac438facf366702b60d6dfcebd39815b582f19b591b3fdf69240c6966f4fc23` |
| IV (hex) | `c6ff2e39d98843bc3c26b8a33a15b5c9` |
| Plaintext length | 1,327 bytes |
| Plaintext SHA-256 | `4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081` |
| Entropy (bits/byte) | 7.8702 |
| Printable ratio | 0.4017 |
| Legible? | **No** — high entropy, no readable text |
| Prize match? | No |

The raw-AES-key test with the same `(key, IV)` produces exactly the same 1,327-byte plaintext.

### 7.2 Other candidate that produced valid PKCS#7 padding

One additional Cosmic candidate from this run passed the strict padding check by chance:

| Label | `lastwords/suffix_5/sep=' '/literal/md5` |
| --- | --- |
| Password (literal) | `adequately put the problem is` |
| KDF digest | `md5` |
| Plaintext length | 1,327 bytes |
| Entropy (bits/byte) | 7.8421 |
| Printable ratio | 0.3836 |
| First 32 bytes (hex) | `1e6e1acfec64dd0a55c3383604594937ed8b13309d024220f1bc469d83f40c0c` |
| Legible? | **No** |
| Prize match? | No |

### 7.3 All other candidates

All remaining candidates (159 of 161) failed strict PKCS#7 unpadding under one or both of `md5` / `sha256` KDF and one or more of the four password forms. No candidate produced a legible or structured plaintext, and no candidate yielded a 32-byte value matching either prize target through `targets.gate_scalar_bytes`.

This is consistent with the measured chance padding rate on the Cosmic envelope: approximately 0.325% of random passwords produce valid PKCS#7 padding (`salvation_coherence_audit.json`). <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\salvation_coherence_audit.json" />

---

## 8. Results rejected and reasons

| Result | Status | Reason |
| --- | --- | --- |
| 7-token XOR Cosmic decrypt | **rejected as solve** | Valid padding, but plaintext entropy 7.87 bits/byte, printable 0.40, no readable text, no prize match. Padding is consistent with chance. <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\salvation_coherence_audit.json" /> |
| `lastwords` suffix 5 padding hit | **rejected as solve** | Valid padding, but entropy 7.84 bits/byte, printable 0.38, no readable text, no prize match. Expected chance padding. |
| Poster resistor row/column sum → Architect index lists | **negative** | 162 unique scalars, 0 prize matches. <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\creator_pipeline_poster_architect_audit.json" /> |
| S91/S570 `matrixsumlist` sums | **negative** | 3,672 scalar candidates, 0 prize matches, 0 legible AES breaks, self-labelling test failed. <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\matrixsumlist_instruction_audit.json" /> |
| `yellowblueprimes` prime/zeroing families | **negative** | 678 unique scalars, 4,020 AES attempts, 11 chance padding hits, 0 prize matches. <ref_file file="C:\Users\lucas\github-repos\puzle\gsmgio-5btc-puzzle-master\second_door_yellowblueprimes_audit.json" /> |
| `asbothbeginningandend` / `beginningandend` | **negative** | All 16 forms failed padding or produced high-entropy output, no prize match. |
| All 7-token / 4-phrase concatenations | **negative** | No valid padding or no legible plaintext, no prize match. |

The rejection rule used throughout is the repository's own: **valid PKCS#7 padding alone is not success**; the plaintext must be legible/structured *or* the derived 32-byte scalar must match one of the funded targets through `solver.targets`.

---

## 9. The single narrowest unresolved step

The 479 yin-yang balance is reproducible:
- Yellow sum = 479
- Blue sum = 484
- Difference = the blue prime 5
- Zero the blue prime 5 → 479 = 479
- Architect `plaintext[479:]` = `PRIVATEKEYYOUVEEARNEDITBUTPLEASE...`

That structural hit is exact, but it is **not** a key derivation. It points at the operation that should come next.

**The single narrowest unresolved step is: what is the exact operation that takes the balanced 479 and the `matrixsumlist` / `lastwordsbeforearchichoice` tokens and produces the AES password for the yin-yang envelope?**

The creator has named the ingredients (`yellowblueprimes`, `matrixsumlist`, `lastwordsbeforearchichoice`, `yinyang`), confirmed that primes and zeroing are involved, and said the remaining step should be solvable in hours once yin-yang is reached. He has not specified:
- which object `matrixsumlist` sums (poster grid vs S91 vs S570),
- how the sum list is encoded (decimal, raw bytes, mod-26, etc.),
- how the last-word candidate is combined with the sum,
- whether the result is used as a literal password, a SHA-256 digest, a raw 32-byte AES key, or a WIF,
- which envelope is the yin-yang lock (the SalPhaseIon short `env48`/`raw48`, the Cosmic envelope, or another layer).

Every bounded reading that makes one of these choices explicit has failed. The step is underdetermined because the creator has not supplied the composition rule, and the artifacts contain no other constraint that selects it uniquely.

---

## 10. Completed preregistered AES test of the 14×14 poster resistor sum lists

The preregistered experiment described in the previous version of this report has been executed and sealed.

**Scope.** Four 14-entry poster resistor sum lists (rows/columns, eye-zeroed and eye-nine) were encoded as raw bytes, mod-10 digits/bytes, mod-9 digits/bytes, mod-26 (0-based and 1-based, upper and lower case), and two-digit decimal. Each encoding was tested in four password forms (literal, SHA-256 raw digest, SHA-256 lowercase-hex ASCII, SHA-256 hex decoded) and both `EVP_BytesToKey` digests (`md5`, `sha256`). `env48` was decrypted using its own `Salted__` salt; `raw48` was decrypted with both the EVP-derived IV and the `env48`-ciphertext-tail continuation IV.

**Result.** 960 AES attempts. 1 valid PKCS#7 padding hit (`poster_resistor_col_sums_eye_zeroed` / `mod10_digits` / `sha256_hex_ascii` / `sha256` / `env48`, 31 bytes, entropy 4.89, printable 0.32, not readable, no format or prize match). 0 legible outputs, 0 prize matches, 0 accepted records.

**Conclusion.** The 14×14 poster grid resistor sum lists are ruled out as the `matrixsumlist` object that yields the yin-yang AES password under any of the tested standard encodings and both KDFs. The only remaining move is the one the creator identified: the missing personal/contextual composition rule from 479 / `matrixsumlist` / `lastwordsbeforearchichoice` to the yin-yang lock has not been supplied by the artifacts.

**Artifacts.** `solver/poster_resistor_split_envelope_audit.py`, `poster_resistor_split_envelope_preregistered.json` (seal `ff37c813…0280ffd8`), `poster_resistor_split_envelope_results.json`.

---

## Provenance table

| Step | Exact input | Source artifact | Creator support | Operation | Exact output | Degrees of freedom | Status |
| ---- | ----------- | --------------- | --------------- | --------- | ------------ | ------------------ | ------ |
| 1. First artifact | `sources/follow_the_white_rabbit.png` | archived creator image | explicitly confirmed ("go back to the first puzzle piece") | 350×350 → 14×14 majority sampling; counter-clockwise spiral | `gsmg.io/theseedisplanted`, `F73D92`, off-white at (7,4) | spiral direction and bit assignment are solved by the readable output | SOLVED |
| 2. Yellow/blue numbers | 24 marker colours (15 blue, 9 yellow) | first image | explicitly confirmed ("Yellow has a number and so does Blue") | assign consecutive primes 2..89 to the 24 marker positions and sum by colour | Blue = 484, Yellow = 479, difference = 5 | prime assignment and colour→number mapping are clue-driven | FITTED / exact arithmetic |
| 3. Zero the balancing prime | blue prime 5 | derived from 484 - 479 | strongly implied ("some characters need to be 'zeroed out'") | subtract blue prime 5 from blue sum | 479 = 479; points to `plaintext[479]` | which prime and which side to zero | FITTED |
| 4. Index into Architect | offset 479, zero-based | Architect plaintext | strongly implied by `PRIVATEKEY` at 479 | `plaintext[479:]` | `PRIVATEKEYYOUVEEARNEDITBUTPLEASE...` | zero- vs one-based indexing | FITTED structural hit |
| 5. `matrixsumlist` as S91/S570 instruction | `s91`, `s570` fields from SalPhaseIon | archived HTML textarea | literal is authenticated, as instruction is solver inference | build every rectangular matrix, sum rows/columns, serialise | 102 lists; 4 match `lastwords` length; no prize/legible break | which field, which factorisation, which axis, which serialisation | NEGATIVE for bounded family |
| 6. `matrixsumlist` as 14×14 poster grid | poster resistor values 0/4/6/9 | first image | strongly implied by "Yellow has a number" + resistor code | row/column sums as index lists and as AES passwords (raw bytes, mod-10/9/26, two-digit, SHA-256 forms) | 162 scalar candidates, no prize match; 960 AES attempts against env48/raw48, 1 chance padding hit, no legible/accepted output | eye=0 or 9, index mode, overlay, serialisation | NEGATIVE |
| 7. Last words | "As you adequately put, the problem is choice." | Matrix Reloaded film quote, field name `lastwordsbeforearchichoice` | strongly implied by field name and film quote | every suffix, 4 password forms, 2 KDFs, Cosmic envelope | 1 chance padding hit (`adequately put the problem is` / md5 / literal), high entropy, no prize | number of words, separator, form, KDF | NEGATIVE |
| 8. AES oracle | Phase 3.2 envelope, 64-ASCII-hex password | committed `README.md` and `phase32_classical.py` | SOLVED/authenticated | OpenSSL `EVP_BytesToKey(sha256)`, AES-256-CBC, PKCS#7 | plaintext opens `I've been waiting for you...`; SHA-256 `b82afeb8...` | none | SOLVED (validation control) |
| 9. Cosmic decrypt | Cosmic `Salted__` envelope, 7-token XOR password | `salphaseion.py` derives tokens; `chains.py` uses XOR | community construction, not creator-sourced | `EVP_BytesToKey(md5)`, AES-256-CBC | 1,327 bytes, SHA-256 `4f7a1e4e...`, entropy 7.87 | none | DECRYPTS but REJECTED (not legible) |
| 10. Prize gate | every 32-byte candidate | `solver/targets.py` | exact funded targets | `gate_scalar_bytes` / `gate_point` | no Half or Better Half match in any family | — | NO_MATCH |

---

## Summary

The creator's confirmed pipeline is reconstructed deterministically through the first image, the 479/484 yin-yang balance, and the 479 pointer into the Architect plaintext. `matrixsumlist` and `lastwordsbeforearchichoice` are the next named objects, but no bounded interpretation of `matrixsumlist` as a matrix-sum instruction, and no defensible "last words" candidate, yields a legible AES break or a prize-matching scalar. The original Cosmic envelope decrypts only to the known high-entropy 1,327-byte plaintext, which is not a solution by the creator's own legibility criterion. The 14×14 poster resistor sum lists have now been tested as AES passwords against the split SalPhaseIon `env48`/`raw48` halves in every unapplied standard encoding and both KDFs; the result is a single chance padding hit and no accepted output. The narrowest remaining gap is the exact composition rule that turns the 479 balance and the `matrixsumlist` / last-words tokens into the yin-yang AES password; it remains underdetermined by the committed artifacts.
