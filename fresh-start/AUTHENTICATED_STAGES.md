# Authenticated stages

"Authenticated" means an exact hash, decryption, or independent source fixes the
result. Items marked **fitted** reproduce under a solver-chosen convention.

## Stage map

| stage | URL / artifact | authenticated output |
| --- | --- | --- |
| Poster | `gsmg.io/Puzzle` image | `gsmg.io/theseedisplanted` |
| Poster markers | 24 coloured cells on spiral | packed bits `F73D92` |
| Rebus | eight tiles / song | `theflowerblossomsthroughwhatseemstobeaconcretesurface` |
| Phase 2 part 1 | AES blob | password = `sha256("causality").hexdigest()` (64 ASCII hex chars) |
| Phase 2 seven-part | concatenation gate | SHA-256 = `1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5` |
| Phase 3 URL slug | first page text | `sha256("GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")` → `89727c59…52f6a32` |
| Phase 3 riddles | three answers | `sha256("jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple").hexdigest()` opens Phase 3.2 |
| Phase 3.2 | AES blob | password = 64 ASCII bytes `250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c` |
| Symbol record | 1,539 raw bytes inside Phase 3.2 | SHA-256 `bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b` |
| Beaufort | key `THEMATRIXHASYOU`, P = K − C mod 26 | 1,539-letter Architect plaintext; SHA-256 `56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241` |
| VIC checkerboard | 149 digits, alphabet `FUBCDORA.LETHINGKYMVPS.JQZXW`, row digits 1 and 4 | see `artifacts/checkerboard_message.txt` |
| Decentraland | stereo MP3, mono = L − R | spectrogram text `HASHTHETEXT` |
| SalPhaseIon literals | binary and decimal fields on page | `matrixsumlist`, `enter`, `lastwordsbeforearchichoice`, `thispassword`, etc. |

Full Architect plaintext: `artifacts/architect_plaintext.txt` (1,539 letters).

## Poster (exact)

- Image: 350×350 PNG, 14×14 grid of 25px cells, five colours.
- Read: counter-clockwise inward spiral from top-left; black+blue = 1, white+yellow = 0.
- Result: 24 ASCII bytes + 4 zero bits → `gsmg.io/theseedisplanted`.
- 24 blue/yellow cells mark every 8th spiral bit (byte LSB positions) → `F73D92`.

## Phase 3.2 plaintext structure

After AES decrypt, the payload contains:

1. English preamble ending `One for one, four for one.`
2. 1,539-byte 26-symbol record (pre-Beaufort "source")
3. 149-digit VIC record
4. 80-byte OpenSSL envelope (SalPhaseIon short blob)
5. Additional page content (SalPhaseIon fields, Cosmic textarea, etc.)

Phase 3.2 opening (human-readable portion) is in `artifacts/phase32_preamble.txt`.

## Architect plaintext — named substrings (zero-based offsets)

These offsets are **observations** on the authenticated A–Z stream after
Beaufort. Indexing convention (0-based vs 1-based) is not creator-stated.

| offset | substring at offset |
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

Continuation excerpt `[472:619]` (147 characters spanning `TAKETHE` through
part of the Filmmaker rewrite): `artifacts/architect_continuation_excerpt.txt`.

## SalPhaseIon page — decoded literals (physical order)

From the archived SalPhaseIon HTML (earliest capture `20230601222752`), fields
decode to:

1. `matrixsumlist` (binary a/b block)
2. `lastwordsbeforearchichoice` (decimal → hex → ASCII)
3. `thispassword` (decimal → hex → ASCII)
4. `shabefourfirsthintisyourlastcommand` (a/b block)
5. `enter` (binary a/b block, between Base64 portions)
6. `shabefanstoo` (a/b block)

Raw symbol streams: `artifacts/salphaseion_fields.json` (`S91`, `S570`, etc.).

The page also contains Base64 ciphertext blobs (short 48-byte envelope, longer
"Cosmic" textarea). **Decrypting those blobs to high-entropy output is
reproducible under various passwords but is not authenticated as correct
plaintext** by the creator's 2021-03-14 criterion ("breaking salphation should
be giving the feeling of the phase's name").

## Cryptographic parameters (Phase 3.x)

- AES-256-CBC, OpenSSL salted format (`Salted__`)
- KDF: `EVP_BytesToKey` with **SHA-256** digest for Phase 3.2 password
- Phase 3.2 password is the **64 ASCII hex characters**, not the 32 decoded bytes

## Fitted observations (not authenticated conventions)

These exact arithmetic relationships have been noted by solvers. Each depends on
at least one unproven convention:

- Assigning the first 24 primes to the 24 poster marker bits: blue sum 484,
  yellow sum 479; removing blue prime 5 yields 479 = 479.
- Under **zero-based** indexing of the Architect A–Z stream, offset 479 lands on
  `PRIVATEKEY`. Under one-based indexing, position 479 is the letter before
  `PRIVATEKEY`.

Treat these as hypotheses until a creator instruction or exact independent
check fixes the convention.
