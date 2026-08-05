# Solved-stage re-audit

Re-derived from primary artifacts on 2026-08-05. “Authenticated” means an exact
hash, decryption, or independent source control fixes the result. “Fitted” means
the arithmetic reproduces but at least one operator, serialization, or indexing
convention was solver-selected.

## Correctly authenticated

| Stage | Recomputed result | Boundary |
| --- | --- | --- |
| Poster | Majority-cell, down-first counter-clockwise spiral; black/blue=1, white/yellow/off-white=0 → `gsmg.io/theseedisplanted`, residual `0000` | Exact image decode |
| Poster markers | Spiral marker bits are URL-byte LSBs → `F73D92`; row-major is `BE2B9B` | Exact |
| Rebus | Four lines read “cryptologic warning, can you dig it?” | Exact pairing; line order inferred from English |
| Phase-one form | `theflowerblossomsthroughwhatseemstobeaconcretesurface` | Strong contemporaneous/song evidence; historical POST unavailable |
| Phase-two part one | `sha256("causality").hexdigest()` as 64 ASCII bytes, SHA-256 `EVP_BytesToKey`, AES-256-CBC | Exact decryption |
| Seven-part gate | Exact 227-byte concatenation hashes to `1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5` | Exact decryption; puzzle FEN intentionally retains noncanonical halfmove `0` |
| SalPhaseIon URL | `sha256("GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")` → `89727c59…` | Exact; not the seven-part digest |
| Three-riddle gate | `sha256("jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple").hexdigest()` | Exact decryption |
| Symbol record | 1,539 raw bytes, 26-symbol bijection; external Architect crib fixes 23 symbols and language scoring fixes the last 3 | Crib-assisted but independently reproducible |
| Beaufort | `THEMATRIXHASYOU`, `P=K-C mod 26` → 1,539-letter Architect plaintext, SHA-256 `56c43a30…` | Coherent full-text authentication |
| Checkerboard | 149 digits decode exactly to the Half/Better-Half funds message | VIC-style checkerboard only, not a full VIC cipher |
| SalPhaseIon literals | Exact segmentation; binary → `matrixsumlist`/`enter`; decimal→hex→ASCII → `lastwordsbeforearchichoice`/`thispassword` | Values authenticated; operational roles open |
| Blockchain | Half uncompressed public key and Better-Half transaction amounts | Exact chain data |
| Decentraland | Audio difference channel → `HASHTHETEXT` | Exact |

## Correct arithmetic with fitted interpretation

| Claim | Exact calculation | Unauthenticated choice |
| --- | --- | --- |
| Poster balance | First 24 primes on authenticated markers: Blue=484, Yellow=479, difference=blue prime 5, so 484−5=479 | Consecutive-prime assignment and “zero” operation |
| Offset 479 | A–Z plaintext `[479:]` begins `PRIVATEKEY…` | Zero-based indexing; one-based position 479 is `E` |
| Fresco quote | Selected quote has 23 words and 140 characters after removing five punctuation marks | Exact full quote is community editorial context |
| Passport XOR | `11092001=0xA94021`; `F73D92 XOR A94021=5E7DB3`; significant binary has 23 bits, 16 ones, 7 zeroes | Date serialization, XOR, dropping the leading zero, bit direction, word alignment |
| Chain 1/2 | Five-token password decrypts 79 bytes; first 32 bytes serialized as WIF decrypt the second 79-byte envelope | Password order/repetition and WIF interpretation; link is one-way |
| Cosmic/103² | Seven-digest XOR decrypts 1,327 bytes; the 103×103/+7/base-38 arithmetic reproduces | Token selection, XOR, matrix layout, +7/range/base and 32+32+4 split |

## High-value cross-check calculations

- Across all 24 cyclic rotations of the authenticated colour stream, only the
  authenticated rotation has a one-term balance where the sum difference is
  itself a prime assigned to the larger colour side.
- Row-major primes give Blue=602, Yellow=361 (difference 241); reversed order
  gives 719/244; reverse-within-byte order gives 468/495. None reproduces the
  removable blue 5.
- The fixed-width XOR is `010111100111110110110011`: 24 bits, 16 ones and 8
  zeroes. The advertised 23/16/7 counts require dropping its leading zero.
- Straightforward passport alternatives do not preserve the full alignment:
  `MMDDYYYY=9112001` is composite, `YYYYMMDD=20010911` is composite,
  `DDMMYY=110901` is composite, and their XOR masks do not give 23/16/7.
- The two repeated `matrixsumlist` digests cancel in the seven-token Cosmic XOR.
  Whatever that operation represents, it algebraically depends on only five
  distinct token digests.
- Of the eight poster symmetries, only the authenticated orientation yields all
  24 printable URL bytes and aligns every colour marker to a byte LSB.

## Corrections that affect downstream work

1. `cryptologicwarningcanyoudigit` is the rebus summary, not the supported
   historical form password.
2. The off-white cell is payload index 163 (byte 20, bit 3), inside `planted`.
3. Majority sampling gives 101 one-cells and residual `0000`; centre sampling
   reads a rabbit stroke and produces the spurious 102/`0100`.
4. `F73D92` is packed marker data. RGB `#F73D92` occurs zero times in the source.
5. Phase-two and Phase-3.2 passwords are 64 ASCII-hex bytes with SHA-256
   `EVP_BytesToKey`; raw digest bytes and MD5 defaults are wrong.
6. The formal chess FEN after `Rc6+` would end `1 1`, but the authenticated
   puzzle concatenation requires the published `0 1`.
7. The Phase-3.2 binary controls must retain CRLF bytes; `.gitattributes` now
   prevents text normalization of `*.bin`.
8. A fitted structural hit is not a prize-key oracle. All proposed continuations
   must still match Half’s exact public key or Better Half’s hash160.

## Frontier decision and execution

The highest-ranked untested creator-text-led operation was the literal Architect
sequence “return to the source codes” / “reinserting the prime basics” applied
to the authenticated 1,539-byte pre-Beaufort record. The experiment was sealed
before execution and excluded Cosmic and community-only operands.

Result: **COMPLETE_NO_MATCH**. All 168 preregistered records produced valid
scalars (132 unique), and none matched Half’s exact public key or Better Half’s
hash160. This closes the literal prime-position select/zero/xor/LSB family, not
every possible reading of the Architect prose.

The next highest-information unfinished calculation was the already sealed
shared base-9 substitution over S91 and S570. It was also executed completely:
all 362,880 shared digit mappings and 5,806,080 byte representations were
checked under the preregistered exact-file, decompression, and readable-text
gates. Result: **NO_ACCEPTED_OUTPUT**.

After these two closures, the best remaining creator-authenticated frontier is
the independent 48-byte SalPhaseIon envelope and the operational meaning of the
four decoded field literals. Existing instruction-family sweeps are extensive,
so the next useful advance requires a new source-authenticated control—not a
wider password or Cosmic search.
