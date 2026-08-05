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

## Recommended frontier

The best untested, creator-text-led operation is the literal Architect sequence
“return to the source codes” / “reinserting the prime basics” applied to the
authenticated 1,539-byte pre-Beaufort record. It is bounded, avoids Cosmic and
community-only operands, and can be checked directly against both prize oracles.
See `architect_source_prime_reinsertion_preregistered.json`.
