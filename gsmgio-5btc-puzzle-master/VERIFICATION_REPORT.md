# GSMG.IO 5 BTC Puzzle Verification Report

Generated deterministically by `python -m solver.report` from the checked-in README/images plus the provenance-recorded Cosmic ciphertext in `solver/data/cosmic_duality.txt`.

## Result

The public chain is reproduced through Chain 4 and the independent 103x103 interpretation. The prize private key is **not** derived. The precise public frontier remains the absence of reproducible bytes or rules for `cosmic_A`/`ca`, `row1-4`, and `K_I1`.

## Confirmed stages

| Stage | Length | SHA-256 / value |
|---|---:|---|
| Seven-token digest XOR | 32 | `a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735` |
| Chain 1 plaintext | 79 | `1449a2178eea7c0e3fabac8c1ad2afa294be4fc1800c594a025a056e88c626bf` |
| K_C1 uncompressed WIF | 51 chars | `5K2byJMssxFKuTgnk9YQjpBz5FhkwwF2LaZoAyTus8HjGEpz8AT` |
| Chain 2 plaintext | 79 | `b40fce72ef5638e4f79b3233e653f8a5dbdb0d4ae2009d2d3da2c98b70f4d004` |
| Cosmic plaintext | 1327 | `4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081` |
| Cosmic remainder | 1169 | `018e1dc4967accb53f51e267c0cb6be46e335cb209b1cd7aaf97d744d5728456` |
| Masked embedded envelope | 1168 | `f0bd54d102d8d930fbbd0c5f8e4d7b7ffd64cab5d192a3751374d688c5115add` |
| Chain 4 plaintext | 1151 | `e4269ed5fbb202a81e5e1aa6b5190fdd1ea126b2c8547ea7cdbdf45387ea135b` |
| Chain 4 tail at byte 246 | 905 | `9f06936a48d393c858a6fdce281540946e8f5365d632ad756c280b400c9d632c` |
| Base-38 output | 68 | `9c7bbaec63f8179c8b0fd014163adbd174920f05cfd4a7ddfd523e0b21cab6a6` |

The four advanced AES layers use the exact legacy OpenSSL convention: `Salted__`, an 8-byte salt, MD5 `EVP_BytesToKey`, AES-256-CBC, and strict PKCS#7 validation. The earlier Phase 3.2 blob is a version-sensitive positive control: it requires the OpenSSL 1.1.0+ SHA-256 EVP default and decrypts to 2422 bytes beginning `I've been waiting for you.` The digest is therefore explicit at every call site.

## Phase 3.2 classical stages and layer ownership

The Phase 3.2 plaintext contains a 1,539-byte, 26-symbol record at offset 447 and a separate 149-digit record. The symbol layer is no longer accepted merely from the published table. A 76-letter Matrix Architect opening crib fixes 23/26 assignments without conflict; only 6 residual permutations remain. A generic English trigram/quadgram model built from wordfreq 3.1.1 ranks the winning assignment by a score margin of 1469.908, before the published mapping is consulted. The recovered map then agrees 26/26 with the published map and yields plaintext SHA-256 `56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241`. From that independently recovered boundary onward the solver reproduces:

- Beaufort with key `THEMATRIXHASYOU`: 1,539 letters, SHA-256 `56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241`.
- VIC straddling checkerboard with alphabet `FUBCDORA.LETHINGKYMVPS.JQZXW` and row digits `1,4`: `INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE`.

Crucially, `TAKE THE PRIVATE KEY`, `REINSERTING THE PRIME BASICS`, and final `CIAO BELLA O` belong to this authenticated Phase 3.2.1 Architect message. They are not newly recovered Chain 4 plaintext. Issue #87's “all of it” wording enumerates earlier puzzle stages and does not specify Beaufort as the Chain 4 cipher.

## SalPhaseIon evidence boundary

`matrixsumlist`, `enter`, `lastwordsbeforearchichoice`, and `thispassword` are decoded mechanically from the raw SalPhaseIon line in `README.md`. Reusing `matrixsumlist` as token 5 and reading `yourlastcommand` / `secondanswer` are semantic or fitted steps. Their combination gains strong downstream support because it produces two sibling 79-byte `32+32+15` structures, the documented WIF, another sibling 79-byte structure, a repeated pair of structures in Cosmic, and the Chain 4 embedded `Salted__` header and exact hash. This is substantially stronger than padding success alone, but it is not a creator-authored token proof.

The instruction-style hypothesis has now been tested directly rather than rejected semantically. First, its quoted original-grid transcription is incorrect: authenticated pixel sampling gives row sums `[6, 10, 8, 7, 6, 6, 5, 5, 9, 9, 7, 8, 7, 9]`, column sums `[8, 10, 8, 10, 8, 7, 4, 6, 7, 5, 9, 6, 6, 8]`, total 102, and blue=1/yellow=0 stream `101111100010101110011011` (`BE2B9B`), not total 101 / `F73D92`. Both authentic and supplied variants were nevertheless retained. The bounded construction generated 17,614 unique preimages from S91/S570 layouts, row/column/diagonal sums, all rectangular symmetries and four route families, `matrixsumlist` column ordering/weighting, S570 indexing, the 26-character `lastwords...` key/alphabet readings, five checkerboard row-pairs, `enter` insertions, last-bit reuse, access-loop strings, and Half/Better-Half forms. Raw, SHA-256, hex, and double-hash spellings expand these to 140,908 distinct password byte strings, each tested under MD5 and SHA-256 against all three envelopes.

At this scale padding behaves exactly like noise: 1,090 short-blob, 1,033 direct small-blob, and 1,154 Cosmic hits from 281,816 decryptions per envelope. Thirteen short-blob candidates also pass small-blob padding after WIF derivation. Only one reaches the exact 1151-byte `+-` plus 35-block Chain 4 structure: the already-published five-token MD5 password; zero non-control candidates do. Cosmic likewise has exactly one Chain 4 structure hit, the canonical seven-digest-XOR control, and zero non-control hits. No candidate SHA-256 or 32-byte spelling derives the prize point. Thus this enumerated instruction reading is negative, while the published path is demonstrably more than a padding-only false positive.

The seven-token XOR is `a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735`. The Cosmic AES key is `6ac438facf366702b60d6dfcebd39815b582f19b591b3fdf69240c6966f4fc23` and IV is `c6ff2e39d98843bc3c26b8a33a15b5c9`.

## Chain parsing

Chains 1 and 2 independently decrypt to 79 bytes, exactly `32 + 32 + 15`. The first 158 Cosmic bytes repeat that layout twice, leaving exactly 1169 bytes. This repeated byte structure and the fact that `E_C || E_S || E_B[:2]` exposes a valid embedded OpenSSL envelope justify the labels `K_C*`, `K_S*`, `K_B*`, and `K_H*`; they were not imposed merely because slices were printable.

Chain 4 has an exact 31-byte prefix followed by 35 aligned 32-byte blocks:

- marker `[0:2]`: `+-`
- operand/header remainder `[2:31]`: `ca9ebcdc7722e80ab9aa8bb166ab2cc79c2fef75ce3c638f45b3e70537` (29 bytes)
- alternate opcode parse: `+` at `[0:1]`, then `2dca9ebcdc7722e80ab9aa8bb166ab2cc79c2fef75ce3c638f45b3e70537` at `[1:31]` (30 bytes)
- block region `[31:1151]`: 1120 bytes = 35 x 32

The offsets and alignment are exact; the semantics are not. Nothing public selects the two-byte `+-` marker plus 29-byte operand over the one-byte `+` opcode plus 30-byte operand. The often-reported 905-byte tail is a separate observed boundary at `[246:1151]`; it does not align with the 31-byte/32-byte structural split.

## 103x103 interpretation

The 1327 bytes are 10616 MSB-first bits: 10609 matrix bits and trailing bits `0111010`. Invariants reproduce as `S=5193`, `Wr=268603`, and `Wc=268828`.

Exhausting all 103 cyclic column shifts finds 15 shifts whose sums stay within 80..117: `0, 7, 11, 14, 46, 47, 50, 64, 69, 76, 77, 84, 95, 96, 102`. Shift 7 is the **only** shift that attains the full exact range 80..117. Thus `+7` is selected by a specific invariant, but the broader printable-range test alone is not unique.

Subtracting 80 produces digits 0..37, making 38 the smallest valid positional base. Base 39 also produces 68 bytes, so output length alone does not uniquely prove base 38; base 38 is the canonical minimal-base choice and is independently checked by both published addresses.

- Half: `0423d9115a1dc756d5d08d2de880ab508bd4745fc97709f4fcb513f2cb8fcc35` -> `1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu`
- Better Half: `48cc46e66bdd36b09ae344552f606a761f9d90681f20dfefe2b43db18b623971` -> `145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ`
- trailing bytes / `trail1`: `fc0c1b02`

## Prize public key

The reported x-coordinate is on secp256k1. Its odd-y root is `9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559` and independently hashes as an uncompressed public key to the exact prize address `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`. This validates the public point, not knowledge of its private scalar.

## Failed or unavailable claims

- The older 79-byte SHA-256 claim `e2590f15...` is refuted for the README Chain 1 blob. The reproduced hash is `1449a2178eea7c0e3fabac8c1ad2afa294be4fc1800c594a025a056e88c626bf`.
- `cosmic_A` is known only by the reported prefix `cd3fea3d...`; no bytes, full SHA-256, length, or reproducible derivation were found.
- `ca[280:312]`, `row1-4`, and `K_I1` have no public reproducible definition in the inspected canonical history, PR material, or issue evidence.
- `k_new = cc[833:865] XOR ca[280:312]` is therefore not executable. A claimed vanity-prefix match is not accepted as evidence.
- No tested or reported step here yields a private scalar whose public key equals the prize point.
- The exact serialized eight-row missing-node recurrence `parent[j] = child[j] XOR child[j+1]` has been independently rerun over 18,432 layouts; it has zero internally consistent survivors. This falsifies that finite interpretation, not the undefined general phrase “XOR triangle.”
- Completing the raw 31-byte Chain 4 prefix with each single `trail1` byte creates exactly 36 words, but all 4096 serialized T8 layouts violate the XOR recurrence; the best layouts still fail all 28 equations.
- The July 2026 `Door-2 LCP7` comment is ambiguous. Its literal lowercase ASCII-hex-text interpretation reproduces target-x LCP5, not LCP7, and no audited encoding matches the target.
- The reported 246/905 entropy contrast is not a structural discriminator: a 10,000-permutation fixed-split test gives one-sided `p=0.489`. The observed entropy gap is almost exactly the random-partition mean and byte 246 is not aligned to the 31+32-byte structure.
- As a bounded falsification despite the layer mismatch, the Issue #87 phrases were tested across every Chain 4 offset and periods 1..64 under repeating XOR and three byte-domain Beaufort/Vigenere conventions. Every model has zero pairs agreeing on four shared key bytes. This does not test the authentic alphabetic Phase 3.2 Beaufort stage, which is reproduced separately.

## Provenance of unresolved terms

- “XOR triangle”: earliest immutable public comment located, 2025-12-25, [PR #68 comment](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/pull/68#issuecomment-3691156333); no formula.
- `K_I1`: earliest visible occurrence located, 2026-03-13, [Issue #87](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/87); claimed but not disclosed.
- `cosmic_A`, `ca`, `row1-4`, and the slice formula: earliest currently visible occurrence located in the editable body of [Issue #88](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/88), timestamped 2026-03-29. Because issue bodies can be edited, that timestamp is an earliest-visible bound, not proof that every line appeared on creation.
- `trail1`: the same editable Issue #88 body is the earliest visible label occurrence. Unlike the other terms, its four bytes are independently reproduced as the tail of the 68-byte matrix output: `fc0c1b02`, SHA-256 `bbf54842988b73cba4273885954b9d9a95d736f0454b55d2d90942fabc6c5ca4`.

## Precise current frontier

The reproducible public state ends with two independently verified branches: Chain 4 (`e4269ed5...`) and the matrix-derived Half/Better Half pair. There is no public, complete operand connecting either branch to the prize scalar. `cosmic_A`/`ca`, the definition of `row1-4`, and the derivation of `K_I1` remain unavailable.

The new bounded cross-branch experiment tested every one of the 1120 contiguous 32-byte Chain 4 windows under direct, XOR, modular addition/subtraction, and ordered SHA-256 composition with 12 verified constants derived from Half, Better Half, `trail1`, and both prefix parses. It generated 81760 candidates (79519 unique nonzero scalars) and found zero exact target-point matches. This falsifies only that enumerated family.

The queued contiguous `trail1` splice experiment is also complete. It formed 10 exact 32-byte completions of the 29-byte and 30-byte prefix operands and tested them standalone and under four operations with all 35 aligned blocks. All 1410 generated candidates were unique nonzero scalars; none matched the full target point or address.

The ordered non-repeating extension formed 72 prefix completions and tested 10152 unique nonzero scalars, again with zero matches. The more structural one-byte completion produced an exact 36-word T8-sized record, but none of its 4096 row-order/orientation layouts satisfies even one complete XOR-triangle recurrence.

The public L4 phrases `REINSERTING THE PRIME BASICS`, `please take the private key`, and `CIAO BELLA O` also fail as exact repeating-XOR cribs over the complete Chain 4 record: 0 mutually consistent pairs and 0 recovered full-period keys.

All three literal byte-domain Beaufort/Vigenere modes likewise yield zero consistent crib pairs. More importantly, the phrases are now deterministically assigned to Phase 3.2 rather than Chain 4, removing the claimed L4 crib route from the evidence-backed frontier.

The literal authenticated prime-reinsertion route is now exhausted for its explicit finite family. The README supplies a 91-symbol prefix, while direct image sampling finds 15 blue and 9 yellow cells, exactly matching the 24 one-indexed prime positions in 1..91. As a positive control, the same sampled bit grid spirals to `gsmg.io/theseedisplanted`. The audit generated 16 reinsertion records, 1344 byte decodings, and 1376 scalar candidate records (160 unique nonzero scalars). None derives the full prize point; the instruction is authentic, but the enumerated stream/offset interpretations remain exploratory.

The bounded `matrixsumlist` model is also exact-gated. Its 8 grid symmetries, 3 row statistics, 6 pair/interval list constructions, 2 equivalent positive-integer mod-9 spellings, 6 triangle traversals, and 3 arithmetic combinations produce 5184 structural hypotheses and 36288 base-9 outputs. No generated key equals the authentic S91 field; the best agrees at only 19/91 positions. Hashing the explicit digit and byte serializations yields 62208 scalar records (9216 unique nonzero scalars), with zero target-point matches. This family is exploratory: `matrixsumlist` is authentic, but these transformations are not creator-documented.

The unused authenticated S570 field is now extracted directly at symbols 195..764 before the first `z`: length 570, SHA-256 `066191b4aafc114fbca7f0d168382f40129c4ff18490375b689741081d5ef3c2`. The independent port exactly reproduces the prior 40456 30-value lists and 54792 unique selector/sign-fold scalars. It also identifies two dead legacy branches: 30 selectors cannot permute all 35 blocks, and a 30-byte record cannot equal the 29-byte magnitude. The corrected audit therefore enumerates 40568 properly sized lists and 688872 direct/hash/prefix serialization records. Across both legacy and corrected families, 575419 unique nonzero scalars yield zero exact target-point matches.

The exact `35 = C(7,3) = C(7,4)` coincidence is now structurally audited against the authenticated “seven intertwined passwords” phrase. The 48 explicit raw-token/digest/separator/order models generate 1680 hashes, but none equals even one Chain 4 block; flexible bipartite coverage is 0/35. After removing 18 duplicate digest-representation comparisons from the older loop, all 66 unique C(7,3)/C(7,4) sum/XOR multiset comparisons are negative. More decisively, the 35 blocks have GF(2) rank 35 (rank 36 with the operand), so they cannot be XOR combinations of any seven latent vectors under any assignment. The natural lexicographic triple-sum system is also inconsistent over the curve order: coefficient rank 7, augmented rank 8. No block-order scalar search is inferred from a nonexistent structural assignment.

The additive-selection route is now independently closed in point space. A libsecp256k1 Gray-code MITM engine first agrees with the independent package scalar multiplier and recovers the planted synthetic subset `[0,3,7,11]`. Its terminal checkpoints then exhaust M1 (`2^35` block subsets x 7 prefix shifts), M2/M3 (each `2^36` with the operand or magnitude), M4 (`2^43` over blocks plus eight recovered K values), and M5 (`2^35` x 9 Half/Better-Half point shifts). These represent 9483287789568 logical subset/shift evaluations; all half tables have zero point collisions and every family has zero matches. This is a complete negative certificate for additive subsets of those explicit scalar sets and shifts, not for non-additive operations.

The literal signed-block reading of the `+-` marker is also exhaustively closed. The identity `c + sum(s_i*b_i) = c - sum(b_i) + sum_{i in A}(2*b_i)` reduces every one of the `2^35` sign assignments to the same checkpointed point-space MITM. S1 tests all 7 zero/prefix/operand constants (240518168576 logical assignments), while S2 tests all 8 signed Half/Better-Half combinations (274877906944). A planted signed pattern is recovered, both real families have zero point collisions, and neither reaches the prize point. This does not cover omitted blocks or an unavailable external operand.

## Blockchain signature and nonce audit

At Bitcoin tip `960921` (`00000000000000000000b8eb81537b8c5c9890640d7964fa66d65643324ca8ae`), the confirmed histories of the prize address and the two component addresses independently yield 187 P2PKH signatures in 179 spending transactions. The address counts are `{"145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ": 90, "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe": 6, "1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu": 91}`. All 204 required raw current/prevout transactions rederive their txids; every prevout script and value agrees with its history record; and all signatures verify against locally serialized legacy sighash preimages. The reconstructed core `(address, txid, vin, r, s)` inventory exactly reproduces SHA-256 `691b6f15b6eb87d488d066ca8631dd99a58080db810601ea4c69f116d23f41a1`.

All 187 signatures use sighash type 1 and all 187 `r` values are distinct, so there is no repeated-`r` nonce recovery. The original six-target-signature x 35-block test is reproduced as 210 equations. The expanded exact audit tests 96 signed nonce scalars across the full corpus (17952 equations), covering the 35 blocks, both prefix operands, eight recovered K values, and Half/Better Half. It finds zero matching `r` values, zero recovered prize scalars, and zero direct prize-scalar matches. This closes only those explicit nonce families; it is not a general ECDSA discrete-log attack.

The complementary x-coordinate interpretation is also reconstructed with a stricter combination model than the historical probe. Exactly 22 of 35 blocks lift to curve points. Selecting distinct block indices before assigning either y parity, and applying no shift or either sign of the operand, magnitude, structured prefix, Half, and Better Half points, exhausts 146168 singleton/pair/triple relations. A planted three-block-plus-Half relation is recovered by the same engine; the prize point has zero relations. Even a relation would not expose the lifted points' discrete logarithms, so this is a negative structural certificate and not a private-key recovery method.

The nonlinear XOR route is now independently closed for the clue-motivated subset sizes 3, 4, and 7. First-index terminal checkpoints cover 6,545, 52,360, and 6,724,520 subsets respectively. With the recorded plain, operand-XOR, operand-add, and operand-subtract variants, the engine performs 13,684,660 exact libsecp256k1 point gates and finds zero prize matches. Every partition records its candidate-stream digest, and a six-block fixture successfully rediscovers its planted three-block/operand-XOR scalar and uncompressed address. This certificate does not cover other subset sizes.

The parallel modular-product route is closed over the same subset sizes. Its Q3/Q4 families apply plain product and operand multiply, divide, add, and subtract; Q7 applies plain product and operand multiplication. Across 13,743,565 exact point gates, all terminal partition streams are hashed and there are zero prize matches. The enumerated control rediscovers a planted three-block product divided by the operand and verifies its complete point and uncompressed address. These product results cannot be inferred from either the additive or XOR searches.

The bounded nested-AES and whole-integer probe is also independently reproduced without hard-coded recovered keys. It derives 18 AES-256 keys from the eight K values, six unique token digests, Cosmic master value, Chain 4 password, and two operand paddings. The engine performs 630 ECB block decryptions, 54 CBC body decryptions with 1890 chunk gates, 10 whole-integer candidates, and 18 header-selected candidates. AES roundtrips and a known component-point gate pass; there are zero structural hits, component matches, or prize matches. Printable output is never treated as key evidence.

The four 15-byte E fragments are now covered by an independent scalar-family audit. It reproduces raw family counts F1=2052, F2=61, F3=224, and F4=72: 2,409 generated attempts in total. Global deduplication removes 692 repeated values, exactly reproducing 1,717 unique point gates. There are zero component or prize matches. The enumerated F2 control recovers its planted scalar through both equivalent left-pad and integer serializations, directly checking the deduplication boundary.

The more literal `+-` grammar audit is complete as well. It tests all 896 `15+15+2` E-fragment passwords with strict PKCS#7 validation, 10 whole/unstripped integer readings, 12,360 sign-window scalars, and 72 natural sign folds. Nine passwords pass padding by chance, but exactly one has the canonical `+-` plus 31+35x32 layout: the already-known `E_C || E_S || E_B[:2]` password and the verified Chain 4 plaintext. Every new scalar family has zero prize matches; C and D are additionally subsumed by the exhaustive signed-block certificate.

## Public-source audit boundary

The canonical history at `fb92dd1`, PR heads #68 and #93, 70 public forks, all issue/comment text, and 60 of 61 public attachment URLs were searched. The attachments collapse to 32 unique SHA-256 values; none has the reported `cd3fea3d...` prefix and no raw attachment metadata/body contains the unresolved terms. The sole unavailable attachment is recorded in `artifacts.json`.

The original Decentraland clue is now independently authenticated rather than accepted from a later reconstruction. The active scene entity `QmRK2YoLei9wrxLvHUKisywobxEvczTicXepPxKLKzN51v` at parcels `-41,-16, -41,-17` names `sounds/puzzlepiece.mp3` with CID `QmeRy5MjmEZ2W6J3DwhQfht5HKBKXBFpoGzSkzmjeGKiDK`. The downloaded 212,031-byte MP3 exactly reproduces that CID/SHA-256, and the scene script references the same path. Subtracting the right channel from the left and rendering the spectrogram visibly yields `HASHTHETEXT`. Because this could alter the ambiguous SalPhaseIon phrase “our first hint is your last command,” the audit also places `HASHTHETEXT`, its lowercase form, and other source-grounded strings into both semantic token slots: 96 pairs, exactly one strict-padding/1327-byte hit (`yourlastcommand`, `secondanswer`), and zero hits containing `HASHTHETEXT`. The authentic audio therefore validates the instruction that leads back to the first-page hash but does not replace the literal SalPhaseIon token or add a post-Chain-4 operand.

The refreshed Wayback CDX snapshot contains 788 URL-local digest-collapsed capture rows across 414 original URLs and 756 globally unique digest values. The previously reported 787 count was a collapsed-row count, not a globally distinct digest count. The first provenance-recovered selection yields exactly 64 primary SalPhaseIon/`app.js`/JSON targets plus 5 source-map/font controls. The broader early-site audit then covers every 2019-2021 puzzle-adjacent CDX row after excluding only account/shared/subscription surfaces: 80 exact captures, 73 unique bodies, all content-digest verified. This includes every captured home/page variant, `/Puzzle`, the exact lowercase `/puzzle` PNG (byte-identical to local `puzzle.png`), `/theseedisplanted`, its eight clue images, JavaScript, source maps, CSS, JSON, icons, and robots text. The broader corpus has zero unresolved-term hits, zero standalone 29/30/32-byte literals, zero `cd3fea3d` body-hash prefixes, and zero target-point candidates.

## Next required evidence

No further computational family is justified by the authenticated public bytes. The next productive step is acquisition, not another transformation search: obtain the actual `cosmic_A`/`ca` bytes (with full SHA-256 and length) or a creator/source-authenticated derivation of `ca[280:312]`, plus exact definitions for `row1-4` and `K_I1`. Any claimed final formula must then reproduce the complete prize point and address. Until one of those inputs appears, continuing to invent XOR triangles, ciphers, or block formulas would expand an unconstrained search rather than solve the documented puzzle.

Full byte-level provenance is in `artifacts.json`; generated binaries are under `artifacts/bin/`.
