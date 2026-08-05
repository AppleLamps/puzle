# Reproducible SalPhaseIon breakthrough: `AFFECT THIS B` -> `HILL ONE / ASK H'S KEY` -> `SPACE` -> `COMPS` -> `WITVEEN`

> **Historical source report.** The arithmetic is preserved and summarized in
> [`../WITTEVEEN_IDENTITY_AUDIT.md`](../WITTEVEEN_IDENTITY_AUDIT.md). Its use as
> the final/yin-yang route is superseded by the direct 479 balance; see
> [`../../../docs/ATTEMPT_LOG.md`](../../../docs/ATTEMPT_LOG.md).

## Status first

This is **not a solved/private-key claim**. I do not have the private key yet.

It is a reproducible public-data route through the previously unresolved `dbbi...` / `faed...` section mentioned in [puzzlehunt issue #86](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/86). It produces several consecutive English controls and matches the creator's 2026 triangular hint. Every scalar reported below was checked against the exact prize public key; there is no match yet.

Starting references:

- https://github.com/consigcody94/gsmg-puzzle-solver
- https://github.com/consigcody94/gsmgio-5btc-puzzle

## Exact target oracle

I use the public key, not vanity-prefix similarity, as the pass/fail test:

```text
address = 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
h160    = a9553269572a317e39f0f518cb87c1a0ee1dbae4
pubkey  = 04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559
```

## 1. The 91-character `dbbi...` block is T13 and says `AFFECT THIS B`

The first unresolved lowercase block has 91 symbols, exactly:

```text
T13 = 1 + 2 + ... + 13 = 91
```

Place it row-major in a 13-row triangle, map `a..i` to A1 values `1..9`, and mark the prime-numbered cells with the original 24 blue/yellow genesis colors:

```text
BBBBYBBBYYBBBBYBBYYBYYBY
```

Sum by columns from right to left. Keep blue/yellow subtotals separate through column 4, then add them from column 4 onward. The shared pivot is intentional:

```text
separate subtotals through col 4 = AFFECT
combined subtotals from col 4   = THISB
result                           = AFFECTTHISB
```

This is an exact self-modifying instruction, not a language-score guess.

There is also a unique variable-length parse of this same block: for the numbers 1..83, a non-prime consumes one symbol, while a prime consumes either `b` (blue) or `be` (yellow). The 83 base symbols plus eight extra `e` markers consume all 91 characters and yield 23 colors:

```text
BBBBYBBBYYBBBBYBBYYBBYY
```

The sums of the prime numbers assigned to each color are exact:

```text
Blue   = 474
Yellow = 400
```

## 2. Apply 400 and 474 to B; the 570-character block opens

The following `faed...` block has 570 symbols. Split it into two 285-symbol halves `A` and `B`, reverse `B`, and map `a..i` to A0 values `0..8`.

Combining `AFFECT THIS B`, the two color sums, and the creator's separate statement that characters must be "zeroed out" strongly indicates zeroing the two selected entries of B. In zero-based coordinates in the original 570-symbol stream:

```text
raw[400] = i = 8  -> reversed-B position 169
raw[474] = h = 7  -> reversed-B position 95
```

Then add `A[i] + B[i]`. The 285 results split exactly as:

```text
7-character header + T23 (276 cells) + 2-character trailer
```

The header is:

```text
HILLONE
```

`HILLONE` is already present before the two mutations, so it is a structural control rather than evidence for the zeroing by itself. The mutations instead repair the central prime-column instruction described next.

The trailer is:

```text
KG
```

## 3. Reinsert the prime basics in T23

Put the middle 276 values row-major into a 23-row triangle. Select prime-numbered cells, convert each selected value to A1 by adding 1, sum by column, read columns right-to-left, and render the sums as A1 letters.

Before the two zero operations, the same prime-column route gives:

```text
___OHICGFASKOAKEYTFMDJK
```

Zeroing `raw[474]` changes `O -> H`, and zeroing `raw[400]` changes `A -> S`. The corrected exact output is:

```text
___OHICGFASKHSKEYTFMDJK
```

The three leading blanks are structural: T23 columns 21, 22, and 23 contain no prime-numbered cells.

The central control is naturally spaced as:

```text
ASK H'S KEY
```

The first two T23 source cells are `JK`, which reappear at the end under the reversed-column read. Together with the trailer `KG`, this gives:

```text
JKKG
```

Using A1 values, `JKKG` is the Hill matrix:

```text
[[10, 11],
 [11,  7]]
```

Its determinant is `-51 mod 26 = 1`, an exact and useful invariant. I have not yet proved where this matrix belongs in the final route.

## 4. `H = 42` identifies cell 42 and the key `HA`

The official theory-of-everything wording suggests the interpretation `H = 42`. The following observations in the data then check that interpretation:

- T23 cell 42 is exactly `H` after the B mutation.
- It is row 9, column 6, diagonal 4.
- Its underlying A/B pair is `h + a`, i.e. `HA`.
- Among the H-valued cells this source spelling is unique.

There is a second exact H decomposition in the phrase output. The `H` in `ASKHSKEY` has only two prime contributors:

```text
cell 89  -> A1 value 1 = A
cell 131 -> A1 value 7 = G
sum                         H
```

So the two reproducible H-key candidates are:

```text
HA -> A1 digits 8,1 -> decimal 81 -> 81 mod 26 = 3
AG -> A1 decimal key 17
```

The `HA -> 81 -> 3` conversion concatenates A1 digits and is not a standard Hill convention. It is an inference, as is reading `HILL ONE` as a scalar cipher. The route is nevertheless strongly self-validating in the next step.

## 5. Order-one Hill with key 3 produces the literal word `SPACE`

Remove the three structural blanks from the T23 output:

```text
OHICGFASKHSKEYTFMDJK
```

Treat `HILL ONE` literally as a one-dimensional Hill multiplication. Under standard A0 letters, multiply every character by the scalar `3 mod 26`:

```text
OHICGFASKHSKEYTFMDJK
          x 3 mod 26
= QVYGSPACEVCEMUFPKJBE
```

The exact literal `SPACE` appears at the instruction boundary once those conventions are chosen. This is the strongest validation so far of `H=42 -> HA -> 81 -> 3`.

## 6. The creator's five-dot hint is a literal T5

The 2026 hint was preceded by five consecutive creator posts:

```text
.
..
...
....
.....
```

The natural interpretation is a 15-cell T5. It fits the independently derived controls exactly:

```text
HILLONE + ASKHSKEY = 7 + 8 = 15

    H
   I L
  L O N
 E A S K
H S K E Y
```

The bottom row is literally `HSKEY`, and the `ASK` cells sit immediately above/down-left from the `KEY` cells. This is far more specific than a generic "try a triangle" clue.

A strongly supported, but still interpretive, next move is to obey the newly produced `SPACE`: remove the word `SPACE` and place the remaining 15 letters row-major into T5:

```text
QVYGVCEMUFPKJBE

    Q
   V Y
  G V C
 E M U F
P K J B E
```

## 7. Row sums produce `COMPS`

Sum every row using A0 values. The five integer sums are:

```text
[16, 45, 29, 41, 39]
```

Render those sums as A1 letters:

```text
PSCOM
```

Using A0 for the row sums, A1 for rendering, then rotating right by the inferred key `3` (equivalently starting at position 3) gives:

```text
COMPS
```

The arithmetic output is exact under those conventions; selecting the mixed bases and rotation remains inferred. This is the current frontier.

## 8. Two bounded readings of `COMPS`

### A. Composite-numbered T5 cells

The composite T5 cell IDs are:

```text
4, 6, 8, 9, 10, 12, 14, 15
```

They select:

```text
GCMUFKBE
```

No standard direct/hash/AES use of that string has matched the target.

### B. Blue/yellow components of the T23 column sums

Under the hypothesis that the uniquely parsed 23-color `dbbi` stream cycles across the T23 prime cells, preserve the nonzero blue/yellow component of every output column. There are 29 nonzero components. Retaining one placeholder for each of the three forced empty columns gives exactly 32 entries / 16 pairs under this convention:

```text
___OHICGFASKAGVWKWHKNJJZFCJDNVZK
```

The raw component values in hexadecimal are:

```text
00 00 00 0f 08 09 03 07 06 01 13 0b 01 07 16 17
0b 17 08 25 0e 0a 0a 1a 06 1d 0a 1e 28 16 34 25
```

This exact `3 + 29 = 32`, hence 16 pairs, may be the first concrete structural match for the Architect text's "SIXTEEN ENCRYPTIONS". Applying `JKKG` to those 16 pairs is natural, but the tested A0/A1/raw, direction, pair-order, and inverse variants have not produced the target or coherent SalPhaseIon plaintext.

A recursive variant is also worth recording: map the composite T5 cells back to their T23 output columns, then retain their nonzero blue/yellow components. Removing the one zero produces exactly another T5:

```text
CVWWHKNJJCJNVZK
```

The original 24-color genesis cycle produces only 14 symbols here, so this recursion favors the 23-color stream.

## 9. Preserve the zero: the eight component pairs form 4x4 and yield `WITVEEN`

Instead of dropping the zero, preserve both the blue and yellow entry for each of the eight composite T5 cells. Their source columns and raw ordered pairs are:

```text
T5 composite IDs = 4, 6, 8, 9, 10, 12, 14, 15
T23 columns       = 16, 9, 7, 6, 5, 3, 1, 0
B/Y pairs         = [3,0] [22,23] [23,8] [37,14]
                    [10,10] [29,10] [40,22] [52,37]
```

Rendering those values as A1 symbols while retaining the genuine zero gives 16 slots:

```text
C_VWWHKNJJCJNVZK
```

The natural 4x4 layout is:

```text
C _ V W
W H K N
J J C J
N V Z K
```

This creates exactly seven NW-SE diagonals. In the top-right to bottom-left order, their strings and A0 sums are:

```text
W | VN | _KJ | CHCK | WJZ | JV | N

22, 34, 19, 21, 56, 30, 13
 W,  I,  T,  V,  E,  E,  N
```

Therefore the next exact output under this convention is:

```text
WITVEEN
```

I enumerated the full bounded orbit: all eight D4 rotations/reflections, rows, columns, both diagonal families, forward/reverse order, and A0/A1 input/output conventions. They produce 32 unique strings; `WITVEEN` is the only clear word or proper name.

This is a strong structural signal because it simultaneously uses `COMPS`, the 16 component slots, `matrixsumlist`, and the Architect's "seven intertwined passwords." It is not yet a solved instruction. It still depends on the 23-color cycling hypothesis, row-major 4x4 placement, A0-to-A0 summation, and one canonical diagonal direction.

Direct, case-normalized, and SHA-256 forms of `WITVEEN` do not match the prize public key and did not decrypt the official SalPhaseIon blob. The immediate frontier is determining whether the seven diagonal strings above are the intended seven passwords and how the page's `sha256 ans too` instruction combines them.

## Exact negative results

These were bounded by actual clues; padding-only outputs were not counted as solutions.

| Audit | Result |
|---|---:|
| Standard/order-one and small Hill routes over the authentic strings | 57,572 scalar candidates; 0 target matches |
| 32-component vector, `JKKG`, half operations, direct/hash checks | 5,224 expanded candidates / 31,344 scalar-form checks; 0 target matches |
| 32-component vector used against the SalPhaseIon/Cosmic AES material | 156,720 decryptions; 0 coherent plaintext/target |
| AES-128/192/256 CBC/ECB, EVP MD5/SHA1/SHA256/SHA512 and PBKDF2 variants over clue-derived passwords | 298,458 decryptions; padding rate matched random; 0 coherent plaintext/target |
| T5 symmetries, 16 apex-to-base paths, line reads, overlay `MUF/JBE`, raw/SHA-256 passwords | 952 decryptions; 0 coherent plaintext/target |
| Literal `<3`, "best of everything", A/B/fold bitstreams, canonical T23 traversals | 15,288 scalar candidates and 61,152 AES tests; 0 target/coherent result |
| Structurally canonical 276 -> 256 reductions (T5+5 omissions, one-per-active-column, route ends) | 13,104 reductions, 56,128 unique scalars, 209,664 direct/hash/endian checks; 0 target |
| On-chain ECDSA nonce reuse/small-relation/HNP checks | no exploitable relation found |
| Hal Finney, H=+/-42, Conway/Life, and common Matrix phrase routes | no target match |

## Why I am not building on the current "Cosmic/Chain4" claims

I could not reproduce a public derivation of `cosmic_A` / `ca[280:312]` (also the blocker documented in [puzzlehunt issue #92](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/92)). The widely repeated 79-byte SalPhaseIon output ends in a one-byte `0x01` padding condition, which occurs by chance about 1/256 of the time; it does not yield coherent plaintext or the target key. The later 1327-byte/Chain4/XOR-triangle constructions depend on that unverified operand or on unpublished files.

I therefore kept this route anchored only to bytes in the public repository, the official clues, and exact English/control outputs.

## How close does this seem?

**Structurally, much closer than before. Cryptographically, not solved.**

`AFFECTTHISB`, `HILLONE`, `ASKHSKEY`, `SPACE`, `COMPS`, and now the uniquely language-like `WITVEEN` are consecutive structural signals, and the 15-letter stages match the creator's explicit five-row hint. That makes coincidence very unlikely and puts the solve on an authentic route.

The unresolved step is now narrower: determine the intended use of `WITVEEN` and of the seven diagonal strings `W | VN | _KJ | CHCK | WJZ | JV | N`, while separately testing the 32 full components / 16 pairs with `JKKG`. Every result must be verified against the full public key above. Until that succeeds, no candidate should be called the private key.

If anyone can reproduce `WITVEEN` and obtain the next exact instruction, please post the complete transform, indexing convention, and target-public-key check--not only a vanity-prefix score or valid PKCS#7 byte.
