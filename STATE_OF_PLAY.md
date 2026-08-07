# State of play — GSMG.IO 5 BTC puzzle

Last updated 2026-08-06. One page. Read this first, then
[`CLAUDE.md`](CLAUDE.md) for discipline and [`docs/ATTEMPT_LOG.md`](docs/ATTEMPT_LOG.md)
for the full record. The funded key has **not** been recovered.

## The one open question

**What is the intended operation at Architect plaintext offset 479, and what
object does the creator's phrase `yinyang` name?**

Everything else is either authenticated, or a bounded negative, or a
convention-dependent side branch. This is the whole frontier.

## The single most important fact about the frontier

The gap is a **missing idea, not a missing computation.** The repository holds
~1.59 million gated scalars and millions of AES trials against one cheap exact
oracle (Half's public key), and none hit. This session added five more
sealed families (v51–v54 plus the S-field null); all negative. Widening a
family has near-zero expected value and is the documented failure mode here.

The creator's own words point the same way: `yinyang` is a single conceptual
step, still unreached as of 2026-03-03; once reached the prize falls in hours;
and his **close friends who recognize how he thinks** are better placed than
skilled cryptanalysts (2026-07-12, his only self-declared hint). That describes
personal context, not more search.

## What is authenticated (do not re-derive)

Poster spiral → `gsmg.io/theseedisplanted`; 24 markers → `F73D92`; rebus;
phase 1; phase 2 seven-part hash; phase 3 URL; phase 3.2 Beaufort
(`THEMATRIXHASYOU`) → the 1,539-letter Architect plaintext; the VIC
checkerboard → the Half/Better-Half funds message; the SalPhaseIon literals
`matrixsumlist` / `enter` / `lastwordsbeforearchichoice` / `thispassword`;
Decentraland audio → `HASHTHETEXT`; Half's on-chain public key. All reproduced
from committed bytes this session.

**Authentication boundary:** nothing after phase 3.2 is authenticated. Under the
creator's criterion "breaking salphation should give the feeling of the phase's
name," phase 3.2 reads; the chain-1, chain-2, and Cosmic unlocks are
high-entropy and consistent with chance padding (v49: 12,132 clean unpaddings,
zero legible). Cosmic / Chain 4 / base-38 are solver conventions the creator
never named.

**Stronger as of 2026-08-07 (v79):** the three unlocks are not merely
*consistent with* chance padding, they are measured as it. All three strip
exactly one PKCS#7 byte where the authenticated phase 3.2 open strips ten;
99.58% of chance unpaddings of chain 1 are exactly the 79 bytes that the
32+32+15 grammar was built to explain; and the chain1 → chain2 WIF cascade
arises for 8.59% of chance unpaddings under the natural serialisation menu.
Treat all three envelopes as **unopened creator ciphertexts** and do not use
their plaintexts, the derived WIF, or anything below Cosmic as an operand.
`ATTEMPT_LOG.md` §36.

## Strongest fitted (not authenticated) result

The **479 balance**: 24 poster colours on the first 24 primes give Blue 484 /
Yellow 479; the imbalance is the blue prime 5; zero it → 479 = 479; Architect
`plaintext[479:]` = `PRIVATEKEYYOUVEEARNEDITBUTPLEASE…`. Exact arithmetic, but
consecutive-prime assignment, zeroing semantics and zero-based indexing are
solver-selected. Treat as **yin-yang located, door not yet opened** — the
creator says yin-yang is unreached, so 479 is at best incomplete.

## Closed this session (2026-08-06)

- **Unity-of-opposites phrase** — the Time-Life *Cosmic Duality* book-cover lead
  is verified (creator: "very specific" / "scary specific" / "provided a very
  specific hint already"), but the book's organising phrase and the creator-
  endorsed turn-inward clause do not open any envelope or gate to either target.
  `unity_of_opposites_audit.json`, `ATTEMPT_LOG.md` §19.
- **S570 seven 9×9 matrix fold** — faed = "fae" + 7×9×9; summed (sequential or
  intertwined) and 180-folded to 40 pairs + 1 center, verified exact, but no
  encoding of the sum/fold/pairs/spiral reaches the prize or opens an envelope.
  `s570_seven_matrix_fold_audit.json`, `ATTEMPT_LOG.md` §20.
- **S570 fold as Architect[479] selector** — the 40 pair values used as offsets
  into the authenticated Architect plaintext under the creator's sealed
  2023-02-23 pipeline rule set (4 index bases, 5 serializations, 3 overlays,
  offset 479): 624 unique scalars, 0 hits; 4,608 AES, 0 legible. Closes the
  fold-as-selector line without added parameters. `s570_fold_architect_selector_audit.json`,
  `ATTEMPT_LOG.md` §21.
- **v51** — split SalPhaseIon envelopes (env48/raw48) under the authenticated
  sha256-hex password format, legibility gate. 1,850 trials, 0 legible, 0 match.
- **v52** — the "close friends" hint as a preregistered recognition set (Fresco/
  Venus Project, GSMG meaning, better half, Matrix callbacks, passport date, his
  stated "ASCII 127", Hope quote, Dutch asides, Bella Ciao, Witteveen). 3,960
  trials, 0 legible, 0 match.
- **v53** — the red divider used as a real operand (resistor 2) on the
  first-image resistor grid with prime-zeroing. 288 derivations, 0 match. Closes
  the repo's own "red line barely used" gap.
- **v54** — the F-A-E Sonata reading. S570's own statistics reject a note stream
  under three mappings (chromatic note/rest small-step share 0.46 vs 0.6–0.8;
  motto `fae` 2× vs 0.65 chance). No score needed. Also rechecked the 63-sum ×
  F63 pairing: noise, confirming v45. **Both recorded §13 next-actions resolved
  negative.**
- **First image, from raw pixels** — rebuilt `follow_the_white_rabbit.png`: exact
  70×70 (5-px) grid, every cell uniform except the 7 the bunny crosses, so the
  nest holds one sub-grid object (the rabbit drawing) and no hidden bitstream.
  Spiral, markers, F73D92, 479 all reproduced.
- **Record corrections** — the 2026-07-12 "qubits" line restored to its full
  conditional quote (classical solvability is the creator's primary claim; ECDLP
  reading superseded); `faed[94:201]` corrected to gated-v40; post-3.2
  authentication boundary stated in `README.md`.
- **On-chain** — prize `1GSMG…` = 1.25634510 BTC, unmoved; `17ucy…` =
  3.75054755 BTC, never spent. Puzzle live; yin-yang unreached.

## Do not spend time on (each a documented dead end)

Cosmic / Chain 4 / base-38 as the next lock; new key derivations mined from the
`YOUWON` alignment (explaining it is open, mining it is closed); `faed[94:201]`
format sweeps (v40); Better Half as a second target (one oracle, settled);
Telegram media as password sources (creator items are reaction memes; the one
exception — the Time-Life *Cosmic Duality* book cover the creator rated "very
specific"/"scary specific" and called the already-given hint — is an endorsed
object with no attached operation, see `ATTEMPT_LOG.md` §19); the F-A-E Sonata
(v54); hashing any poster property that has no operation attached; and any
candidate accepted on padding, a readable fragment, a vanity prefix, a
community label, or on-chain activity at a solver-published address.

## The only two moves with new information

1. **A non-arbitrary reading of the 479 instruction** — "RETURN TO THE SOURCE
   CODES … REINSERTING THE PRIME BASICS … SEVEN INTERTWINED PASSWORDS" — that
   introduces **zero** new free conventions and continues to a scalar within
   hours (the creator's timing is the acceptance test). Every complete route
   tried so far adds at least one unforced choice; that is why they are
   falsifiable-only.
2. **Someone who knew the creator's thinking** applied to the 479 → yinyang
   step. This is what his one self-declared hint actually points at.

Both bring a genuinely new input. Everything runnable without one is exhausted.

## How to test a candidate

Gate every scalar through `solver/targets.py` (`gate_scalar` / `gate_scalar_bytes`),
never re-declare the constants, seal the family before searching, search AES
under a **legibility** gate not padding, and append one row to
`docs/ATTEMPT_LOG.md`. Clean padding, readable fragments, vanity prefixes,
community labels, and solver-published-address activity are **not** evidence.
