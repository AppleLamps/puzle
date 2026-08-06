# Agent orientation

This repository is a forensic research record of the **GSMG.IO 5 BTC puzzle**.
The funded private keys have **not** been recovered. Nothing here is a solution
in progress that you can finish by tidying it — every cheap idea has been tried,
and most of the value in this repo is the precise record of *what was ruled out
and why*.

Read this file, then [`docs/ATTEMPT_LOG.md`](docs/ATTEMPT_LOG.md), before
proposing anything. The single most common failure mode for an agent here is
re-running a bounded family that section 12 already records as **NEGATIVE**.

## Where everything is

| Path | What it holds |
| --- | --- |
| `README.md` | Entry point and current result summary |
| `SOLUTION.md` | Narrative reconstruction of every reproduced stage |
| `CREATOR_SOURCED.md` | Creator-authenticated chronology; the provenance boundary |
| `docs/INDEX.md` | Index of every maintained document — start navigation here |
| `docs/ATTEMPT_LOG.md` | **Canonical append-only log** of approaches, 12 sections |
| `docs/SOLVED_STAGE_REAUDIT.md` | Independent re-derivation; authenticated vs fitted |
| `docs/HALF_AND_BETTER_HALF.md` | Why there is exactly one prize target |
| `docs/TRANSCRIPTS.md` | Provenance of every transcript and prior-agent claim |
| `docs/TELEGRAM_2026_REVIEW.md` | What the 2026-08-05 Telegram export adds |
| `sources/` | Archived creator pages, their asset bundles, the poster image |
| `scripts/` | Standalone stage scripts; read `sources/`, write `derived/` |
| `derived/` | Plaintexts, extracted fields, and audit JSON built from `sources/` |
| `transcripts/` | The one rollout transcript archived in-repo (25.7 MB) |
| `gsmgio-5btc-puzzle-master/` | The tested solver package — the real working surface |
| `telegram/` | 566 MB community export; **gitignored, local only** |

Inside the package:

| Path | What it holds |
| --- | --- |
| `solver/` | ~120 reproducible experiment modules, one per hypothesis |
| `solver/targets.py` | **The only acceptance gate.** Never re-declare targets |
| `artifacts/` | Acquired source artifacts with provenance records |
| `artifacts/bin/` | Byte-sealed mirrors of the result JSON; do not edit by hand |
| `artifacts.json` | Manifest, addressed from the **repository root** |
| `results/README.md` | Catalog of every result JSON |
| `tests/` | 47 tests; `python -m pytest -q` from the package directory |
| `tmp/` | Historical community notes (kenorb, cody); **not canonical** |
| `RESEARCH_LEDGER.md`, `VERIFICATION_REPORT.md`, `SALPHASEION_PREREGISTRATION.md` | Claim ledger, generated verification, preregistration v1–v39 |

Path conventions in `docs/ATTEMPT_LOG.md`: a bare filename is relative to
`gsmgio-5btc-puzzle-master/`; a `../` prefix means the repository root.

## The two prize targets

Everything is judged against these, and only these:

| | Address | Gate available |
| --- | --- | --- |
| **Half** | `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` | Exact public key — it has spent, so `x = f4d1bbd9…5d5a464` is on chain |
| **Better Half** | `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` | `hash160` only — never spent, so no public point exists |

Two traps are encoded in `solver/targets.py` because they already caused real
defects:

- A gate written against a *public key* silently rejects every correct Better
  Half candidate. Better Half must be gated by `hash160`, under **both**
  serializations, because its correct encoding is unknown.
- The two 32-byte halves of the Cosmic base-38 output were historically
  mislabelled "Half" and "Better_Half". They are solver derivations, were
  published publicly, and were swept to zero from 2026-04-12. Their on-chain
  activity is a consequence of publication and is **never** creator
  confirmation. They live in `NON_TARGETS` so this cannot recur.

Gate every candidate through `solver.targets.gate_scalar` /
`gate_scalar_bytes`. Do not copy target constants into a new module.

## What is established

Authenticated — an exact hash, decryption, or independent source fixes it:

| Stage | Result |
| --- | --- |
| Poster | 14×14 down-first counter-clockwise spiral, majority-cell sampling → `gsmg.io/theseedisplanted`, residual `0000` |
| Poster markers | 24 markers on every 8th spiral bit; marker colour restates that bit → `F73D92` |
| Rebus | Eight tiles pair into "cryptologic warning, can you dig it?" |
| Phase one | `theflowerblossomsthroughwhatseemstobeaconcretesurface` |
| Phase two | 227-byte seven-part concatenation → `1a57c572…d2ec30d5` |
| Phase 3 URL | `sha256("GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")` — the first page's own text, **not** the phase-2 answer |
| Phase 3.2 | Beaufort key `THEMATRIXHASYOU`, `P = K − C mod 26` → 1,539-letter Architect plaintext |
| Checkerboard | 149 digits → the Half/Better-Half funds message |
| SalPhaseIon literals | `matrixsumlist`, `enter`, `lastwordsbeforearchichoice`, `thispassword` |
| Decentraland | Stereo MP3, mono = L − R, spectrogram → `HASHTHETEXT` |
| Blockchain | Half's uncompressed public key; the halving relationship |

Fitted — the arithmetic reproduces, but a convention was solver-selected:

- The **479 yin-yang milestone**: 24 poster colours + consecutive primes give
  Blue 484 / Yellow 479; zeroing the balancing blue prime 5 leaves 479 = 479,
  and Architect `plaintext[479:]` begins `PRIVATEKEYYOUVEEARNEDITBUTPLEASE`.
  The hit is exact and it is the strongest structural result in the repo — but
  consecutive-prime assignment, zeroing semantics, and zero-based indexing are
  all clue-driven conventions. It is not a key derivation.
- The Witteveen chain, the `YOUWON` alignment at S91 index 21, and the
  Cosmic → Chain 4 branch are in the same category or weaker. Chain 4 is
  unauthenticated.

## The open frontier

From `docs/ATTEMPT_LOG.md` §12, unchanged as of 2026-08-05:

1. The intended operation after Architect offset 479.
2. The 23/16/7 partition, without introducing a free cipher/key choice.
3. Recovering or rejecting the unavailable community operands with provenance.
4. A scalar matching Half's exact public key.
5. The `YOUWON` alignment at S91 index 21.

Also recorded but unassigned: gate the ~107-char `faed[94:201]` S570 slice; the
unexplained creator `NOTES` callback of 2026-07-16; read
`telegram/files/Cosmic Duality (Mysteries of the Unknown).pdf`; the 49-char
middle block after `YOUWON`.

## What not to do

**Never treat these as evidence of a solve.** Each has already produced a false
positive in this repository's history:

- Valid AES/PKCS#7 padding. A `Salted__` envelope that unpads cleanly proves
  nothing — the search spaces here are large enough that clean padding arises by
  chance. `SHA256("MatrixSumlist\nAnsToo")` was accepted on this basis and later
  retracted, twice, by two independent agents.
- A readable English fragment inside otherwise random output.
- A vanity address prefix.
- A community label, a forum claim, or a number that "works out".
- On-chain activity at an address a solver published.

**Do not:**

- Re-declare prize constants outside `solver/targets.py`.
- Edit `artifacts/bin/*` or the sealed manifests by hand — they exist so a later
  claim can be checked against bytes that predate it.
- Report a sealed-but-unexecuted preregistration as a failed test. Unexecuted is
  **OPEN**, never NEGATIVE.
- Delete or rewrite a superseded interpretation. Mark it **SUPERSEDED** and keep
  the reasoning; the corrections are the most reusable part of this record.
- Rewrite `gsmgio-5btc-puzzle-master/README.md` as current analysis. It is the
  upstream corpus and extractor input.
- Present a *fitted* result as *authenticated*. This distinction is the whole
  epistemic backbone of the repository.
- Commit anything from `telegram/`. Extract creator messages plus minimal reply
  context; never reproduce unrelated participants' data, session files,
  credentials, or phone numbers.

## Working discipline

When you add an experiment (from `docs/INDEX.md`, still binding):

1. Preserve the exact input and its provenance.
2. Add or update a reproducible solver module.
3. Record the result JSON and its cryptographic acceptance gate.
4. Gate every candidate scalar through `solver/targets.py`.
5. Append one row to `docs/ATTEMPT_LOG.md`.
6. Mark replaced interpretations **superseded** rather than deleting them.

Preregister before you search. The `SALPHASEION_PREREGISTRATION.md` ledger
(v1–v39) exists because post-hoc acceptance criteria are how a bounded negative
turns into a false positive.

Verify the package still passes before and after a change:

```bash
cd gsmgio-5btc-puzzle-master
python -m pytest -q        # 47 tests, roughly 3 minutes
python -m solver.targets   # re-derives every target constant
python -m solver.report    # regenerates VERIFICATION_REPORT.md
```

The standalone stage scripts resolve their inputs through `scripts/_paths.py`
and run from any directory:

```bash
python scripts/solve.py          # stage one spiral
python scripts/solve_rebus.py    # stage two rebus tiles
python scripts/phase23.py        # phases two and three
python scripts/inspect_bundle.py # the phase1verification 404
```

Note that `python3` is not on PATH on this machine; use `py` or `python`.

## Known defects, recorded not fixed

- The committed VIC alphabet `FUBCDORA.LETHINGKYMVPS.JQZXW` has 28 characters
  but only 27 distinct: `.` is duplicated where the README's own derivation
  produces `/` (line 332 derives the `/` form, line 336 invokes the `.` form).
  Decoding the phase-3.2 ciphertext under both alphabets gives byte-identical
  plaintext, because the differing cell is never selected — so no result
  changes, but any future decode that reaches that cell would be wrong.
- `oracle.py` searches a **wrongly attributed** digest. Its 437-million-attempt
  campaign is retained as a historical negative; the slug it targets is the
  SHA-256 of the first poster's visible text, not of phase-two parts 1..7. Do
  not use it as a current phase-two oracle. Its docstring says so.
