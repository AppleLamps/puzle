# GSMG.IO 5 BTC puzzle research

This repository combines the original puzzle artifacts, reproducible solver
code, archived community material, and several agents' forensic investigations.
The funded private keys have **not** been recovered.

## Start here

0. [Agent orientation](CLAUDE.md) — layout, established facts, and the
   discipline this repository holds itself to. Read this first.
1. [Creator-sourced evidence](CREATOR_SOURCED.md) — facts separated from solver
   interpretation.
2. [Solved-stage re-audit](docs/SOLVED_STAGE_REAUDIT.md) — independent
   re-derivation, exact bytes, and fitted/authenticated boundaries.
3. [Solution walkthrough](SOLUTION.md) — reproduced stages and corrections.
4. [Attempt log](docs/ATTEMPT_LOG.md) — running, deduplicated list of solved,
   negative, superseded, and open approaches.
5. [Transcript index](docs/TRANSCRIPTS.md) — community and agent sources.
6. [Telegram 2026 review](docs/TELEGRAM_2026_REVIEW.md) — what the current
   Telegram export adds, confirms, and refutes.
7. [Documentation index](docs/INDEX.md) — every maintained research document.
8. [Verification report](gsmgio-5btc-puzzle-master/VERIFICATION_REPORT.md) —
   machine-checked claims and exact cryptographic gates.

## Current result

The strongest new result is the creator-named yin-yang milestone:

```text
24 poster colours + consecutive primes:
Blue = 484, Yellow = 479

zero the balancing blue prime 5:
479 = 479

authenticated Architect plaintext[479:]:
PRIVATEKEYYOUVEEARNEDITBUTPLEASE...
```

The arithmetic and word-boundary hit are exact. Consecutive-prime assignment,
zeroing semantics, and zero-based indexing remain clue-driven conventions, so
this is a strong fitted structural hit—not a cryptographically authenticated
private-key derivation.

## Repository map

| Path | Purpose |
| --- | --- |
| `CLAUDE.md` | Orientation for an agent picking the puzzle up |
| `CREATOR_SOURCED.md` | Creator chronology and provenance audit |
| `SOLUTION.md` | Narrative reconstruction and corrections |
| `docs/` | Navigation, transcripts, and unified attempt history |
| `sources/` | Archived creator pages, their asset bundles, and the poster image |
| `scripts/` | Standalone stage scripts that read `sources/` and write `derived/` |
| `derived/` | Plaintexts, extracted fields, and audit JSON produced from `sources/` |
| `transcripts/` | Prior agent rollout transcripts |
| `gsmgio-5btc-puzzle-master/` | Tested Python solver package and generated audits |
| `gsmgio-5btc-puzzle-master/solver/` | Reproducible experiment modules |
| `gsmgio-5btc-puzzle-master/results/README.md` | Virtual catalog of result JSON files |
| `gsmgio-5btc-puzzle-master/artifacts/` | Acquired source artifacts and provenance records |
| `gsmgio-5btc-puzzle-master/tmp/` | Historical community/agent notes; not canonical |
| `telegram/` | 2026-08-05 community export; local only, never committed |

`gsmgio-5btc-puzzle-master/` keeps its own internal layout, because its modules,
tests, and the `artifacts.json` manifest address each other by those paths.

## Running the verified package

```bash
cd gsmgio-5btc-puzzle-master
python3 -m pytest -q
python3 -m solver.report
```

Run an individual audit with:

```bash
python3 -m solver.<audit_module>
```

The standalone stage scripts resolve their inputs through `scripts/_paths.py`,
so they run from any directory:

```bash
python3 scripts/solve.py          # stage one spiral
python3 scripts/solve_rebus.py    # stage two rebus tiles
python3 scripts/phase23.py        # phases two and three
python3 scripts/inspect_bundle.py # the phase1verification 404
```

## Status vocabulary

- **Solved** — mechanically reproduced with an independent control.
- **Negative** — a precisely bounded family was tested without a target match.
- **Open** — no intended operation or prize result is known.
- **Superseded** — a later finding corrected or better explained the attempt.
- **Fitted** — depends on solver-selected conventions not authenticated by the
  creator or a cryptographic oracle.

Do not treat readable fragments, AES padding, vanity prefixes, or community
labels as proof.
