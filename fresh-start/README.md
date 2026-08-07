# Fresh start — independent analysis workspace

This folder is a **clean room** for analyzing the GSMG.IO 5 BTC puzzle without
inheriting conclusions from the parent repository's research record.

## What is here

Only material that can be checked against **primary sources**:

- Creator statements (`CREATOR_STATEMENTS.md`)
- On-chain prize facts (`PRIZE_TARGETS.md`)
- Cryptographically authenticated stage outputs (`AUTHENTICATED_STAGES.md`)
- Archived page and image locations (`PRIMARY_SOURCES.md`)
- Commands to reproduce authenticated stages (`REPRODUCTION.md`)
- Plaintext extracts in `artifacts/` (Architect, checkerboard, SalPhaseIon fields)

## What is deliberately excluded

The parent repository (`../`) contains solver experiments, attempt logs, bounded
negatives, fitted conventions, community claims, and agent write-ups. **None of
that is copied here.** An agent working in this folder should not treat parent-repo
analysis sections, README summaries, or result JSON as evidence unless it
independently re-derives them from primary sources.

Specifically excluded from this folder:

- Lists of approaches already tried or ruled out
- Interpretations presented elsewhere as settled (e.g. which operand a clue acts on)
- Solver-selected conventions passed off as creator instructions
- Community password orders, Cosmic/Chain labels, or publication-derived addresses
- Recommendations about what to try or avoid based on prior agents

## Epistemic rules

1. **Creator-published artifacts** (pages, images, ciphertexts) and **messages
   from `Jrk Bgrt`** are the strongest evidence.
2. **Successful AES decryption** to coherent plaintext is self-authenticating for
   that ciphertext and password.
3. **Exact hashes** (SHA-256 of a named byte string) fix a result once reproduced.
4. **On-chain data** (addresses, spends, public keys) is independently verifiable.
5. Everything else — including readable fragments inside random-looking output,
   padding-valid AES, vanity prefixes, and forum claims — requires independent
   proof before use.

When a result depends on a chosen convention (index base, prime assignment,
matrix orientation, token order), label it **fitted** until the creator or an
exact cross-check fixes the convention.

## Prize status

As of the archived material in this repository, the funded private keys have
**not** been publicly recovered. The creator has stated the puzzle remains valid
and classically solvable; verify current address balances on chain yourself.

## Layout

| File | Contents |
| --- | --- |
| `CREATOR_STATEMENTS.md` | Verbatim creator chronology and 2023-02-23 pipeline |
| `PRIZE_TARGETS.md` | Half and Better Half addresses; verification gates |
| `AUTHENTICATED_STAGES.md` | Reproduced stages, passwords, digests |
| `PRIMARY_SOURCES.md` | Where archived creator artifacts live |
| `REPRODUCTION.md` | Commands to re-derive authenticated outputs |
| `artifacts/` | Extracted plaintexts and field data (no audit JSON) |

## Working from here

1. Read `PRIMARY_SOURCES.md` and open the archived pages or images.
2. Run the reproduction commands in `REPRODUCTION.md`.
3. Compare outputs to the digests and plaintexts in `AUTHENTICATED_STAGES.md`
   and `artifacts/`.
4. Form hypotheses from creator statements and authenticated text only.

Do not read `../docs/ATTEMPT_LOG.md`, `../CREATOR_SOURCED.md` analysis sections,
or `../gsmgio-5btc-puzzle-master/results/` until you have your own independent
baseline — those files record prior work and can anchor assumptions.
