# Transcript and prior-agent index

This file records where historical claims came from. A transcript is evidence
that an approach was attempted; it is not proof that its conclusion is correct.

## Agent transcript

### `rollout-2026-08-04T21-14-50-019fcf7c-cc26-7b91-b013-c82ce7cfddf0.jsonl`

- Approximately 23 MB and 5,919 events.
- Covers an autonomous investigation on 2026-08-05.
- Cross-checked in `SOLUTION.md`, `RESEARCH_LEDGER.md`, and the unified
  [attempt log](ATTEMPT_LOG.md).

Important contributions:

- Falsified the supplied 12×12 rabbit-maze reading and confirmed the 14×14
  spiral.
- Corrected the marker ordering to spiral `F73D92`.
- Connected 24 marker colours with 24 primes.
- Built SalPhaseIon preregistration families through v39.
- Ran bounded Chain 4, prefix-completion, book-anchor, Witteveen, Playfair,
  nonce, BIP32, and Half/Better-Half searches.
- Confirmed the authentic on-chain halving relationship.

Important corrections:

- The reported residual stage-one bits `0100` came from centre-pixel sampling;
  majority-cell sampling gives `0000`.
- The rabbit maze, QR-merlon payload, `0x77` block selector, Cosmic public
  point, Cosmic BIP32 interpretation, and several late Playfair/Four-square
  loops were falsified or superseded.
- The run ended without a private key.

## Community Telegram export

### `gsmgio-5btc-puzzle-master/tmp/chat_transcript.txt`

- 51,177 messages, 2019-04-20 through 2026-06-12.
- SHA-256 `63a85c037b83d87e7f55f25fa65941caa39c9bd2b02396c659e22c27dc79cb78`
  (`tmp/creator_jrk.txt`: `9ac8ef442f634597e4fd7578e3b08773833367ac0de401159ce984d036cfd312`).
  A newer export must be diffed against this hash before its extra messages are
  treated as new evidence.
- Contains creator posts, community speculation, deleted-account material, and
  solver-authored Bitcoin messages.
- Creator-only extraction:
  `gsmgio-5btc-puzzle-master/tmp/creator_jrk.txt`.

Use the raw transcript to recover surrounding conversation, not merely isolated
creator lines. Community conclusions must be independently reproduced.

Creator-linked highlights extracted from the transcript:

- 2020 first-image/second-door poem.
- 2021 prime and zero-out hints.
- 2021 Neo passport-expiry hint.
- 2022 reaction to the user-posted yin-yang image.
- 2023 reversed-bit pipeline.
- 2023/2025 statements that yin-yang is the next major phase.
- 2020-11-24 / 2021-01-07 / 2023-01-12 statements that the prize is deliberately
  halved at each Bitcoin halving, and that the reward is "the remaining" balance.
- 2025-04-28 and 2026-03-03 idiomatic uses of "the better half" for the
  creator's partner. See [HALF_AND_BETTER_HALF.md](HALF_AND_BETTER_HALF.md).

## Historical agent/community notes

### `tmp/kenorb-analysis.md` and `tmp/kenorb-gap.md`

These capture an older 500–1,500-password campaign over Matrix dialogue,
Architect phrases, prior stage passwords, numeric sums, KDF variants, and
classical ciphers. The exact helper scripts cited there are not all present, so
the aggregate counts are historical claims rather than fully reproducible
certificates. The seven-token Cosmic result was later reproduced; many “not yet
attempted” items in the gap document are now closed.

### `tmp/cody-chain.md`

Source report for:

```text
AFFECTTHISB → HILLONE → ASKHSKEY → SPACE → COMPS
→ WITVEEN → WITTEVEEN
```

The arithmetic is reproduced by `solver/witteveen_identity_audit.py`. Its
interpretation as the final key route is not established and has been
superseded as the primary yin-yang explanation by the direct `479 = 479`
construction.

## Git history as an agent record

The commit history preserves corrections and bounded experiments that are not
all narrated in a single transcript. Notable milestones include:

- stage-one spiral and rebus solves;
- Wayback phase recovery;
- correction of the 437-million-attempt wrong phase-two oracle;
- creator-sourced rebuild;
- second-door/yin-yang negative audits;
- Architect 479 discovery and continuation tests.

Use:

```bash
git log --oneline --all
git show <commit>
```

## Missing referenced material

The rollout mentions an external `MEMORY.md` and prior rollout-summary path.
Neither is present in this repository. Claims depending solely on those missing
files are not considered reproduced.
