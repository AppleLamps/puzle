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

### `telegram/` (2026-08-05 Telegram Desktop HTML export)

The current corpus. Not committed: 566 MB, and it contains unrelated
participant data.

- 56,693 non-service messages across 59 `messages*.html` files,
  `20.04.2019 02:55:39` through `05.08.2026 19:25:53`. 52,931 carry text,
  4,291 carry media, 507 distinct senders.
- Normalized transcript SHA-256
  `c7d3cf2c8e899278455a76ed3a9ce1e1126dc761e08f705802943bbdf1690166`
  (7,794,519 bytes), produced by walking `div.message.default`, skipping
  `service`, and inheriting the sender across `joined` continuations.
- Strict superset of `tmp/chat_transcript.txt`: +5,516 messages and roughly two
  further months. 2,397 messages postdate 2026-06-13. The 1,705 old messages
  that appear "missing" from the new export are link-rendering differences
  between the two exports, not deletions — sampled and confirmed.
- 482 creator messages. The last is 2026-07-16; the creator also appeared on
  2026-07-12, and both batches postdate the `CREATOR_SOURCED.md` table.
- `telegram/puzzle-telegram-transcript.json` (29,398,419 bytes) is the
  machine-readable form of the same export and is the preferred parse target.
  It carries stable numeric `id`s, `from_id`, numeric `reply_to_message_id`
  (no anchor resolution needed), and resolved media paths. Its message counts
  agree exactly with the HTML parse: 58,476 entries, 1,783 service and 56,693
  messages, 482 of them from `Jrk Bgrt` (`user9815232`), 148 of those replies.
- **Photos are complete.** All 2,334 photo references resolve to files on disk
  (2,525 files, 174,774,461 bytes, of which 284 are thumbnails). Coverage is
  continuous from 2019-04 to 2026-08; the earlier 2023-08 cutoff is closed.
- The JSON marks 1,957 messages' media "(File not included. Change data
  exporting settings to download.)", but `stickers/`, `video_files/`, `images/`
  and most of `files/` are physically on disk under their *original* names,
  referenced by neither index. The JSON still records `file_name` and
  `file_size` for each, which is enough to rebuild the mapping.
  `tools/telegram_media_reattach.py` does this and recovers **841** of them
  (571 documents, 141 stickers, 109 animations, 15 audio, 5 video).
- Genuinely absent after re-attachment: 1,116 items — 920 animations, 122
  stickers, 69 video files, 5 voice messages.
- Creator media: 18 items. All 3 photos resolve directly; re-attachment
  recovers 10 of the remaining 15. Every recovered creator item is a reaction
  meme, including both 2023-08-03 clips posted minutes from "the hardest part
  is done" (two *Mr. Robot* GIFs). The five still missing are
  `tumbleweed.mp4`, `the-train.mp4`,
  `matrix-merowinger-aktion-reaktion.mp4`, `forrest-gump-wave.mp4` and
  `happy-carrot.mp4`; their names and surrounding context identify them as
  jokes, so this gap is no longer a research priority.
- `telegram/files/` holds attachments the repository does not otherwise have,
  notably `Cosmic Duality (Mysteries of the Unknown).pdf` (19,542,842 bytes,
  MD5 `c94862274a5616cc0ecf78b82ced757c`) — the book the Cosmic page is named
  after — plus `The game of logic -- Lewis Carroll.pdf`, `covertQRcodes.pdf`
  and `2020-301.pdf`.

Handling rule, unchanged: extract creator messages plus minimal reply context.
Do not reproduce unrelated participant data in reports, and do not commit
session files, API credentials, or phone numbers.

### `gsmgio-5btc-puzzle-master/tmp/chat_transcript.txt`

Superseded by the 2026-08-05 export above, but retained as the hashed baseline
that the newer export was diffed against.

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
