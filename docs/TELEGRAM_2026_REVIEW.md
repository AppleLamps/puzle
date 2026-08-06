# Telegram corpus review, 2026-08-05 export

> Navigation: [repository index](../README.md) ·
> [creator-sourced rebuild](../CREATOR_SOURCED.md) ·
> [running attempt log](ATTEMPT_LOG.md) ·
> [transcript index](TRANSCRIPTS.md)

A full re-read of the newly exported Telegram corpus against the eight
categories requested, checking what the repository already covers and what it
did not. Export statistics and handling rules are in
[TRANSCRIPTS.md](TRANSCRIPTS.md); they are not repeated here.

The headline: the export is a strict superset of the committed transcript
(56,693 vs 51,177 messages, roughly two additional months), it contains two
previously unseen creator appearances, and it contains one technical result the
repository had recorded only as a transcript rumour and which now reproduces
exactly. It does not contain a solution.

## 1. Reconstructed puzzle stages

The community's stage reconstruction and this repository's agree, and the
agreement is now checkable rather than assumed. Three independent SHA-256
checkpoints published in the new window match what this repository computes:

| stage | checkpoint | status |
| --- | --- | --- |
| Cosmic plaintext, 1327 bytes | `4f7a1e4e…` | matches |
| Chain 4 `+-` record, 1151 bytes | `e4269ed5…` | matches |
| Chain 4 35 × 32-byte block region, 1120 bytes | `43d3fe43…` | matches |

This matters because a competing public branch hashes to `a80a399a…` at the
Cosmic step and everything downstream of it is unreachable. We are not on that
branch. No stage of the reconstruction was revised by anything in the new
material.

The chain as both sides now hold it: poster spiral → rebus → phase 2 seven-part
hash → phase 3 → phase 3.2 (VIC + Beaufort) → SalPhaseIon fields → Cosmic
Duality → Chain 4 → **yin-yang, unreached**.

## 2. Official creator clues and hints

Four creator appearances postdate the previous `CREATOR_SOURCED.md` table
(2026-03-03, 2026-05-28, 2026-07-12, 2026-07-16). All are now recorded there
with their reply context; the analysis is in
[CREATOR_SOURCED.md](../CREATOR_SOURCED.md#the-2026-statements-read-carefully).
The three that change how the search should be framed:

- **2026-03-03** — "I only need to look at the address. If any of you reaches
  the next phase, the price is taken in no-time." Third independent statement
  that yin-yang is terminal. There is nothing to design for after it.
- **2026-07-12** — "it's all still solvable with a few stable qubits", raised
  alongside BIP 360 twice. The creator's own model of the remaining gap is
  discrete-log hardness, not a missing clue.
- **2026-07-12** — "My close friends have the best chance of solving it (a few
  tried). But they don't have the skills some of you do." followed immediately
  by "NOTE: that is a hint." The only self-declared hint in four years of
  transcript. It points at personal knowledge of the creator rather than
  cryptanalysis — structurally the same shape as "Half and Better Half" turning
  out to be his partner rather than two derivable keys.

Two things in the new window read like hints and are not: "you have to be in
your prime" is a pun in a thread about whether 2 counts as prime, and "it's
hidden in a room with a hidden door" is about his physical laptop. Both are
annotated as such so they are not mined later.

## 3. Confirmed solutions and partial results

Nothing in the new window solves a stage. One previously unverified result is
now fully reproduced and committed.

**The `YOUWON` alignment at S91 index 21.** Subtracting the Phase 3.2 VIC
plaintext from S91 letterwise mod 26 spells `YOUWON` starting at zero-based
index 21, splitting 91 as 21 / 49 / 21. The repository held this only as an
`ATTEMPT_LOG` row marked "transcript-only". It is now
`solver/youwon_index21_audit.py`, which sources both operands from committed
artifacts and reproduces all five published checkpoints, plus the two published
checkpoints of the claimed continuation.

Two further signals select the same index:

- The subtraction's **borrow rail** has its only run of seven ones there,
  reading `1111111` = 127 = `DEL`.
- The Phase 3.2 checkerboard's **codeword-width rail** has its longest run
  (nine) there.

**The honest caveat, which the repository now records and the original post
partly acknowledged.** These are not three independent witnesses. The
subtraction underflows exactly when `m + a ≥ 26`, and the letters of `YOUWON`
force that at all six positions — the borrow run is a consequence of the word,
not evidence for it. Only the VIC rail is independent of S91, and under 20,000
random permutations of the VIC plaintext the two rails' longest runs coincide
8.4% of the time. The alignment is a real, unexplained structural fact and worth
keeping; it is not a 1-in-a-million coincidence.

## 4. Promising technical approaches

- **`faed[94:201]` as an unexamined operand.** Reading the 2021-04-01
  `{1},{4},{21}` line as row indices into a 21-row decomposition of the
  SalPhaseIon plaintext — row 1 = `dbbi`/S91, row 21 = `anstoo`, row 4 =
  `faed[94:201]` — so that the line reads "two doors you've got, one you don't".
  **Treat the framing as dead and the slice as merely untested.** Pressed for
  the 22 boundary offsets, the claimant answered honestly that the 21-row split
  "isn't from an independent rule, it's as-transcribed from the soup layout …
  the 21 boundaries were NOT fixed independently before applying {1,4,21}", and
  that the slice is "just whatever the 4th transcribed row covers". Checked
  here: the canonical `textarea1` has no line breaks at all, so there is no
  21-row structure to recover. What survives is a ~107-character slice of S570
  that nobody has run through the gates, which is worth an hour, not a theory.
- **`NOTES` (2026-07-16).** A capitalised callback to "NOTE: that is a hint",
  left unexplained. Open, uninterpreted.
- **Continuing the alignment.** The 49-character middle block that `YOUWON`
  opens is undigested. The published continuation (`KMODEST` → `MODEST` →
  `YOU WON - BE MODEST`) is gated and negative, and its last step is disclaimed
  by its own author, but the middle block itself is not exhausted.

## 5. Dead ends and refuted claims

- **The `btcseed` BIP39 mnemonic.** The most-discussed claim in the new window
  and it does not hold. The channel split is real, but a valid checksum is not
  evidence: 13 of 3,624 mapping × offset windows are checksum-valid by chance
  against an expected 14, offset 27 and length 132 are unmotivated free
  parameters, BIP44/49/84 derivations and the raw entropy miss both addresses,
  and — decisively — the prize address is a vanity address, so it cannot come
  from a seed phrase at all. A textbook checksum overfit, and the community
  reached the same verdict.
- **The 21-row `{1},{4},{21}` decomposition.** Retracted by its own author when
  asked for the boundary offsets, and independently falsified here: the
  canonical `textarea1` has no line breaks.
- **`YOU WON - BE MODEST` as a key.** Terminal strings gated through the
  production target gate; no match.
- **The bounded family around the alignment.** 143 unique in-range scalars from
  25 string sources × 3 letter cases × {SHA-256, XOR `0x7f`, byte-reversed},
  plus five integer readings. All rejected, with a planted positive control
  accepted on the same code path.

## 6. Relevant attachments and references

The export carries files the repository did not have. Most important:

- **`Cosmic Duality (Mysteries of the Unknown).pdf`** (19,542,842 bytes, MD5
  `c94862274a5616cc0ecf78b82ced757c`) — the book the Cosmic page is named after.
  Never examined here.
- `The game of logic -- Lewis Carroll.pdf`, `covertQRcodes.pdf`, `2020-301.pdf`,
  plus community analysis scripts and spreadsheets.

**The photo gap is now closed.** A second export supplied all 2,334 photos
(2,525 files, 175 MB) plus `puzzle-telegram-transcript.json`, whose counts agree
exactly with the HTML parse. What the images actually contained is in §6a.

The non-photo media turned out to be recoverable without another export. The
JSON marks 1,957 items "not included", but `stickers/`, `video_files/` and
`images/` are physically present under their original names, orphaned by both
indexes — and the JSON still records each item's `file_name` and `file_size`.
Matching on those (`tools/telegram_media_reattach.py`) recovers **841**,
including **10 of the creator's 15** unresolved posts. 1,116 remain absent.

## 6a. What the recovered photos showed

The creator posted exactly three photos in seven years, and all three are now
readable:

- **2020-01-04** — a still from *The Matrix Reloaded*: the Merovingian's cake.
  That is the "causality" scene, and `causality` is the authenticated phase-two
  part-one password. Posted ten days before the "Roses are White" poem. It does
  not change the solve, but it is creator-sourced provenance for a password we
  had only inferred.
- **2020-02-20** — a Decentraland screenshot captioned 😎, with the parcel
  label visible: **"GSMG.io Puzzle piece, -41,-17"**. Creator provenance for the
  Decentraland stage, whose audio difference channel decodes `HASHTHETEXT`.
- **2026-07-16** — a Clonazepam side-effects screenshot, replying "Nice" to a
  `ClonaZepamIon` pun. No puzzle content.

**The creator's animations carry nothing.** This was the open question after the
photos landed, and re-attachment answers it. All ten recovered items are
reaction memes, including the two posted on 2023-08-03 within a minute of "the
hardest part is done" — both are *Mr. Robot* GIFs ("Is there something you want
to tell me?", "What if I told you we could make it like none of this ever
happened?"), aimed at the chat rather than encoding anything. The 2023-01-12
halving-day clip is *The Big Lebowski* "You don't say"; 2021-03-27 is South Park
"Drugs are bad, mkay"; 2020-05-11 is a bored Alice in Wonderland. The five still
missing are named `tumbleweed`, `the-train`,
`matrix-merowinger-aktion-reaktion`, `forrest-gump-wave` and `happy-carrot`, and
their surrounding context is a "give us a hint" thread the creator was
deflecting — the Merovingian clip lands two seconds after "Hint? Hint? Heh, what
craziness are you talking about? There is no hint."

The one durable observation: the creator reaches for the Merovingian repeatedly
— the 2020-01-04 cake photo and the 2024-11-29 `aktion-reaktion` clip are both
the causality scene. Thematically consistent with `causality` being the
authenticated phase-two password, and with nothing more.

From the 95 community photos in the new window, two claims were worth checking
and both were checked here:

- **The off-white cell as a "dual-prime index."** Claimed as spiral 163 /
  row-major 103, both prime. The cell is at zero-based `(7,4)`, which this
  repository already records. But zero-based row-major is 7·14+4 = **102**,
  which is not prime, and one-based spiral is **164**, which is not prime. The
  claim holds only by taking the spiral index zero-based and the row-major index
  one-based. Convention shopping, not a signal.
- **The diagonal-91 observation.** A 14×14 grid minus its main diagonal splits
  into two triangles of (196−14)/2 = **91** cells each, and 91 = C(14,2). S91 is
  exactly 91 characters, and the `YOUWON` split's 21 = C(7,2). The arithmetic is
  right and the echo is real; there is no construction attached to it, and 91 is
  a small enough number that this is suggestive at best. Logged, not built on.

Two other new-window items are noise and are recorded as such so they are not
re-mined: `another door found on 1.4.21` is a joke pairing the hint with a
COLDCARD firmware advisory, and the "hidden room with a hidden door" screenshot
confirms that line was answering a joke about searching Ibiza for the creator's
laptop.

## 7. Recommended next steps

1. ~~Acquire the missing media.~~ **Done and closed.** Photos resolve directly,
   `tools/telegram_media_reattach.py` recovers 841 more, and every recovered
   creator item is a reaction meme. The 1,116 still absent are community GIFs
   and stickers. Media is no longer a research priority.
2. ~~**Gate `faed[94:201]`.**~~ **Done and closed.** Recorded here as unrun, but
   the slice was already gated as v40 (`salphaseion_faed_slice_audit.json`, 50
   unique scalars, no match). Corrected 2026-08-06; only a new family beyond
   that format sweep would be fresh work.
3. **Read the Cosmic Duality PDF** against the Cosmic page — the name is the
   creator's, not a solver's label.
4. **Continue treating Half's exact public key as the single prize gate.** The
   2026 statements reinforce this: one address, one oracle, no second target.
5. **Do not build further on the alignment without a new independent signal.**
   The 8.4% figure is the reason.

## 8. Current status and unresolved bottlenecks

The puzzle is live, the coins are unspent, and the creator confirmed both in
2026-05 and 2026-07. Yin-yang remains unreached as of the creator's last
statement on it, and he treats reaching it as equivalent to the prize being
claimed.

The bottleneck has not moved: **no derivation of a scalar matching Half's exact
public key.** Everything after Chain 4 is convention-dependent, and the new
material adds one reproducible structural observation without adding a
derivation. The creator's own framing — "still solvable with a few stable
qubits" — is a reason to suspect the remaining step is not a clue we have
missed, and his one self-declared hint points away from cryptanalysis entirely.

Open frontier items are tracked in
[ATTEMPT_LOG.md](ATTEMPT_LOG.md#12-current-open-frontier).
