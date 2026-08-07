# Primary sources

Archived creator artifacts in the parent repository. Prefer verifying against
Wayback or live captures when possible.

## Archived HTML pages

| path | original URL (approx.) |
| --- | --- |
| `../sources/GSMG _ GSMG.html` | `gsmg.io/Puzzle` — poster page |
| `../sources/GSMG Puzzle2.html` | phase 1 rebus |
| `../sources/GSMG Puzzle3 - phase2.html` | phase 2 |
| `../sources/GSMG Puzzle4 - phase3 salphaseion.html` | phase 3 / SalPhaseIon |
| `../sources/TheArchitectChoice.html` | Architect choice page |

## Poster image

The puzzle PNG is referenced as `follow_the_white_rabbit.png` on the first page.
It may not be present in all clones of this repository. Wayback capture example:

`https://web.archive.org/web/20201115074715id_/https://gsmg.io/img/follow_the_white_rabbit.png`

Scripts expect it at `../sources/follow_the_white_rabbit.png` when available.

## Solver package inputs

The tested package reads ciphertext envelopes and README extracts from:

`../gsmgio-5btc-puzzle-master/README.md`

That README embeds Base64 blobs for phase 2, phase 3.2, SalPhaseIon, and related
material. It is a **solver corpus**, not a creator primary — but the embedded
ciphertexts match archived pages.

## Derived plaintexts (recomputed from sources)

| path | contents |
| --- | --- |
| `../derived/phase2_part1_plaintext.txt` | phase 2 part 1 decrypt |
| `../derived/phase3_plaintext.txt` | phase 3 opening |
| `../derived/phase32_plaintext.txt` | phase 3.2 opening (includes binary record) |
| `../derived/salphaseion_parts.json` | S91, S570, auxiliary fields |

This folder's `artifacts/` holds **subset extracts** for convenience; re-derive
from sources when integrity matters.

## Telegram

Creator messages (`Jrk Bgrt`) appear in a local Telegram export under
`../telegram/` (gitignored, not committed). Do not rely on community
participants' messages as creator evidence.

## Decentraland

Creator posted parcel coordinates **(-41, -17)** with caption referencing the
puzzle piece (2020-02-20). Audio asset must be obtained from Decentraland or
archives independently.

## What not to treat as primary

- `../docs/ATTEMPT_LOG.md` — prior experiment record
- `../CREATOR_SOURCED.md` sections after the creator statement tables — solver analysis
- `../gsmgio-5btc-puzzle-master/results/` — audit JSON from bounded searches
- `../gsmgio-5btc-puzzle-master/tmp/` — community notes
- `../transcripts/` — prior agent rollouts
