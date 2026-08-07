# Primary sources

Archived creator artifacts in the parent repository. Prefer verifying against
Wayback or live captures when possible.

## Creator website (offline — use Wayback)

Live **gsmg.io puzzle pages are offline**. Full URL catalog with recommended
Wayback captures:

- **`CREATOR_WEBSITE_LINKS.md`** — human-readable stage order + asset links
- **`links.json`** — same data for scripts/agents
- **`archives/`** — local HTML copies for manual review

Parent-tree copies (also mirrored under `fresh-start/archives/`):

| path | original URL (approx.) |
| --- | --- |
| `../sources/GSMG _ GSMG.html` | `gsmg.io/phase1verification` (404 page) |
| `../sources/GSMG Puzzle2.html` | `gsmg.io/theseedisplanted` |
| `../sources/GSMG Puzzle3 - phase2.html` | phase 2 Merovingian slug |
| `../sources/GSMG Puzzle4 - phase3 salphaseion.html` | SalPhaseIon slug |
| `../sources/TheArchitectChoice.html` | `gsmg.io/TheArchitectChoice` |

Poster page (`gsmg.io/puzzle`) and `follow_the_white_rabbit.png` are **not**
saved locally — fetch from Wayback (links in `CREATOR_WEBSITE_LINKS.md`).

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
