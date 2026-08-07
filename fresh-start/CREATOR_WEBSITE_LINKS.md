# Creator website links (gsmg.io)

The live puzzle pages at **gsmg.io are offline** (domain parking or unrelated
content as of 2026). Use the **Wayback Machine** links below to open the
creator-published pages in a browser and review them manually.

Local HTML copies of pages saved in this repository appear under
`archives/` — see `archives/README.md` for the mapping.

**Puzzle PNGs** (poster + eight rebus tiles) are committed under `images/` —
see `images/README.md` for SHA-256 fingerprints.

## How to use this file

1. Open the **recommended Wayback capture** for each stage in a browser.
2. Compare against the local `archives/*.html` copy when one exists.
3. For assets (PNG tiles, poster image), use the **image** Wayback links
   (`im_` prefix) or download from capture.
4. To find additional captures: replace the timestamp in any Wayback URL, or
   browse the [CDX index](#full-wayback-index).

Do not assume every URL ever seen under `gsmg.io/*` is a creator puzzle page.
Review each capture yourself.

---

## Puzzle progression (canonical URLs)

### Stage 0 — entry / poster

| Role | Original URL (offline) | Recommended Wayback capture |
| --- | --- | --- |
| First puzzle page (poster) | `https://gsmg.io/puzzle` | [2020-11-09](https://web.archive.org/web/20201109085204/https://gsmg.io/Puzzle) · [2020-11-12 PNG redirect](https://web.archive.org/web/20201112011308im_/https://gsmg.io/puzzle) |
| Poster image | `https://gsmg.io/img/follow_the_white_rabbit.png` | [2020-11-15](https://web.archive.org/web/20201115074715im_/https://gsmg.io/img/follow_the_white_rabbit.png) · local: `images/poster/follow_the_white_rabbit.png` |
| Puzzle starts here (landing) | `https://gsmg.io/thepuzzlestartshere` | [2026-04-18 capture](https://web.archive.org/web/20260418154559/https://gsmg.io/thepuzzlestartshere) |

Decoded destination from poster (not a separate page slug in early captures):
`gsmg.io/theseedisplanted`

### Stage 1 — rebus / flower password

| Role | Original URL (offline) | Recommended Wayback capture |
| --- | --- | --- |
| Rebus form page | `https://gsmg.io/theseedisplanted` | [2020-11-12](https://web.archive.org/web/20201112021936/https://gsmg.io/theseedisplanted) · [2022-12-24](https://web.archive.org/web/20221224100253/https://gsmg.io/theseedisplanted) |
| POST target (404 when wrong password) | `https://gsmg.io/phase1verification` | [2023-09-08](https://web.archive.org/web/20230908000102/https://gsmg.io/phase1verification) — local copy: `archives/phase1verification.html` |

**Rebus tile images** — local copies in `images/rebus/`; Wayback originals:

| Local file | Wayback (PNG) |
| --- | --- |
| `images/rebus/black_banking - war.png` | [capture](https://web.archive.org/web/20201115075203im_/https://gsmg.io/img/black_banking%20-%20war.png) |
| `images/rebus/blue_ca.png` | [capture](https://web.archive.org/web/20201115075203im_/https://gsmg.io/img/blue_ca.png) |
| `images/rebus/blue_dig_i.png` | [capture](https://web.archive.org/web/20201115075203im_/https://gsmg.io/img/blue_dig_i.png) |
| `images/rebus/blue_lock_lo.png` | [capture](https://web.archive.org/web/20201115075204im_/https://gsmg.io/img/blue_lock_lo.png) |
| `images/rebus/red_crypto_gic.png` | [capture](https://web.archive.org/web/20201115075203im_/https://gsmg.io/img/red_crypto_gic.png) |
| `images/rebus/red_n_you.png` | [capture](https://web.archive.org/web/20201202082956im_/https://gsmg.io/img/red_n_you.png) |
| `images/rebus/red_open_lock_n_ing.png` | [capture](https://web.archive.org/web/20201115075203im_/https://gsmg.io/img/red_open_lock_n_ing.png) |
| `images/rebus/red_t.png` | [capture](https://web.archive.org/web/20201115075203im_/https://gsmg.io/img/red_t.png) |

Local copy of rebus page: `archives/theseedisplanted.html` (img tags point at `../images/rebus/`)

### Stage 2 — Merovingian / AES riddles

| Role | Original URL (offline) | Recommended Wayback capture |
| --- | --- | --- |
| Phase 2 page (full slug) | `https://gsmg.io/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself` | [2020-11-12](https://web.archive.org/web/20201112015439/https://gsmg.io/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself) · [2022-12-23](https://web.archive.org/web/20221223013654/https://gsmg.io/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself) |

Local copy: `archives/phase2_choice.html`

Shorter slug variant (truncated Merovingian line, may differ):

`https://gsmg.io/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessert`

### Stage 3 — SalPhaseIon

| Role | Original URL (offline) | Recommended Wayback capture |
| --- | --- | --- |
| Phase 3 URL (SHA-256 slug of first-page text) | `https://gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32` | [2023-06-01](https://web.archive.org/web/20230601222752/https://gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32) · [2023-11-27](https://web.archive.org/web/20231127181947/https://gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32) |
| Alternate slug | `https://gsmg.io/salphaseion` | [2026-04-10](https://web.archive.org/web/20260410131115/https://gsmg.io/salphaseion) |

Local copy: `archives/salphaseion_phase3.html`

Phase 3.2 Jacque Fresco quote and Architect/VIC material appear on this page
and in the solver README ciphertext extracts — verify against the 2023-06-01
capture.

### Architect choice page

| Role | Original URL (offline) | Recommended Wayback capture |
| --- | --- | --- |
| The Architect's choice | `https://gsmg.io/TheArchitectChoice` | [2025-08-24](https://web.archive.org/web/20250824124745/https://gsmg.io/TheArchitectChoice) |

Local copy: `archives/TheArchitectChoice.html`

---

## Other archived gsmg.io paths (review manually)

These URLs appear in the Wayback CDX index. Some may be puzzle-related; others
may be typos, parking pages, or later infrastructure. **Open and judge each
capture yourself.**

| URL | Example Wayback capture |
| --- | --- |
| `https://gsmg.io/phase1` | [2026-04-18](https://web.archive.org/web/20260418154030/https://gsmg.io/phase1) |
| `https://gsmg.io/phase2` | [2026-04-18](https://web.archive.org/web/20260418154051/https://gsmg.io/phase2) |
| `https://gsmg.io/phase3` | [2026-04-18](https://web.archive.org/web/20260418154138/https://gsmg.io/phase3) |
| `https://gsmg.io/phase3_2_2` | [2026-04-18](https://web.archive.org/web/20260418154159/https://gsmg.io/phase3_2_2) |
| `https://gsmg.io/phase3_2_2_2` | [2026-04-18](https://web.archive.org/web/20260418154220/https://gsmg.io/phase3_2_2_2) |
| `https://gsmg.io/hopeisthequintessentialhumandelusion` | [2026-03-10](https://web.archive.org/web/20260310083358/https://gsmg.io/hopeisthequintessentialhumandelusion) |
| `https://gsmg.io/hopeisthequintessentialhumandelusionsimultaneouslythesourceofyourgreateststrengthandyourgreatestweakness` | [2026-03-10](https://web.archive.org/web/20260310083345/https://gsmg.io/hopeisthequintessentialhumandelusionsimultaneouslythesourceofyourgreateststrengthandyourgreatestweakness) |
| `https://gsmg.io/puzzle/stage5` | [2025-05-05](https://web.archive.org/web/20250505123927/https://gsmg.io/puzzle/stage5) |
| `https://www.gsmg.io/puzzlesupposethisone` | [2024-04-11](https://web.archive.org/web/20240411234420/https://www.gsmg.io/puzzlesupposethisone) |
| `https://gsmg.io/door.png` | [2025-05-05](https://web.archive.org/web/20250505202719/https://gsmg.io/door.png) |

---

## Full Wayback index

The URLs above were selected from a CDX sweep of the domain (788 collapsed
captures, 414 unique URLs). Re-run the query to rebuild the full index for
yourself — it is a live archive, so it may now return more:

```text
https://web.archive.org/cdx/search/cdx?url=gsmg.io/*&output=json&filter=statuscode:200&collapse=digest
```

Browse any URL's capture history:

```text
https://web.archive.org/web/*/https://gsmg.io/<path>
```

---

## Decentraland (creator-posted, not gsmg.io)

Creator screenshot (2020-02-20): parcel **(-41, -17)**, caption references the
puzzle piece. Obtain the scene audio from Decentraland archives or community
exports independently.

---

## Machine-readable catalog

Same links in JSON: `links.json`
