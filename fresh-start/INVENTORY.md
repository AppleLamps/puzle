# Inventory — what is here, where it came from, what is missing

Every path below is inside this folder. `SHA256SUMS` fingerprints all of them:

```bash
sha256sum -c SHA256SUMS
```

## Creator-published material

| Path | What it is | Original URL |
| --- | --- | --- |
| `images/poster/follow_the_white_rabbit.png` | Stage 0 poster, 350×350 | `gsmg.io/img/follow_the_white_rabbit.png` |
| `images/rebus/*.png` | Eight stage 1 rebus tiles | `gsmg.io/img/*.png` |
| `archives/theseedisplanted.html` | Rebus / password page | `gsmg.io/theseedisplanted` |
| `archives/phase1verification.html` | The 404 returned on a wrong password | `gsmg.io/phase1verification` |
| `archives/phase2_choice.html` | Phase 2 page; carries two AES envelopes | `gsmg.io/choiceisanillusion…iwroteitmyself` |
| `archives/salphaseion_phase3.html` | SalPhaseIon page; symbol stream + one envelope | `gsmg.io/89727c59…52f6a32` |
| `archives/TheArchitectChoice.html` | Architect page | `gsmg.io/TheArchitectChoice` |

The gsmg.io puzzle pages are offline. `CREATOR_WEBSITE_LINKS.md` lists a Wayback
capture for each one so you can check any local copy against the archive.

`archives/theseedisplanted.html` is the only file that differs from its original
capture: the `<img>` paths were rewritten to point at `images/rebus/` so the page
renders offline. Every other archived file is byte-for-byte as captured, Internet
Archive wrapper markup included.

## Ciphertexts

Extracted from the pages above by `tools/extract_ciphertexts.py`, so each blob
traces back to a page you can open rather than to someone's transcription.

| File | Bytes | Source |
| --- | ---: | --- |
| `ciphertexts/phase2_keymaker.b64` | 672 | `phase2_choice.html`, first envelope |
| `ciphertexts/phase3_riddles.b64` | 4,112 | `phase2_choice.html`, second envelope |
| `ciphertexts/salphaseion_cosmic.b64` | 1,344 | `salphaseion_phase3.html` textarea |
| `ciphertexts/phase32.b64` | 2,448 | inside the phase 3 *plaintext* |

The phase 3.2 envelope is on no archived page: it only appears once phase 3 has
been decrypted. It is committed for convenience, and `tools/phase2_phase3.py`
rewrites it bit-identically from the decrypt, so the copy in the folder is not
something you have to take on trust.

## Plaintext extracts

`artifacts/` holds committed copies so you can diff your own output against
them. They are convenience copies, not sources — `tools/` regenerates all of
them into `derived/`, and `verify_all.py` checks the two agree.

| File | Contents |
| --- | --- |
| `artifacts/architect_plaintext.txt` | The 1,539-letter Architect plaintext |
| `artifacts/architect_continuation_excerpt.txt` | `[472:619]` of that plaintext |
| `artifacts/checkerboard_message.txt` | The 149-digit VIC decode |
| `artifacts/phase32_preamble.txt` | Readable opening of the phase 3.2 plaintext |
| `artifacts/salphaseion_fields.json` | The SalPhaseIon stream fields |
| `artifacts/seven_phrases.txt` | The creator's 2023-02-23 seven phrases, in order |

## What is not here, and why

- **The 2023-02-23 encoded image.** The seven phrases in
  `artifacts/seven_phrases.txt` are quoted from the creator's own decode
  description, not re-derived — the source image is not in this folder. The
  *order* is creator-stated; treat the phrase list as a quotation.
- **The Telegram export.** `CREATOR_STATEMENTS.md` quotes creator messages from
  an export that is not committed here (it is large, and it contains unrelated
  participants' data). Those quotes are the one class of claim in this folder
  you cannot check from the folder itself. Verify them against an export you
  trust before building on any single one.
- **The Decentraland audio.** The creator posted parcel coordinates
  **(-41, -17)** on 2020-02-20. The MP3 is not committed; obtain it from
  Decentraland or an archive if you want to reproduce that stage.
- **The rebus reading.** The eight tiles are committed, but pairing them into
  "cryptologic warning, can you dig it?" is a visual reading, not a computation.
  Open the PNGs and do it yourself.
- **Two SalPhaseIon literals.** Earlier write-ups list
  `lastwordsbeforearchichoice` and `thispassword` among the page's decoded
  fields. Neither reproduces from `archives/salphaseion_phase3.html`: the two
  digit fields after the `z` separators do not resolve to ASCII under
  digits→hex or digits→decimal. What *does* reproduce is recorded in
  `AUTHENTICATED_STAGES.md`. Both strings do appear in the creator's seven
  phrases, so they are not invented — but this folder cannot show them decoding
  off that page, and does not claim it.
