# Local HTML archives

Offline copies of the creator-published pages. gsmg.io is offline, so open the
Wayback capture when you need embedded assets that are not saved locally, and
whenever you want to confirm a local copy against the archive.

| Local file | Original URL | Wayback capture |
| --- | --- | --- |
| `theseedisplanted.html` | `https://gsmg.io/theseedisplanted` | 2020-11-12 |
| `phase1verification.html` | `https://gsmg.io/phase1verification` | 2023-09-08 |
| `phase2_choice.html` | `https://gsmg.io/choiceisanillusion…iwroteitmyself` | see `../CREATOR_WEBSITE_LINKS.md` |
| `salphaseion_phase3.html` | `https://gsmg.io/89727c59…52f6a32` | [2023-06-01](https://web.archive.org/web/20230601222752/https://gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32) |
| `TheArchitectChoice.html` | `https://gsmg.io/TheArchitectChoice` | see `../CREATOR_WEBSITE_LINKS.md` |

`https://gsmg.io/puzzle` — the poster page HTML — is not saved locally. Use the
[2020-11-09 capture](https://web.archive.org/web/20201109085204/https://gsmg.io/Puzzle).
The poster image itself is committed at `../images/poster/`.

## Which of these carry ciphertext

| File | Envelopes |
| --- | --- |
| `phase2_choice.html` | two: the phase 2 payload and the phase 3 payload |
| `salphaseion_phase3.html` | one in a textarea, plus a second split across the letter stream |

`../tools/extract_ciphertexts.py` pulls them into `../ciphertexts/`.

## Provenance

Every file is byte-for-byte as captured, Internet Archive wrapper markup
included — with one exception: `theseedisplanted.html` has its `<img>` paths
rewritten to `../images/rebus/` so the page renders offline. Strip Wayback
chrome, or use the `id_`/`im_` raw capture URLs, when extracting bytes.

Fingerprints for every file here are in `../SHA256SUMS`.

Full link catalogue: `../CREATOR_WEBSITE_LINKS.md`.
