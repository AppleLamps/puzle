# Puzzle images

Creator-published PNG assets recovered from the Internet Archive (2020-11
captures). Full-length fingerprints for these files are in `../SHA256SUMS`;
verify with `sha256sum -c SHA256SUMS` from the folder root.

## Poster (stage 0)

| File | Size | SHA-256 | Wayback |
| --- | ---: | --- | --- |
| `poster/follow_the_white_rabbit.png` | 350×350 | `5e8d84b8…90d204f` | [2020-11-15](https://web.archive.org/web/20201115074715im_/https://gsmg.io/img/follow_the_white_rabbit.png) |

14×14 colour grid with a white-rabbit drawing. Decodes to
`gsmg.io/theseedisplanted` under a spiral read with majority-colour cell
sampling: `python3 tools/poster_spiral.py`.

## Rebus tiles (stage 1)

Eight tiles from `gsmg.io/theseedisplanted`. Each holds up to two elements
stacked vertically: pictograms (a bank, a closed padlock, an open padlock,
`+`, `−`) and letter fragments. Blue and black tiles have their colour block
flush left with white padding right; red tiles mirror that — so each original
line is a [blue-or-black | red] pair cut through the white gutter.

Pairing them is a **visual** reading, not a computation. No tool here does it;
open the PNGs, or open `../archives/theseedisplanted.html` in a browser, and do
it yourself.

| File | Size | SHA-256 |
| --- | ---: | --- |
| `rebus/black_banking - war.png` | 78×70 | `907b489f…3410d2` |
| `rebus/blue_ca.png` | 78×70 | `e59d42e8…9dd8be` |
| `rebus/blue_dig_i.png` | 77×70 | `a6889a2e…6d05f9` |
| `rebus/blue_lock_lo.png` | 82×70 | `60b01e5b…97cc6b` |
| `rebus/red_crypto_gic.png` | 79×70 | `8aad87b9…dd4a6f6` |
| `rebus/red_n_you.png` | 80×70 | `89a81a1b…f86aeb` |
| `rebus/red_open_lock_n_ing.png` | 82×70 | `ea1cd545…f3d203` |
| `rebus/red_t.png` | 79×70 | `86fb2eff…fd04d35` |

Wayback capture URLs for each tile are in `../CREATOR_WEBSITE_LINKS.md`.

## Viewing locally

Open the PNGs directly, or open `../archives/theseedisplanted.html` in a
browser — its image paths point back at `../images/rebus/`.
