# Git archaeology results

## Official solver repository, PR #16

- Repository: `puzzlehunt/gsmgio-5btc-puzzle`
- Fetched ref: `refs/pull/16/head`
- Commit: `f6468725bad55d41b0545d5f60a2bd0044b11736`
- Complete PR diff: 76 changed files, including 28 files under `hints/`.
- The branch contains `2023-08-06-1.png`, `-2.png`, `-3.png`, and `-4.png`; none was omitted.
- All 28 hint files are enumerated and transcribed in `TRANSCRIPTIONS.md`.
- Original-resolution OCR, dimensions, byte sizes, and SHA-256 values are in `raw_ocr.json`.

## HosterjackAGV repository

Repository: `HosterjackAGV/gsmg-5btc-puzzle`.

Checks performed against a non-shallow clone with full reachable history:

- fetched all advertised branches and tags;
- checked `main`, `feat/arcade-phase-games-governance`, and `game-rebuild`;
- ran `git log --all --diff-filter=D --name-status`;
- searched every reachable object name;
- inspected unreachable commit trees and scanned reachable/unreachable text-sized blobs for Telegram/export markers;
- queried GitHub releases and release assets;
- queried the public fork network.

Results:

- No Telegram export, `jrk_all_messages.txt`, or creator-message corpus was ever found as a tracked/deleted path.
- No public releases or release assets contain it.
- GitHub's public fork endpoint returned no forks.
- `.gitignore` explicitly excludes `jrk_all_messages.txt`, `jrk_*.txt`, `*jrk*messages*`, `telegram_export.*`, `*telegram_export*`, and `telegram_export_media/`.

Because the underlying corpus is absent, later quote compilations in that repository remain secondary evidence. A privacy-preserving source request was opened as [HosterjackAGV/gsmg-5btc-puzzle issue #4](https://github.com/HosterjackAGV/gsmg-5btc-puzzle/issues/4).
