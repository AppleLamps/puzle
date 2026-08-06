"""Re-attach orphaned Telegram media to the messages that posted them.

The two Telegram exports in ``telegram/`` are complementary and neither is
self-sufficient:

* ``puzzle-telegram-transcript.json`` indexes every message and resolves all
  2,334 photos, but marks animations, stickers, video, audio and documents as
  ``(File not included. Change data exporting settings to download.)``.
* The HTML export links only ``files/``.
* ``stickers/``, ``video_files/`` and ``images/`` sit on disk under their
  *original* names, referenced by neither index.

The JSON still records ``file_name`` and ``file_size`` for every item it could
not include, which is enough to rebuild the mapping: match on exact byte size,
disambiguate by base name, and account for the ``name (2).ext`` suffixes
Telegram appends on collisions.

Run from the package root::

    python tools/telegram_media_reattach.py            # summary + creator media
    python tools/telegram_media_reattach.py --dump     # every resolved id

Recovering a file is not the same as the file mattering. Every creator item
recovered so far has been a reaction meme; see
``../../docs/TELEGRAM_2026_REVIEW.md``.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

EXPORT_ROOT = Path(__file__).resolve().parents[2] / "telegram"
TRANSCRIPT = EXPORT_ROOT / "puzzle-telegram-transcript.json"
SEARCH_DIRS = ("files", "stickers", "video_files", "images", "photos")
NOT_INCLUDED = "(File not included"
CREATOR = "Jrk Bgrt"


def index_by_size(root: Path) -> dict[int, list[Path]]:
    sizes: dict[int, list[Path]] = collections.defaultdict(list)
    for name in SEARCH_DIRS:
        directory = root / name
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if path.is_file():
                sizes[path.stat().st_size].append(path)
    return sizes


def strip_collision_suffix(stem: str) -> str:
    """``giphy (4)`` -> ``giphy``; Telegram numbers duplicate names."""
    if stem.endswith(")") and " (" in stem:
        head, _, tail = stem.rpartition(" (")
        if tail[:-1].isdigit():
            return head
    return stem


def resolve(message: dict, sizes: dict[int, list[Path]]) -> Path | None:
    size = message.get("file_size")
    name = message.get("file_name")
    if not size or not name:
        return None
    candidates = sizes.get(size, [])
    if not candidates:
        return None
    wanted = Path(name)
    exact = [
        path
        for path in candidates
        if strip_collision_suffix(path.stem) == strip_collision_suffix(wanted.stem)
        and path.suffix.lower() == wanted.suffix.lower()
    ]
    if exact:
        return exact[0]
    # A unique size is decisive even when the name was rewritten.
    return candidates[0] if len(candidates) == 1 else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", action="store_true", help="print every resolved message id")
    parser.add_argument("--root", type=Path, default=EXPORT_ROOT)
    arguments = parser.parse_args()

    transcript = arguments.root / TRANSCRIPT.name
    messages = json.loads(transcript.read_text(encoding="utf-8"))["messages"]
    sizes = index_by_size(arguments.root)

    unresolved = [
        m
        for m in messages
        if m.get("type") == "message" and str(m.get("file", "")).startswith(NOT_INCLUDED)
    ]

    recovered: dict[int, Path] = {}
    found: collections.Counter = collections.Counter()
    absent: collections.Counter = collections.Counter()
    for message in unresolved:
        kind = message.get("media_type", "document")
        hit = resolve(message, sizes)
        if hit is None:
            absent[kind] += 1
        else:
            found[kind] += 1
            recovered[message["id"]] = hit

    print(f"messages whose media the JSON could not include: {len(unresolved)}")
    print(f"re-attached from disk: {sum(found.values())} {dict(found)}")
    print(f"still absent:          {sum(absent.values())} {dict(absent)}")

    print("\ncreator media:")
    for message in unresolved:
        if message.get("from") != CREATOR:
            continue
        hit = recovered.get(message["id"])
        where = str(hit.relative_to(arguments.root)) if hit else "STILL MISSING"
        print(
            f"  {message['id']:>6} {message['date']} "
            f"{message.get('media_type', '?'):<10} "
            f"{message.get('file_name', '?'):<40} {where}"
        )

    if arguments.dump:
        print()
        for identifier, path in sorted(recovered.items()):
            print(identifier, path.relative_to(arguments.root))


if __name__ == "__main__":
    main()
