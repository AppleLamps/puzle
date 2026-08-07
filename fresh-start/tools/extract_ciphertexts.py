#!/usr/bin/env python3
"""Extract every AES envelope from the archived creator pages into `ciphertexts/`.

Run this first. It reads only `archives/*.html` and writes only `ciphertexts/`,
so the Base64 blobs the later tools consume are traceable to a page you can open
in a browser rather than to a transcription in someone's write-up.

The phase 3.2 envelope is not on any archived page: it appears inside the phase 3
plaintext, so it is written out by `phase2_phase3.py` after that decrypt runs.
"""

from __future__ import annotations

import hashlib
import re

from _paths import ARCHIVES, CIPHERTEXTS
from openssl_aes import unarmour

# (archived page, index of the envelope within that page, output name)
ENVELOPES = [
    ("phase2_choice.html", 0, "phase2_keymaker.b64"),
    ("phase2_choice.html", 1, "phase3_riddles.b64"),
    ("salphaseion_phase3.html", 0, "salphaseion_cosmic.b64"),
]


def envelopes_in(path):
    html = path.read_text(encoding="utf-8", errors="replace")
    return ["".join(m.group(0).split())
            for m in re.finditer(r"U2FsdGVkX1[A-Za-z0-9+/=\s]{20,}", html)]


def wrap(packed: str, width: int = 64) -> str:
    return "\n".join(packed[i:i + width] for i in range(0, len(packed), width)) + "\n"


def main() -> None:
    CIPHERTEXTS.mkdir(exist_ok=True)
    cache: dict[str, list[str]] = {}
    for page, index, name in ENVELOPES:
        blobs = cache.setdefault(page, envelopes_in(ARCHIVES / page))
        packed = blobs[index]
        raw = unarmour(packed)
        (CIPHERTEXTS / name).write_text(wrap(packed))
        print(f"{name:26} {len(raw):5} bytes  salt={raw[8:16].hex()}  "
              f"sha256={hashlib.sha256(raw).hexdigest()[:16]}…  <- {page}[{index}]")


if __name__ == "__main__":
    main()
