"""Path resolution for the fresh-start tools.

Every path resolves inside the `fresh-start/` folder. Nothing here reads or
writes outside it, so the folder can be copied anywhere and still run.
"""

from __future__ import annotations

from pathlib import Path

FRESH_START = Path(__file__).resolve().parents[1]

ARCHIVES = FRESH_START / "archives"
"""Local HTML copies of creator-published pages."""

IMAGES = FRESH_START / "images"
"""Creator-published PNG assets (poster, rebus tiles)."""

ARTIFACTS = FRESH_START / "artifacts"
"""Committed plaintext extracts, for comparison against your own output."""

CIPHERTEXTS = FRESH_START / "ciphertexts"
"""Base64 `Salted__` envelopes extracted from the archived pages."""

DERIVED = FRESH_START / "derived"
"""Output directory for anything the tools compute. Not committed."""


def derived(name: str) -> Path:
    DERIVED.mkdir(exist_ok=True)
    return DERIVED / name
