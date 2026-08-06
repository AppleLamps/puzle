"""Repository paths for the root scripts.

These scripts used to live at the repository root and addressed their inputs
with bare relative names, so they only ran with the root as the current
directory. They now live in `scripts/` and resolve everything from this
module instead, which makes them runnable from anywhere.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCES = ROOT / "sources"
"""Archived creator pages, their asset bundles, and the poster image."""

DERIVED = ROOT / "derived"
"""Plaintexts, extracted fields, and audit result JSON produced from SOURCES."""

PACKAGE = ROOT / "gsmgio-5btc-puzzle-master"
"""The tested solver package."""


def use_solver_package() -> None:
    """Put `solver` on `sys.path` so the audits can import the tested modules."""
    if str(PACKAGE) not in sys.path:
        sys.path.insert(0, str(PACKAGE))
