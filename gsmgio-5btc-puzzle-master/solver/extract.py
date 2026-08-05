"""Extract ciphertexts and SalPhaseIon source tokens from checked-in data."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .openssl_compat import decode_base64_envelope


ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
COSMIC_SOURCE = Path(__file__).resolve().parent / "data" / "cosmic_duality.txt"


@dataclass(frozen=True)
class ExtractedInputs:
    readme_path: Path
    cosmic_path: Path
    chain1_envelope: bytes
    chain2_envelope: bytes
    phase32_envelope: bytes
    cosmic_envelope: bytes


def _lines(readme: Path = README) -> list[str]:
    return readme.read_text(encoding="utf-8-sig").splitlines()


def _base64_lines_after(lines: list[str], marker: str, count: int) -> str:
    start = next(i for i, line in enumerate(lines) if marker in line)
    found: list[str] = []
    for line in lines[start + 1 :]:
        compact = "".join(line.split())
        if re.fullmatch(r"[A-Za-z0-9+/=]+", compact or ""):
            found.append(compact)
            if len(found) == count:
                return "".join(found)
        elif found:
            break
    raise ValueError(f"could not extract {count} base64 lines after {marker!r}")


def extract_chain1_envelope(readme: Path = README) -> bytes:
    lines = _lines(readme)
    start = next(i for i, line in enumerate(lines) if line.strip() == "### AES Blob")
    chunks: list[str] = []
    for line in lines[start + 1 :]:
        if not line.startswith(">"):
            if chunks:
                break
            continue
        compact = re.sub(r"[^A-Za-z0-9+/=]", "", line)
        if compact:
            chunks.append(compact)
    return decode_base64_envelope("".join(chunks))


def extract_chain2_envelope(readme: Path = README) -> bytes:
    return decode_base64_envelope(
        _base64_lines_after(_lines(readme), "Raising the stakes without extra chances", 2)
    )


def extract_phase32_envelope(readme: Path = README) -> bytes:
    return decode_base64_envelope(
        _base64_lines_after(_lines(readme), "Phase 3.2 is ciphered", 51)
    )


def extract_cosmic_envelope(source: Path = COSMIC_SOURCE) -> bytes:
    return decode_base64_envelope(source.read_text(encoding="ascii"))


def extract_all(readme: Path = README, cosmic_source: Path = COSMIC_SOURCE) -> ExtractedInputs:
    return ExtractedInputs(
        readme_path=readme,
        cosmic_path=cosmic_source,
        chain1_envelope=extract_chain1_envelope(readme),
        chain2_envelope=extract_chain2_envelope(readme),
        phase32_envelope=extract_phase32_envelope(readme),
        cosmic_envelope=extract_cosmic_envelope(cosmic_source),
    )

