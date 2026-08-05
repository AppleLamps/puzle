"""Reproduce the SalPhaseIon token decoding and seven-digest XOR."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .extract import README


REPORTED_TOKENS = (
    "matrixsumlist",
    "enter",
    "lastwordsbeforearchichoice",
    "thispassword",
    "matrixsumlist",
    "yourlastcommand",
    "secondanswer",
)


@dataclass(frozen=True)
class SalPhaseIonResult:
    directly_decoded: tuple[str, str, str, str]
    semantic_tokens: tuple[str, str, str]
    tokens: tuple[str, ...]
    digests: tuple[bytes, ...]
    xor_password: bytes


def decode_ab(tokens: list[str]) -> str:
    bits = "".join("0" if token == "a" else "1" for token in tokens)
    if len(bits) % 8:
        raise ValueError("a/b token count is not byte aligned")
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)).decode("ascii")


def decode_ai_o(tokens: list[str]) -> str:
    mapping = {chr(ord("a") + i): str(i + 1) for i in range(9)} | {"o": "0"}
    decimal = "".join(mapping[token] for token in tokens)
    value = int(decimal, 10)
    hex_text = format(value, "x")
    if len(hex_text) % 2:
        hex_text = "0" + hex_text
    return bytes.fromhex(hex_text).decode("ascii")


def _raw_salph_lines(readme: Path) -> tuple[str, str]:
    lines = readme.read_text(encoding="utf-8-sig").splitlines()
    first = next(line for line in lines if line.startswith("> d b b i b f"))
    second = next(line for line in lines if line.startswith("> U 2 F s d G V k"))
    return first, second


def derive_tokens(readme: Path = README) -> SalPhaseIonResult:
    first, second = _raw_salph_lines(readme)
    ab1_match = re.search(r"\*\*((?:[ab]\s+)+[ab])\*\*", first)
    ab2_match = re.search(r"\*\*((?:[ab]\s+)+[ab])\*\*", second)
    if not ab1_match or not ab2_match:
        raise ValueError("missing highlighted a/b sections")
    p1 = decode_ab(ab1_match.group(1).split())
    p2 = decode_ab(ab2_match.group(1).split())

    z_parts = first.split("**z**")
    if len(z_parts) != 4:
        raise ValueError("expected three highlighted z separators")
    numeric_segments = []
    for part in z_parts[1:3]:
        tokens = re.findall(r"(?<![a-z])[a-io](?![a-z])", part)
        numeric_segments.append(decode_ai_o(tokens))
    p3, p4 = numeric_segments

    # These three are semantic readings rather than direct alphabet decodes.
    # Their status is explicitly recorded in the report rather than hidden.
    p5 = p1
    p6 = "yourlastcommand"
    p7 = "secondanswer"
    tokens = (p1, p2, p3, p4, p5, p6, p7)
    digests = tuple(hashlib.sha256(token.encode("utf-8")).digest() for token in tokens)
    xor_password = bytes(a ^ b ^ c ^ d ^ e ^ f ^ g for a, b, c, d, e, f, g in zip(*digests))
    return SalPhaseIonResult(
        directly_decoded=(p1, p2, p3, p4),
        semantic_tokens=(p5, p6, p7),
        tokens=tokens,
        digests=digests,
        xor_password=xor_password,
    )

