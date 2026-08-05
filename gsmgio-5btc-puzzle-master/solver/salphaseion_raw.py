"""Mechanical extraction of the archived SalPhaseIon page.

This module deliberately knows nothing about any proposed decrypted plaintext,
target public key, Chain 4, or community password construction.  Its only job
is to turn the earliest archived HTML textarea into named, byte-stable fields.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .extract import ROOT
from .openssl_compat import validate_envelope
from .salphaseion import decode_ab, decode_ai_o


EARLIEST_CAPTURE_TIMESTAMP = "20230601222752"
EARLIEST_CAPTURE_PATH = (
    ROOT
    / "artifacts"
    / "wayback_cache"
    / "bodies"
    / "5806148bf02a63bd2835f893e64ca56e1c62dc4bbf7be541a30afa54411c37c1.bin"
)
CAPTURE_PATHS = (
    EARLIEST_CAPTURE_PATH,
    ROOT / "artifacts/wayback_cache/bodies/d29ebcf688fd904dea201fab4f023a5b14f3fe49fcf6e92969dcbad31c5e67c0.bin",
    ROOT / "artifacts/wayback_cache/bodies/0eeb42e361a2781846ce16d2fdadd1a879793d969aa624c5fa43552347d6c4d0.bin",
    ROOT / "artifacts/wayback_cache/bodies/8e05fdbbe88f4b859948ddc4c05864bcc017f80b0b75a74e5a69cccd908d930e.bin",
    ROOT / "artifacts/wayback_cache/bodies/bb28e34bb35a21a75c03e01e550466bf8fa8000052d79944f94b768d86f118bd.bin",
)


@dataclass(frozen=True)
class RawSalPhaseIon:
    html: bytes
    textarea1: bytes
    textarea2: bytes
    s91: str
    matrix_marker_bits: str
    matrix_marker: str
    s570: str
    lastwords_numeric: str
    lastwords_marker: str
    password_numeric: str
    password_marker: str
    sha_first_hint: str
    enter_bits: str
    enter_marker: str
    sha_answer_too: str
    short_base64: str
    short_envelope: bytes
    cosmic_base64: str
    cosmic_envelope: bytes


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_capture(path: Path) -> bytes:
    raw = path.read_bytes()
    return gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw


def _textareas(html: bytes) -> tuple[bytes, bytes]:
    values = re.findall(rb"<textarea[^>]*>(.*?)</textarea>", html, re.I | re.S)
    if len(values) != 2:
        raise ValueError(f"expected exactly two textareas, found {len(values)}")
    return values[0], values[1]


def extract_raw(path: Path = EARLIEST_CAPTURE_PATH) -> RawSalPhaseIon:
    html = _decode_capture(path)
    textarea1, textarea2 = _textareas(html)
    tokens = textarea1.decode("ascii").split()
    if len(tokens) != 1075 or any(len(token) != 1 for token in tokens):
        raise ValueError("unexpected first-textarea token structure")

    s91 = "".join(tokens[:91])
    matrix_bits = "".join(tokens[91:195])
    s570 = "".join(tokens[195:765])
    if len(s91) != 91 or set(s91) - set("abcdefghi"):
        raise ValueError("invalid S91 field")
    if len(matrix_bits) != 104 or set(matrix_bits) - {"a", "b"}:
        raise ValueError("invalid 104-symbol matrix marker")
    if len(s570) != 570 or set(s570) - set("abcdefghi"):
        raise ValueError("invalid S570 field")

    cursor = 765
    if tokens[cursor] != "z":
        raise ValueError("missing first z delimiter")
    cursor += 1
    first_z = tokens.index("z", cursor)
    lastwords_tokens = tokens[cursor:first_z]
    cursor = first_z + 1
    second_z = tokens.index("z", cursor)
    password_tokens = tokens[cursor:second_z]
    cursor = second_z + 1

    if tokens[cursor] != "s":
        raise ValueError("unexpected SHA first-hint field start")
    base64_start = tokens.index("U", cursor)
    sha_first_tokens = tokens[cursor:base64_start]

    enter_bits = "".join(
        f"{byte:08b}" for byte in b"enter"
    ).translate(str.maketrans("01", "ab"))
    enter_tokens = list(enter_bits)
    ending = list("shabefanstoo")
    if tokens[-len(ending):] != ending:
        raise ValueError("missing terminal shabefanstoo field")
    payload_end = len(tokens) - len(ending)
    matches = [
        index
        for index in range(base64_start, payload_end - len(enter_tokens) + 1)
        if tokens[index:index + len(enter_tokens)] == enter_tokens
    ]
    if len(matches) != 1:
        raise ValueError(f"expected unique enter marker, found {len(matches)}")
    enter_start = matches[0]
    base64_tokens = tokens[base64_start:enter_start] + tokens[enter_start + len(enter_tokens):payload_end]
    short_base64 = "".join(base64_tokens)
    short_envelope = base64.b64decode(short_base64, validate=True)
    validate_envelope(short_envelope)

    cosmic_base64 = "".join(textarea2.decode("ascii").split())
    cosmic_envelope = base64.b64decode(cosmic_base64, validate=True)
    validate_envelope(cosmic_envelope)

    result = RawSalPhaseIon(
        html=html,
        textarea1=textarea1,
        textarea2=textarea2,
        s91=s91,
        matrix_marker_bits=matrix_bits,
        matrix_marker=decode_ab(list(matrix_bits)),
        s570=s570,
        lastwords_numeric="".join(lastwords_tokens),
        lastwords_marker=decode_ai_o(lastwords_tokens),
        password_numeric="".join(password_tokens),
        password_marker=decode_ai_o(password_tokens),
        sha_first_hint="".join(sha_first_tokens),
        enter_bits=enter_bits,
        enter_marker=decode_ab(enter_tokens),
        sha_answer_too="".join(ending),
        short_base64=short_base64,
        short_envelope=short_envelope,
        cosmic_base64=cosmic_base64,
        cosmic_envelope=cosmic_envelope,
    )
    expected = (
        "matrixsumlist",
        "lastwordsbeforearchichoice",
        "thispassword",
        "shabefourfirsthintisyourlastcommand",
        "enter",
        "shabefanstoo",
    )
    actual = (
        result.matrix_marker,
        result.lastwords_marker,
        result.password_marker,
        result.sha_first_hint,
        result.enter_marker,
        result.sha_answer_too,
    )
    if actual != expected:
        raise ValueError(f"decoded source fields changed: {actual!r}")
    return result


def capture_stability() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in CAPTURE_PATHS:
        html = _decode_capture(path)
        first, second = _textareas(html)
        records.append({
            "path": str(path.relative_to(ROOT)).replace("\\", "/"),
            "raw_sha256": sha256_hex(path.read_bytes()),
            "decoded_html_length": len(html),
            "decoded_html_sha256": sha256_hex(html),
            "textarea1_length": len(first),
            "textarea1_sha256": sha256_hex(first),
            "textarea2_length": len(second),
            "textarea2_sha256": sha256_hex(second),
        })
    if len({record["textarea1_sha256"] for record in records}) != 1:
        raise ValueError("first textarea changed across archived captures")
    if len({record["textarea2_sha256"] for record in records}) != 1:
        raise ValueError("second textarea changed across archived captures")
    return records
