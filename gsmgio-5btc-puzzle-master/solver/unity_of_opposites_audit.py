"""Sealed audit of the Time-Life *Cosmic Duality* organising phrase.

Provenance (verified against the 2026-08-05 Telegram export):

* 2022-12-10 a solver (semaj) posted the *Cosmic Duality* book cover
  (message 8310).  The creator replied "That is very specific" (8311) and
  "If the puzzle is solved you'll see how scary specific that is" (8315).
  On 2023-01-08 the creator added "@barrystyle, provided a very specific
  hint already." (8328).  Solvers afterwards described the object as "a
  very specific book cover, not that easy to find" and its contents as
  "Name of the book, yellow and blue suns on the book cover."
* 2026-03-03 a solver message argued "we should be turning inward to find
  the solution"; the creator replied to it with an explicit "point-up +
  salute" endorsement (message 60285), the only emoji endorsement of a
  solver message this session found.

The book's opening essay is titled "The Unity of Opposites" (verified in
the 152-page Time-Life scan's table of contents).  That phrase has never
appeared in this repository's recorded attempt families.

This module tests the organising phrase and the endorsed turn-inward
clause against (a) both prize targets, (b) the authenticated AES
envelopes, and (c) the two visible SalPhaseIon streams dbbi (91 symbols)
and faed (570 symbols) read through the already authenticated VIC
straddling-checkerboard, including the "turning inward" reversed-stream
reading (one opposite turned toward the other).  Every decoded stream is
then sha256-gated as a scalar, and every legible plaintext is used as an
AES password under the puzzle's own "shabef" (sha256) convention.

No result is accepted on padding alone: the AES legibility gate requires
printable >= 0.85 and (Shannon entropy <= 5.9 or an >= 6-letter English
run), matching the v51 convention.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass

from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import _vic_decode
from .targets import gate_scalar_bytes

RESULT_PATH = ROOT / "unity_of_opposites_audit.json"

# --- Sealed phrase family: the book's organising essay plus the endorsed ---
# --- turn-inward clause and its minimal derived forms. -------------------
PHRASES = (
    "theunityofopposites",
    "TheUnityOfOpposites",
    "unityofopposites",
    "UnityOfOpposites",
    "unity of opposites",
    "the unity of opposites",
    "turninginward",
    "turninward",
    "turninginwardtofindthesolution",
    "TURNINGINWARD",
)

# --- SalPhaseIon streams, extracted from the archived page at run time. ---
# dbbi is the leading 91-symbol run; faed is the 570-symbol run that begins
# immediately after the 128-symbol "abba" binary blob ("matrixsumlist").
SOURCES_HTML = ROOT.parent / "sources" / "GSMG Puzzle4 - phase3 salphaseion.html"


def _streams_from_html() -> tuple[str, str]:
    html = SOURCES_HTML.read_text(encoding="utf-8")
    match = re.search(r"<textarea[^>]*>(.*?)</textarea>", html, re.DOTALL)
    if match is None:
        raise ValueError("SalPhaseIon textarea not found in archived page")
    stream = "".join(match.group(1).split())
    dbbi = stream[:91]
    faed_start = stream.index("faed")
    faed = stream[faed_start : faed_start + 570]
    if not re.fullmatch(r"[a-i]+", dbbi) or not re.fullmatch(r"[a-i]+", faed):
        raise ValueError("dbbi/faed extraction is not a pure a..i stream")
    return dbbi, faed


DBBI, FAED = _streams_from_html()


def _pad28(seed: str) -> str:
    letters = "".join(dict.fromkeys(re.sub(r"[^A-Za-z]", "", seed).upper()))
    letters += "".join(ch for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if ch not in letters)
    letters = letters[:26]
    return letters[:8] + "." + letters[8:17] + "." + letters[17:]


def _digits(stream: str, mapping: dict[str, str]) -> str:
    return "".join(mapping[ch] for ch in stream)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(ch.isprintable() and (ch.isascii()) for ch in text)
    return printable / len(text)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _english_run(text: str) -> int:
    best = current = 0
    for ch in text:
        if "A" <= ch <= "Z":
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def _legible(text: str) -> bool:
    if _printable_ratio(text) < 0.85:
        return False
    return _entropy(text) <= 5.9 or _english_run(text) >= 6


def _legible_bytes(data: bytes) -> bool:
    """Legibility directly on raw bytes (never pre-substitute non-printables)."""
    if not data:
        return False
    printable = sum(32 <= b < 127 for b in data)
    if printable / len(data) < 0.85:
        return False
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    if entropy <= 5.9:
        return True
    best = current = 0
    for b in data:
        if 65 <= b <= 90:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best >= 6


def _scalar_forms(phrase: bytes) -> dict[str, bytes]:
    h1 = hashlib.sha256(phrase).digest()
    return {
        "sha256": h1,
        "double-sha256": hashlib.sha256(h1).digest(),
    }


def run() -> dict[str, object]:
    inputs = extract_all()
    envelopes = {
        "chain1": inputs.chain1_envelope,
        "chain2": inputs.chain2_envelope,
        "phase32": inputs.phase32_envelope,
        "cosmic": inputs.cosmic_envelope,
    }

    # ---------------------------------------------------------------- Part A
    scalar_attempts = 0
    scalar_hits: list[dict[str, object]] = []
    for phrase in PHRASES:
        for form_name, value in _scalar_forms(phrase.encode("utf-8")).items():
            scalar_attempts += 1
            hit = gate_scalar_bytes(value)
            if hit is not None:
                scalar_hits.append({"phrase": phrase, "form": form_name, **hit})

    # ---------------------------------------------------------------- Part B
    aes_attempts = 0
    padding_hits = 0
    legible_accepts: list[dict[str, object]] = []
    for phrase in PHRASES:
        phrase_bytes = phrase.encode("utf-8")
        password_forms = {
            "raw": phrase_bytes,
            "sha256-lowerhex": hashlib.sha256(phrase_bytes).hexdigest().encode("ascii"),
            "sha256-digest": hashlib.sha256(phrase_bytes).digest(),
        }
        for form_name, password in password_forms.items():
            for kdf in ("md5", "sha256"):
                for blob_name, envelope in envelopes.items():
                    aes_attempts += 1
                    try:
                        plaintext = decrypt_salted_aes256_cbc(envelope, password, digest=kdf).plaintext
                    except ValueError:
                        continue
                    padding_hits += 1
                    if _legible_bytes(plaintext):
                        text = "".join(chr(b) if 32 <= b < 127 else " " for b in plaintext)
                        legible_accepts.append({
                            "phrase": phrase,
                            "form": form_name,
                            "kdf": kdf,
                            "blob": blob_name,
                            "plaintext_length": len(plaintext),
                            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
                            "printable_ratio": round(_printable_ratio(text), 4),
                            "entropy": round(_entropy(text), 4),
                            "english_run": _english_run(text),
                        })

    # ---------------------------------------------------------------- Part C
    # VIC straddling-checkerboard reads of dbbi and faed under an alphabet
    # keyed by the organising phrase, including the "turning inward"
    # (reversed) opposite-stream reading.  Every decoded plaintext is then
    # sha256-gated as a scalar, and every legible plaintext becomes an AES
    # password under both EVP digests, mirroring the puzzle's own "shabef"
    # convention (decode -> sha256 -> key).
    vic_attempts = 0
    vic_decodes: list[dict[str, object]] = []
    letter_maps = {
        "a0_i8": {chr(ord("a") + i): str(i) for i in range(9)},
        "a1_i9": {chr(ord("a") + i): str(i + 1) for i in range(9)},
    }
    row_digit_sets = (("1", "4"), ("4", "1"))
    # stream name -> (symbols) ; the "turn inward" readings reverse one
    # opposite stream so that dbbi and faed meet head-to-head.
    stream_pool: list[tuple[str, str]] = [
        ("dbbi", DBBI),
        ("faed", FAED),
        ("dbbi-inward", DBBI[::-1]),
        ("faed-inward", FAED[::-1]),
        ("dbbi||faed", DBBI + FAED),
        ("faed||dbbi", FAED + DBBI),
        ("dbbi||faed-inward", DBBI + FAED[::-1]),
        ("faed-inward||dbbi", FAED[::-1] + DBBI),
    ]

    for phrase in PHRASES:
        alphabet = _pad28(phrase)
        for map_name, mapping in letter_maps.items():
            for row_digits in row_digit_sets:
                for stream_name, symbols in stream_pool:
                    vic_attempts += 1
                    record: dict[str, object] = {
                        "phrase": phrase,
                        "alphabet": alphabet,
                        "letter_map": map_name,
                        "row_digits": list(row_digits),
                        "stream": stream_name,
                        "stream_length": len(symbols),
                    }
                    try:
                        decoded = _vic_decode(_digits(symbols, mapping), alphabet, row_digits)
                    except ValueError as exc:
                        record["status"] = "invalid-vic-code"
                        record["detail"] = str(exc)
                        vic_decodes.append(record)
                        continue
                    record["status"] = "decoded"
                    record["plaintext_length"] = len(decoded)
                    record["plaintext_sha256"] = hashlib.sha256(decoded.encode("ascii")).hexdigest()
                    record["printable_ratio"] = round(_printable_ratio(decoded), 4)
                    record["entropy"] = round(_entropy(decoded), 4)
                    record["english_run"] = _english_run(decoded)
                    record["legible"] = _legible(decoded)
                    if _legible(decoded):
                        record["plaintext"] = decoded
                    # sha256-gate the decoded answer (the RB / shabef route).
                    for form_name, value in _scalar_forms(decoded.encode("ascii")).items():
                        record[f"scalar_{form_name}"] = bool(gate_scalar_bytes(value))
                    if record.get(f"scalar_sha256") or record.get("scalar_double-sha256"):
                        record["scalar_match"] = True
                    # AES-open the decoded answer when legible.
                    if _legible(decoded):
                        for kdf in ("md5", "sha256"):
                            for blob_name, envelope in envelopes.items():
                                try:
                                    plaintext = decrypt_salted_aes256_cbc(
                                        envelope, decoded.encode("ascii"), digest=kdf
                                    ).plaintext
                                except ValueError:
                                    continue
                                record[f"aes_{blob_name}_{kdf}"] = {
                                    "padding_hit": True,
                                    "legible": _legible_bytes(plaintext),
                                    "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
                                    "printable_ratio": round(
                                        sum(32 <= b < 127 for b in plaintext) / len(plaintext), 4
                                    ),
                                }
                    vic_decodes.append(record)

    scalar_legible_decodes = sum(
        1 for record in vic_decodes if record.get("scalar_match")
    )
    aes_opens_from_decodes = sum(
        1 for record in vic_decodes
        if any(str(key).startswith("aes_") and record[key].get("legible") for key in record)
    )

    result = {
        "schema": "unity-of-opposites-audit-v1",
        "status": (
            "MATCH"
            if (scalar_hits or legible_accepts or scalar_legible_decodes or aes_opens_from_decodes)
            else "COMPLETE_NO_ACCEPT"
        ),
        "provenance": {
            "book_essay": "The Unity of Opposites (Time-Life, Cosmic Duality, contents page)",
            "creator_very_specific": {
                "message_8311": ".... That is very specific",
                "message_8315": "If the puzzle is solved you'll see how scary specific that is",
                "message_8328": "@barrystyle, provided a very specific hint already.",
                "reply_to": "2022-12-10 image of the Cosmic Duality book cover (message 8310)",
            },
            "turn_inward": {
                "endorsed_message": "Instead we should be turning inward to find the solution.",
                "creator_reply": "point-up + salute emoji (2026-03-03, message 60285)",
            },
            "evidence_boundary": "The image identity rests on the export, the creator replies, and solver descriptions ('a very specific book cover'; 'Name of the book, yellow and blue suns on the book cover'), not on an OCR of the photograph here.",
        },
        "phrases_sealed": list(PHRASES),
        "part_a": {
            "scalar_attempts": scalar_attempts,
            "scalar_hits": scalar_hits,
        },
        "part_b": {
            "aes_attempts": aes_attempts,
            "strict_padding_hits": padding_hits,
            "legible_accepts": legible_accepts,
        },
        "part_c": {
            "vic_attempts": vic_attempts,
            "decoded_or_invalid": len(vic_decodes),
            "legible_decodes": sum(1 for r in vic_decodes if r.get("legible")),
            "scalar_matches_from_decodes": scalar_legible_decodes,
            "aes_opens_from_decodes": aes_opens_from_decodes,
            "records": vic_decodes,
        },
        "scope_note": (
            "Exhausts the sealed phrase family against the prize targets, the four "
            "authenticated envelopes, and the two SalPhaseIon streams under the "
            "canonical 28-cell checkerboard (row digits 1,4 and 4,1; a=0..i=8 and "
            "a=1..i=9; eight stream readings including reversed 'turn inward' "
            "variants). Does not vary the checkerboard escape digits, the alphabet "
            "padding rule, or the transposition layer."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
