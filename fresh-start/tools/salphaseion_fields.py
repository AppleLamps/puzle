#!/usr/bin/env python3
"""Split the SalPhaseIon stream into its fields and decode the literals.

The archived SalPhaseIon page carries one long letter stream in a textarea. It
is not a single encoding: runs of `a`/`b` are binary (a = 0, b = 1) and decode
straight to ASCII, while the surrounding runs use `a`–`i` (and sometimes `o`)
as digits 1–9 and 0.

What is *authenticated* here is only that these substrings decode to English
words — nothing about what the words instruct you to do. The field boundaries
below are read off the stream itself (the binary runs and the `z` separators);
the names `S91` and `S570` are just lengths.

Run `phase2_phase3.py` first only if you want the ciphertexts; this tool reads
the archived page directly.
"""

from __future__ import annotations

import json
import re

from _paths import ARCHIVES, derived

DIGITS = {c: str(n) for n, c in enumerate("abcdefghi", 1)} | {"o": "0"}


def textareas(path) -> list[str]:
    html = path.read_text(encoding="utf-8", errors="replace")
    return ["".join(t.split())
            for t in re.findall(r"<textarea[^>]*>([\s\S]*?)</textarea>", html)]


def bits_to_ascii(run: str, zero: str = "a") -> str:
    bits = "".join("0" if c == zero else "1" for c in run)
    usable = len(bits) // 8 * 8
    return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, usable, 8))


def digits_to_ascii(field: str) -> str:
    """Digit pairs read as hex → ASCII, which is how the decimal fields resolve."""
    packed = "".join(DIGITS[c] for c in field)
    try:
        return bytes.fromhex(packed).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return ""


def main() -> None:
    stream, cosmic = textareas(ARCHIVES / "salphaseion_phase3.html")
    print(f"stream: {len(stream)} chars, alphabet {''.join(sorted(set(stream)))}")
    print(f"cosmic textarea: {len(cosmic)} base64 chars\n")

    print("binary (a/b) runs, in physical page order:")
    fields = {}
    for match in re.finditer(r"[ab]{16,}", stream):
        text = bits_to_ascii(match.group(0))
        if text.isprintable():
            print(f"  offset {match.start():4}  {len(match.group(0)):4} bits  {text!r}")
            fields[text] = {"kind": "binary a/b", "offset": match.start()}

    # Head-of-stream fields, split at the first binary run and the `z` marks.
    first_run = re.search(r"[ab]{16,}", stream)
    head = stream[:first_run.start()]
    tail = stream[first_run.end():]
    s570 = tail.split("z")[0]
    print(f"\nleading field: {len(head)} chars (alphabet {''.join(sorted(set(head)))})")
    print(f"field after the first binary run: {len(s570)} chars "
          f"(alphabet {''.join(sorted(set(s570)))})")

    print("\ndigit fields that resolve to ASCII:")
    for name, field in (("head", head), ("after-run", s570)):
        text = digits_to_ascii(field)
        if text:
            print(f"  {name}: {text!r}")

    for chunk in re.findall(r"[a-io]{10,}", stream):
        text = digits_to_ascii(chunk)
        if text and text.isalpha():
            print(f"  digits→hex→ascii: {text!r}")
            fields[text] = {"kind": "digits→hex→ascii", "length": len(chunk)}

    out = derived("salphaseion_fields.json")
    out.write_text(json.dumps({
        "stream_length": len(stream),
        "leading_field": head,
        "field_after_first_binary_run": s570,
        "decoded_literals": fields,
        "cosmic_textarea_base64_chars": len(cosmic),
    }, indent=2) + "\n")
    print(f"\nwrote {out.relative_to(out.parents[2])}")


if __name__ == "__main__":
    main()
