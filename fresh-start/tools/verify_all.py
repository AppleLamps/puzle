#!/usr/bin/env python3
"""Run every stage in this folder end to end and check it against its digest.

One command that starts from the committed PNG and HTML and re-derives
everything the folder claims. If a line says FAIL, believe the line, not the
documentation.

    python3 tools/verify_all.py
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

from _paths import ARCHIVES, ARTIFACTS, CIPHERTEXTS, DERIVED, IMAGES  # noqa: E402
from openssl_aes import find_envelopes, sha256_hex, try_digests, unarmour  # noqa: E402

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> bool:
    results.append((ok, label))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    return ok


def main() -> int:
    print("inputs present")
    for path in (IMAGES / "poster" / "follow_the_white_rabbit.png",
                 ARCHIVES / "phase2_choice.html",
                 ARCHIVES / "salphaseion_phase3.html"):
        check(path.exists(), str(path.relative_to(TOOLS.parent)))

    print("\nstage 0 — poster spiral")
    import poster_spiral

    grid = poster_spiral.read_grid(IMAGES / "poster" / "follow_the_white_rabbit.png")
    colours = [grid[r][c] for r, c in poster_spiral.spiral(poster_spiral.SIZE)]
    bits = "".join("1" if c in poster_spiral.ONE_BITS else "0" for c in colours)
    url = "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, 192, 8))
    check(url == "gsmg.io/theseedisplanted", f"spiral decodes to {url!r}")
    check(bits[192:] == "0000", "residual bits are 0000")
    marks = [(i, c) for i, c in enumerate(colours) if c in poster_spiral.MARKERS]
    check([i for i, _ in marks] == list(range(7, 192, 8)),
          "24 markers land on every 8th bit")
    packed = int("".join("1" if c == poster_spiral.BLUE else "0" for _, c in marks), 2)
    check(f"{packed:06X}" == "F73D92", f"marker bits pack to {packed:06X}")

    print("\nstage 2/3 — AES chain")
    subprocess.run([sys.executable, str(TOOLS / "extract_ciphertexts.py")],
                   check=True, capture_output=True)
    blob = unarmour((CIPHERTEXTS / "phase2_keymaker.b64").read_text())
    hit = try_digests(blob, sha256_hex("causality"))
    check(hit is not None and b"keymaker" in hit[1], "phase 2 decrypts under sha256('causality')")

    blob = unarmour((CIPHERTEXTS / "phase3_riddles.b64").read_text())
    hit = try_digests(blob, b"1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5")
    check(hit is not None and b"merovingian" in hit[1],
          "phase 3 decrypts under the seven-part digest")
    phase3 = hit[1].decode("utf-8", "replace")

    packed_b64 = find_envelopes(phase3)[0]
    hit = try_digests(unarmour(packed_b64), sha256_hex(
        "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"))
    check(hit is not None, "phase 3.2 envelope found inside phase 3 and decrypts")
    phase32 = hit[1]
    check(hashlib.sha256(phase32).hexdigest() ==
          "b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34",
          "phase 3.2 plaintext digest")

    print("\nstage 3.2 — classical")
    import phase32_classical as classical

    lines = classical.sections(phase32)
    record = max(lines, key=len)
    digits = next(l for l in lines if l.isdigit())
    check(len(record) == 1539 and hashlib.sha256(record).hexdigest() ==
          classical.EXPECTED["symbol_record"], "1,539-byte symbol record digest")

    letters = classical.to_letters(record)
    check(len(set(letters)) == 26, "EBCDIC map is a 26-letter bijection")
    architect = classical.beaufort(letters, classical.BEAUFORT_KEY)
    check(hashlib.sha256(architect.encode()).hexdigest() ==
          classical.EXPECTED["architect_plaintext"], "Architect plaintext digest")
    check(architect == (ARTIFACTS / "architect_plaintext.txt").read_text().strip(),
          "Architect plaintext matches artifacts/architect_plaintext.txt")

    message = classical.checkerboard(digits.decode())
    check(hashlib.sha256(message.encode()).hexdigest() ==
          classical.EXPECTED["checkerboard"], "VIC checkerboard digest")
    check(message == (ARTIFACTS / "checkerboard_message.txt").read_text().strip(),
          "checkerboard matches artifacts/checkerboard_message.txt")

    print("\nArchitect plaintext — named substrings at stated 0-based offsets")
    for offset, word in ((479, "PRIVATEKEY"), (511, "TAKETHISTOHEART"),
                         (535, "WISEMANABOVE"), (562, "HUNDREDFOURTY"),
                         (1021, "SOURCECODES"), (1103, "PRIMEBASICS"),
                         (1157, "TWENTYTHREECIPHERS"), (1175, "SIXTEENENCRYPTIONS"),
                         (1198, "SEVENINTERTWINEDPASSWORDS"), (1238, "PRIVATEKEY"),
                         (1529, "CIAOBELLAO")):
        check(architect[offset:offset + len(word)] == word, f"[{offset}] {word}")

    print("\nURL slug")
    slug = hashlib.sha256(
        b"GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe").hexdigest()
    check(slug == "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
          "phase 3 slug is the SHA-256 of the first page's own visible text")

    print("\nSalPhaseIon literals")
    import salphaseion_fields as fields

    stream = fields.textareas(ARCHIVES / "salphaseion_phase3.html")[0]
    literals = {fields.bits_to_ascii(m.group(0))
                for m in __import__("re").finditer(r"[ab]{16,}", stream)}
    check("matrixsumlist" in literals, "'matrixsumlist' decodes from the a/b field")
    check("enter" in literals, "'enter' decodes from the a/b field")
    check("shabefourfirsthintisyourlastcommand" in stream and "shabefanstoo" in stream,
          "'shabefour…' and 'shabefanstoo' appear as page literals")

    print("\nprize gate")
    import prize_gate

    check(prize_gate.hash160(prize_gate.HALF_PUBKEY) == prize_gate.HALF_HASH160,
          "Half's published public key hashes to Half's address")
    check(prize_gate.gate_scalar(1) is None, "gate rejects a non-matching scalar")

    failed = [label for ok, label in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("failed: " + "; ".join(failed))
    print(f"derived outputs in {DERIVED}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
