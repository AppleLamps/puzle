#!/usr/bin/env python3
"""Run the creator's stated phase 3 pipeline and test its outputs as passphrases.

The hint quoted in the second agent's transcript is

    yellow blue primes -> matrix sum list -> last words before archi choice -> yin yang

and the field geometry fits it: there are exactly 24 colour markers in the stage
one grid and exactly 24 primes in 1..91, `matrixsumlist` is 13 characters and
S91 is 7 x 13, and `lastwordsbeforearchichoice` + `thispassword` is 38
characters while S570 is 15 x 38.

This builds every reading of those steps that the wording allows, then tries the
results against all four ciphertexts. It turns the interpretation into something
falsifiable instead of an argument.
"""

import base64
import hashlib
import itertools
import re
from collections import Counter

from Crypto.Cipher import AES
from PIL import Image

from _paths import SOURCES

CELL, GRID = 25, 14
BLUE, YELLOW = (63, 72, 204), (255, 242, 0)
VALUE = {c: n for n, c in enumerate("abcdefghi", 1)} | {"o": 0}

ARCHITECT = "asyouadequatelyputtheproblemis"
LAST_WORDS = "lastwordsbeforearchichoice"
THIS_PASSWORD = "thispassword"


def spiral(n):
    order = []
    top, bottom, left, right = 0, n - 1, 0, n - 1
    while top <= bottom and left <= right:
        for r in range(top, bottom + 1):
            order.append((r, left))
        left += 1
        for c in range(left, right + 1):
            order.append((bottom, c))
        bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                order.append((r, right))
            right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                order.append((top, c))
            top += 1
    return order


def marker_bits(path=SOURCES / "follow_the_white_rabbit.png"):
    pixels = Image.open(path).convert("RGB").load()

    def cell(r, c):
        counts = Counter(
            pixels[x, y]
            for y in range(r * CELL, (r + 1) * CELL)
            for x in range(c * CELL, (c + 1) * CELL)
        )
        return counts.most_common(1)[0][0]

    colours = [cell(r, c) for r, c in spiral(GRID)]
    return [1 if c == BLUE else 0 for c in colours if c in (BLUE, YELLOW)]


def fields(path=SOURCES / "GSMG Puzzle4 - phase3 salphaseion.html"):
    html = open(path, encoding="utf-8", errors="replace").read()
    stream = "".join(re.findall(r"<textarea[^>]*>([\s\S]*?)</textarea>", html)[0].split())
    head = stream[: stream.find("shabefour")]
    run = re.search(r"[ab]{16,}", head)
    s570, f63, f29 = head[run.end() :].split("z")[:3]
    return head[: run.start()], s570, f63, f29


def primes(limit):
    return [p for p in range(2, limit + 1) if all(p % d for d in range(2, int(p**0.5) + 1))]


def column_sums(vec, rows, cols, order):
    if order == "row":
        grid = [vec[r * cols : (r + 1) * cols] for r in range(rows)]
    else:
        grid = [[vec[c * rows + r] for c in range(cols)] for r in range(rows)]
    return [sum(grid[r][c] for r in range(rows)) for c in range(cols)]


def renderings(nums):
    """Every plausible way to write a list of small numbers as a passphrase."""
    out = {
        "digits": "".join(str(n) for n in nums),
        "dashed": "-".join(str(n) for n in nums),
        "spaced": " ".join(str(n) for n in nums),
    }
    if all(1 <= n <= 26 for n in nums):
        out["a1z26"] = "".join(chr(96 + n) for n in nums)
    out["mod26"] = "".join(chr(97 + (n % 26)) for n in nums)
    out["letters_ai"] = "".join("abcdefghi"[(n - 1) % 9] for n in nums)
    return out


def build_candidates():
    bits = marker_bits()
    s91, s570, f63, f29 = fields()
    d91 = [VALUE[c] for c in s91]
    d570 = [VALUE[c] for c in s570]
    pr = primes(91)
    assert len(pr) == len(bits) == 24

    cands = {}

    # step 1+2: yellow/blue bits into the prime slots, then the matrix sum list
    for polarity, bs in (("b1", bits), ("b0", [1 - b for b in bits])):
        for fill in ("zero", "keep"):
            base = [0] * 91 if fill == "zero" else list(d91)
            for p, bit in zip(pr, bs):
                base[p - 1] = bit
            for order in ("row", "col"):
                sums = column_sums(base, 7, 13, order)
                for name, text in renderings(sums).items():
                    cands[f"sumlist/{polarity}/{fill}/{order}/{name}"] = text
                # step 4: yin/yang, the list added to and subtracted from S570
                for op, sign in (("yang", 1), ("yin", -1)):
                    mixed = [
                        (d570[i] + sign * sums[i % len(sums)]) % 10 for i in range(len(d570))
                    ]
                    cands[f"yinyang/{polarity}/{fill}/{order}/{op}/digits"] = "".join(
                        map(str, mixed)
                    )
                    cands[f"yinyang/{polarity}/{fill}/{order}/{op}/alpha"] = "".join(
                        chr(97 + v % 26) for v in mixed
                    )

    # step 3: the architect phrases, alone and joined
    for name, text in (
        ("architect", ARCHITECT),
        ("lastwords", LAST_WORDS),
        ("lastwords+pw", LAST_WORDS + THIS_PASSWORD),
        ("matrixsumlist", "matrixsumlist"),
    ):
        cands[f"phrase/{name}"] = text

    # the marker stream itself and the transcript's derived variants
    marker_hex = f"{int(''.join(map(str, bits)), 2):06X}"
    value = int(marker_hex, 16)
    cands["marker/hex"] = marker_hex
    cands["marker/hex_lower"] = marker_hex.lower()
    cands["marker/bits"] = "".join(map(str, bits))
    cands["marker/colours"] = "".join("B" if b else "Y" for b in bits)
    for label, v in (("half", value // 2), ("half+3", value // 2 + 3)):
        cands[f"marker/{label}"] = f"{v:06X}"
        cands[f"marker/{label}_lower"] = f"{v:06X}".lower()
        cands[f"marker/{label}_colours"] = "".join(
            "B" if c == "1" else "Y" for c in bin(v)[2:]
        )
    return cands


def evp(passphrase, salt, digest, key_len=32, iv_len=16):
    data, block = b"", b""
    while len(data) < key_len + iv_len:
        block = hashlib.new(digest, block + passphrase + salt).digest()
        data += block
    return data[:key_len], data[key_len : key_len + iv_len]


def blobs():
    def grab(path, index):
        html = open(path, encoding="utf-8", errors="replace").read()
        area = "".join(re.findall(r"<textarea[^>]*>([\s\S]*?)</textarea>", html)[index].split())
        return base64.b64decode(area)

    p2 = SOURCES / "GSMG Puzzle3 - phase2.html"
    p3 = SOURCES / "GSMG Puzzle4 - phase3 salphaseion.html"
    stream = "".join(
        re.findall(r"<textarea[^>]*>([\s\S]*?)</textarea>",
                   open(p3, encoding="utf-8", errors="replace").read())[0].split()
    )
    tail = stream[stream.find("shabefour") :]
    m = re.match(
        r"shabefour.*?(U2FsdGVkX18[A-Za-z0-9+/=]*?)[ab]{20,}([A-Za-z0-9+/=]+?)shabefanstoo", tail
    )
    return {
        "keymaker": grab(p2, 0),
        "phase3": grab(p2, 1),
        "cosmic": grab(p3, 1),
        "embedded": base64.b64decode(m.group(1) + m.group(2)),
    }


def main():
    cands = build_candidates()
    targets = blobs()
    print(f"{len(cands)} candidates x {len(targets)} blobs")

    tried = 0
    for name, word in cands.items():
        forms = (
            word.encode(),
            hashlib.sha256(word.encode()).hexdigest().encode(),
            hashlib.sha256(word.encode()).digest(),
        )
        for blob_name, blob in targets.items():
            salt, ct = blob[8:16], blob[16:]
            for passphrase in forms:
                for digest in ("md5", "sha256"):
                    tried += 1
                    key, iv = evp(passphrase, salt, digest)
                    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
                    pad = plain[-1]
                    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
                        continue
                    body = plain[:-pad]
                    if sum(32 <= b < 127 or b in (9, 10, 13) for b in body) >= len(body) * 0.9:
                        print(f"HIT {blob_name} <- {name} = {word[:60]!r}")
                        print(body.decode("utf-8", "replace")[:400])
                        return
    print(f"no hit after {tried} trial decryptions")
    for name in sorted(cands):
        if name.startswith(("sumlist", "marker")):
            print(f"  {name:44} {cands[name][:60]}")


if __name__ == "__main__":
    main()
