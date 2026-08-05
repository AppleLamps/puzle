#!/usr/bin/env python3
"""Large dictionary attack on the remaining GSMG ciphertexts.

`causality` opened the phase 2 keymaker blob, and it is an ordinary English word
lifted from the film the puzzle quotes. That makes a full English wordlist worth
running against the blobs that are still closed.

Trial decryptions are cheap because CBC lets the padding be checked from the
final block alone: the last plaintext block is D(C_n) XOR C_(n-1), so one AES
block decrypt rejects about 99.6% of candidates before any full decrypt.
"""

import base64
import hashlib
import re
import sys
import time

from Crypto.Cipher import AES


def evp(passphrase, salt, digest, key_len=32, iv_len=16):
    data, block = b"", b""
    while len(data) < key_len + iv_len:
        block = hashlib.new(digest, block + passphrase + salt).digest()
        data += block
    return data[:key_len], data[key_len : key_len + iv_len]


def textarea(path, index):
    html = open(path, encoding="utf-8", errors="replace").read()
    return "".join(re.findall(r"<textarea[^>]*>([\s\S]*?)</textarea>", html)[index].split())


def blobs():
    p2, p3 = "GSMG Puzzle3 - phase2.html", "GSMG Puzzle4 - phase3 salphaseion.html"
    stream = textarea(p3, 0)
    tail = stream[stream.find("shabefour") :]
    m = re.match(
        r"shabefour.*?(U2FsdGVkX18[A-Za-z0-9+/=]*?)[ab]{20,}([A-Za-z0-9+/=]+?)shabefanstoo", tail
    )
    return {
        "phase3": base64.b64decode(textarea(p2, 1)),
        "cosmic": base64.b64decode(textarea(p3, 1)),
        "embedded": base64.b64decode(m.group(1) + m.group(2)),
    }


class Target:
    """One ciphertext, with a fast last-block padding pre-filter."""

    def __init__(self, name, blob):
        self.name = name
        self.salt = blob[8:16]
        self.ct = blob[16:]
        self.last = self.ct[-16:]
        self.prev = self.ct[-32:-16]

    def check(self, passphrase, digest):
        key, iv = evp(passphrase, self.salt, digest)
        tail = AES.new(key, AES.MODE_ECB).decrypt(self.last)
        pad = tail[15] ^ self.prev[15]
        if not 1 <= pad <= 16:
            return None
        for i in range(1, pad):
            if tail[15 - i] ^ self.prev[15 - i] != pad:
                return None
        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(self.ct)[:-pad]
        if not plain:
            return None
        good = sum(32 <= b < 127 or b in (9, 10, 13) for b in plain)
        return plain if good >= len(plain) * 0.9 else None


def main():
    words_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/words_alpha.txt"
    targets = [Target(n, b) for n, b in blobs().items()]
    print("targets:", ", ".join(t.name for t in targets))

    started = time.time()
    count = 0
    with open(words_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            word = line.strip()
            if not word:
                continue
            count += 1
            raw = word.encode()
            forms = (raw, hashlib.sha256(raw).hexdigest().encode(), hashlib.sha256(raw).digest())
            for passphrase in forms:
                for digest in ("md5", "sha256"):
                    for target in targets:
                        plain = target.check(passphrase, digest)
                        if plain:
                            print(f"\n*** HIT {target.name} word={word!r} md={digest}")
                            print(plain.decode("utf-8", "replace")[:1500])
                            return
            if count % 25000 == 0:
                rate = count / (time.time() - started)
                print(f"  {count} words, {rate:.0f}/s", flush=True)
    print(f"no hit after {count} words")


if __name__ == "__main__":
    main()
