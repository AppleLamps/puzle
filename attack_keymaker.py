#!/usr/bin/env python3
"""Dictionary attack on the phase 2 "keymaker" blob, which grants part 1.

The page frames it as: "1... are you looking for the private keymaker? You come
to me, without it. Come to me with it and you'll have the power to continue.
It'll grant the first part." followed by `/(aaa, connected enf)` — which reads as
a note that the part is lower case and written without separators.

The blob is `openssl enc -aes-256-cbc -a` output and the page says the passphrase
is `sha-256(password)`, so each candidate is tried raw, as its hex digest and as
its raw digest, under both key-derivation digests OpenSSL has defaulted to.
"""

import base64
import hashlib
import itertools
import re
import sys

from Crypto.Cipher import AES

MATRIX = """neo morpheus trinity oracle architect merovingian keymaker persephone niobe
cypher tank dozer switch apoc mouse seraph sati rama link zee kid smith agentsmith
zion nebuchadnezzar logos hammer sentinel squiddy construct matrix thematrix
redpill bluepill whiterabbit rabbit spoon thereisnospoon followthewhiterabbit
thematrixhasyou wakeupneo theone iamtheone freeyourmind knock knockneo
choice illusion causality karma purpose anomaly source prime program exile
deja vu dejavu keys key door doors backdoor gateway train trainman
""".split()

BITCOIN = """bitcoin satoshi nakamoto satoshinakamoto genesis genesisblock blockchain
privatekey publickey brainwallet wallet seed seedphrase mnemonic wif hash sha256
secp256k1 halving halvening coinbase chancellor bailout thetimes block0
gsmg meganigma prize btc fivebtc 5btc
""".split()

PUZZLE = """theseedisplanted cryptologicwarningcanyoudigit canyoudigit cryptologic warning
choiceisanillusion choiceisanillusioncreatedbetweenthosewithpowerandthosewithout
averyspecialdessertiwroteitmyself iwroteitmyself salphaseion cosmicduality
matrixsumlist enter yinyang yin yang halfandbetterhalf half betterhalf
phase1 phase2 phase3 firstpart thefirstpart part1
11110 executiveorder11110 eo11110 kennedy jfk truman eisenhower mcafee norton belize
1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe 17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa
""".split()

PHRASES = [
    "areyoulookingforthekeymaker",
    "areyoulookingfortheprivatekeymaker",
    "theprivatekeymaker",
    "privatekeymaker",
    "iamthekeymaker",
    "thekeymaker",
    "comeetomewithit",
    "cometomewithit",
    "youcometomewithoutit",
    "thepowertocontinue",
    "youllhavethepowertocontinue",
    "itllgrantthefirstpart",
    "iknowbecauseimustknow",
    "itismypurpose",
    "thereasonforwhichiamhere",
    "iamthekeymakeriknowbecauseimustknow",
]


def load(path="GSMG Puzzle3 - phase2.html", index=0):
    html = open(path, encoding="utf-8", errors="replace").read()
    area = "".join(re.findall(r"<textarea[^>]*>([\s\S]*?)</textarea>", html)[index].split())
    blob = base64.b64decode(area)
    return blob[8:16], blob[16:]


def evp(passphrase, salt, digest, key_len=32, iv_len=16):
    data, block = b"", b""
    while len(data) < key_len + iv_len:
        block = hashlib.new(digest, block + passphrase + salt).digest()
        data += block
    return data[:key_len], data[key_len : key_len + iv_len]


def readable(plain):
    pad = plain[-1]
    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
        return None
    body = plain[:-pad]
    if not body:
        return None
    good = sum(32 <= b < 127 or b in (9, 10, 13) for b in body)
    return body if good >= len(body) * 0.9 else None


def candidates():
    base = set(MATRIX) | set(BITCOIN) | set(PUZZLE) | set(PHRASES)
    for word in list(base):
        base.add(word.lower())
        base.add(word.upper())
        base.add(word.capitalize())
    # two-word joins of the most thematic terms
    core = ["keymaker", "private", "key", "thekeymaker", "matrix", "neo", "source", "door"]
    for a, b in itertools.permutations(core, 2):
        base.add(a + b)
    return sorted(w for w in base if w)


def main():
    salt, ciphertext = load(index=int(sys.argv[1]) if len(sys.argv) > 1 else 0)
    words = candidates()
    print(f"{len(words)} candidates")
    tried = 0
    for word in words:
        forms = (
            word.encode(),
            hashlib.sha256(word.encode()).hexdigest().encode(),
            hashlib.sha256(word.encode()).hexdigest().upper().encode(),
            hashlib.sha256(word.encode()).digest(),
        )
        for passphrase in forms:
            for digest in ("md5", "sha256"):
                tried += 1
                key, iv = evp(passphrase, salt, digest)
                body = readable(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))
                if body:
                    print(f"*** HIT word={word!r} md={digest}")
                    print(body.decode("utf-8", "replace"))
                    return
    print(f"no hit after {tried} trial decryptions")


if __name__ == "__main__":
    main()
