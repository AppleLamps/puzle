#!/usr/bin/env python3
"""Shared GSMG prize gate: one checker for every repository.

This file is byte-identical in every GSMG research repository.  It exists
because several repos gated candidates against Half's public key only, which
rejects every correct Better Half key without saying so, and because some
gates hashed every candidate first, which rejects a raw key stored as data.

What it checks
--------------
Both prize targets, each under both public-key serializations:

* Half          1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe  (spent; public key on chain)
* Better Half   17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa  (never spent; hash160 only)

Every candidate scalar is turned into a public key, serialized compressed and
uncompressed, hashed with hash160, and compared with both targets.  Half is
also compared byte-for-byte with its on-chain uncompressed public key.

What it parses out of a plaintext or stored output
--------------------------------------------------
* raw32    every 32-byte window of binary data
* hex64    every 64-character window of a hex run (either case)
* wif      Base58Check WIF keys, compressed and uncompressed (mainnet)
* mini     Casascius mini private keys (22 and 30 characters)
* b64      base64 tokens that decode to exactly 32 bytes
* dec      decimal integers of 60 to 78 digits
* derived  sha256 of the whole input and of the stripped input (brainwallet)

Hex and base64 blobs are decoded and parsed again once, so a key written as
text inside a hex- or base64-encoded plaintext is still found.  Gzip files are
decompressed and their content parsed.

Usage
-----
    python prize_gate.py selftest            planted controls; must print PASS
    python prize_gate.py key <hex|WIF|...>   gate one candidate string
    python prize_gate.py scan PATH ... [--json OUT]

``scan`` exits 3 if any prize target matches, 0 otherwise.  A clean scan is a
bounded negative over the files and encodings listed above, nothing more.

Speed: ``pip install coincurve`` gives roughly 18,000 scalars per second.
Without it the module falls back to ``cryptography`` and then to pure Python,
which is correct but slow.

Inside the ``puzle`` package (imported as ``solver.prize_gate``) the target
constants come from ``solver.targets``, the only place that repository allows
them to be declared.  Everywhere else they are declared below.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import os
import re
import sys
import time

__version__ = "1.0.1"

# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

if __package__ == "solver":  # the puzle package: canonical constants only
    from . import targets as _canonical

    HALF_ADDRESS = _canonical.HALF_ADDRESS
    BETTER_ADDRESS = _canonical.BETTER_ADDRESS
    HALF_PUBLIC_UNCOMPRESSED = _canonical.HALF_PUBLIC_UNCOMPRESSED
else:
    HALF_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    BETTER_ADDRESS = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
    HALF_PUBLIC_UNCOMPRESSED = bytes.fromhex(
        "04"
        "f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
        "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
    )

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(B58)}


# --------------------------------------------------------------------------
# Hashing and Base58
# --------------------------------------------------------------------------

def _ripemd160_fallback(data: bytes) -> bytes:
    """Pure-Python RIPEMD-160, used only when hashlib lacks it."""
    r1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    r2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    s1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    s2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    k1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    k2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    mask = 0xFFFFFFFF

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & mask

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + (8 * len(data)).to_bytes(8, "little")
    for i in range(0, len(msg), 64):
        x = [int.from_bytes(msg[i + 4 * j:i + 4 * j + 4], "little") for j in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = rol((al + (f(j, bl, cl, dl) & mask) + x[r1[j]] + k1[j // 16]) & mask, s1[j]) + el
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t & mask
            t = rol((ar + (f(79 - j, br, cr, dr) & mask) + x[r2[j]] + k2[j // 16]) & mask, s2[j]) + er
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t & mask
        t = (h[1] + cl + dr) & mask
        h[1] = (h[2] + dl + er) & mask
        h[2] = (h[3] + el + ar) & mask
        h[3] = (h[4] + al + br) & mask
        h[4] = (h[0] + bl + cr) & mask
        h[0] = t
    return b"".join(v.to_bytes(4, "little") for v in h)


try:
    hashlib.new("ripemd160", b"")

    def _ripemd160(data: bytes) -> bytes:
        return hashlib.new("ripemd160", data).digest()
except ValueError:  # OpenSSL 3 builds without the legacy provider
    _ripemd160 = _ripemd160_fallback


def hash160(data: bytes) -> bytes:
    return _ripemd160(hashlib.sha256(data).digest())


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def b58encode(data: bytes) -> str:
    value = int.from_bytes(data, "big")
    out = ""
    while value:
        value, digit = divmod(value, 58)
        out = B58[digit] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + sha256d(payload)[:4])


def b58check_decode(text: str) -> bytes | None:
    """Return the payload of a Base58Check string, or None if it is invalid."""
    value = 0
    for ch in text:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            return None
        value = value * 58 + digit
    leading = len(text) - len(text.lstrip("1"))
    raw = b"\0" * leading + value.to_bytes((value.bit_length() + 7) // 8, "big")
    if len(raw) < 5:
        return None
    payload, check = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != check:
        return None
    return payload


def address_from_public(public: bytes) -> str:
    return b58check_encode(b"\x00" + hash160(public))


def _address_h160(address: str) -> bytes:
    payload = b58check_decode(address)
    if payload is None or len(payload) != 21 or payload[0] != 0:
        raise ValueError(f"not a mainnet P2PKH address: {address}")
    return payload[1:]


HALF_H160 = _address_h160(HALF_ADDRESS)
BETTER_H160 = _address_h160(BETTER_ADDRESS)
PRIZE_TARGETS = {"half": HALF_H160, "better_half": BETTER_H160}


# --------------------------------------------------------------------------
# secp256k1
# --------------------------------------------------------------------------

def _pure_point(k: int) -> tuple[int, int]:
    """Jacobian double-and-add; correct but slow."""
    def jdouble(p):
        x, y, z = p
        if y == 0:
            return (0, 0, 0)
        s = 4 * x * y * y % P
        m = 3 * x * x % P
        nx = (m * m - 2 * s) % P
        ny = (m * (s - nx) - 8 * pow(y, 4, P)) % P
        return (nx, ny, 2 * y * z % P)

    def jadd(p, q):
        if p[2] == 0:
            return q
        if q[2] == 0:
            return p
        x1, y1, z1 = p
        x2, y2, z2 = q
        u1 = x1 * z2 * z2 % P
        u2 = x2 * z1 * z1 % P
        s1 = y1 * pow(z2, 3, P) % P
        s2 = y2 * pow(z1, 3, P) % P
        if u1 == u2:
            return jdouble(p) if s1 == s2 else (0, 0, 0)
        h = u2 - u1
        r = s2 - s1
        h2 = h * h % P
        h3 = h * h2 % P
        nx = (r * r - h3 - 2 * u1 * h2) % P
        ny = (r * (u1 * h2 - nx) - s1 * h3) % P
        return (nx, ny, h * z1 * z2 % P)

    acc = (0, 0, 0)
    add = (G[0], G[1], 1)
    while k:
        if k & 1:
            acc = jadd(acc, add)
        add = jdouble(add)
        k >>= 1
    zinv = pow(acc[2], P - 2, P)
    return acc[0] * zinv * zinv % P, acc[1] * pow(zinv, 3, P) % P


def _make_public_keys():
    """Return f(k) -> (uncompressed, compressed) using the fastest backend.

    Set PRIZE_GATE_BACKEND=cryptography or =pure-python to force a slower one.
    """
    forced = os.environ.get("PRIZE_GATE_BACKEND", "")
    try:
        if forced in ("cryptography", "pure-python"):
            raise ImportError(forced)
        from coincurve import PrivateKey

        def via_coincurve(k: int):
            pub = PrivateKey(k.to_bytes(32, "big")).public_key
            return pub.format(compressed=False), pub.format(compressed=True)

        return "coincurve", via_coincurve
    except ImportError:
        pass
    try:
        if forced == "pure-python":
            raise ImportError(forced)
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization as ser

        curve = ec.SECP256K1()

        def via_cryptography(k: int):
            pub = ec.derive_private_key(k, curve).public_key()
            return (pub.public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint),
                    pub.public_bytes(ser.Encoding.X962, ser.PublicFormat.CompressedPoint))

        return "cryptography", via_cryptography
    except ImportError:
        pass

    def via_python(k: int):
        x, y = _pure_point(k)
        xb = x.to_bytes(32, "big")
        return b"\x04" + xb + y.to_bytes(32, "big"), bytes([2 + (y & 1)]) + xb

    return "pure-python", via_python


BACKEND, public_keys = _make_public_keys()


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

def gate_scalar(k: int, targets: dict[str, bytes] | None = None) -> dict | None:
    """Gate one scalar against every target, both serializations.

    ``targets`` maps a name to a hash160 and defaults to the two prize
    targets.  It is overridable only so that planted controls can exercise
    exactly this code path.  Returns None unless something matches.
    """
    targets = PRIZE_TARGETS if targets is None else targets
    k %= N
    if k == 0:
        return None
    unc, comp = public_keys(k)
    digests = {"uncompressed": hash160(unc), "compressed": hash160(comp)}
    hits = {}
    for name, h160 in targets.items():
        forms = [form for form, d in digests.items() if d == h160]
        if forms:
            hits[name] = forms
    if unc == HALF_PUBLIC_UNCOMPRESSED:
        hits["half_exact_public_key"] = True
    if not hits:
        return None
    return {
        "scalar": f"{k:064x}",
        "matches": hits,
        "addresses": {form: address_from_public(pub) for form, pub in
                      (("uncompressed", unc), ("compressed", comp))},
    }


def gate_bytes(value: bytes, targets: dict[str, bytes] | None = None) -> dict | None:
    if len(value) != 32:
        raise ValueError("a private scalar is 32 bytes")
    return gate_scalar(int.from_bytes(value, "big"), targets)


# --------------------------------------------------------------------------
# Extraction: every way a key can sit inside a plaintext
# --------------------------------------------------------------------------

_HEX_RUN = re.compile(rb"[0-9a-fA-F]{64,}")
_B58_RUN = re.compile(rb"[1-9A-HJ-NP-Za-km-z]{22,}")
_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{43,}={0,2}")
_DEC_RUN = re.compile(rb"(?<![0-9])[0-9]{60,78}(?![0-9])")
_HEXISH = re.compile(rb"[0-9a-fA-F]+")

MAX_HEX_RUN = 1 << 20     # longer hex runs are decoded but not windowed
MAX_B58_RUN = 4096        # longer base58 runs are not searched for WIF


def _wif_scalar(text: str) -> tuple[int, str] | None:
    payload = b58check_decode(text)
    if payload is None or payload[0] != 0x80:
        return None
    if len(payload) == 33:
        return int.from_bytes(payload[1:], "big"), "wif_uncompressed"
    if len(payload) == 34 and payload[33] == 1:
        return int.from_bytes(payload[1:33], "big"), "wif_compressed"
    return None


def extract(data: bytes, *, windows: bool = True, derived: bool = True,
            depth: int = 1):
    """Yield (kind, scalar, offset) for every candidate key in ``data``.

    ``windows`` adds every raw 32-byte window; use it for binary plaintexts.
    ``derived`` adds sha256(data) and sha256(data.strip()).
    ``depth`` controls how many times decoded hex/base64 blobs are re-parsed.
    """
    if windows and len(data) >= 32:
        for i in range(len(data) - 31):
            yield "raw32", int.from_bytes(data[i:i + 32], "big"), i
    if derived and data:
        yield "derived_sha256", int.from_bytes(hashlib.sha256(data).digest(), "big"), 0
        stripped = data.strip()
        if stripped and stripped != data:
            yield "derived_sha256_stripped", int.from_bytes(hashlib.sha256(stripped).digest(), "big"), 0

    for m in _HEX_RUN.finditer(data):
        run = m.group()
        if len(run) <= MAX_HEX_RUN:
            for i in range(len(run) - 63):
                yield "hex64", int(run[i:i + 64], 16), m.start() + i
        if depth > 0 and len(run) >= 64:
            for shift in (0, 1):
                chunk = run[shift:]
                chunk = chunk[: len(chunk) // 2 * 2]
                try:
                    blob = binascii.unhexlify(chunk)
                except binascii.Error:
                    continue
                for kind, k, off in extract(blob, windows=False, derived=False, depth=depth - 1):
                    if kind != "hex64":
                        yield "hexblob/" + kind, k, m.start()

    for m in _B58_RUN.finditer(data):
        run = m.group().decode()
        if len(run) > MAX_B58_RUN:
            continue
        for i, ch in enumerate(run):
            if ch in "5KL":
                for length in (51, 52):
                    if i + length <= len(run):
                        got = _wif_scalar(run[i:i + length])
                        if got:
                            yield got[1], got[0], m.start() + i
            if ch == "S":
                for length in (22, 30):
                    if i + length <= len(run):
                        cand = run[i:i + length].encode()
                        if hashlib.sha256(cand + b"?").digest()[0] == 0:
                            yield "mini", int.from_bytes(hashlib.sha256(cand).digest(), "big"), m.start() + i

    for m in _B64_RUN.finditer(data):
        token = m.group()
        if _HEXISH.fullmatch(token.rstrip(b"=")):
            continue  # pure hex or decimal; already parsed as such
        if len(token) in (43, 44):
            padded = token + b"=" * (-len(token) % 4)
            try:
                raw = base64.b64decode(padded, validate=True)
            except (binascii.Error, ValueError):
                raw = b""
            if len(raw) == 32:
                yield "b64", int.from_bytes(raw, "big"), m.start()
        elif depth > 0 and len(token) >= 64 and len(token) % 4 == 0:
            try:
                blob = base64.b64decode(token, validate=True)
            except (binascii.Error, ValueError):
                continue
            for kind, k, off in extract(blob, windows=True, derived=False, depth=depth - 1):
                yield "b64blob/" + kind, k, m.start()

    for m in _DEC_RUN.finditer(data):
        value = int(m.group())
        if 0 < value < N:
            yield "dec", value, m.start()


def gate_plaintext(data: bytes, *, windows: bool = True, derived: bool = True,
                   targets: dict[str, bytes] | None = None, seen: set | None = None):
    """Run every extracted candidate through the gate.

    Returns (hits, counts) where counts is a {kind: number gated} dict.
    ``seen`` lets a caller skip scalars it has already gated.
    """
    hits, counts = [], {}
    for kind, k, off in extract(data, windows=windows, derived=derived):
        k %= N
        if k == 0:
            continue
        if seen is not None:
            if k in seen:
                continue
            seen.add(k)
        counts[kind] = counts.get(kind, 0) + 1
        result = gate_scalar(k, targets)
        if result:
            result.update(kind=kind, offset=off)
            hits.append(result)
    return hits, counts


# --------------------------------------------------------------------------
# Planted controls
# --------------------------------------------------------------------------

def selftest(verbose: bool = True) -> bool:
    """Every check must pass before a clean scan means anything."""
    results = []

    def check(name, ok):
        results.append((name, bool(ok)))
        if verbose:
            print(("PASS " if ok else "FAIL ") + name)

    # 1. Known secp256k1 vector: private key 1.
    unc, comp = public_keys(1)
    check("vector k=1 compressed -> 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
          address_from_public(comp) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    check("vector k=1 uncompressed -> 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
          address_from_public(unc) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
    if BACKEND != "pure-python":
        check("backend agrees with pure-python reference",
              public_keys(0xC0FFEE)[0][1:33] == _pure_point(0xC0FFEE)[0].to_bytes(32, "big"))

    # 2. Targets re-derived from address text and the on-chain key.
    check("Half public key hashes to Half address", hash160(HALF_PUBLIC_UNCOMPRESSED) == HALF_H160)
    check("Better Half hash160 = 4bc46844...4ed6",
          BETTER_H160.hex() == "4bc468447fe1b048ad030a2f9a125478eabc4ed6")
    check("ripemd160 fallback agrees with active implementation",
          _ripemd160_fallback(b"abc") == _ripemd160(b"abc"))

    # 3. Planted keys, one per encoding, each against a planted target that
    #    occupies the Half slot and then the Better Half slot, under each
    #    serialization.  A hash160-only target is exactly Better Half's case.
    key = int.from_bytes(hashlib.sha256(b"prize_gate planted control").digest(), "big") % N
    kb = key.to_bytes(32, "big")
    unc, comp = public_keys(key)
    rng = hashlib.sha256(b"filler").digest() * 8
    mini, mini_key = None, None
    for i in range(100000):
        cand = ("S" + "".join(B58[b % 58] for b in hashlib.sha256(b"mini%d" % i).digest()[:29])).encode()
        if hashlib.sha256(cand + b"?").digest()[0] == 0:
            mini, mini_key = cand, int.from_bytes(hashlib.sha256(cand).digest(), "big")
            break
    wif_u = b58check_encode(b"\x80" + kb).encode()
    wif_c = b58check_encode(b"\x80" + kb + b"\x01").encode()
    plants = {
        "raw32": (rng[:17] + kb + rng[:9], True, key),
        "hex64 lower": (b"the key is " + kb.hex().encode() + b".\n", False, key),
        "hex64 upper": (b"KEY=" + kb.hex().upper().encode() + b"\n", False, key),
        "hex64 inside longer hex run": (rng[:5].hex().encode() + kb.hex().encode() + b"ab", False, key),
        "wif uncompressed": (b"wif: " + wif_u + b"\n", False, key),
        "wif compressed": (b"(" + wif_c + b")", False, key),
        "mini key": (b"mini " + mini + b" end", False, mini_key),
        "base64 32 bytes": (b"k=" + base64.b64encode(kb) + b";", False, key),
        "decimal": (b"n " + str(key).encode() + b" ", False, key),
        "WIF inside hex blob": (binascii.hexlify(b"x " + wif_c + b" y"), False, key),
        "WIF inside base64 blob": (base64.b64encode(b"stored: " + wif_u + b" ok....."), False, key),
        "brainwallet sha256(text)": (b"some passphrase", False,
                                     int.from_bytes(hashlib.sha256(b"some passphrase").digest(), "big")),
    }
    for label, (blob, windows, expect) in plants.items():
        eu, ec_ = public_keys(expect)
        for slot in ("half", "better_half"):
            for form, pub in (("uncompressed", eu), ("compressed", ec_)):
                planted = {"half": HALF_H160, "better_half": BETTER_H160, slot: hash160(pub)}
                hits, _ = gate_plaintext(blob, windows=windows, targets=planted)
                ok = any(h["matches"].get(slot) == [form] and h["scalar"] == f"{expect % N:064x}"
                         for h in hits)
                check(f"planted {label} -> {slot} slot, {form}", ok)

    # 4. Negative control: unrelated data matches nothing.
    hits, counts = gate_plaintext(rng + b"no key here 0123", windows=True)
    check(f"negative control: {sum(counts.values())} candidates, 0 hits", not hits)

    passed = all(ok for _, ok in results)
    if verbose:
        print(f"{'PASS' if passed else 'FAIL'}: {sum(ok for _, ok in results)}/{len(results)} "
              f"checks, backend={BACKEND}, prize_gate {__version__}")
    return passed


# --------------------------------------------------------------------------
# File scanning
# --------------------------------------------------------------------------

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".pytest_cache"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".mp4", ".mp3",
            ".wav", ".ogg", ".webm", ".mov", ".m4a", ".pdf", ".zip", ".gz", ".7z",
            ".tgs", ".woff", ".woff2", ".ttf", ".otf", ".pyc", ".exe", ".dll", ".so"}


def _is_binary(data: bytes) -> bool:
    sample = data[:8192]
    if b"\0" in sample:
        return True
    text = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return bool(sample) and text / len(sample) < 0.85


def iter_files(paths):
    for root in paths:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                yield os.path.join(dirpath, name)


def scan(paths, *, raw_limit: int = 16 << 20, text_windows: bool = False,
         max_bytes: int = 1 << 30, progress: bool = False) -> dict:
    """Gate every candidate found in every file under ``paths``.

    Binary files up to ``raw_limit`` bytes get every raw 32-byte window.
    Text files get the text parsers, plus raw windows if ``text_windows``.
    """
    started = time.time()
    seen: set[int] = set()
    summary = {"prize_gate_version": __version__, "backend": BACKEND,
               "targets": {"half": HALF_ADDRESS, "better_half": BETTER_ADDRESS},
               "files_scanned": 0, "binary_files": 0, "bytes_scanned": 0,
               "skipped": [], "candidates_by_kind": {}, "unique_scalars_gated": 0,
               "files_with_candidates": {}, "hits": []}
    for path in iter_files(paths):
        ext = os.path.splitext(path)[1].lower()
        if ext in SKIP_EXT:
            summary["skipped"].append({"path": path, "reason": f"media/archive {ext}"})
            continue
        try:
            size = os.path.getsize(path)
            if size > max_bytes:
                summary["skipped"].append({"path": path, "reason": f"size {size}"})
                continue
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            summary["skipped"].append({"path": path, "reason": str(exc)})
            continue
        if data[:2] == b"\x1f\x8b":  # gzip (e.g. cached web bodies): parse the content
            try:
                data = gzip.decompress(data)
                summary["gzip_decompressed"] = summary.get("gzip_decompressed", 0) + 1
            except (OSError, EOFError):
                pass
        binary = _is_binary(data)
        windows = (binary and len(data) <= raw_limit) or text_windows
        if binary and len(data) > raw_limit:
            summary["skipped"].append({"path": path, "reason": f"raw windows skipped, size {len(data)}"})
        hits, counts = gate_plaintext(data, windows=windows, derived=True, seen=seen)
        summary["files_scanned"] += 1
        summary["binary_files"] += int(binary)
        summary["bytes_scanned"] += size
        if counts:
            summary["files_with_candidates"][path] = counts
        for kind, n in counts.items():
            summary["candidates_by_kind"][kind] = summary["candidates_by_kind"].get(kind, 0) + n
        for hit in hits:
            hit["path"] = path
            summary["hits"].append(hit)
            print("PRIZE MATCH", json.dumps(hit), file=sys.stderr)
        if progress and summary["files_scanned"] % 200 == 0:
            print(f"  {summary['files_scanned']} files, {len(seen)} scalars, "
                  f"{time.time() - started:.0f}s", file=sys.stderr)
    summary["unique_scalars_gated"] = len(seen)
    summary["seconds"] = round(time.time() - started, 1)
    return summary


def _candidate_from_string(text: str) -> list[tuple[str, int]]:
    out = [(kind, k) for kind, k, _ in extract(text.encode(), windows=False, derived=False)]
    if not out:
        out = [("derived_sha256", int.from_bytes(hashlib.sha256(text.encode()).digest(), "big"))]
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    p_key = sub.add_parser("key")
    p_key.add_argument("candidate")
    p_scan = sub.add_parser("scan")
    p_scan.add_argument("paths", nargs="+")
    p_scan.add_argument("--json", help="write the full summary here")
    p_scan.add_argument("--raw-limit", type=int, default=16 << 20)
    p_scan.add_argument("--text-windows", action="store_true")
    p_scan.add_argument("--progress", action="store_true")
    args = parser.parse_args(argv)

    if args.cmd == "selftest":
        return 0 if selftest() else 1
    if args.cmd == "key":
        found = False
        for kind, k in _candidate_from_string(args.candidate):
            result = gate_scalar(k)
            print(kind, f"{k % N:064x}", "MATCH " + json.dumps(result) if result else "no match")
            found |= bool(result)
        return 3 if found else 0
    if not selftest(verbose=False):
        print("selftest failed; refusing to scan", file=sys.stderr)
        return 1
    summary = scan(args.paths, raw_limit=args.raw_limit, text_windows=args.text_windows,
                   progress=args.progress)
    summary["selftest"] = "PASS"
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(summary, fh, indent=1, sort_keys=True)
            fh.write("\n")
    print(json.dumps({k: summary[k] for k in ("files_scanned", "binary_files", "bytes_scanned",
                                              "candidates_by_kind", "unique_scalars_gated",
                                              "seconds", "backend")}, indent=1))
    print(f"prize hits: {len(summary['hits'])}")
    return 3 if summary["hits"] else 0


if __name__ == "__main__":
    sys.exit(main())
