#!/usr/bin/env python3
"""The only acceptance test: does a candidate scalar control a prize address?

Two targets, and they must be gated differently:

* **Half** has spent, so its exact uncompressed public key is on chain. A
  candidate can be checked against the public point itself.
* **Better Half** has never spent, so no public point exists — only a hash160.
  Its correct serialisation is therefore unknown, and a gate written against a
  *public key* would silently reject every correct Better Half candidate. It
  must be checked against hash160 under **both** compressed and uncompressed
  encodings.

Everything is recomputed here from the two addresses: the addresses decode to
their hash160s, and the published public key hashes to Half's. Nothing is taken
on faith from a constant someone typed in.

    from prize_gate import gate_scalar
    gate_scalar(0x1234…)   # -> None, or the name of the target it matches

Run this file directly to see the self-checks pass.
"""

from __future__ import annotations

import hashlib

# --- targets, as published on chain -------------------------------------------

HALF_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER_HALF_ADDRESS = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"

# Half's uncompressed public key, recovered from its spending transaction.
HALF_PUBKEY = bytes.fromhex(
    "04"
    "f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)

# --- secp256k1 ----------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], P - 2, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], P - 2, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)


def multiply(k: int, point=G):
    """Scalar multiplication. Plain double-and-add — this gates candidates, it
    does not handle secrets, so constant time is not a requirement."""
    result, addend = None, point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def serialise(point, compressed: bool) -> bytes:
    x, y = point
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# --- addresses ----------------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def b58decode_check(address: str) -> bytes:
    number = 0
    for char in address:
        number = number * 58 + B58.index(char)
    raw = number.to_bytes(25, "big")
    leading = len(address) - len(address.lstrip("1"))
    raw = b"\x00" * leading + raw.lstrip(b"\x00")
    raw = raw[-25:]
    body, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != checksum:
        raise ValueError(f"bad base58 checksum: {address}")
    return body[1:]


def b58encode_check(payload: bytes, version: int = 0) -> str:
    body = bytes([version]) + payload
    full = body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    number = int.from_bytes(full, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = B58[rem] + out
    return "1" * (len(full) - len(full.lstrip(b"\x00"))) + out


HALF_HASH160 = b58decode_check(HALF_ADDRESS)
BETTER_HALF_HASH160 = b58decode_check(BETTER_HALF_ADDRESS)

# Addresses that are NOT targets. Two key pairs derived from later solver work
# were published publicly and their balances swept afterwards. On-chain activity
# at an address a solver published is a consequence of publication, never
# creator confirmation, so they are listed here to stop them being mistaken for
# a hit.
NON_TARGETS = {
    "1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu",
    "15E3pcDDXSKhvi3CLVhRTHEgd8dbVKvSZg",
    "145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ",
    "1FhbJnrdq1FmeiXrpTqnpQ8jvYV7naze96",
}


# --- the gate -----------------------------------------------------------------

def gate_scalar(k: int) -> str | None:
    """Return "Half", "Better Half", or None. This is the whole acceptance test."""
    if not 1 <= k < N:
        return None
    point = multiply(k)
    uncompressed = serialise(point, compressed=False)
    compressed = serialise(point, compressed=True)

    if uncompressed == HALF_PUBKEY:
        return "Half"
    for encoding in (uncompressed, compressed):
        digest = hash160(encoding)
        if digest == HALF_HASH160:
            return "Half"
        if digest == BETTER_HALF_HASH160:
            return "Better Half"
    return None


def gate_scalar_bytes(raw: bytes) -> str | None:
    if len(raw) != 32:
        raise ValueError("expected a 32-byte scalar")
    return gate_scalar(int.from_bytes(raw, "big"))


def _self_check() -> None:
    print(f"Half         {HALF_ADDRESS}")
    print(f"  hash160 from address    {HALF_HASH160.hex()}")
    print(f"  hash160 of published pk {hash160(HALF_PUBKEY).hex()}")
    assert hash160(HALF_PUBKEY) == HALF_HASH160, "published public key does not hash to Half"
    assert b58encode_check(HALF_HASH160) == HALF_ADDRESS

    print(f"Better Half  {BETTER_HALF_ADDRESS}")
    print(f"  hash160 from address    {BETTER_HALF_HASH160.hex()}")
    print("  public key              unknown — never spent, so both serialisations are gated")
    assert b58encode_check(BETTER_HALF_HASH160) == BETTER_HALF_ADDRESS

    # secp256k1 sanity: k=1 gives the generator, and a known key gives a known address.
    assert multiply(1) == G
    known = 0x0000000000000000000000000000000000000000000000000000000000000001
    assert b58encode_check(hash160(serialise(multiply(known), True))) == \
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    assert gate_scalar(1) is None
    assert gate_scalar(0) is None
    assert gate_scalar(N) is None
    print("\nself-check OK — the gate rejects non-matching scalars and the "
          "target constants re-derive from the addresses")


if __name__ == "__main__":
    _self_check()
