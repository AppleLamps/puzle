"""Small dependency-free secp256k1 and Base58Check verification module."""

from __future__ import annotations

import hashlib


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _inverse(value: int) -> int:
    return pow(value % P, P - 2, P)


def point_add(left: tuple[int, int] | None, right: tuple[int, int] | None) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * _inverse(2 * y1) % P
    else:
        slope = (y2 - y1) * _inverse(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def scalar_multiply(scalar: int) -> tuple[int, int]:
    if not 1 <= scalar < N:
        raise ValueError("private scalar is outside secp256k1 range")
    result = None
    addend = G
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    assert result is not None
    return result


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def base58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, digit = divmod(value, 58)
        encoded = BASE58[digit] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + encoded


def public_key(private_key: bytes, compressed: bool) -> bytes:
    x, y = scalar_multiply(int.from_bytes(private_key, "big"))
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def p2pkh_address(private_key: bytes, compressed: bool) -> str:
    return base58check(b"\x00" + hash160(public_key(private_key, compressed)))


def wif(private_key: bytes, compressed: bool = False) -> str:
    if len(private_key) != 32 or not 1 <= int.from_bytes(private_key, "big") < N:
        raise ValueError("invalid private key")
    suffix = b"\x01" if compressed else b""
    return base58check(b"\x80" + private_key + suffix)


def addresses_for_x(x_bytes: bytes) -> tuple[tuple[int, str, str], tuple[int, str, str]]:
    if len(x_bytes) != 32:
        raise ValueError("x-coordinate must be 32 bytes")
    x = int.from_bytes(x_bytes, "big")
    y0 = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    results = []
    for y in (y0, P - y0):
        public = b"\x04" + x_bytes + y.to_bytes(32, "big")
        results.append((y & 1, base58check(b"\x00" + hash160(public)), y.to_bytes(32, "big").hex()))
    return results[0], results[1]

