"""Minimal pure-Python AES-256-CBC decryption.

This exists so the fresh-start folder runs on a bare Python 3 install with no
third-party packages. If `cryptography` or `pycryptodome` is importable it is
used instead, because it is much faster; the pure-Python path is the fallback
and produces identical output.

Decryption only — nothing here needs to encrypt.
"""

from __future__ import annotations

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _expand_key(key: bytes) -> list[list[int]]:
    """Key schedule for AES-256: 15 round keys of 16 bytes."""
    nk, rounds = len(key) // 4, len(key) // 4 + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(rounds + 1)]


def _decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = [b ^ k for b, k in zip(block, round_keys[-1])]
    for rnd in range(len(round_keys) - 2, -1, -1):
        # InvShiftRows
        state = [state[(i - 4 * (i % 4)) % 16] for i in range(16)]
        # InvSubBytes
        state = [INV_SBOX[b] for b in state]
        # AddRoundKey
        state = [b ^ k for b, k in zip(state, round_keys[rnd])]
        if rnd:
            # InvMixColumns
            mixed = []
            for c in range(4):
                col = state[4 * c:4 * c + 4]
                mixed += [
                    _mul(col[0], 14) ^ _mul(col[1], 11) ^ _mul(col[2], 13) ^ _mul(col[3], 9),
                    _mul(col[0], 9) ^ _mul(col[1], 14) ^ _mul(col[2], 11) ^ _mul(col[3], 13),
                    _mul(col[0], 13) ^ _mul(col[1], 9) ^ _mul(col[2], 14) ^ _mul(col[3], 11),
                    _mul(col[0], 11) ^ _mul(col[1], 13) ^ _mul(col[2], 9) ^ _mul(col[3], 14),
                ]
            state = mixed
    return bytes(state)


def _cbc_decrypt_pure(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    round_keys = _expand_key(key)
    out, previous = bytearray(), iv
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(block, round_keys), previous))
        previous = block
    return bytes(out)


def _backend():
    """Prefer an installed AES implementation; fall back to the pure-Python one."""
    import importlib.util

    try:
        # `cryptography`'s Rust bindings abort the process-wide stderr with a
        # pyo3 panic when their cffi backend is missing, so check for it first
        # rather than triggering the noisy failed import.
        if importlib.util.find_spec("_cffi_backend") is None:
            raise ImportError("cffi backend unavailable")
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def run(key, iv, ciphertext):
            d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            return d.update(ciphertext) + d.finalize()

        run(b"\0" * 32, b"\0" * 16, b"\0" * 16)  # some installs import but cannot run
        return run, "cryptography"
    except BaseException:
        # BaseException, not Exception: a half-installed `cryptography` raises a
        # pyo3 PanicException, which does not inherit from Exception.
        pass
    try:
        from Crypto.Cipher import AES as _AES

        return (lambda key, iv, ct: _AES.new(key, _AES.MODE_CBC, iv).decrypt(ct)), "pycryptodome"
    except BaseException:
        pass
    return _cbc_decrypt_pure, "pure-python"


_RUN, BACKEND = _backend()


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-CBC decrypt. No padding handling — the caller strips PKCS#7."""
    if len(ciphertext) % 16:
        raise ValueError("ciphertext is not a whole number of blocks")
    return _RUN(key, iv, ciphertext)


if __name__ == "__main__":
    # FIPS-197 AES-256 test vector, so a broken backend is caught immediately.
    key = bytes(range(32))
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert cbc_decrypt(key, b"\0" * 16, cipher) == plain
    assert _cbc_decrypt_pure(key, b"\0" * 16, cipher) == plain
    print(f"AES-256 test vector OK (backend: {BACKEND})")
