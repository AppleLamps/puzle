"""Seal the all-source S91 prime-list reinsertion.

There are 24 primes through 91, so S91 splits exactly into 67 non-prime
symbols followed by 24 prime symbols.  The authenticated Architect instruction
``REINSERTING THE PRIME BASICS`` therefore admits a literal, lossless reading:
put the last 24 source symbols at the one-based prime positions and the first
67 symbols at every remaining position.  The adjacent ``matrixsumlist`` is
then applied to the resulting 7x13 rectangle.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v12 import _primes
from .salphaseion_preregister_v14 import SEAL_PATH as V14_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v15.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v15.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v15.json"


def _reinsert_prime_tail(text: str) -> str:
    primes = set(_primes(len(text)))
    nonprime_count = len(text) - len(primes)
    ordinary = iter(text[:nonprime_count])
    prime = iter(text[nonprime_count:])
    output = [next(prime) if position in primes else next(ordinary)
              for position in range(1, len(text) + 1)]
    for iterator, name in ((ordinary, "ordinary"), (prime, "prime")):
        try:
            next(iterator)
            raise ValueError(f"unused {name} source symbol")
        except StopIteration:
            pass
    return "".join(output)


def _integer_bytes(digits: list[int], base: int) -> bytes:
    value = 0
    for digit in digits:
        value = value * base + digit
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _decimal_to_hex_bytes(text: str) -> bytes:
    decimal = "".join(str(ord(character) - 96) for character in text)
    hexadecimal = format(int(decimal), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def _serializations(values: list[int]):
    decimal = [str(value) for value in values]
    yield "python-list", repr(values).encode("ascii")
    yield "json-compact", ("[" + ",".join(decimal) + "]").encode("ascii")
    yield "decimal-concatenated", "".join(decimal).encode("ascii")
    yield "decimal-spaces", " ".join(decimal).encode("ascii")
    yield "decimal-commas", ",".join(decimal).encode("ascii")
    if all(0 <= value <= 255 for value in values):
        yield "raw-bytes", bytes(values)
    yield "mod9-a0", "".join(chr(97 + value % 9) for value in values).encode("ascii")
    yield "mod9-i0", "".join("iabcdefgh"[value % 9] for value in values).encode("ascii")
    yield "mod26-a0", "".join(chr(97 + value % 26) for value in values).encode("ascii")
    yield "mod26-a1", "".join(chr(97 + (value - 1) % 26) for value in values).encode("ascii")


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    primes = _primes(91)
    if len(raw.s91) != 91 or len(primes) != 24 or 91 - len(primes) != 67:
        raise ValueError("S91 prime split changed")
    reinserted = _reinsert_prime_tail(raw.s91)

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"s91-prime-tail-reinsertion/{label}")

    add("symbols", reinserted.encode("ascii"))
    add("decimal-to-hex-bytes", _decimal_to_hex_bytes(reinserted))
    add("base9-a0-integer-bytes", _integer_bytes([ord(c) - 97 for c in reinserted], 9))
    add("base9-a1-i0-integer-bytes", _integer_bytes([(ord(c) - 96) % 9 for c in reinserted], 9))

    for origin in (0, 1):
        values = [ord(character) - 97 + origin for character in reinserted]
        grid = [values[offset:offset + 13] for offset in range(0, 91, 13)]
        vectors = {
            "row-sums": [sum(row) for row in grid],
            "column-sums": [sum(row[column] for row in grid) for column in range(13)],
            "rows-then-columns": (
                [sum(row) for row in grid]
                + [sum(row[column] for row in grid) for column in range(13)]
            ),
        }
        for vector_name, vector in vectors.items():
            for serialization, encoded in _serializations(vector):
                add(f"matrixsumlist/origin-{origin}/{vector_name}/{serialization}", encoded)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v15c{len(candidates):03d}",
                "preimage_hex": preimage.hex(),
                "password_expansion": expansion,
                "password_hex": password.hex(),
                "password_sha256": sha256_hex(password),
                "provenance": sorted(preimages[preimage]),
            })

    blobs = {
        "salphaseion-short": extracted.chain1_envelope,
        "phase32-small": extracted.chain2_envelope,
        "cosmic-duality": extracted.cosmic_envelope,
    }
    return {
        "schema": "salphaseion-source-only-preregistration-v15-prime-tail-list",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v14_manifest_sha256": V14_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "architect_instruction": "REINSERTING THE PRIME BASICS",
            "adjacent_instruction": "matrixsumlist",
            "prime_positions_one_based": primes,
            "split_rule": "S91[:67] fills non-prime positions; S91[67:] fills the 24 prime positions",
            "source_prefix_67_sha256": sha256_hex(raw.s91[:67].encode("ascii")),
            "source_prime_tail_24_sha256": sha256_hex(raw.s91[67:].encode("ascii")),
            "reinserted_sha256": sha256_hex(reinserted.encode("ascii")),
            "candidate_rule": "lossless prime-tail permutation, then direct numeric forms or 7x13 row/column sum lists",
        },
        "blobs": {
            name: {
                "length": len(envelope),
                "sha256": sha256_hex(envelope),
                "salt_hex": envelope[8:16].hex(),
                "ciphertext_length": len(envelope) - 16,
            }
            for name, envelope in blobs.items()
        },
        "declared_crypto": {
            "cipher": "AES-256-CBC",
            "password_to_key": "OpenSSL EVP_BytesToKey",
            "kdf_digests": ["md5", "sha256"],
            "padding": "strict PKCS#7",
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
        },
        "declared_acceptance": {
            "inherits_v1_rules_verbatim": True,
            "padding_alone": False,
            "forbidden_evidence": [
                "expected padding length", "community plus/minus block grammar", "Half/Better Half",
                "target point or address", "known community plaintext hashes",
            ],
        },
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def main() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({
        "manifest": str(MANIFEST_PATH),
        "candidate_count": manifest["candidate_count"],
        "seal_sha256": sha256_hex(encoded),
    }, indent=2))


if __name__ == "__main__":
    main()
