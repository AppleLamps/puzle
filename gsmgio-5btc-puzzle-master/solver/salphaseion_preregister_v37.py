"""Seal the missing S91-prefix plus URL-LSB prime insertion.

The 24 colored first-grid cells are the least-significant bits of the 24 URL
bytes (F73D92) and occur at spiral positions 8, 16, ..., 192.  S91 has 67
non-prime positions and 24 prime positions.  This round therefore fills the
non-prime positions from S91[:67] and inserts the authenticated URL bits at
the prime positions.  S91[67:] is retained explicitly as the 24-symbol
remainder; no decryption output is consulted while building this manifest.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v12 import _primes
from .salphaseion_preregister_v15 import _integer_bytes, _serializations
from .salphaseion_preregister_v36 import SEAL_PATH as V36_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v37.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v37.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v37.json"
SPIRAL_TEXT = "gsmg.io/theseedisplanted"


def _insert(prefix: str, bits: str) -> tuple[str, list[int]]:
    primes = set(_primes(91))
    ordinary = iter(prefix)
    basics = iter(bits)
    symbols: list[str] = []
    values: list[int] = []
    for position in range(1, 92):
        if position in primes:
            bit = next(basics)
            symbols.append("b" if bit == "1" else "a")
            values.append(int(bit))
        else:
            symbol = next(ordinary)
            symbols.append(symbol)
            values.append(ord(symbol) - 96)
    for iterator, name in ((ordinary, "prefix"), (basics, "URL bits")):
        try:
            next(iterator)
            raise ValueError(f"unused {name} value")
        except StopIteration:
            pass
    return "".join(symbols), values


def _decimal_to_hex_bytes(values: list[int]) -> bytes:
    hexadecimal = format(int("".join(str(value) for value in values)), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    bits = "".join(str(ord(character) & 1) for character in SPIRAL_TEXT)
    primes = _primes(91)
    if bits != "111101110011110110010010" or len(primes) != 24:
        raise ValueError("URL-LSB/prime invariant changed")
    if len(raw.s91) != 91 or len(raw.s91[:67]) != 67 or len(raw.s91[67:]) != 24:
        raise ValueError("S91 67+24 split changed")

    symbolic, values = _insert(raw.s91[:67], bits)
    remainder = raw.s91[67:]
    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"s91-prefix-url-lsb-primes/{label}")

    add("mixed-symbols-bit-as-ab", symbolic.encode("ascii"))
    add("mixed-decimal-concatenated", "".join(map(str, values)).encode("ascii"))
    add("mixed-decimal-to-hex-bytes", _decimal_to_hex_bytes(values))
    add("mixed-base10-integer-bytes", _integer_bytes(values, 10))
    add("remainder-symbols", remainder.encode("ascii"))
    add("mixed-symbols-then-remainder", symbolic.encode("ascii") + remainder.encode("ascii"))
    add("remainder-then-mixed-symbols", remainder.encode("ascii") + symbolic.encode("ascii"))

    matrix_records: list[dict[str, object]] = []
    for origin in (0, 1):
        matrix_values = [value - 1 + origin if position not in set(primes) else value
                         for position, value in enumerate(values, 1)]
        grid = [matrix_values[offset:offset + 13] for offset in range(0, 91, 13)]
        vectors = {
            "row-sums": [sum(row) for row in grid],
            "column-sums": [sum(row[column] for row in grid) for column in range(13)],
        }
        vectors["rows-then-columns"] = vectors["row-sums"] + vectors["column-sums"]
        for vector_name, vector in vectors.items():
            for serialization, encoded in _serializations(vector):
                add(f"matrixsumlist/origin-{origin}/{vector_name}/{serialization}", encoded)
            matrix_records.append({"origin": origin, "vector": vector_name, "values": vector})

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v37c{len(candidates):03d}",
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
        "schema": "salphaseion-source-only-preregistration-v37-prefix-url-lsb-primes",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v36_manifest_sha256": V36_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "architect_instruction": "REINSERTING THE PRIME BASICS",
            "adjacent_instruction": "matrixsumlist",
            "spiral_text": SPIRAL_TEXT,
            "ascii_lsb_bits": bits,
            "ascii_lsb_hex": f"{int(bits, 2):06X}",
            "colored_spiral_positions_one_based": list(range(8, 193, 8)),
            "prime_positions_one_based": primes,
            "split_rule": "S91[:67] fills non-primes; URL LSBs fill primes; S91[67:] is preserved as remainder",
            "source_prefix_67_sha256": sha256_hex(raw.s91[:67].encode("ascii")),
            "remainder_24": remainder,
            "remainder_24_sha256": sha256_hex(remainder.encode("ascii")),
            "mixed_symbolic_sha256": sha256_hex(symbolic.encode("ascii")),
            "mixed_values": values,
            "matrix_records": matrix_records,
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
            "forbidden_evidence": ["expected padding length", "target point or address", "known plaintext hashes"],
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
