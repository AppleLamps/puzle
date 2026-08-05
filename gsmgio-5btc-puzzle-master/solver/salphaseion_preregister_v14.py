"""Seal URL-LSB reinsertion at the 24 prime positions of S91.

The first puzzle's authenticated spiral text has 24 characters.  Their least
significant ASCII bits are the verified F73D92 sequence.  There are exactly 24
prime positions in S91 (1..91), and the Architect plaintext says to reinsert
the prime basics.  This round puts those binary basics at those positions while
preserving every non-prime S91 symbol, then applies only page-established
numeric decoding and the already sealed equal-width S570 bridge.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v12 import _primes
from .salphaseion_preregister_v13 import _combine
from .salphaseion_preregister_v13 import SEAL_PATH as V13_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v14.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v14.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v14.json"
SPIRAL_TEXT = "gsmg.io/theseedisplanted"


def _replace_prime_digits(s91: str, bits: str) -> str:
    primes = set(_primes(91))
    iterator = iter(bits)
    output: list[str] = []
    for position, symbol in enumerate(s91, 1):
        output.append(next(iterator) if position in primes else str(ord(symbol) - 96))
    try:
        next(iterator)
        raise ValueError("unused URL bit")
    except StopIteration:
        pass
    return "".join(output)


def _decimal_to_hex_bytes(decimal: str) -> bytes:
    hexadecimal = format(int(decimal), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    bits = "".join(str(ord(character) & 1) for character in SPIRAL_TEXT)
    if len(SPIRAL_TEXT) != 24 or bits != "111101110011110110010010":
        raise ValueError("authenticated first-puzzle LSB sequence changed")
    primes = _primes(91)
    if len(primes) != len(bits) or len(raw.s91) != 91:
        raise ValueError("prime/LSB/S91 cardinality mismatch")

    digits = _replace_prime_digits(raw.s91, bits)
    left = _decimal_to_hex_bytes(digits)
    bit_symbols = "".join("b" if digit == "1" else "a" for digit in bits)
    symbol_iterator = iter(bit_symbols)
    symbolic = "".join(
        next(symbol_iterator) if position in set(primes) else symbol
        for position, symbol in enumerate(raw.s91, 1)
    )
    if len(left) != 38:
        raise ValueError("URL-LSB reinsertion no longer yields the 38-byte bridge")

    values0 = [ord(character) - 97 for character in raw.s570]
    values1 = [value + 1 for value in values0]
    right_operands: dict[str, bytes] = {}
    for origin, values in (("a0", values0), ("a1", values1)):
        grid = [values[offset:offset + 38] for offset in range(0, len(values), 38)]
        right_operands[origin] = bytes(
            sum(row[column] for row in grid) for column in range(38)
        )
    key38 = (raw.lastwords_marker + raw.password_marker).encode("ascii")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"url-lsb-prime-reinsertion/{label}")

    add("decimal-digits", digits.encode("ascii"))
    add("binary-as-ab-symbols", symbolic.encode("ascii"))
    add("decimal-to-hex-bytes", left)
    operations = ("xor", "left-plus-right", "left-minus-right", "right-minus-left")
    bridge_records: list[dict[str, object]] = []
    for origin, right in right_operands.items():
        add(f"bridge/{origin}/concatenated", left + right)
        for operation in operations:
            paired = _combine(left, right, operation)
            add(f"bridge/{origin}/{operation}/direct", paired)
            bridge_records.append({
                "s570_origin": origin,
                "operation": operation,
                "result_sha256": sha256_hex(paired),
            })
            for key_operation in operations:
                add(
                    f"bridge/{origin}/{operation}/then-adjacent-key/{key_operation}",
                    _combine(paired, key38, key_operation),
                )

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v14c{len(candidates):03d}",
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
        "schema": "salphaseion-source-only-preregistration-v14-url-lsb-primes",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v13_manifest_sha256": V13_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "architect_instruction": "REINSERTING THE PRIME BASICS",
            "spiral_text": SPIRAL_TEXT,
            "spiral_text_length": len(SPIRAL_TEXT),
            "ascii_lsb_bits": bits,
            "ascii_lsb_hex": f"{int(bits, 2):06X}",
            "prime_positions_one_based": primes,
            "cardinality_rule": "24 URL character LSBs exactly match 24 primes <= 91",
            "reinsertion_rule": "replace prime positions with LSB digits; preserve S91 values at every non-prime position",
            "decoded_length": len(left),
            "decoded_sha256": sha256_hex(left),
            "bridge_records": bridge_records,
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
            "direct_decoded_and_bridge_bytes_are_evaluated_for_readable_or_exact_structure": True,
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
