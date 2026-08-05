"""Seal the seven-by-91 matrix, 24-prime-remainder construction.

This round joins four authenticated numerical facts that earlier rounds kept
separate:

* S91 contributes one row of length 91;
* S570 is six further rows of 91 plus a 24-symbol remainder;
* there are exactly 24 one-based prime positions through 91; and
* the Architect plaintext says ``SEVEN INTERTWINED PASSWORDS``, ``REINSERTING
  THE PRIME BASICS``, and (earlier) ``SUM OF A REMAINDER``.

The seven source-order rows are summed by column in Z/9Z.  The 24-symbol tail
is then assigned, in order, to the 24 prime-numbered columns.  Literal
"reinsert" has two frozen meanings: add the tail symbol to the existing sum,
or replace the prime-position sum with it.  No AES output is consulted.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v12 import _primes
from .salphaseion_preregister_v19 import SEAL_PATH as V19_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v20.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v20.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v20.json"


def _encode_symbols(values: list[int], convention: str) -> bytes:
    if convention == "a0":
        return "".join(chr(97 + value % 9) for value in values).encode("ascii")
    if convention == "i0":
        return "".join("iabcdefgh"[value % 9] for value in values).encode("ascii")
    raise ValueError(convention)


def _serializations(values: list[int], symbol_convention: str):
    decimal = [str(value % 9) for value in values]
    yield f"symbols-{symbol_convention}", _encode_symbols(values, symbol_convention)
    yield "digits-compact", "".join(decimal).encode("ascii")
    yield "digits-spaces", " ".join(decimal).encode("ascii")
    yield "python-list", repr([value % 9 for value in values]).encode("ascii")
    yield "json-compact", ("[" + ",".join(decimal) + "]").encode("ascii")
    yield "raw-residue-bytes", bytes(value % 9 for value in values)


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    width = len(raw.s91)
    row_payload_length = 6 * width
    if width != 91 or len(raw.s570) != row_payload_length + 24:
        raise ValueError("S91/S570 seven-row-plus-prime-remainder relation changed")

    row_texts = [raw.s91] + [
        raw.s570[offset:offset + width]
        for offset in range(0, row_payload_length, width)
    ]
    prime_tail = raw.s570[row_payload_length:]
    primes = _primes(width)
    if len(row_texts) != 7 or any(len(row) != width for row in row_texts):
        raise ValueError("expected seven source-order rows of width 91")
    if len(prime_tail) != len(primes) or len(primes) != 24:
        raise ValueError("prime remainder cardinality changed")

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"seven-by-91-prime-remainder/{label}")

    constructions: list[dict[str, object]] = []
    for origin, symbol_convention in ((0, "a0"), (1, "i0")):
        rows = [[(ord(character) - 97 + origin) % 9 for character in row] for row in row_texts]
        tail = [(ord(character) - 97 + origin) % 9 for character in prime_tail]
        column_sums = [sum(row[column] for row in rows) % 9 for column in range(width)]

        for reinsertion in ("add-at-primes", "replace-at-primes"):
            result = column_sums.copy()
            for prime, tail_value in zip(primes, tail):
                index = prime - 1
                if reinsertion == "add-at-primes":
                    result[index] = (result[index] + tail_value) % 9
                else:
                    result[index] = tail_value
            base = f"origin-{origin}/{reinsertion}"
            for serialization, encoded in _serializations(result, symbol_convention):
                add(f"{base}/{serialization}", encoded)
            constructions.append({
                "origin": origin,
                "symbol_convention": symbol_convention,
                "reinsertion": reinsertion,
                "column_sums_mod9": column_sums,
                "result_mod9": result,
                "result_symbol_sha256": sha256_hex(_encode_symbols(result, symbol_convention)),
            })

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v20c{len(candidates):03d}",
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
        "schema": "salphaseion-source-only-preregistration-v20-seven-by-91-primes",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v19_manifest_sha256": V19_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "dimension_rule": "S91 + first 546 of S570 = seven source-order rows of 91; S570 tail has 24 symbols",
            "architect_clues": [
                "SUM OF A REMAINDER",
                "REINSERTING THE PRIME BASICS",
                "SEVEN INTERTWINED PASSWORDS",
            ],
            "matrix_instruction": raw.matrix_marker,
            "prime_positions_one_based": primes,
            "row_sha256": [sha256_hex(row.encode("ascii")) for row in row_texts],
            "prime_tail": prime_tail,
            "candidate_rule": (
                "sum seven source-order 91-symbol rows by column modulo nine, then add or "
                "replace the 24 source-remainder symbols at the 24 one-based prime positions"
            ),
            "constructions": constructions,
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
                "expected padding length", "community token list", "plus/minus grammar",
                "Half/Better Half", "target point or address", "known community plaintext hashes",
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
