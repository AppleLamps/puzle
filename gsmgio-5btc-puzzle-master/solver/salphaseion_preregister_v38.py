"""Seal the zero-prime matrix-sum VIC construction.

This round follows the creator-hint order without treating intermediate data as
an AES password: yellow/blue selects complementary subsets of the 24 primes
through 91; selected S91 entries are zeroed; the natural 7x13 column-sum list
is repeated over S570; yin/yang is represented by the two modular subtraction
directions (with addition as the self-inverse control); and the result is read
with the already authenticated VIC checkerboard family.  Decoded answers are
sealed before any AES output is inspected.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import itertools
import json
import re

from .extract import ROOT, extract_all
from .phase32_classical import _vic_decode
from .salphaseion_preregister_v11 import _decrypt_route, _encrypt_route
from .salphaseion_preregister_v12 import _primes
from .salphaseion_preregister_v37 import SEAL_PATH as V37_SEAL, SPIRAL_TEXT
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v38.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v38.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v38.json"


def _pad28(seed: str) -> str:
    letters = "".join(dict.fromkeys(re.sub(r"[^A-Za-z]", "", seed).upper()))
    letters += "".join(character for character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if character not in letters)
    letters = letters[:26]
    return letters[:8] + "." + letters[8:17] + "." + letters[17:26]


def _answer_forms(answer: str) -> set[bytes]:
    letters = re.sub(r"[^A-Za-z]", "", answer)
    return {
        answer.encode("ascii"), answer.lower().encode("ascii"), answer.upper().encode("ascii"),
        letters.encode("ascii"), letters.lower().encode("ascii"), letters.upper().encode("ascii"),
    }


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    primes = _primes(91)
    url_bits = "".join(str(ord(character) & 1) for character in SPIRAL_TEXT)
    if len(primes) != 24 or url_bits != "111101110011110110010010":
        raise ValueError("prime/color invariant changed")
    blue = {prime for prime, bit in zip(primes, url_bits) if bit == "1"}
    yellow = {prime for prime, bit in zip(primes, url_bits) if bit == "0"}
    masks = {
        "none-control": set(),
        "all-primes": set(primes),
        "spiral-yellow": yellow,
        "spiral-blue": blue,
        "grouped-yellow-first-9": set(primes[:9]),
        "grouped-blue-last-15": set(primes[9:]),
    }
    if len(yellow) != 9 or len(blue) != 15:
        raise ValueError("yellow/blue cardinality changed")

    alphabets = {
        "phase32-control": "FUBCDORA.LETHINGKYMVPS.JQZXW",
        "neo-core": _pad28("theproblemischoice"),
        "neo-full": _pad28("choicetheproblemischoice"),
        "architect-reference": _pad28("asyouadequatelyputtheproblemischoice"),
        "lastwords-marker": _pad28(raw.lastwords_marker),
        "yellowblueprimes": _pad28("yellowblueprimes"),
        "matrixsumlist": _pad28(raw.matrix_marker),
    }
    row_pairs = [("phase32", ("1", "4"))] + [
        (f"prime-{left}{right}", (str(left), str(right)))
        for left, right in itertools.combinations((2, 3, 5, 7), 2)
    ]
    routes = {
        "source": raw.s570,
        "key38-column-decrypt-ascending": _decrypt_route(
            raw.s570, raw.lastwords_marker + raw.password_marker, False),
        "key38-column-encrypt-ascending": _encrypt_route(
            raw.s570, raw.lastwords_marker + raw.password_marker, False),
    }

    preimages: dict[bytes, set[str]] = defaultdict(set)
    records: list[dict[str, object]] = []
    invalid_vic = 0
    decoded_answers = 0
    for mask_name, zero_positions in masks.items():
        for key_origin in (0, 1):
            key_values = [
                0 if position in zero_positions else (ord(symbol) - 97 + key_origin) % 9
                for position, symbol in enumerate(raw.s91, 1)
            ]
            matrix = [key_values[offset:offset + 13] for offset in range(0, 91, 13)]
            raw_sums = [sum(row[column] for row in matrix) for column in range(13)]
            for sum_mode, sums in (
                ("raw", raw_sums),
                ("mod9", [value % 9 for value in raw_sums]),
                ("mod10", [value % 10 for value in raw_sums]),
            ):
                for payload_origin in (0, 1):
                    for route_name, routed in routes.items():
                        payload = [(ord(symbol) - 97 + payload_origin) % 9 for symbol in routed]
                        for modulus in (9, 10):
                            repeated = [sums[index % len(sums)] % modulus for index in range(len(payload))]
                            operations = {
                                "payload-minus-sums": [(left - right) % modulus for left, right in zip(payload, repeated)],
                                "sums-minus-payload": [(right - left) % modulus for left, right in zip(payload, repeated)],
                                "payload-plus-sums-control": [(left + right) % modulus for left, right in zip(payload, repeated)],
                            }
                            for operation, values in operations.items():
                                digits = "".join(map(str, values))
                                for alphabet_name, alphabet in alphabets.items():
                                    for rows_name, row_digits in row_pairs:
                                        try:
                                            answer = _vic_decode(digits, alphabet, row_digits)
                                        except ValueError:
                                            invalid_vic += 1
                                            continue
                                        decoded_answers += 1
                                        label = (
                                            f"zero-prime-matrix-vic/{mask_name}/key-origin-{key_origin}/"
                                            f"{sum_mode}/payload-origin-{payload_origin}/{route_name}/mod-{modulus}/"
                                            f"{operation}/{alphabet_name}/{rows_name}"
                                        )
                                        for form in _answer_forms(answer):
                                            preimages[form].add(label)
            records.append({
                "mask": mask_name,
                "key_origin": key_origin,
                "zero_positions_one_based": sorted(zero_positions),
                "column_sums": raw_sums,
            })

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v38c{len(candidates):06d}",
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
        "schema": "salphaseion-source-only-preregistration-v38-zero-prime-matrix-vic",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v37_manifest_sha256": V37_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "creator_hint_order": "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang",
            "zeroing_hint": "some characters need to be zeroed out",
            "field_model": "S91 is a 7x13 structured key; S570 is the payload",
            "prime_positions_one_based": primes,
            "url_lsb_bits": url_bits,
            "masks": {name: sorted(values) for name, values in masks.items()},
            "alphabets": alphabets,
            "row_digit_pairs": [{"name": name, "digits": list(pair)} for name, pair in row_pairs],
            "payload_routes": list(routes),
            "matrix_records": records,
            "decoded_answer_records": decoded_answers,
            "invalid_vic_records": invalid_vic,
        },
        "blobs": {
            name: {
                "length": len(envelope), "sha256": sha256_hex(envelope),
                "salt_hex": envelope[8:16].hex(), "ciphertext_length": len(envelope) - 16,
            }
            for name, envelope in blobs.items()
        },
        "declared_crypto": {
            "cipher": "AES-256-CBC", "password_to_key": "OpenSSL EVP_BytesToKey",
            "kdf_digests": ["md5", "sha256"], "padding": "strict PKCS#7",
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
        },
        "declared_acceptance": {
            "aes": "readable text or exact parser/format only", "padding_alone": False,
            "forbidden_evidence": ["English score", "expected padding length", "target-derived fitting"],
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
        "manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"],
        "decoded_answer_records": manifest["source"]["decoded_answer_records"],
        "seal_sha256": sha256_hex(encoded),
    }, indent=2))


if __name__ == "__main__":
    main()
