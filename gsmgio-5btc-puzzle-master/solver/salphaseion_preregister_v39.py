"""Seal the exact 13-column/30-column SalPhaseIon interpretation family."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import re

from .extract import ROOT, extract_all
from .phase32_classical import _vic_decode
from .salphaseion_preregister_v11 import _decrypt_route, _encrypt_route
from .salphaseion_preregister_v12 import _primes
from .salphaseion_preregister_v37 import SPIRAL_TEXT
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v39.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v39.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v39.json"
ARCHITECT_BEFORE_CHOICE = "asyouadequatelyputtheproblemis"


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


def _routes(text: str, key: str) -> dict[str, str]:
    return {
        "source-control": text,
        "column-decrypt-ascending": _decrypt_route(text, key, False),
        "column-encrypt-ascending": _encrypt_route(text, key, False),
    }


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    if len(raw.matrix_marker) != 13 or len(raw.s91) != 7 * 13:
        raise ValueError("13-column key invariant changed")
    if len(ARCHITECT_BEFORE_CHOICE) != 30 or len(raw.s570) != 19 * 30:
        raise ValueError("30-column Architect key invariant changed")

    primes = _primes(91)
    color_bits = "".join(str(ord(character) & 1) for character in SPIRAL_TEXT)
    blue = {prime for prime, bit in zip(primes, color_bits) if bit == "1"}
    yellow = {prime for prime, bit in zip(primes, color_bits) if bit == "0"}
    masks = {
        "none-control": set(),
        "all-primes": set(primes),
        "spiral-blue-primes": blue,
        "spiral-yellow-primes": yellow,
    }
    alphabets = {
        "phase32-control": "FUBCDORA.LETHINGKYMVPS.JQZXW",
        "architect-before-choice": _pad28(ARCHITECT_BEFORE_CHOICE),
        "architect-through-choice": _pad28(ARCHITECT_BEFORE_CHOICE + "choice"),
        "matrixsumlist": _pad28(raw.matrix_marker),
        "yellowblueprimes": _pad28("yellowblueprimes"),
    }
    # 1,4 is authenticated by Phase 3.2.2.  The other two pairs are the
    # decimal digits of the 9th and 15th primes: yellow=9, blue=15.
    escape_pairs = {"phase32-14": ("1", "4"), "yellow-prime-23": ("2", "3"), "blue-prime-47": ("4", "7")}

    index_text = "".join(chr(0x100 + index) for index in range(len(raw.s91)))
    s91_orders = {
        name: [ord(character) - 0x100 for character in routed]
        for name, routed in _routes(index_text, raw.matrix_marker).items()
    }
    s570_routes = _routes(raw.s570, ARCHITECT_BEFORE_CHOICE)
    preimages: dict[bytes, set[str]] = defaultdict(set)
    decoded_records = 0
    invalid_records = 0
    route_records: list[dict[str, object]] = []

    for mask_name, zero_positions in masks.items():
        for key_origin in (0, 1):
            source_values = [(ord(symbol) - 97 + key_origin) % 9 for symbol in raw.s91]
            for key_route_name, order in s91_orders.items():
              for zero_timing in ("before-route", "after-route"):
                if zero_timing == "before-route":
                    masked = [0 if position in zero_positions else value for position, value in enumerate(source_values, 1)]
                    key_values = [masked[index] for index in order]
                else:
                    routed_values = [source_values[index] for index in order]
                    key_values = [0 if position in zero_positions else value for position, value in enumerate(routed_values, 1)]
                grid = [key_values[offset:offset + 13] for offset in range(0, 91, 13)]
                row_sums = [sum(row) % 9 for row in grid]
                column_sums = [sum(grid[row][column] for row in range(7)) % 9 for column in range(13)]
                key_streams = {
                    "routed91": key_values,
                    "row-sums7": row_sums,
                    "column-sums13": column_sums,
                    "matrix-sum-list20": row_sums + column_sums,
                }
                route_records.append({
                    "mask": mask_name,
                    "key_origin": key_origin,
                    "key_route": key_route_name,
                    "zero_timing": zero_timing,
                    "zero_positions_one_based": sorted(zero_positions),
                    "row_sums_mod9": row_sums,
                    "column_sums_mod9": column_sums,
                })
                for payload_origin in (0, 1):
                    for payload_route_name, payload_route in s570_routes.items():
                        payload = [(ord(symbol) - 97 + payload_origin) % 9 for symbol in payload_route]
                        for stream_name, stream in key_streams.items():
                            repeated = [stream[index % len(stream)] for index in range(len(payload))]
                            operations = {
                                "payload-minus-key": [(left - right) % 9 for left, right in zip(payload, repeated)],
                                "key-minus-payload": [(right - left) % 9 for left, right in zip(payload, repeated)],
                                "payload-plus-key": [(left + right) % 9 for left, right in zip(payload, repeated)],
                            }
                            for operation, values in operations.items():
                                digits = "".join(map(str, values))
                                for alphabet_name, alphabet in alphabets.items():
                                    for escapes_name, escapes in escape_pairs.items():
                                        try:
                                            answer = _vic_decode(digits, alphabet, escapes)
                                        except ValueError:
                                            invalid_records += 1
                                            continue
                                        decoded_records += 1
                                        label = (
                                            f"v39/{mask_name}/ko{key_origin}/{key_route_name}/"
                                            f"{zero_timing}/"
                                            f"po{payload_origin}/{payload_route_name}/{stream_name}/"
                                            f"{operation}/{alphabet_name}/{escapes_name}"
                                        )
                                        for form in _answer_forms(answer):
                                            preimages[form].add(label)

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        digest = hashlib.sha256(preimage).digest()
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", digest.hex().encode("ascii")),
            ("sha256-raw-digest", digest),
        ):
            candidates.append({
                "candidate_id": f"v39c{len(candidates):06d}",
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
        "schema": "salphaseion-source-only-preregistration-v39-exact-13x30-keys",
        "status": "SEALED_BEFORE_DECRYPTION",
        "source": {
            "capture_stability": capture_stability(),
            "creator_instruction": "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang",
            "matrix_key": raw.matrix_marker,
            "matrix_key_length": len(raw.matrix_marker),
            "s91_shape": [7, 13],
            "architect_words_before_choice": ARCHITECT_BEFORE_CHOICE,
            "architect_key_length": len(ARCHITECT_BEFORE_CHOICE),
            "s570_shape": [19, 30],
            "prime_positions_one_based": primes,
            "color_bits": color_bits,
            "masks": {name: sorted(values) for name, values in masks.items()},
            "alphabets": alphabets,
            "escape_pairs": {name: list(values) for name, values in escape_pairs.items()},
            "s91_routes": list(s91_orders),
            "s570_routes": list(s570_routes),
            "route_records": route_records,
            "decoded_answer_records": decoded_records,
            "invalid_vic_records": invalid_records,
        },
        "blobs": {
            name: {"length": len(blob), "sha256": sha256_hex(blob), "salt_hex": blob[8:16].hex(), "ciphertext_length": len(blob) - 16}
            for name, blob in blobs.items()
        },
        "declared_crypto": {
            "cipher": "AES-256-CBC",
            "password_to_key": "OpenSSL EVP_BytesToKey",
            "kdf_digests": ["md5", "sha256"],
            "padding": "strict PKCS#7",
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
        },
        "declared_acceptance": {
            "aes": "readable text or exact parser/format only",
            "padding_alone": False,
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
        "manifest": str(MANIFEST_PATH),
        "candidate_count": manifest["candidate_count"],
        "decoded_answer_records": manifest["source"]["decoded_answer_records"],
        "seal_sha256": sha256_hex(encoded),
    }, indent=2))


if __name__ == "__main__":
    main()
