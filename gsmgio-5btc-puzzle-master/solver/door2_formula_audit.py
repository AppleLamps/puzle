"""Audit the public Door-2/LCP7 formula under explicit 32-byte encodings."""

from __future__ import annotations

import hashlib
import json

from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .frontier_experiment import TARGET_X, TARGET_Y, _target_match
from .salphaseion import derive_tokens
from .secp256k1_verify import N, p2pkh_address, scalar_multiply


RESULT_PATH = ROOT / "door2_formula_audit.json"
CLAIM_TEXT = "M3DGNJTGMZTCMZTG"
TARGET_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
CLAIM_URL = "https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/92#issuecomment-4944877522"


def _xor3(first: bytes, second: bytes, third: bytes) -> bytes:
    return bytes(a ^ b ^ c for a, b, c in zip(first, second, third))


def _common_prefix_length(left: str, right: str) -> int:
    return next((index for index, pair in enumerate(zip(left, right)) if pair[0] != pair[1]), min(len(left), len(right)))


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    matrix = analyze(chains.cosmic_decryption.plaintext)
    raw = CLAIM_TEXT.encode("ascii")
    encodings = {
        "literal_ascii_hex_lower_text": raw.hex().encode("ascii"),
        "literal_ascii_hex_upper_text": raw.hex().upper().encode("ascii"),
        "ascii_repeated_twice": raw * 2,
        "ascii_left_zero_padded": raw.rjust(32, b"\0"),
        "ascii_right_zero_padded": raw.ljust(32, b"\0"),
        "sha256_ascii": hashlib.sha256(raw).digest(),
    }
    if any(len(value) != 32 for value in encodings.values()):
        raise AssertionError("every audited encoding must be exactly 32 bytes")

    target_x_hex = f"{TARGET_X:064x}"
    results: list[dict[str, object]] = []
    for label, encoded in encodings.items():
        candidate_bytes = _xor3(encoded, matrix.half, matrix.better_half)
        candidate = int.from_bytes(candidate_bytes, "big") % N
        if not candidate:
            results.append({"encoding": label, "encoded_hex": encoded.hex(), "candidate_zero_mod_n": True})
            continue
        private_key = candidate.to_bytes(32, "big")
        x, y = scalar_multiply(candidate)
        x_hex = f"{x:064x}"
        addresses = {
            "uncompressed": p2pkh_address(private_key, False),
            "compressed": p2pkh_address(private_key, True),
        }
        results.append(
            {
                "encoding": label,
                "encoded_hex": encoded.hex(),
                "private_hex": private_key.hex(),
                "public_x": x_hex,
                "public_y": f"{y:064x}",
                "target_x_hex_nibble_lcp": _common_prefix_length(x_hex, target_x_hex),
                "addresses": addresses,
                "exact_target_point": _target_match(candidate),
                "exact_target_address": TARGET_ADDRESS in addresses.values(),
            }
        )

    literal = next(item for item in results if item["encoding"] == "literal_ascii_hex_lower_text")
    matches = [item for item in results if item.get("exact_target_point") or item.get("exact_target_address")]
    result: dict[str, object] = {
        "status": "MATCH" if matches else "NO_MATCH_IN_EXPLICIT_ENCODINGS",
        "claim_url": CLAIM_URL,
        "claim_text": CLAIM_TEXT,
        "claimed_label": "Door-2 LCP7 = ascii_hex(text) XOR Half XOR Better",
        "lcp_metric_used": "leading equal hexadecimal nibbles of candidate public x and target public x",
        "literal_lowercase_ascii_hex_lcp": literal["target_x_hex_nibble_lcp"],
        "literal_claim_reproduces_lcp7": literal["target_x_hex_nibble_lcp"] == 7,
        "target": {"x": target_x_hex, "y": f"{TARGET_Y:064x}", "address": TARGET_ADDRESS},
        "results": results,
        "matches": matches,
        "scope_note": "The public comment does not define ascii_hex or the LCP comparison field. This refutes LCP7 only under the listed explicit encodings and x-coordinate metric.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
