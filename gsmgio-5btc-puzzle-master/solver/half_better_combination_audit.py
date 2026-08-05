"""Exact point-gated combinations of the Half and Better Half scalars."""

from __future__ import annotations

import hashlib
import hmac
import json

from coincurve import PrivateKey

from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "half_better_combination_audit.json"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")


def _sha(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def run() -> dict[str, object]:
    cosmic = reconstruct(extract_all(), derive_tokens()).cosmic_decryption.plaintext
    matrix = analyze(cosmic)
    half_bytes = matrix.half
    better_bytes = matrix.better_half
    half = int.from_bytes(half_bytes, "big")
    better = int.from_bytes(better_bytes, "big")

    shared_scalar = half * better % N
    shared_public = PrivateKey(shared_scalar.to_bytes(32, "big")).public_key
    shared_compressed = shared_public.format(compressed=True)
    shared_uncompressed = shared_public.format(compressed=False)

    candidates = {
        "half+better": half + better,
        "half-better": half - better,
        "better-half": better - half,
        "half*better": shared_scalar,
        "half/better": half * pow(better, -1, N),
        "better/half": better * pow(half, -1, N),
        "half XOR better": half ^ better,
        "SHA256(half||better)": int.from_bytes(_sha(half_bytes + better_bytes), "big"),
        "SHA256(better||half)": int.from_bytes(_sha(better_bytes + half_bytes), "big"),
        "SHA256(SHA256(half||better))": int.from_bytes(_sha(_sha(half_bytes + better_bytes)), "big"),
        "SHA256(SHA256(better||half))": int.from_bytes(_sha(_sha(better_bytes + half_bytes)), "big"),
        "HMAC-SHA256(key=half,msg=better)": int.from_bytes(hmac.new(half_bytes, better_bytes, hashlib.sha256).digest(), "big"),
        "HMAC-SHA256(key=better,msg=half)": int.from_bytes(hmac.new(better_bytes, half_bytes, hashlib.sha256).digest(), "big"),
        "ECDH-x": int.from_bytes(shared_uncompressed[1:33], "big"),
        "SHA256(ECDH-compressed)": int.from_bytes(_sha(shared_compressed), "big"),
        "SHA256(ECDH-uncompressed)": int.from_bytes(_sha(shared_uncompressed), "big"),
    }

    records: list[dict[str, object]] = []
    matches: list[dict[str, object]] = []
    for derivation, value in candidates.items():
        scalar = value % N
        if not scalar:
            records.append({"derivation": derivation, "zero": True, "target": False})
            continue
        public = PrivateKey(scalar.to_bytes(32, "big")).public_key
        point_match = public.format(compressed=True) == TARGET_COMPRESSED
        address = base58check(b"\0" + hash160(public.format(compressed=False)))
        record = {
            "derivation": derivation,
            "candidate_sha256": hashlib.sha256(scalar.to_bytes(32, "big")).hexdigest(),
            "point_match": point_match,
            "address_match": address == TARGET_ADDRESS,
        }
        records.append(record)
        if point_match and address == TARGET_ADDRESS:
            matches.append({
                "derivation": derivation,
                "private_hex": f"{scalar:064x}",
                "address": address,
            })

    result = {
        "schema": "half-better-direct-combination-audit-v1",
        "source": {
            "cosmic_sha256": hashlib.sha256(cosmic).hexdigest(),
            "half_sha256": hashlib.sha256(half_bytes).hexdigest(),
            "better_half_sha256": hashlib.sha256(better_bytes).hexdigest(),
        },
        "candidate_count": len(records),
        "records": records,
        "matches": matches,
        "status": "MATCH" if matches else "NO_MATCH",
        "scope": "Only the listed direct two-share arithmetic, hash, HMAC, and ECDH-derived constructions are covered.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"],
        "candidate_count": output["candidate_count"],
        "matches": output["matches"],
    }, indent=2))
