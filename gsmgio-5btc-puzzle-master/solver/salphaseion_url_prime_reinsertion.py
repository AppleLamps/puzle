"""Seal and evaluate literal URL-character reinsertion at S91 prime slots.

This experiment is intentionally narrow.  The authenticated first-grid spiral
has 24 characters and there are exactly 24 one-based primes through 91.  The
Architect plaintext later says to return to the source codes and to perform
``REINSERTING THE PRIME BASICS``.  Earlier round v14 inserted only the URL
characters' least-significant bits; this round tests the characters themselves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math

from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion_blind_eval import _formats, _readable
from .salphaseion_raw import extract_raw, sha256_hex
from .secp256k1_verify import p2pkh_address


MANIFEST_PATH = ROOT / "url_prime_reinsertion_preregistered.json"
SEAL_PATH = ROOT / "url_prime_reinsertion_preregistered.sha256"
RESULT_PATH = ROOT / "url_prime_reinsertion_results.json"
SPIRAL_URL = b"gsmg.io/theseedisplanted"
TARGET_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"


def _primes(limit: int) -> list[int]:
    return [
        value
        for value in range(2, limit + 1)
        if all(value % divisor for divisor in range(2, math.isqrt(value) + 1))
    ]


def _layouts(s91: bytes) -> dict[str, tuple[bytes, bytes]]:
    primes = set(_primes(91))
    if len(s91) != 91 or len(SPIRAL_URL) != len(primes) != 24:
        raise ValueError("source cardinalities changed")

    url_iter = iter(SPIRAL_URL)
    replaced = bytes(
        next(url_iter) if position in primes else symbol
        for position, symbol in enumerate(s91, 1)
    )

    url_iter = iter(SPIRAL_URL)
    source_iter = iter(s91[:67])
    filled = bytes(
        next(url_iter) if position in primes else next(source_iter)
        for position in range(1, 92)
    )
    return {
        "replace-existing-prime-symbols": (
            replaced,
            bytes(symbol for position, symbol in enumerate(s91, 1) if position in primes),
        ),
        "fill-nonprimes-from-prefix": (filled, s91[67:]),
    }


def _source_records() -> tuple[bytes, dict[str, tuple[bytes, bytes]]]:
    s91 = extract_raw().s91.encode("ascii")
    return s91, _layouts(s91)


def build_manifest() -> dict[str, object]:
    s91, layouts = _source_records()
    extracted = extract_all()
    candidates: list[dict[str, object]] = []
    for layout_name, (preimage, residue) in layouts.items():
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"urlprime{len(candidates):02d}",
                "layout": layout_name,
                "preimage_hex": preimage.hex(),
                "preimage_sha256": sha256_hex(preimage),
                "residue_hex": residue.hex(),
                "residue_sha256": sha256_hex(residue),
                "password_expansion": expansion,
                "password_hex": password.hex(),
                "password_sha256": sha256_hex(password),
            })
    blobs = {
        "salphaseion-short": extracted.chain1_envelope,
        "phase32-small": extracted.chain2_envelope,
        "cosmic-duality": extracted.cosmic_envelope,
    }
    return {
        "schema": "salphaseion-url-character-prime-reinsertion-v1",
        "status": "SEALED_BEFORE_DECRYPTION",
        "source": {
            "s91_sha256": sha256_hex(s91),
            "spiral_url": SPIRAL_URL.decode("ascii"),
            "spiral_url_length": len(SPIRAL_URL),
            "prime_positions_one_based": _primes(91),
            "architect_instruction": "RETURN TO THE SOURCE CODES ... REINSERTING THE PRIME BASICS",
        },
        "candidate_family": {
            "layouts": list(layouts),
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
            "kdf_digests": ["md5", "sha256"],
            "excluded": ["reversal", "case changes", "extra separators", "post-hoc slicing"],
        },
        "blobs": {
            name: {"length": len(blob), "sha256": sha256_hex(blob)}
            for name, blob in blobs.items()
        },
        "candidates": candidates,
    }


def prepare() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({
        "manifest": str(MANIFEST_PATH),
        "candidate_count": len(manifest["candidates"]),
        "seal_sha256": sha256_hex(encoded),
    }, indent=2))


def run() -> None:
    encoded = MANIFEST_PATH.read_bytes()
    seal = SEAL_PATH.read_text(encoding="ascii").strip()
    if sha256_hex(encoded) != seal:
        raise ValueError("manifest seal mismatch")
    manifest = json.loads(encoded)
    if manifest["status"] != "SEALED_BEFORE_DECRYPTION":
        raise ValueError("manifest is not sealed")

    extracted = extract_all()
    blobs = {
        "salphaseion-short": extracted.chain1_envelope,
        "phase32-small": extracted.chain2_envelope,
        "cosmic-duality": extracted.cosmic_envelope,
    }
    for name, blob in blobs.items():
        if sha256_hex(blob) != manifest["blobs"][name]["sha256"]:
            raise ValueError(f"sealed source changed: {name}")

    padding_hits: list[dict[str, object]] = []
    accepted: list[dict[str, object]] = []
    target_matches: list[dict[str, object]] = []
    attempts = 0
    for candidate in manifest["candidates"]:
        password = bytes.fromhex(candidate["password_hex"])
        if len(password) == 32 and 0 < int.from_bytes(password, "big"):
            addresses = {
                "uncompressed": p2pkh_address(password, compressed=False),
                "compressed": p2pkh_address(password, compressed=True),
            }
            if TARGET_ADDRESS in addresses.values():
                target_matches.append({"candidate_id": candidate["candidate_id"], "addresses": addresses})
        for digest in manifest["candidate_family"]["kdf_digests"]:
            for blob_name, envelope in blobs.items():
                attempts += 1
                try:
                    decrypted = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
                except ValueError:
                    continue
                readable, metrics = _readable(decrypted.plaintext)
                formats = _formats(decrypted.plaintext)
                record = {
                    "candidate_id": candidate["candidate_id"],
                    "layout": candidate["layout"],
                    "password_expansion": candidate["password_expansion"],
                    "kdf_digest": digest,
                    "blob": blob_name,
                    "plaintext_length": len(decrypted.plaintext),
                    "plaintext_sha256": sha256_hex(decrypted.plaintext),
                    "padding_length": decrypted.padding_length,
                    "readable": readable,
                    "metrics": metrics,
                    "formats": formats,
                }
                padding_hits.append(record)
                if readable or formats:
                    accepted.append(record)

    result = {
        "schema": "salphaseion-url-character-prime-reinsertion-results-v1",
        "manifest_sha256": seal,
        "attempts": attempts,
        "padding_hits": padding_hits,
        "accepted": accepted,
        "target_matches": target_matches,
        "status": "ACCEPTED" if accepted or target_matches else "NO_ACCEPTED_RESULT",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "manifest_sha256": seal,
        "attempts": attempts,
        "strict_padding_hits": len(padding_hits),
        "accepted": len(accepted),
        "target_matches": len(target_matches),
        "status": result["status"],
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "run"))
    arguments = parser.parse_args()
    if arguments.mode == "prepare":
        prepare()
    else:
        run()


if __name__ == "__main__":
    main()
