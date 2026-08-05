"""Seal the SHA-256 raw-digest representation extension.

The page says SHA-256 but does not mechanically distinguish the 32 digest
bytes from their 64-character lowercase hexadecimal display.  v1/v2 registered
the latter; this final representation-only round registers the former without
adding any new semantic preimage.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister import MANIFEST_PATH as V1_MANIFEST, SEAL_PATH as V1_SEAL
from .salphaseion_preregister_v2 import MANIFEST_PATH as V2_MANIFEST, SEAL_PATH as V2_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v3.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v3.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v3.json"


def build_manifest() -> dict[str, object]:
    source_manifests = [json.loads(V1_MANIFEST.read_text()), json.loads(V2_MANIFEST.read_text())]
    preimages: dict[bytes, set[str]] = defaultdict(set)
    for round_index, manifest in enumerate(source_manifests, 1):
        for candidate in manifest["candidates"]:
            preimage = bytes.fromhex(candidate["preimage_hex"])
            for provenance in candidate["provenance"]:
                preimages[preimage].add(f"v{round_index}/{provenance}")

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        password = hashlib.sha256(preimage).digest()
        candidates.append({
            "candidate_id": f"v3c{len(candidates):04d}",
            "preimage_hex": preimage.hex(),
            "password_expansion": "sha256-raw-digest",
            "password_hex": password.hex(),
            "password_sha256": sha256_hex(password),
            "provenance": sorted(preimages[preimage]),
        })

    raw = extract_raw()
    extracted = extract_all()
    blobs = {
        "salphaseion-short": extracted.chain1_envelope,
        "phase32-small": extracted.chain2_envelope,
        "cosmic-duality": extracted.cosmic_envelope,
    }
    return {
        "schema": "salphaseion-source-only-preregistration-v3",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_manifest_sha256": {
            "v1": V1_SEAL.read_text(encoding="ascii").strip(),
            "v2": V2_SEAL.read_text(encoding="ascii").strip(),
        },
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "representation_rule": "SHA256 preimage digest bytes, exactly 32 bytes",
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
            "password_expansions": ["sha256-raw-digest"],
        },
        "declared_acceptance": {
            "inherits_v1_rules_verbatim": True,
            "padding_alone": False,
            "forbidden_evidence": [
                "expected padding length", "plus/minus grammar", "Half/Better Half",
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
