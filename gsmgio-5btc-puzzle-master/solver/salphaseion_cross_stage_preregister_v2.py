"""Seal whole-plaintext SHA-answer-too validation for source-layout v23-v26."""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_cross_stage_preregistered_v2.json"
SEAL_PATH = ROOT / "salphaseion_cross_stage_preregistered_v2.sha256"
RESULT_PATH = ROOT / "salphaseion_cross_stage_results_v2.json"


def build_manifest() -> dict[str, object]:
    inputs = []
    canonical_blobs = None
    for version in range(23, 27):
        path = ROOT / f"salphaseion_preregistered_candidates_v{version}.json"
        encoded = path.read_bytes()
        manifest = json.loads(encoded)
        seal_path = path.with_suffix(".sha256")
        actual = sha256_hex(encoded)
        if manifest.get("status") != "SEALED_BEFORE_DECRYPTION" or seal_path.read_text(encoding="ascii").strip() != actual:
            raise ValueError(f"unsealed input manifest: {path.name}")
        blobs = manifest["blobs"]
        if canonical_blobs is None:
            canonical_blobs = blobs
        elif {name: value["sha256"] for name, value in blobs.items()} != {name: value["sha256"] for name, value in canonical_blobs.items()}:
            raise ValueError("input manifests bind different blobs")
        inputs.append({"path": path.name, "sha256": actual, "candidate_count": manifest["candidate_count"]})
    return {
        "schema": "salphaseion-cross-stage-preregistration-v2-source-layout",
        "status": "SEALED_BEFORE_DECRYPTION",
        "inputs": inputs,
        "total_candidate_records": sum(item["candidate_count"] for item in inputs),
        "blobs": canonical_blobs,
        "stage_one": {"cipher": "AES-256-CBC", "kdf_digests": ["md5", "sha256"], "candidate_scope": "every password record in sealed v23-v26 manifests", "gate": "strict PKCS#7 only; carry forward every hit without inspection"},
        "stage_two": {"source": "entire unmodified stage-one plaintext", "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"], "target_scope": "each other independently salted blob", "kdf_digests": ["md5", "sha256"]},
        "declared_acceptance": {"second_stage_only": True, "padding_alone": False, "required": "readable UTF-8 English-like text or exact parser/checksum format", "forbidden": ["splitting plaintext", "expected padding length", "Half/Better Half", "target point or address", "community plaintext hashes"]},
    }


def main() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(hashlib.sha256(encoded).hexdigest() + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "total_candidate_records": manifest["total_candidate_records"], "seal_sha256": hashlib.sha256(encoded).hexdigest()}, indent=2))


if __name__ == "__main__":
    main()
