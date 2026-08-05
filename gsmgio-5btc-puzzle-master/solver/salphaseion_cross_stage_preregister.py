"""Seal a whole-plaintext, SHA-answer-too cross-blob validation rule."""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_cross_stage_preregistered.json"
SEAL_PATH = ROOT / "salphaseion_cross_stage_preregistered.sha256"
RESULT_PATH = ROOT / "salphaseion_cross_stage_results.json"


def _candidate_manifest_paths():
    yield ROOT / "salphaseion_preregistered_candidates.json"
    for version in range(2, 23):
        yield ROOT / f"salphaseion_preregistered_candidates_v{version}.json"


def build_manifest() -> dict[str, object]:
    inputs: list[dict[str, object]] = []
    canonical_blobs = None
    for path in _candidate_manifest_paths():
        encoded = path.read_bytes()
        manifest = json.loads(encoded)
        if manifest.get("status") != "SEALED_BEFORE_DECRYPTION":
            raise ValueError(f"unsealed input manifest: {path.name}")
        seal_path = path.with_suffix(".sha256")
        expected = seal_path.read_text(encoding="ascii").strip()
        actual = sha256_hex(encoded)
        if actual != expected:
            raise ValueError(f"input manifest seal mismatch: {path.name}")
        blobs = manifest["blobs"]
        if canonical_blobs is None:
            canonical_blobs = blobs
        elif {
            name: value["sha256"] for name, value in blobs.items()
        } != {
            name: value["sha256"] for name, value in canonical_blobs.items()
        }:
            raise ValueError("input manifests do not bind the same blobs")
        inputs.append({
            "path": path.name,
            "seal_path": seal_path.name,
            "sha256": actual,
            "candidate_count": manifest["candidate_count"],
        })

    return {
        "schema": "salphaseion-cross-stage-preregistration-v1",
        "status": "SEALED_BEFORE_DECRYPTION",
        "inputs": inputs,
        "total_candidate_records": sum(int(item["candidate_count"]) for item in inputs),
        "blobs": canonical_blobs,
        "stage_one": {
            "cipher": "AES-256-CBC",
            "kdf_digests": ["md5", "sha256"],
            "candidate_scope": "every password record in sealed v1-v22 manifests",
            "gate": "strict PKCS#7 only; no plaintext inspection or selection",
        },
        "stage_two": {
            "source": "the entire unmodified stage-one plaintext",
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
            "target_scope": "each of the other two independently salted blobs",
            "kdf_digests": ["md5", "sha256"],
        },
        "declared_acceptance": {
            "second_stage_only": True,
            "padding_alone": False,
            "required": "readable UTF-8 English-like text or an exact parser/checksum format",
            "forbidden": [
                "splitting stage-one plaintext into fitted fields",
                "expected padding length",
                "Half/Better Half",
                "target point or address",
                "known community plaintext hashes",
            ],
        },
        "rationale": (
            "mechanically decoded 'shabefanstoo' means SHA256 answer too; this rule can "
            "authenticate an otherwise binary first-stage answer by unlocking a different blob"
        ),
    }


def main() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(hashlib.sha256(encoded).hexdigest() + "\n", encoding="ascii")
    print(json.dumps({
        "manifest": str(MANIFEST_PATH),
        "total_candidate_records": manifest["total_candidate_records"],
        "seal_sha256": hashlib.sha256(encoded).hexdigest(),
    }, indent=2))


if __name__ == "__main__":
    main()
