"""Seal whole-plaintext SHA-answer-too validation for Lo Shu v27."""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v27 import MANIFEST_PATH as INPUT_PATH, SEAL_PATH as INPUT_SEAL
from .salphaseion_raw import sha256_hex

MANIFEST_PATH = ROOT / "salphaseion_cross_stage_preregistered_v3.json"
SEAL_PATH = ROOT / "salphaseion_cross_stage_preregistered_v3.sha256"
RESULT_PATH = ROOT / "salphaseion_cross_stage_results_v3.json"


def main() -> None:
    encoded_input = INPUT_PATH.read_bytes()
    input_hash = sha256_hex(encoded_input)
    if INPUT_SEAL.read_text(encoding="ascii").strip() != input_hash:
        raise ValueError("v27 seal mismatch")
    source = json.loads(encoded_input)
    manifest = {
        "schema": "salphaseion-cross-stage-preregistration-v3-lo-shu", "status": "SEALED_BEFORE_DECRYPTION",
        "inputs": [{"path": INPUT_PATH.name, "sha256": input_hash, "candidate_count": source["candidate_count"]}],
        "total_candidate_records": source["candidate_count"], "blobs": source["blobs"],
        "stage_one": {"cipher": "AES-256-CBC", "kdf_digests": ["md5", "sha256"], "gate": "strict PKCS#7; carry every hit without inspection"},
        "stage_two": {"source": "entire unmodified stage-one plaintext", "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"], "target_scope": "each other independently salted blob", "kdf_digests": ["md5", "sha256"]},
        "declared_acceptance": {"padding_alone": False, "required": "readable text or exact parser/checksum format", "forbidden": ["splitting plaintext", "expected padding length", "Half/Better Half", "target point", "community hashes"]},
    }
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded); SEAL_PATH.write_text(hashlib.sha256(encoded).hexdigest() + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "total_candidate_records": manifest["total_candidate_records"], "seal_sha256": hashlib.sha256(encoded).hexdigest()}, indent=2))


if __name__ == "__main__": main()
