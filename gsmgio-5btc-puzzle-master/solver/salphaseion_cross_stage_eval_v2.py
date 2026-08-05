"""Evaluate sealed whole-plaintext cross-stage v23-v26 rule."""

from __future__ import annotations

import base64
import hashlib
import json

from .extract import extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion_blind_eval import _formats, _readable
from .salphaseion_cross_stage_preregister_v2 import MANIFEST_PATH, RESULT_PATH, SEAL_PATH


def evaluate() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    seal = SEAL_PATH.read_text(encoding="ascii").strip()
    if hashlib.sha256(encoded).hexdigest() != seal:
        raise ValueError("cross-stage manifest seal mismatch")
    rule = json.loads(encoded)
    blobs = {"salphaseion-short": extract_all().chain1_envelope, "phase32-small": extract_all().chain2_envelope, "cosmic-duality": extract_all().cosmic_envelope}
    stage_one_attempts = stage_one_padding_hits = stage_two_attempts = 0
    stage_two_padding = []
    accepted = []
    for input_record in rule["inputs"]:
        manifest_bytes = MANIFEST_PATH.parent.joinpath(input_record["path"]).read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != input_record["sha256"]:
            raise ValueError("input manifest changed")
        manifest = json.loads(manifest_bytes)
        for candidate in manifest["candidates"]:
            password = bytes.fromhex(candidate["password_hex"])
            for first_digest in rule["stage_one"]["kdf_digests"]:
                for first_blob, first_envelope in blobs.items():
                    stage_one_attempts += 1
                    try:
                        first = decrypt_salted_aes256_cbc(first_envelope, password, digest=first_digest)
                    except ValueError:
                        continue
                    stage_one_padding_hits += 1
                    whole = first.plaintext
                    expansions = (("raw", whole), ("sha256-lowerhex", hashlib.sha256(whole).hexdigest().encode("ascii")), ("sha256-raw-digest", hashlib.sha256(whole).digest()))
                    for expansion, next_password in expansions:
                        for second_digest in rule["stage_two"]["kdf_digests"]:
                            for second_blob, second_envelope in blobs.items():
                                if second_blob == first_blob:
                                    continue
                                stage_two_attempts += 1
                                try:
                                    second = decrypt_salted_aes256_cbc(second_envelope, next_password, digest=second_digest)
                                except ValueError:
                                    continue
                                readable, metrics = _readable(second.plaintext)
                                formats = _formats(second.plaintext)
                                record = {"input_manifest": input_record["path"], "candidate_id": candidate["candidate_id"], "stage_one_blob": first_blob, "stage_one_kdf": first_digest, "stage_one_plaintext_sha256": hashlib.sha256(whole).hexdigest(), "stage_two_expansion": expansion, "stage_two_blob": second_blob, "stage_two_kdf": second_digest, "stage_two_plaintext_sha256": hashlib.sha256(second.plaintext).hexdigest(), "readable_text": readable, "text_metrics": metrics, "formats": formats}
                                stage_two_padding.append(record)
                                if readable or formats:
                                    accepted_record = dict(record)
                                    accepted_record["stage_two_plaintext_base64"] = base64.b64encode(second.plaintext).decode("ascii")
                                    accepted.append(accepted_record)
    result = {"schema": "salphaseion-cross-stage-results-v2-source-layout", "rule_manifest_sha256": seal, "stage_one_attempts": stage_one_attempts, "stage_one_padding_hits": stage_one_padding_hits, "stage_two_attempts": stage_two_attempts, "stage_two_padding_hits": len(stage_two_padding), "accepted_count": len(accepted), "status": "ACCEPTED" if accepted else "NO_ACCEPTED_CROSS_STAGE_RESULT", "accepted": accepted, "stage_two_padding_without_acceptance": stage_two_padding}
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    result = evaluate()
    print(json.dumps({key: result[key] for key in ("rule_manifest_sha256", "stage_one_attempts", "stage_one_padding_hits", "stage_two_attempts", "stage_two_padding_hits", "accepted_count", "status")}, indent=2))
