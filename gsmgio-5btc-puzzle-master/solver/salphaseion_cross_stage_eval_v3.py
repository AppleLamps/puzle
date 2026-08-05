"""Evaluate sealed v27 whole-plaintext cross stage."""

from __future__ import annotations

import base64
import hashlib
import json

from .extract import extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion_blind_eval import _formats, _readable
from .salphaseion_cross_stage_preregister_v3 import MANIFEST_PATH, RESULT_PATH, SEAL_PATH


def evaluate():
    encoded = MANIFEST_PATH.read_bytes(); seal = SEAL_PATH.read_text(encoding="ascii").strip()
    if hashlib.sha256(encoded).hexdigest() != seal: raise ValueError("seal mismatch")
    rule = json.loads(encoded); extracted = extract_all()
    blobs = {"salphaseion-short": extracted.chain1_envelope, "phase32-small": extracted.chain2_envelope, "cosmic-duality": extracted.cosmic_envelope}
    a1 = h1 = a2 = 0; pad2 = []; accepted = []
    for item in rule["inputs"]:
        raw = MANIFEST_PATH.parent.joinpath(item["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != item["sha256"]: raise ValueError("input changed")
        for candidate in json.loads(raw)["candidates"]:
            password = bytes.fromhex(candidate["password_hex"])
            for d1 in rule["stage_one"]["kdf_digests"]:
                for b1, envelope1 in blobs.items():
                    a1 += 1
                    try: first = decrypt_salted_aes256_cbc(envelope1, password, digest=d1)
                    except ValueError: continue
                    h1 += 1; whole = first.plaintext
                    for expansion, next_password in (("raw", whole), ("sha256-lowerhex", hashlib.sha256(whole).hexdigest().encode()), ("sha256-raw-digest", hashlib.sha256(whole).digest())):
                        for d2 in rule["stage_two"]["kdf_digests"]:
                            for b2, envelope2 in blobs.items():
                                if b2 == b1: continue
                                a2 += 1
                                try: second = decrypt_salted_aes256_cbc(envelope2, next_password, digest=d2)
                                except ValueError: continue
                                readable, metrics = _readable(second.plaintext); formats = _formats(second.plaintext)
                                record = {"candidate_id": candidate["candidate_id"], "stage_one_blob": b1, "stage_one_kdf": d1, "stage_one_plaintext_sha256": hashlib.sha256(whole).hexdigest(), "stage_two_expansion": expansion, "stage_two_blob": b2, "stage_two_kdf": d2, "stage_two_plaintext_sha256": hashlib.sha256(second.plaintext).hexdigest(), "readable": readable, "metrics": metrics, "formats": formats}
                                pad2.append(record)
                                if readable or formats:
                                    record["plaintext_base64"] = base64.b64encode(second.plaintext).decode(); accepted.append(record)
    result = {"schema": "salphaseion-cross-stage-results-v3-lo-shu", "rule_manifest_sha256": seal, "stage_one_attempts": a1, "stage_one_padding_hits": h1, "stage_two_attempts": a2, "stage_two_padding_hits": len(pad2), "accepted_count": len(accepted), "status": "ACCEPTED" if accepted else "NO_ACCEPTED_CROSS_STAGE_RESULT", "accepted": accepted, "stage_two_padding_without_acceptance": pad2}
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"); return result


if __name__ == "__main__":
    result=evaluate(); print(json.dumps({k:result[k] for k in ("rule_manifest_sha256","stage_one_attempts","stage_one_padding_hits","stage_two_attempts","stage_two_padding_hits","accepted_count","status")},indent=2))
