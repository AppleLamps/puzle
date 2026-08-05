"""Evaluate sealed sum-list transpositions, including direct route bytes."""

from __future__ import annotations

import base64
import hashlib
import json

from .salphaseion_blind_eval import _formats, _readable, evaluate
from .salphaseion_preregister_v29 import MANIFEST_PATH, RESULT_PATH, SEAL_PATH


def main():
    aes = evaluate(MANIFEST_PATH, SEAL_PATH, RESULT_PATH)
    manifest = json.loads(MANIFEST_PATH.read_bytes())
    unique = {}
    for candidate in manifest["candidates"]:
        unique.setdefault(candidate["preimage_hex"], candidate["provenance"])
    direct = []
    for value_hex, provenance in unique.items():
        value = bytes.fromhex(value_hex)
        readable, metrics = _readable(value)
        formats = _formats(value)
        if readable or formats:
            direct.append({"sha256": hashlib.sha256(value).hexdigest(), "base64": base64.b64encode(value).decode("ascii"), "provenance": provenance, "readable": readable, "metrics": metrics, "formats": formats})
    aes["unique_preimage_count"] = len(unique)
    aes["accepted_direct_count"] = len(direct)
    aes["accepted_direct"] = direct
    aes["status"] = "ACCEPTED" if direct or aes["accepted"] or aes["cross_blob"] else "NO_ACCEPTED_RESULT"
    RESULT_PATH.write_text(json.dumps(aes, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"manifest_sha256": aes["manifest_sha256"], "unique_preimage_count": len(unique), "attempts": aes["attempts"], "strict_padding_hit_count": aes["strict_padding_hit_count"], "accepted_direct_count": len(direct), "accepted_single_blob_count": aes["accepted_single_blob_count"], "accepted_cross_blob_rule_count": aes["accepted_cross_blob_rule_count"], "status": aes["status"]}, indent=2))


if __name__ == "__main__": main()
