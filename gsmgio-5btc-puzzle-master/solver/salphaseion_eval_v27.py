"""Evaluate the sealed v27 Lo Shu construction."""

from __future__ import annotations

import json

from .salphaseion_blind_eval import evaluate
from .salphaseion_preregister_v27 import MANIFEST_PATH, RESULT_PATH, SEAL_PATH


if __name__ == "__main__":
    result = evaluate(MANIFEST_PATH, SEAL_PATH, RESULT_PATH)
    print(json.dumps({key: result[key] for key in ("manifest_sha256", "attempts", "strict_padding_hit_count", "accepted_single_blob_count", "accepted_cross_blob_rule_count", "status")}, indent=2))
