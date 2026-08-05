"""Evaluate the sealed Architect-keyed completed-matrix sum candidates."""

from __future__ import annotations

import json

from .salphaseion_blind_eval import evaluate
from .salphaseion_preregister_v30 import MANIFEST_PATH, RESULT_PATH, SEAL_PATH


def main():
    result = evaluate(MANIFEST_PATH, SEAL_PATH, RESULT_PATH)
    print(json.dumps({key: result[key] for key in (
        "manifest_sha256", "attempts", "strict_padding_hit_count",
        "accepted_single_blob_count", "accepted_cross_blob_rule_count", "status",
    )}, indent=2))


if __name__ == "__main__":
    main()
