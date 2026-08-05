from __future__ import annotations

import hashlib
import json

from solver.salphaseion_blind_eval import evaluate
from solver.salphaseion_cross_stage_eval_v2 import evaluate as evaluate_cross_v2
from solver.salphaseion_cross_stage_eval_v3 import evaluate as evaluate_cross_v3
from solver.salphaseion_cross_stage_preregister_v2 import (
    MANIFEST_PATH as CROSS_V2_MANIFEST,
    SEAL_PATH as CROSS_V2_SEAL,
)
from solver.salphaseion_cross_stage_preregister_v3 import (
    MANIFEST_PATH as CROSS_V3_MANIFEST,
    SEAL_PATH as CROSS_V3_SEAL,
)
from solver.salphaseion_preregister_v23 import MANIFEST_PATH as V23_MANIFEST, RESULT_PATH as V23_RESULT, SEAL_PATH as V23_SEAL
from solver.salphaseion_preregister_v24 import MANIFEST_PATH as V24_MANIFEST, RESULT_PATH as V24_RESULT, SEAL_PATH as V24_SEAL
from solver.salphaseion_preregister_v25 import MANIFEST_PATH as V25_MANIFEST, RESULT_PATH as V25_RESULT, SEAL_PATH as V25_SEAL
from solver.salphaseion_preregister_v26 import MANIFEST_PATH as V26_MANIFEST, RESULT_PATH as V26_RESULT, SEAL_PATH as V26_SEAL
from solver.salphaseion_preregister_v27 import MANIFEST_PATH as V27_MANIFEST, RESULT_PATH as V27_RESULT, SEAL_PATH as V27_SEAL


def _assert_seal(path, seal_path) -> str:
    encoded = path.read_bytes()
    seal = seal_path.read_text(encoding="ascii").strip()
    assert hashlib.sha256(encoded).hexdigest() == seal
    return seal


def test_v23_through_v27_source_connections_are_sealed_and_negative() -> None:
    for manifest, seal_path, result_path, candidates, attempts, padding in (
        (V23_MANIFEST, V23_SEAL, V23_RESULT, 402, 2412, 8),
        (V24_MANIFEST, V24_SEAL, V24_RESULT, 2784, 16704, 63),
        (V25_MANIFEST, V25_SEAL, V25_RESULT, 1845, 11070, 39),
        (V26_MANIFEST, V26_SEAL, V26_RESULT, 420, 2520, 9),
        (V27_MANIFEST, V27_SEAL, V27_RESULT, 2304, 13824, 73),
    ):
        seal = _assert_seal(manifest, seal_path)
        assert json.loads(manifest.read_bytes())["candidate_count"] == candidates
        result = evaluate(manifest, seal_path, result_path)
        assert result["manifest_sha256"] == seal
        assert result["attempts"] == attempts
        assert result["strict_padding_hit_count"] == padding
        assert result["accepted"] == []
        assert result["cross_blob"] == []
        assert result["status"] == "NO_ACCEPTED_RESULT"


def test_new_source_connections_fail_whole_plaintext_cross_stage() -> None:
    _assert_seal(CROSS_V2_MANIFEST, CROSS_V2_SEAL)
    v2 = evaluate_cross_v2()
    assert (v2["stage_one_attempts"], v2["stage_one_padding_hits"]) == (32706, 119)
    assert (v2["stage_two_attempts"], v2["stage_two_padding_hits"]) == (1428, 4)
    assert v2["accepted_count"] == 0
    assert v2["status"] == "NO_ACCEPTED_CROSS_STAGE_RESULT"

    _assert_seal(CROSS_V3_MANIFEST, CROSS_V3_SEAL)
    v3 = evaluate_cross_v3()
    assert (v3["stage_one_attempts"], v3["stage_one_padding_hits"]) == (13824, 73)
    assert (v3["stage_two_attempts"], v3["stage_two_padding_hits"]) == (876, 5)
    assert v3["accepted_count"] == 0
    assert v3["status"] == "NO_ACCEPTED_CROSS_STAGE_RESULT"
