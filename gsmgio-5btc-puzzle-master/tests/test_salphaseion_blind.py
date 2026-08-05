from __future__ import annotations

import hashlib
import json

from solver.salphaseion_blind_eval import RESULT_PATH, evaluate, main as run_blind
from solver.salphaseion_cross_stage_eval import evaluate as evaluate_cross_stage
from solver.salphaseion_cross_stage_preregister import (
    MANIFEST_PATH as CROSS_STAGE_MANIFEST_PATH,
    SEAL_PATH as CROSS_STAGE_SEAL_PATH,
)
from solver.salphaseion_preregister import MANIFEST_PATH, SEAL_PATH
from solver.salphaseion_preregister_v2 import (
    MANIFEST_PATH as V2_MANIFEST_PATH,
    RESULT_PATH as V2_RESULT_PATH,
    SEAL_PATH as V2_SEAL_PATH,
)
from solver.salphaseion_preregister_v3 import (
    MANIFEST_PATH as V3_MANIFEST_PATH,
    RESULT_PATH as V3_RESULT_PATH,
    SEAL_PATH as V3_SEAL_PATH,
)
from solver.salphaseion_preregister_v4 import (
    MANIFEST_PATH as V4_MANIFEST_PATH,
    RESULT_PATH as V4_RESULT_PATH,
    SEAL_PATH as V4_SEAL_PATH,
)
from solver.salphaseion_preregister_v5 import (
    MANIFEST_PATH as V5_MANIFEST_PATH,
    RESULT_PATH as V5_RESULT_PATH,
    SEAL_PATH as V5_SEAL_PATH,
)
from solver.salphaseion_preregister_v6 import (
    MANIFEST_PATH as V6_MANIFEST_PATH,
    RESULT_PATH as V6_RESULT_PATH,
    SEAL_PATH as V6_SEAL_PATH,
)
from solver.salphaseion_preregister_v7 import (
    MANIFEST_PATH as V7_MANIFEST_PATH,
    RESULT_PATH as V7_RESULT_PATH,
    SEAL_PATH as V7_SEAL_PATH,
)
from solver.salphaseion_preregister_v8 import (
    MANIFEST_PATH as V8_MANIFEST_PATH,
    RESULT_PATH as V8_RESULT_PATH,
    SEAL_PATH as V8_SEAL_PATH,
)
from solver.salphaseion_preregister_v9 import (
    MANIFEST_PATH as V9_MANIFEST_PATH,
    RESULT_PATH as V9_RESULT_PATH,
    SEAL_PATH as V9_SEAL_PATH,
)
from solver.salphaseion_preregister_v10 import (
    MANIFEST_PATH as V10_MANIFEST_PATH,
    RESULT_PATH as V10_RESULT_PATH,
    SEAL_PATH as V10_SEAL_PATH,
)
from solver.salphaseion_preregister_v11 import (
    MANIFEST_PATH as V11_MANIFEST_PATH,
    RESULT_PATH as V11_RESULT_PATH,
    SEAL_PATH as V11_SEAL_PATH,
)
from solver.salphaseion_preregister_v12 import (
    MANIFEST_PATH as V12_MANIFEST_PATH,
    RESULT_PATH as V12_RESULT_PATH,
    SEAL_PATH as V12_SEAL_PATH,
)
from solver.salphaseion_preregister_v13 import (
    MANIFEST_PATH as V13_MANIFEST_PATH,
    RESULT_PATH as V13_RESULT_PATH,
    SEAL_PATH as V13_SEAL_PATH,
)
from solver.salphaseion_preregister_v14 import (
    MANIFEST_PATH as V14_MANIFEST_PATH,
    RESULT_PATH as V14_RESULT_PATH,
    SEAL_PATH as V14_SEAL_PATH,
)
from solver.salphaseion_preregister_v15 import (
    MANIFEST_PATH as V15_MANIFEST_PATH,
    RESULT_PATH as V15_RESULT_PATH,
    SEAL_PATH as V15_SEAL_PATH,
)
from solver.salphaseion_preregister_v16 import (
    MANIFEST_PATH as V16_MANIFEST_PATH,
    RESULT_PATH as V16_RESULT_PATH,
    SEAL_PATH as V16_SEAL_PATH,
)
from solver.salphaseion_preregister_v17 import (
    MANIFEST_PATH as V17_MANIFEST_PATH,
    RESULT_PATH as V17_RESULT_PATH,
    SEAL_PATH as V17_SEAL_PATH,
)
from solver.salphaseion_preregister_v18 import (
    MANIFEST_PATH as V18_MANIFEST_PATH,
    RESULT_PATH as V18_RESULT_PATH,
    SEAL_PATH as V18_SEAL_PATH,
)
from solver.salphaseion_preregister_v19 import (
    MANIFEST_PATH as V19_MANIFEST_PATH,
    RESULT_PATH as V19_RESULT_PATH,
    SEAL_PATH as V19_SEAL_PATH,
)
from solver.salphaseion_preregister_v20 import (
    MANIFEST_PATH as V20_MANIFEST_PATH,
    RESULT_PATH as V20_RESULT_PATH,
    SEAL_PATH as V20_SEAL_PATH,
)
from solver.salphaseion_preregister_v21 import (
    MANIFEST_PATH as V21_MANIFEST_PATH,
    RESULT_PATH as V21_RESULT_PATH,
    SEAL_PATH as V21_SEAL_PATH,
)
from solver.salphaseion_preregister_v22 import (
    MANIFEST_PATH as V22_MANIFEST_PATH,
    RESULT_PATH as V22_RESULT_PATH,
    SEAL_PATH as V22_SEAL_PATH,
)
from solver.salphaseion_raw import capture_stability, extract_raw


def test_raw_archive_extraction_and_stability() -> None:
    raw = extract_raw()
    assert hashlib.sha256(raw.textarea1).hexdigest() == "d39d10b1e1902d2620eb19ebcad4215e23c048de639466cca9a26bdc9303330c"
    assert hashlib.sha256(raw.textarea2).hexdigest() == "5e636bd7f1670a39666c0820f0df3fe9b4962d96f29d40156699dc947cce470b"
    assert hashlib.sha256(raw.short_envelope).hexdigest() == "9e2831e1b34b5f34796df47ccaf6530d48d371c61a6bff84d60db1064fa7a258"
    assert raw.short_envelope[8:16].hex() == "3ab585348552415d"
    assert [
        raw.matrix_marker,
        raw.lastwords_marker,
        raw.password_marker,
        raw.sha_first_hint,
        raw.enter_marker,
        raw.sha_answer_too,
    ] == [
        "matrixsumlist",
        "lastwordsbeforearchichoice",
        "thispassword",
        "shabefourfirsthintisyourlastcommand",
        "enter",
        "shabefanstoo",
    ]
    records = capture_stability()
    assert len(records) == 5
    assert len({record["textarea1_sha256"] for record in records}) == 1
    assert len({record["textarea2_sha256"] for record in records}) == 1


def test_sealed_blind_result_has_no_accepted_candidate() -> None:
    encoded = MANIFEST_PATH.read_bytes()
    seal = SEAL_PATH.read_text(encoding="ascii").strip()
    assert hashlib.sha256(encoded).hexdigest() == seal
    manifest = json.loads(encoded)
    assert manifest["candidate_count"] == 376
    assert manifest["source"]["field_order"] == [
        "matrixsumlist",
        "lastwordsbeforearchichoice",
        "thispassword",
        "shabefourfirsthintisyourlastcommand",
        "enter",
        "shabefanstoo",
    ]

    run_blind()
    result = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert result["manifest_sha256"] == seal
    assert result["attempts"] == 2256
    assert result["status"] == "NO_ACCEPTED_RESULT"
    assert result["accepted"] == []
    assert result["cross_blob"] == []


def test_sealed_v2_through_v22_extensions_have_no_accepted_candidate() -> None:
    for manifest_path, seal_path, result_path, candidate_count, attempts in (
        (V2_MANIFEST_PATH, V2_SEAL_PATH, V2_RESULT_PATH, 488, 2928),
        (V3_MANIFEST_PATH, V3_SEAL_PATH, V3_RESULT_PATH, 428, 2568),
        (V4_MANIFEST_PATH, V4_SEAL_PATH, V4_RESULT_PATH, 516, 3096),
        (V5_MANIFEST_PATH, V5_SEAL_PATH, V5_RESULT_PATH, 600, 3600),
        (V6_MANIFEST_PATH, V6_SEAL_PATH, V6_RESULT_PATH, 282, 1692),
        (V7_MANIFEST_PATH, V7_SEAL_PATH, V7_RESULT_PATH, 102, 612),
        (V8_MANIFEST_PATH, V8_SEAL_PATH, V8_RESULT_PATH, 636, 3816),
        (V9_MANIFEST_PATH, V9_SEAL_PATH, V9_RESULT_PATH, 2436, 14616),
        (V10_MANIFEST_PATH, V10_SEAL_PATH, V10_RESULT_PATH, 2967, 17802),
        (V11_MANIFEST_PATH, V11_SEAL_PATH, V11_RESULT_PATH, 1278, 7668),
        (V12_MANIFEST_PATH, V12_SEAL_PATH, V12_RESULT_PATH, 18, 108),
        (V13_MANIFEST_PATH, V13_SEAL_PATH, V13_RESULT_PATH, 228, 1368),
        (V14_MANIFEST_PATH, V14_SEAL_PATH, V14_RESULT_PATH, 123, 738),
        (V15_MANIFEST_PATH, V15_SEAL_PATH, V15_RESULT_PATH, 192, 1152),
        (V16_MANIFEST_PATH, V16_SEAL_PATH, V16_RESULT_PATH, 123, 738),
        (V17_MANIFEST_PATH, V17_SEAL_PATH, V17_RESULT_PATH, 120, 720),
        (V18_MANIFEST_PATH, V18_SEAL_PATH, V18_RESULT_PATH, 450, 2700),
        (V19_MANIFEST_PATH, V19_SEAL_PATH, V19_RESULT_PATH, 123, 738),
        (V20_MANIFEST_PATH, V20_SEAL_PATH, V20_RESULT_PATH, 72, 432),
        (V21_MANIFEST_PATH, V21_SEAL_PATH, V21_RESULT_PATH, 144, 864),
        (V22_MANIFEST_PATH, V22_SEAL_PATH, V22_RESULT_PATH, 162, 972),
    ):
        encoded = manifest_path.read_bytes()
        seal = seal_path.read_text(encoding="ascii").strip()
        assert hashlib.sha256(encoded).hexdigest() == seal
        assert json.loads(encoded)["candidate_count"] == candidate_count
        result = evaluate(manifest_path, seal_path, result_path)
        assert result["manifest_sha256"] == seal
        assert result["attempts"] == attempts
        assert result["status"] == "NO_ACCEPTED_RESULT"
        assert result["accepted"] == []
        assert result["cross_blob"] == []


def test_sealed_whole_plaintext_cross_stage_rule_has_no_accepted_result() -> None:
    encoded = CROSS_STAGE_MANIFEST_PATH.read_bytes()
    seal = CROSS_STAGE_SEAL_PATH.read_text(encoding="ascii").strip()
    assert hashlib.sha256(encoded).hexdigest() == seal
    assert json.loads(encoded)["total_candidate_records"] == 11864

    result = evaluate_cross_stage()
    assert result["rule_manifest_sha256"] == seal
    assert result["stage_one_attempts"] == 71184
    assert result["stage_one_padding_hits"] == 253
    assert result["stage_two_attempts"] == 3036
    assert result["stage_two_padding_hits"] == 11
    assert result["accepted_count"] == 0
    assert result["status"] == "NO_ACCEPTED_CROSS_STAGE_RESULT"
