from __future__ import annotations

import hashlib
import json

from solver.chains import reconstruct
from solver.extract import extract_all
from solver.salphaseion import derive_tokens
from solver.chance_padding_null_calibration_audit import (
    calibrate,
    cascade_passwords,
    observed_padding_lengths,
)
from solver.chance_padding_null_calibration_preregister import (
    MANIFEST_PATH,
    PREDICTIONS,
    RECORDED_PADDING_LENGTHS,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
)


def test_manifest_is_sealed_and_undrifted() -> None:
    encoded = MANIFEST_PATH.read_bytes()
    assert hashlib.sha256(encoded).hexdigest() == SEAL_PATH.read_text(encoding="ascii").strip()
    assert json.loads(encoded) == json.loads(json.dumps(build_manifest()))


def test_three_disputed_opens_strip_one_byte_and_the_authenticated_one_does_not() -> None:
    padding = observed_padding_lengths()
    assert padding == RECORDED_PADDING_LENGTHS
    assert padding["chain1"] == padding["chain2"] == padding["cosmic"] == 1
    assert padding["phase32"] != 1


def test_canonical_cascade_rule_reproduces_the_recorded_wif() -> None:
    chains = reconstruct(extract_all(), derive_tokens())
    assert cascade_passwords(chains.chain1_decryption.plaintext)[0] == chains.chain1_wif.encode()


def test_chance_unpads_reproduce_the_79_byte_grammar() -> None:
    measured = calibrate(trials=100_000, seed=1)
    band = PREDICTIONS["P1_chain1_unpad_rate"]
    assert band["low"] <= measured["chain1_unpad_rate"] <= band["high"]
    assert measured["len79_share_of_unpads"] >= PREDICTIONS["P2_len79_share_of_unpads"]["low"]


def test_recorded_result_survives_the_null() -> None:
    result = json.loads(RESULT_PATH.read_bytes())
    assert result["status"] == "NULL_SURVIVES"
    assert result["manifest_sha256"] == SEAL_PATH.read_text(encoding="ascii").strip()
    assert all(entry["inside_band"] for entry in result["predictions"].values())
    assert result["controls"]["phase32_legible"] is True
