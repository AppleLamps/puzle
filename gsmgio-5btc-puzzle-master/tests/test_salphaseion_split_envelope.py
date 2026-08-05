from __future__ import annotations

import hashlib
import json

from solver.chains import reconstruct
from solver.extract import extract_all
from solver.salphaseion import derive_tokens
from solver.salphaseion_raw import sha256_hex
from solver.salphaseion_split_envelope_eval import RESULT_PATH, evaluate
from solver.salphaseion_split_envelope_preregister import (
    CHAIN1_PLAINTEXT_SHA256,
    CHAIN1_WIF,
    CHAIN2_PLAINTEXT_SHA256,
    COSMIC_PLAINTEXT_SHA256,
    ENV48_SHA256,
    MANIFEST_PATH,
    RAW48_SHA256,
    SEAL_PATH,
    build_manifest,
    split_envelope,
)


def test_split_reconstruction_matches_pinned_hashes() -> None:
    env48, raw48 = split_envelope()
    assert len(env48) == 48 and len(raw48) == 48
    assert sha256_hex(env48) == ENV48_SHA256
    assert sha256_hex(raw48) == RAW48_SHA256
    assert env48[:8] == b"Salted__"
    assert env48[8:16].hex() == "3ab585348552415d"
    assert env48 + raw48 == extract_all().chain1_envelope


def test_positive_controls_decrypt_to_pinned_hashes() -> None:
    chains = reconstruct(extract_all(), derive_tokens())
    assert len(chains.chain1_decryption.plaintext) == 79
    assert sha256_hex(chains.chain1_decryption.plaintext) == CHAIN1_PLAINTEXT_SHA256
    assert chains.chain1_wif == CHAIN1_WIF
    assert len(chains.chain2_decryption.plaintext) == 79
    assert sha256_hex(chains.chain2_decryption.plaintext) == CHAIN2_PLAINTEXT_SHA256
    assert len(chains.cosmic_decryption.plaintext) == 1327
    assert sha256_hex(chains.cosmic_decryption.plaintext) == COSMIC_PLAINTEXT_SHA256


def test_preregistration_is_deterministic() -> None:
    first = build_manifest()
    second = build_manifest()
    assert first == second
    encoded = (json.dumps(first, indent=2, sort_keys=True) + "\n").encode("utf-8")
    assert encoded == MANIFEST_PATH.read_bytes()
    assert SEAL_PATH.read_text(encoding="ascii").strip() == hashlib.sha256(encoded).hexdigest()


def test_sealed_evaluation_is_negative_and_recovers_planted_control() -> None:
    result = evaluate()
    assert result["manifest_sha256"] == SEAL_PATH.read_text(encoding="ascii").strip()
    assert result["status"] == "NO_ACCEPTED_OUTPUT"
    assert result["accepted_count"] == 0
    assert result["cross_blob"] == []
    assert result["salt_hits"] == []
    assert result["prize_gate"]["matches"] == []

    controls = result["controls"]
    assert controls["chain1_glued_with_joke_password"]["pass"]
    assert controls["chain1_wif"]["pass"]
    assert controls["chain2_with_wif"]["pass"]
    assert controls["cosmic_with_xor_password"]["pass"]

    # Planted control: the sealed first (key, IV) pair encrypts a known message
    # into a synthetic raw48 and the same engine must recover it.
    planted = controls["planted_k1_recovery"]
    assert planted["recovered"]
    assert planted["recoveries"] == [{
        "pair_id": planted["planted_pair"]["pair_id"],
        "key_id": planted["planted_pair"]["key_id"],
        "iv_id": planted["planted_pair"]["iv_id"],
        "plaintext_sha256": planted["message_sha256"],
        "readable_text": True,
    }]

    assert result["family_counts"] == {
        "K1": {"attempts": 112, "padding_hits": 0, "accepted": 0},
        "K2": {"attempts": 84, "padding_hits": 1, "accepted": 0},
        "K3": {
            "stage_one_unique_plaintexts": 1,
            "attempts": 12,
            "stage_two_a_attempts": 4,
            "stage_two_b_attempts": 8,
            "padding_hits": 0,
            "accepted": 0,
        },
        "K4": {
            "windows": 17,
            "scalar_gates": 17,
            "base58check_tests": 18,
            "format_scans": 18,
            "accepted": 0,
        },
        "K5": {"needles": 16, "corpora": 17, "searches": 272, "hits": 0},
    }
    assert result["dedup_counts"] == {
        "k1_duplicate_pairs_removed": 8,
        "k2_duplicate_passwords_removed": 7,
        "k3_duplicate_stage_one_plaintexts": 0,
    }
    assert (
        result["candidate_stream_sha256"]
        == "e89b26f9589504e21b3eea20673f2387cdf401b32ed99681618fab22c827986a"
    )

    on_disk = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert on_disk["manifest_sha256"] == result["manifest_sha256"]
    assert on_disk["status"] == result["status"]
