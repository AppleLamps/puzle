"""Guard the preregistration discipline itself.

A bounded negative is only worth its scope note if the family behind it can
still be rebuilt from committed bytes.  Three ways that broke were found on
2026-08-06, so each one gets a test.
"""

from __future__ import annotations

import hashlib
import json

from solver.preregistration_integrity_audit import run


def test_every_seal_binds_its_manifest_and_no_gate_is_unrepaired() -> None:
    result = run()
    summary = result["summary"]
    assert summary["seal_mismatches"] == 0
    assert summary["unresolved_digests"] == 0, [
        record for record in result["result_digests"] if record["status"] == "UNRESOLVED"
    ]
    assert summary["drift_gates_failing"] == 0, [
        record for record in result["drift_gates"] if not record["passes"]
    ]
    assert result["status"] == "CLEAN"


def test_split_envelope_v1_is_superseded_not_drift_gated() -> None:
    """The v1 seal stays intact; v2 reseal is the auditable drift-gated path."""
    result = run()
    superseded = {entry["module"]: entry for entry in result["superseded_drift_gates"]}
    assert "solver.salphaseion_split_envelope_preregister" in superseded
    entry = superseded["solver.salphaseion_split_envelope_preregister"]
    assert entry["replacement_in_drift_gated"]
    gated_modules = {record["module"] for record in result["drift_gates"]}
    assert "solver.salphaseion_split_envelope_preregister" not in gated_modules
    assert "solver.salphaseion_split_envelope_reseal" in gated_modules
    reseal = next(
        record for record in result["drift_gates"]
        if record["module"] == "solver.salphaseion_split_envelope_reseal"
    )
    assert reseal["passes"]


def test_absent_manifests_are_only_the_two_gitignored_ones() -> None:
    """v38 and v39 are excluded by size, not lost; their digests must be reachable."""
    result = run()
    absent = sorted(record["seal"] for record in result["seals"] if record["status"] == "MANIFEST_ABSENT")
    assert absent == [
        "salphaseion_preregistered_candidates_v38.sha256",
        "salphaseion_preregistered_candidates_v39.sha256",
    ]
    regenerable = {record["result"] for record in result["result_digests"] if record["status"] == "UNRESOLVED_BUT_REGENERABLE"}
    assert regenerable == {"salphaseion_blind_results_v38.json", "salphaseion_blind_results_v39.json"}


def test_new_audits_seal_and_gate_cleanly() -> None:
    from solver import (
        fae_paired_list_audit,
        yinyang_prime_dual_audit,
        yinyang_rot180_partition_audit,
        youwon_middle_block_audit,
    )
    from solver.fae_paired_list_preregister import MANIFEST_PATH as FAE_MANIFEST, SEAL_PATH as FAE_SEAL
    from solver.yinyang_prime_dual_preregister import MANIFEST_PATH as DUAL_MANIFEST, SEAL_PATH as DUAL_SEAL
    from solver.yinyang_rot180_partition_preregister import (
        MANIFEST_PATH as ROT180_MANIFEST,
        SEAL_PATH as ROT180_SEAL,
    )
    from solver.youwon_middle_block_preregister import MANIFEST_PATH as YOUWON_MANIFEST, SEAL_PATH as YOUWON_SEAL

    for manifest, seal in (
        (FAE_MANIFEST, FAE_SEAL),
        (YOUWON_MANIFEST, YOUWON_SEAL),
        (DUAL_MANIFEST, DUAL_SEAL),
        (ROT180_MANIFEST, ROT180_SEAL),
    ):
        assert hashlib.sha256(manifest.read_bytes()).hexdigest() == seal.read_text(encoding="ascii").strip()
        assert json.loads(manifest.read_bytes())["status"] == "SEALED_BEFORE_SCALAR_OR_AES_EVALUATION"

    for module in (
        youwon_middle_block_audit,
        fae_paired_list_audit,
        yinyang_prime_dual_audit,
        yinyang_rot180_partition_audit,
    ):
        outcome = module.run()
        assert outcome["status"] == "NO_PRIZE_MATCH_IN_PREREGISTERED_FAMILY"
        assert outcome["matches"] == []
        assert outcome["control"]["accepted_against_planted_target"]
        assert outcome["control"]["rejected_against_real_targets"]


def test_matrixsumlist_instruction_reading_is_dimensionally_bounded() -> None:
    """Only the 9x63 reading of S570 can address another field at all."""
    from solver.matrixsumlist_instruction_preregister import census, sum_lists

    lists = sum_lists()
    records = census()
    assert len(lists) == 102
    assert len(records) == 4
    assert {record["matches_length_of"] for record in records} == {"lastwords63"}
    assert all("s570_after_fae" in record["sum_list"] for record in records)


def test_matrixsumlist_self_labelling_fails_and_agreement_is_noise() -> None:
    from solver.matrixsumlist_instruction_audit import run

    outcome = run()
    assert outcome["status"] == "NO_PRIZE_MATCH_IN_PREREGISTERED_FAMILY"
    assert outcome["matches"] == []
    assert not outcome["self_labelling_test"]["any_exact"]
    assert outcome["self_labelling_test"]["best_positions_of_13"] <= 2
    # The 12/63 agreement is the only one below 0.05 uncorrected, and there are
    # 16 comparisons, so it does not survive correction.
    below = [record for record in outcome["field_agreements_against_null"] if record["p_value"] < 0.05]
    assert len(below) <= 1
    for record in below:
        assert record["p_value"] * len(outcome["field_agreements_against_null"]) > 0.05


def test_youwon_v44_tests_the_difference_block_not_the_raw_field() -> None:
    """The operand v42 missed: D[21:70], not S91[21:70]."""
    from solver.youwon_middle_block_preregister import difference_state

    state = difference_state()
    assert state["middle49"].startswith("YOUWON")
    assert len(state["middle49"]) == 49
    assert len(state["head21"]) == len(state["tail21"]) == 21
