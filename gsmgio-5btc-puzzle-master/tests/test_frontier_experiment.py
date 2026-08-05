from __future__ import annotations

import unittest

from solver.architect_source_prime_reinsertion_audit import (
    run as run_architect_source_prime_reinsertion_audit,
)
from solver.chain4_completed_triangle import run as run_completed_triangle
from solver.chain4_split_audit import run as run_split_audit
from solver.door2_formula_audit import run as run_door2_audit
from solver.frontier_experiment import TARGET_X, TARGET_Y, _target_match
from solver.l4_crib_audit import run as run_l4_crib_audit
from solver.l4_beaufort_audit import run as run_l4_beaufort_audit
from solver.trail1_permutation_experiment import run as run_trail1_permutations
from solver.trail1_splice_experiment import run as run_trail1_splice
from solver.xor_triangle_audit import run as run_triangle_audit


class FrontierExperimentTests(unittest.TestCase):
    def test_architect_source_prime_reinsertion_preregistered_family(self) -> None:
        result = run_architect_source_prime_reinsertion_audit()
        self.assertEqual(result["schema"], "architect-source-prime-reinsertion-v1")
        self.assertEqual(result["candidate_records"], 168)
        self.assertEqual(result["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(result["matches"], [])

    def test_exact_gate_rejects_known_non_target(self) -> None:
        self.assertFalse(_target_match(1))

    def test_target_coordinates_are_full_width(self) -> None:
        self.assertEqual(len(f"{TARGET_X:064x}"), 64)
        self.assertEqual(len(f"{TARGET_Y:064x}"), 64)

    def test_exact_xor_triangle_family_has_no_survivor(self) -> None:
        result = run_triangle_audit()
        self.assertEqual(result["attempted_layouts"], 18432)
        self.assertEqual(result["exact_triangle_survivors"], [])

    def test_exact_trail1_splice_family(self) -> None:
        result = run_trail1_splice()
        self.assertEqual(result["word_count"], 10)
        self.assertEqual(result["generated_candidates"], 1410)
        self.assertEqual(result["matches"], [])

    def test_exact_trail1_permutation_family(self) -> None:
        result = run_trail1_permutations()
        self.assertEqual(result["word_count"], 72)
        self.assertEqual(result["generated_candidates"], 10152)
        self.assertEqual(result["matches"], [])

    def test_completed_prefix_triangle_family(self) -> None:
        result = run_completed_triangle()
        self.assertEqual(result["completion_count"], 8)
        self.assertEqual(result["attempted_layouts"], 4096)
        self.assertEqual(result["exact_layouts"], [])
        self.assertEqual(result["target_words"], [])

    def test_door2_public_formula_audit(self) -> None:
        result = run_door2_audit()
        self.assertEqual(result["literal_lowercase_ascii_hex_lcp"], 5)
        self.assertFalse(result["literal_claim_reproduces_lcp7"])
        self.assertEqual(result["matches"], [])

    def test_reported_246_split_entropy_claim(self) -> None:
        result = run_split_audit()
        self.assertEqual(result["status"], "NO_FIXED_SPLIT_ENTROPY_EVIDENCE")
        self.assertGreater(result["one_sided_permutation_p_value"], 0.4)
        self.assertLess(result["one_sided_permutation_p_value"], 0.6)
        self.assertEqual(result["block_alignment_remainder"], 23)

    def test_l4_repeating_xor_crib_claim(self) -> None:
        result = run_l4_crib_audit()
        self.assertEqual(result["status"], "NO_REPEATING_XOR_CRIB_SURVIVOR")
        self.assertEqual(result["language_survivors"], [])
        self.assertEqual(result["target_matches"], [])

    def test_l4_byte_domain_beaufort_claim(self) -> None:
        result = run_l4_beaufort_audit()
        self.assertEqual(result["status"], "NO_BYTE_DOMAIN_BEAUFORT_SURVIVOR")
        self.assertEqual(result["total_language_survivors"], 0)
        self.assertEqual(result["total_target_matches"], 0)


if __name__ == "__main__":
    unittest.main()
