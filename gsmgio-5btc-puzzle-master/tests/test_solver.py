from __future__ import annotations

import hashlib
import unittest

from solver.blockchain_nonce_audit import run as run_blockchain_nonce_audit
from solver.chain4 import reconstruct_chain4
from solver.chain4_combinatorial_audit import run as run_chain4_combinatorial_audit
from solver.chain4_mitm_audit import run as run_chain4_mitm_audit
from solver.chain4_signed_mitm_audit import run as run_chain4_signed_mitm_audit
from solver.chain4_plusminus_grammar_audit import run as run_chain4_plusminus_grammar_audit
from solver.chain4_xcoordinate_audit import run as run_chain4_xcoordinate_audit
from solver.chain4_xor_subset_audit import run as run_chain4_xor_subset_audit
from solver.chain4_product_subset_audit import run as run_chain4_product_subset_audit
from solver.chain4_aes_integer_audit import run as run_chain4_aes_integer_audit
from solver.efragment_scalar_audit import run as run_efragment_scalar_audit
from solver.decentraland_audio_audit import run as run_decentraland_audio_audit
from solver.chains import reconstruct
from solver.cosmic_matrix import analyze, base_digits_to_bytes
from solver.extract import extract_all
from solver.openssl_compat import decrypt_salted_aes256_cbc, encrypt_salted_aes256_cbc
from solver.phase32_classical import run as run_phase32_classical
from solver.phase32_symbol_recovery import run as run_phase32_symbol_recovery
from solver.prime_reinsertion_audit import run as run_prime_reinsertion_audit
from solver.matrixsumlist_audit import run as run_matrixsumlist_audit
from solver.salphaseion import derive_tokens
from solver.salphaseion_instruction_audit import run as run_salphaseion_instruction_audit
from solver.secp256k1_verify import addresses_for_x, p2pkh_address, wif
from solver.sfield_reduction_audit import run as run_sfield_reduction_audit
from solver.wayback_source_audit import run as run_wayback_source_audit
from solver.wayback_early_asset_audit import run as run_wayback_early_asset_audit


class SolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inputs = extract_all()
        cls.sal = derive_tokens()
        cls.chains = reconstruct(cls.inputs, cls.sal)
        cls.chain4 = reconstruct_chain4(cls.chains)
        cls.matrix = analyze(cls.chains.cosmic_decryption.plaintext)

    def test_openssl_roundtrip_and_wrong_password(self) -> None:
        envelope = encrypt_salted_aes256_cbc(b"positive control", b"password", bytes.fromhex("0011223344556677"))
        self.assertEqual(decrypt_salted_aes256_cbc(envelope, b"password").plaintext, b"positive control")
        with self.assertRaises(ValueError):
            decrypt_salted_aes256_cbc(envelope, b"wrong")

    def test_salph_tokens_and_xor(self) -> None:
        self.assertEqual(self.sal.directly_decoded, ("matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword"))
        self.assertEqual(self.sal.xor_password.hex(), "a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735")

    def test_phase32_sha256_kdf_positive_control(self) -> None:
        password = b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
        result = decrypt_salted_aes256_cbc(self.inputs.phase32_envelope, password, digest="sha256")
        self.assertTrue(result.plaintext.startswith(b"I've been waiting for you."))
        self.assertEqual(hashlib.sha256(result.plaintext).hexdigest(), "b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34")

    def test_chains(self) -> None:
        self.assertEqual(hashlib.sha256(self.chains.chain1_decryption.plaintext).hexdigest(), "1449a2178eea7c0e3fabac8c1ad2afa294be4fc1800c594a025a056e88c626bf")
        self.assertEqual(self.chains.chain1_wif, "5K2byJMssxFKuTgnk9YQjpBz5FhkwwF2LaZoAyTus8HjGEpz8AT")
        self.assertEqual(hashlib.sha256(self.chains.chain2_decryption.plaintext).hexdigest(), "b40fce72ef5638e4f79b3233e653f8a5dbdb0d4ae2009d2d3da2c98b70f4d004")
        self.assertEqual(len(self.chains.cosmic_decryption.plaintext), 1327)
        self.assertEqual(hashlib.sha256(self.chains.cosmic_decryption.plaintext).hexdigest(), "4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081")

    def test_chain4(self) -> None:
        self.assertEqual(self.chain4.password.hex(), "38d4f4c90cb45fdfc8cff50d0ed1c5740a25de4b8e946d0a5ae2667a23a259cc")
        self.assertEqual(len(self.chain4.decryption.plaintext), 1151)
        self.assertEqual(hashlib.sha256(self.chain4.decryption.plaintext).hexdigest(), "e4269ed5fbb202a81e5e1aa6b5190fdd1ea126b2c8547ea7cdbdf45387ea135b")
        self.assertEqual(self.chain4.marker, b"+-")
        self.assertEqual(self.chain4.opcode, b"+")
        self.assertEqual(len(self.chain4.operand), 29)
        self.assertEqual(len(self.chain4.opcode_operand), 30)
        self.assertEqual(len(self.chain4.blocks), 35)

    def test_chain4_combinatorial_structure(self) -> None:
        result = run_chain4_combinatorial_audit()
        self.assertEqual(result["status"], "NO_STRUCTURAL_ASSIGNMENT")
        explicit = result["explicit_triple_hash_family"]
        self.assertEqual(explicit["triple_count"], 35)
        self.assertEqual(explicit["model_count"], 48)
        self.assertEqual(explicit["generated_hash_records"], 1680)
        self.assertEqual(explicit["unique_generated_hashes"], 1080)
        self.assertEqual(explicit["exact_hash_edges"], [])
        self.assertEqual(explicit["maximum_flexible_bipartite_assignment"], 0)
        legacy = result["legacy_multiset_reproduction"]
        self.assertEqual(legacy["unique_comparisons"], 66)
        self.assertEqual(legacy["redundant_legacy_comparisons"], 18)
        self.assertEqual(legacy["hits"], [])
        algebra = result["linear_algebra"]
        self.assertEqual(algebra["block_gf2_rank"], 35)
        self.assertEqual(algebra["block_plus_operand_gf2_rank"], 36)
        self.assertEqual(algebra["blocks_in_token_digest_span"], 0)
        self.assertEqual(algebra["blocks_in_recovered_k_span"], 0)
        self.assertEqual((algebra["natural_incidence_coefficient_rank_mod_n"], algebra["natural_triple_sum_augmented_rank_mod_n"]), (7, 8))
        self.assertEqual(algebra["natural_triple_xor_inconsistent_bit_count"], 256)
        self.assertEqual(result["latent_total_scalar_audit"]["target_matches"], [])
        self.assertFalse(result["induced_block_scalar_search"]["performed"])

    def test_chain4_mitm_certificates(self) -> None:
        result = run_chain4_mitm_audit()
        self.assertEqual(result["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(result["total_logical_candidate_space"], "9483287789568")
        self.assertTrue(all(control["match"] for control in result["engine"]["point_controls"]))
        synthetic = result["engine"]["synthetic_positive_control"]
        self.assertEqual(synthetic["status"], "COMPLETE")
        self.assertEqual(synthetic["accepted_matches"], 1)
        self.assertEqual(synthetic["matches"][0]["selected_indices"], [0, 3, 7, 11])
        expected = {
            "M1_blocks35_prefix_shifts": (35, "240518168576", 7),
            "M2_blocks35_plus_operand": (36, "68719476736", 1),
            "M3_blocks35_plus_magnitude": (36, "68719476736", 1),
            "M4_blocks35_plus_K8": (43, "8796093022208", 1),
            "M5_blocks35_component_shifts": (35, "309237645312", 9),
        }
        for name, (scalars, space, targets) in expected.items():
            manifest = result["families"][name]
            self.assertEqual(manifest["status"], "COMPLETE")
            self.assertEqual(manifest["scalar_count"], scalars)
            self.assertEqual(manifest["logical_candidate_space"], space)
            self.assertEqual(manifest["target_count"], targets)
            self.assertEqual(manifest["next_right_subset"], manifest["right_subset_count"])
            self.assertEqual(manifest["left_point_collisions"], 0)
            self.assertEqual(manifest["matches"], [])
            self.assertEqual(manifest["accepted_matches"], 0)
        self.assertEqual(result["accepted_matches"], [])

    def test_blockchain_nonce_audit_offline_replay(self) -> None:
        result = run_blockchain_nonce_audit(refresh_histories=False, fetch_missing=False)
        self.assertEqual(result["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(result["chain4_sha256"], "e4269ed5fbb202a81e5e1aa6b5190fdd1ea126b2c8547ea7cdbdf45387ea135b")
        self.assertTrue(result["source"]["historical_inventory_reproduced"])
        corpus = result["corpus"]
        self.assertEqual(corpus["signature_count"], 187)
        self.assertEqual(corpus["unique_spending_transactions"], 179)
        self.assertEqual(corpus["raw_transaction_count"], 204)
        self.assertEqual(corpus["unique_r_count"], 187)
        self.assertTrue(corpus["all_txids_verified"])
        self.assertTrue(corpus["all_signatures_verified"])
        self.assertEqual(corpus["sighash_types"], {"1": 187})
        self.assertEqual(corpus["repeated_r_groups"], {})
        nonce = result["nonce_audit"]
        self.assertEqual(nonce["legacy_target_block_nonce_tests"], 210)
        self.assertEqual(nonce["known_nonce_equation_tests"], 17952)
        self.assertEqual(nonce["repeated_nonce_recoveries"], [])
        self.assertEqual(nonce["known_nonce_r_matches"], [])
        self.assertEqual(nonce["accepted_known_nonce_matches"], [])
        self.assertEqual(nonce["direct_prize_candidate_matches"], [])

    def test_chain4_xcoordinate_audit(self) -> None:
        result = run_chain4_xcoordinate_audit()
        self.assertEqual(result["status"], "COMPLETE_NO_POINT_RELATION")
        self.assertEqual(result["valid_x_coordinate_count"], 22)
        self.assertEqual(result["invalid_x_coordinate_count"], 13)
        self.assertEqual(result["invalid_block_indices"], [2, 4, 5, 11, 12, 15, 21, 23, 24, 25, 26, 28, 33])
        self.assertEqual(result["shift_count"], 11)
        self.assertEqual(result["candidate_counts_by_term_count"], {"1": 484, "2": 10164, "3": 135520})
        self.assertEqual(result["total_candidate_relations"], 146168)
        self.assertEqual(result["point_relation_matches"], [])
        self.assertTrue(result["synthetic_positive_control"]["recovered"])
        self.assertEqual(result["accepted_private_scalars"], [])

    def test_chain4_xor_subset_certificates(self) -> None:
        result = run_chain4_xor_subset_audit(max_workers=1)
        self.assertEqual(result["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(result["block_count"], 35)
        self.assertTrue(result["engine"]["positive_control"]["recovered"])
        self.assertEqual(result["engine"]["positive_control"]["candidate_count"], 80)
        expected = {
            "X3": (3, 6545, 26180, "c86a98ebaed68e371f8f22a3b1d780cfd535ffaed58024fea3dff63314075ec3"),
            "X4": (4, 52360, 209440, "8617ae7b7e30bffbeb878510207c59d01ad2ac8ee847311bd5c14d0bdedc23ca"),
            "X7": (7, 6724520, 13449040, "f2e3a04bd83c57c361d32646cfd9d2a41c6aa85a346cd914373f99ed9e042212"),
        }
        for name, (size, combinations, candidates, digest) in expected.items():
            family = result["families"][name]
            self.assertEqual(family["subset_size"], size)
            self.assertEqual(family["combination_count"], combinations)
            self.assertEqual(family["candidate_count"], candidates)
            self.assertEqual(family["partition_stream_digest_sha256"], digest)
            self.assertEqual(family["zero_scalar_count"], 0)
            self.assertEqual(family["matches"], [])
            self.assertEqual(family["accepted_matches"], 0)
        self.assertEqual(result["total_candidate_scalars"], 13684660)
        self.assertEqual(result["accepted_matches"], [])

    def test_chain4_product_subset_certificates(self) -> None:
        result = run_chain4_product_subset_audit(max_workers=1)
        self.assertEqual(result["status"], "COMPLETE_NO_MATCH")
        self.assertTrue(result["engine"]["positive_control"]["recovered"])
        self.assertEqual(result["engine"]["positive_control"]["candidate_count"], 100)
        expected = {
            "Q3": (3, 6545, 32725, "b75a397c0f0588580a513670ed6bbc804df4fe258c9a15ef797656aedca30128"),
            "Q4": (4, 52360, 261800, "4eb75171d1819ae97ea096340744b3fcde01c1e9c3ade67172c06371b6ab04a5"),
            "Q7": (7, 6724520, 13449040, "57713faf7f504270d3a8057e814769da221a4b62769f13690cc7598548cf43b4"),
        }
        for name, (size, combinations, candidates, digest) in expected.items():
            family = result["families"][name]
            self.assertEqual(family["subset_size"], size)
            self.assertEqual(family["combination_count"], combinations)
            self.assertEqual(family["candidate_count"], candidates)
            self.assertEqual(family["partition_stream_digest_sha256"], digest)
            self.assertEqual(family["zero_scalar_count"], 0)
            self.assertEqual(family["matches"], [])
        self.assertEqual(result["total_candidate_scalars"], 13743565)
        self.assertEqual(result["accepted_matches"], [])

    def test_chain4_aes_integer_audit(self) -> None:
        result = run_chain4_aes_integer_audit()
        self.assertEqual(result["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(result["derived_key_count"], 18)
        self.assertEqual(result["counts"], {
            "A1_ecb_block_decryptions": 630,
            "A2_cbc_body_decryptions": 54,
            "A2_chunk_scalar_gates": 1890,
            "B1_whole_integer_candidates": 10,
            "B2_selector_candidates": 18,
        })
        self.assertEqual(result["candidate_stream_sha256"], "7eaadf98c0e736c4401e491cb6e6f254de666126ca18bc4f9e7402e6ba061bb1")
        self.assertEqual(result["structure_hits"], [])
        self.assertEqual(result["point_matches"], [])
        self.assertEqual(result["accepted_prize_matches"], [])
        self.assertTrue(all(result["positive_controls"].values()))

    def test_efragment_scalar_audit(self) -> None:
        result = run_efragment_scalar_audit()
        self.assertEqual(result["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(result["raw_family_counts"], {"F1": 2052, "F2": 61, "F3": 224, "F4": 72})
        self.assertEqual(result["raw_attempt_count"], 2409)
        self.assertEqual(result["zero_attempt_count"], 0)
        self.assertEqual(result["duplicate_attempt_count"], 692)
        self.assertEqual(result["unique_scalar_count"], 1717)
        self.assertEqual(result["unique_by_first_family"], {"F1": 1380, "F2": 41, "F3": 224, "F4": 72})
        self.assertEqual(result["candidate_stream_sha256"], "5d7ab1e4535c42fba68ff1b595c346bfc63ac033e156ea024fc904ce669d0564")
        self.assertEqual(result["point_matches"], [])
        self.assertEqual(result["accepted_prize_matches"], [])
        self.assertTrue(result["positive_control"]["recovered"])

    def test_matrix_and_addresses(self) -> None:
        self.assertEqual((self.matrix.total_ones, self.matrix.weighted_rows, self.matrix.weighted_columns), (5193, 268603, 268828))
        self.assertEqual([candidate.shift for candidate in self.matrix.exact_range_candidates], [7])
        self.assertEqual(self.matrix.half.hex(), "0423d9115a1dc756d5d08d2de880ab508bd4745fc97709f4fcb513f2cb8fcc35")
        self.assertEqual(self.matrix.better_half.hex(), "48cc46e66bdd36b09ae344552f606a761f9d90681f20dfefe2b43db18b623971")
        self.assertEqual(self.matrix.trail1.hex(), "fc0c1b02")
        self.assertEqual(p2pkh_address(self.matrix.half, True), "1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu")
        self.assertEqual(p2pkh_address(self.matrix.better_half, True), "145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ")
        self.assertEqual(len(base_digits_to_bytes(self.matrix.digits, 39)), 68)

    def test_target_x_coordinate(self) -> None:
        x = bytes.fromhex("f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464")
        self.assertIn("1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe", [entry[1] for entry in addresses_for_x(x)])

    def test_phase32_classical_stages(self) -> None:
        result = run_phase32_classical()
        self.assertEqual(result["status"], "REPRODUCED")
        self.assertEqual(result["symbol_record"]["unique_symbols"], 26)
        self.assertTrue(result["beaufort"]["contains_take_private_key_phrase"])
        self.assertTrue(result["beaufort"]["contains_prime_basics_phrase"])
        self.assertTrue(result["beaufort"]["contains_seven_intertwined_passwords_phrase"])
        self.assertTrue(result["beaufort"]["ends_ciao_bella_o"])
        self.assertEqual(result["vic"]["digit_count"], 149)

    def test_prime_reinsertion_audit(self) -> None:
        result = run_prime_reinsertion_audit()
        self.assertEqual(result["status"], "NO_MATCH_IN_ENUMERATED_FAMILY")
        self.assertEqual(result["source"]["prefix_length"], 91)
        self.assertEqual(result["source"]["prefix_sha256"], "71fe46259e270c113529dfaded4b59c59a9dffd826a7202ab07fc498b6a2c5ca")
        self.assertEqual(result["source"]["spiral_ascii"], "gsmg.io/theseedisplanted")
        self.assertEqual((result["source"]["blue_count"], result["source"]["yellow_count"]), (15, 9))
        self.assertEqual(result["prime_count"], 24)
        self.assertEqual(result["inserted_stream_records"], 16)
        self.assertEqual(result["ordered_stream_records"], 32)
        self.assertEqual(result["decoded_byte_records"], 1344)
        self.assertEqual(result["scalar_candidate_records"], 1376)
        self.assertEqual(result["matches"], [])

    def test_matrixsumlist_audit(self) -> None:
        result = run_matrixsumlist_audit()
        self.assertEqual(result["status"], "NO_MATCH_IN_ENUMERATED_FAMILY")
        self.assertIn("not a creator-documented rule", result["evidence_boundary"])
        self.assertEqual(result["structural_hypotheses"], 5184)
        self.assertEqual(result["base9_output_records"], 36288)
        self.assertEqual(result["maximum_generated_key_equalities_of_91"], 19)
        self.assertEqual(result["exact_generated_key_matches"], [])
        self.assertEqual(result["raw_32_byte_records"], 0)
        self.assertEqual(result["scalar_candidate_records"], 62208)
        self.assertEqual(result["unique_nonzero_scalars"], 9216)
        self.assertEqual(result["matches"], [])

    def test_salphaseion_instruction_audit(self) -> None:
        result = run_salphaseion_instruction_audit()
        self.assertEqual(result["status"], "NO_NEW_AUTHENTICATED_PATH")
        corrections = result["source_corrections"]
        self.assertEqual(corrections["verified_total_ones"], 102)
        self.assertEqual(corrections["verified_colored_hex"], "BE2B9B")
        self.assertEqual(corrections["supplied_total_ones"], 101)
        self.assertEqual(corrections["supplied_colored_hex"], "F73D92")
        family = result["candidate_family"]
        self.assertEqual(family["unique_preimages"], 17614)
        self.assertEqual(family["unique_password_bytes"], 140908)
        self.assertEqual(family["password_candidate_stream_sha256"], "9f7597e0c1bc48d01de038a16eb8a2cc39a6162bd5a330e18a3b9491efc8da04")
        self.assertEqual(result["strict_padding_hit_counts"], {
            "chain1": 1090,
            "chain1-to-chain2": 13,
            "cosmic": 1154,
            "chain2-direct": 1033,
        })
        self.assertEqual(len(result["chain1_to_chain2_hits"]), 13)
        self.assertEqual(len(result["chain1_to_chain2_to_chain4_structure_hits"]), 1)
        self.assertEqual(result["noncontrol_chain1_to_chain2_to_chain4_structure_hits"], [])
        self.assertEqual(len(result["cosmic_to_chain4_structure_hits"]), 1)
        self.assertEqual(result["noncontrol_cosmic_to_chain4_structure_hits"], [])
        self.assertEqual(result["direct_32_byte_scalar_matches"], [])
        self.assertEqual(result["sha256_brainwallet_matches"], [])

    def test_sfield_reduction_audit(self) -> None:
        result = run_sfield_reduction_audit()
        self.assertEqual(result["status"], "NO_MATCH_IN_ENUMERATED_FAMILY")
        self.assertEqual(result["authenticated_inputs"]["s570_length"], 570)
        self.assertEqual(result["authenticated_inputs"]["s570_sha256"], "066191b4aafc114fbca7f0d168382f40129c4ff18490375b689741081d5ef3c2")
        self.assertEqual(result["legacy_reproduction"]["R1_lists30"], 40456)
        self.assertEqual(result["legacy_reproduction"]["R2_unique_nonzero_scalars"], 54792)
        self.assertEqual(result["legacy_reproduction"]["R3_generated_records"], 18)
        self.assertEqual(result["legacy_reproduction"]["dead_permutation_branch_records"], 0)
        self.assertEqual(result["corrected_extension"]["lists29"], 40568)
        self.assertEqual(result["corrected_extension"]["magnitude29_matches"], [])
        self.assertEqual(result["corrected_extension"]["serialization_candidate_records"], 688872)
        self.assertEqual(result["corrected_extension"]["unique_nonzero_scalars"], 520611)
        self.assertEqual(result["combined_unique_nonzero_scalars"], 575419)
        self.assertEqual(result["matches"], [])

    def test_wayback_source_audit_from_verified_cache(self) -> None:
        result = run_wayback_source_audit(refresh_cdx=False, fetch_missing=False)
        self.assertEqual(result["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(result["cdx"]["primary_target_count"], 64)
        self.assertEqual(result["cdx"]["supplementary_octet_stream_count"], 5)
        self.assertEqual(result["retrieval"]["target_count"], 69)
        self.assertEqual(result["retrieval"]["success_count"], 69)
        self.assertEqual(result["retrieval"]["failure_count"], 0)
        self.assertEqual(result["retrieval"]["cdx_digest_verified_count"], 69)
        self.assertEqual(result["scan"]["term_hits"], [])
        self.assertEqual(result["scan"]["inline_source_map_decode_failures"], 0)
        self.assertEqual(result["scan"]["unique_32_byte_scalar_candidates"], 0)
        self.assertEqual(result["scan"]["target_matches"], [])

    def test_signed_block_and_plusminus_certificates(self) -> None:
        signed = run_chain4_signed_mitm_audit()
        self.assertEqual(signed["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(signed["logical_sign_patterns_per_constant"], str(1 << 35))
        self.assertEqual(signed["literal_constant_count"], 7)
        self.assertEqual(signed["cross_branch_constant_count"], 8)
        self.assertTrue(signed["positive_control"]["recovered"])
        self.assertEqual(signed["accepted_matches"], [])

        grammar = run_chain4_plusminus_grammar_audit()
        self.assertEqual(grammar["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(grammar["A_fragment_passwords"]["tested"], 896)
        self.assertEqual(grammar["A_fragment_passwords"]["strict_padding_hits"], 9)
        self.assertEqual(grammar["A_fragment_passwords"]["canonical_structure_hits"], 1)
        self.assertEqual(grammar["C_sign_windows"]["candidate_count"], 12360)
        self.assertEqual(grammar["D_natural_sign_patterns"]["candidate_count"], 72)
        self.assertEqual(grammar["matches"], [])

    def test_phase32_symbol_recovery(self) -> None:
        result = run_phase32_symbol_recovery()
        self.assertEqual(result["status"], "RECOVERED")
        self.assertEqual(result["crib_length"], 76)
        self.assertEqual(result["crib_fixed_symbol_count"], 23)
        self.assertEqual(result["residual_candidate_count"], 6)
        self.assertGreater(result["best_score_margin"], 1000)
        self.assertEqual(result["published_mapping_agreement"], 26)
        self.assertEqual(result["published_mapping_size"], 26)
        self.assertEqual(result["plaintext_sha256"], "56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241")

    def test_wayback_early_assets_from_verified_cache(self) -> None:
        result = run_wayback_early_asset_audit(fetch_missing=False)
        self.assertEqual(result["status"], "COMPLETE_NO_MATCH")
        self.assertEqual(result["cdx"]["selected_capture_rows"], 80)
        self.assertEqual(result["cdx"]["selected_unique_digests"], 73)
        self.assertEqual(result["retrieval"]["capture_rows_covered"], 80)
        self.assertEqual(result["retrieval"]["cdx_digest_verified_count"], 73)
        self.assertEqual(result["scan"]["term_hits"], [])
        self.assertEqual(result["scan"]["unique_32_byte_scalar_candidates"], 0)
        self.assertEqual(result["scan"]["target_matches"], [])
        png_capture = next(
            item for item in result["puzzle_capture_comparison"]["archive_captures"]
            if item["original"].endswith("/puzzle")
        )
        self.assertTrue(png_capture["matches_local_puzzle_png"])

    def test_decentraland_audio_from_verified_cache(self) -> None:
        result = run_decentraland_audio_audit(fetch_missing=False)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["audio"]["sha256"], "ef17a96dce37b4dd7cbf79f210c5cbaf37fcae60e5faf8004de4e0832bd0dfee")
        self.assertEqual(result["audio"]["length"], 212031)
        self.assertEqual(result["entity"]["pointers"], ["-41,-16", "-41,-17"])
        self.assertTrue(result["entity"]["active_entity_association_verified"])
        self.assertTrue(result["game"]["references_audio"])
        self.assertTrue(result["game"]["display_text_present"])
        self.assertEqual(result["reproduction"]["message"], "HASHTHETEXT")
        substitution = result["salphaseion_substitution_audit"]
        self.assertEqual(substitution["tested_pairs"], 96)
        self.assertEqual(len(substitution["strict_padding_hits"]), 1)
        self.assertEqual(substitution["strict_padding_hits"][0]["token6"], "yourlastcommand")
        self.assertEqual(substitution["strict_padding_hits"][0]["token7"], "secondanswer")
        self.assertEqual(substitution["hashthetext_token_hits"], [])


if __name__ == "__main__":
    unittest.main()
