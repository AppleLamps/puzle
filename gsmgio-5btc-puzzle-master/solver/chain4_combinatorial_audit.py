"""Structural audit of the 35 = C(7,3) Chain 4 coincidence."""

from __future__ import annotations

from collections import Counter
import hashlib
import itertools
import json

from coincurve import PrivateKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .phase32_classical import run as run_phase32_classical
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "chain4_combinatorial_audit.json"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")
SEPARATORS = {"empty": b"", "nul": b"\0", "colon": b":", "newline": b"\n"}


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _gf2_rank(values: list[int]) -> int:
    basis: dict[int, int] = {}
    for value in values:
        residual = value
        while residual:
            pivot = residual.bit_length() - 1
            if pivot in basis:
                residual ^= basis[pivot]
            else:
                basis[pivot] = residual
                break
    return len(basis)


def _small_gf2_rank(rows: list[int]) -> int:
    return _gf2_rank(rows)


def _modular_rank(matrix: list[list[int]], modulus: int) -> int:
    work = [[value % modulus for value in row] for row in matrix]
    if not work:
        return 0
    rows, columns = len(work), len(work[0])
    rank = 0
    for column in range(columns):
        pivot = next((row for row in range(rank, rows) if work[row][column]), None)
        if pivot is None:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        inverse = pow(work[rank][column], -1, modulus)
        work[rank] = [(value * inverse) % modulus for value in work[rank]]
        for row in range(rows):
            if row != rank and work[row][column]:
                factor = work[row][column]
                work[row] = [
                    (left - factor * right) % modulus
                    for left, right in zip(work[row], work[rank])
                ]
        rank += 1
        if rank == rows:
            break
    return rank


def _fold_multiset(elements: list[int], size: int, mode: str) -> list[int]:
    output: list[int] = []
    for combination in itertools.combinations(elements, size):
        if mode == "sum_mod_n":
            output.append(sum(combination) % N)
        elif mode == "sum_mod_2^256":
            output.append(sum(combination) % (1 << 256))
        elif mode == "xor":
            value = 0
            for element in combination:
                value ^= element
            output.append(value)
        else:
            raise ValueError(f"unknown fold mode {mode}")
    return sorted(output)


def _maximum_matching(graph: list[set[int]], right_size: int) -> int:
    assigned: list[int | None] = [None] * right_size

    def augment(left: int, visited: set[int]) -> bool:
        for right in graph[left]:
            if right in visited:
                continue
            visited.add(right)
            if assigned[right] is None or augment(assigned[right], visited):
                assigned[right] = left
                return True
        return False

    return sum(augment(left, set()) for left in range(len(graph)))


def _target_match(scalar: int) -> bool:
    scalar %= N
    return bool(scalar) and PrivateKey(scalar.to_bytes(32, "big")).public_key.format(compressed=True) == TARGET_COMPRESSED


def run() -> dict[str, object]:
    sal = derive_tokens()
    chains = reconstruct(extract_all(), sal)
    chain4 = reconstruct_chain4(chains)
    blocks = list(chain4.blocks)
    block_values = [int.from_bytes(block, "big") for block in blocks]
    block_lookup = {block: index for index, block in enumerate(blocks)}
    triples = list(itertools.combinations(range(7), 3))
    if len(blocks) != 35 or len(triples) != 35:
        raise ValueError("expected 35 blocks and 35 seven-choose-three triples")
    phase32 = run_phase32_classical()
    if not phase32["beaufort"]["contains_seven_intertwined_passwords_phrase"]:
        raise ValueError("the authenticated Architect plaintext is missing the seven-password phrase")

    token_bytes = [token.encode("utf-8") for token in sal.tokens]
    token_digests = list(sal.digests)
    model_coverages: list[dict[str, object]] = []
    graph: list[set[int]] = [set() for _ in triples]
    generated_hash_records = 0
    generated_hashes: set[bytes] = set()
    exact_edges: list[dict[str, object]] = []
    for encoding_name, elements in (("raw_tokens", token_bytes), ("sha256_digest_bytes", token_digests)):
        for permutation in itertools.permutations(range(3)):
            for separator_name, separator in SEPARATORS.items():
                generated: list[bytes] = []
                for triple_index, triple in enumerate(triples):
                    ordered = [elements[triple[position]] for position in permutation]
                    digest = _sha(separator.join(ordered))
                    generated.append(digest)
                    generated_hashes.add(digest)
                    generated_hash_records += 1
                    if digest in block_lookup:
                        block_index = block_lookup[digest]
                        graph[triple_index].add(block_index)
                        exact_edges.append({
                            "triple": list(triple),
                            "block_index": block_index,
                            "encoding": encoding_name,
                            "permutation": list(permutation),
                            "separator": separator_name,
                        })
                intersection = sum((Counter(generated) & Counter(blocks)).values())
                model_coverages.append({
                    "encoding": encoding_name,
                    "permutation": list(permutation),
                    "separator": separator_name,
                    "block_multiset_coverage": intersection,
                    "complete_multiset_match": Counter(generated) == Counter(blocks),
                })
    if generated_hash_records != 1680 or len(model_coverages) != 48:
        raise ValueError("triple-hash family cardinality changed")
    maximum_matching = _maximum_matching(graph, len(blocks))

    # Reproduce the prior ordering-independent multiset family without
    # double-counting byte digests and their identical hex-as-integer values.
    directives = [
        "matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword",
        "yourlastcommand", "secondanswer", "sha256anstoo",
    ]
    phase3 = [
        "causality", "Safenet", "Luna", "HSM", "11110",
        "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E"
        "6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
        "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",
    ]
    candidate_sets: dict[str, list[int]] = {
        "tokens7_sha256": [int.from_bytes(value, "big") for value in sal.digests],
        "directives7_sha256": [int.from_bytes(_sha(value.encode()), "big") for value in directives],
        "phase3_7_sha256": [int.from_bytes(_sha(value.encode()), "big") for value in phase3],
    }
    recovered_k = [
        chains.chain1.key1, chains.chain1.key2,
        chains.chain2.key1, chains.chain2.key2,
        chains.cosmic_b.key1, chains.cosmic_b.key2,
        chains.cosmic_h.key1, chains.cosmic_h.key2,
    ]
    for omitted in range(8):
        candidate_sets[f"K8_minus_{omitted}"] = [
            int.from_bytes(value, "big") for index, value in enumerate(recovered_k) if index != omitted
        ]

    targets_by_mode = {
        "sum_mod_n": sorted(value % N for value in block_values),
        "sum_mod_2^256": sorted(block_values),
        "xor": sorted(block_values),
    }
    multiset_hits: list[dict[str, object]] = []
    comparisons = 0
    for set_name, elements in candidate_sets.items():
        for size in (3, 4):
            for mode, target in targets_by_mode.items():
                comparisons += 1
                if _fold_multiset(elements, size, mode) == target:
                    multiset_hits.append({"set": set_name, "subset_size": size, "mode": mode})
    if comparisons != 66:
        raise ValueError(f"unique multiset comparison count changed: {comparisons}")

    # Assignment-independent XOR obstruction: 35 outputs formed from any
    # seven latent vectors must lie in a vector space of rank at most seven.
    block_rank = _gf2_rank(block_values)
    operand_value = int.from_bytes(chain4.opcode_operand, "big")
    block_operand_rank = _gf2_rank(block_values + [operand_value])
    token_digest_rank = _gf2_rank([int.from_bytes(value, "big") for value in sal.digests])
    recovered_k_rank = _gf2_rank([int.from_bytes(value, "big") for value in recovered_k])
    token_span_members = sum(
        _gf2_rank([int.from_bytes(value, "big") for value in sal.digests] + [block]) == token_digest_rank
        for block in block_values
    )
    k_span_members = sum(
        _gf2_rank([int.from_bytes(value, "big") for value in recovered_k] + [block]) == recovered_k_rank
        for block in block_values
    )

    # Natural lexicographic incidence consistency, kept separate from the
    # stronger assignment-independent rank statement.
    incidence = [[int(index in triple) for index in range(7)] for triple in triples]
    coefficient_rank_mod_n = _modular_rank(incidence, N)
    augmented_rank_mod_n = _modular_rank(
        [row + [value] for row, value in zip(incidence, block_values)], N
    )
    coefficient_rows_gf2 = [sum(bit << index for index, bit in enumerate(row)) for row in incidence]
    coefficient_rank_gf2 = _small_gf2_rank(coefficient_rows_gf2)
    inconsistent_xor_bits = 0
    for bit in range(256):
        augmented = [
            row | (((block_values[index] >> bit) & 1) << 7)
            for index, row in enumerate(coefficient_rows_gf2)
        ]
        if _small_gf2_rank(augmented) > coefficient_rank_gf2:
            inconsistent_xor_bits += 1

    total = sum(block_values)
    latent_candidates = {
        "C(7,3)_latent_total": total * pow(15, -1, N) % N,
        "C(7,4)_latent_total": total * pow(20, -1, N) % N,
        "C(9,2)_latent_total": total * pow(8, -1, N) % N,
        "block_sum_mod_n": total % N,
    }
    latent_scalar_records: list[dict[str, object]] = []
    target_matches: list[dict[str, object]] = []
    for name, value in latent_candidates.items():
        variants = {
            name: value,
            f"SHA256({name})": int.from_bytes(_sha(value.to_bytes(32, "big")), "big"),
            f"negative({name})": -value,
        }
        for variant, scalar in variants.items():
            normalized = scalar % N
            match = _target_match(normalized)
            latent_scalar_records.append({"derivation": variant, "private_hex": f"{normalized:064x}", "target": match})
            if match:
                uncompressed = PrivateKey(normalized.to_bytes(32, "big")).public_key.format(compressed=False)
                address = base58check(b"\0" + hash160(uncompressed))
                target_matches.append({
                    "derivation": variant,
                    "private_hex": f"{normalized:064x}",
                    "address": address,
                    "address_verified": address == TARGET_ADDRESS,
                })

    structural_assignment_supported = maximum_matching == 35
    result: dict[str, object] = {
        "status": "MATCH" if target_matches else "NO_STRUCTURAL_ASSIGNMENT",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "authenticated_context": {
            "block_count": len(blocks),
            "combination_identity": "35 = C(7,3) = C(7,4)",
            "architect_phrase_verified": "SEVENINTERTWINEDPASSWORDS",
            "password_evidence_boundary": "The Architect phrase and seven-record count are authenticated; only four SalPhaseIon token values are mechanically decoded, while the final three remain semantic/fitted readings.",
        },
        "explicit_triple_hash_family": {
            "triple_count": len(triples),
            "model_count": len(model_coverages),
            "generated_hash_records": generated_hash_records,
            "unique_generated_hashes": len(generated_hashes),
            "exact_hash_edges": exact_edges,
            "maximum_fixed_model_block_coverage": max(item["block_multiset_coverage"] for item in model_coverages),
            "complete_fixed_model_matches": [item for item in model_coverages if item["complete_multiset_match"]],
            "maximum_flexible_bipartite_assignment": maximum_matching,
            "complete_assignment": structural_assignment_supported,
            "models": model_coverages,
        },
        "legacy_multiset_reproduction": {
            "unique_candidate_sets": len(candidate_sets),
            "unique_comparisons": comparisons,
            "redundant_legacy_comparisons": 18,
            "redundancy_note": "For three textual seven-sets, raw SHA-256 bytes interpreted as an integer and their hexadecimal rendering parsed as an integer are identical; the older loop counted 18 duplicate comparisons.",
            "hits": multiset_hits,
        },
        "linear_algebra": {
            "block_gf2_rank": block_rank,
            "block_plus_operand_gf2_rank": block_operand_rank,
            "seven_token_digest_rank": token_digest_rank,
            "blocks_in_token_digest_span": token_span_members,
            "eight_recovered_k_rank": recovered_k_rank,
            "blocks_in_recovered_k_span": k_span_members,
            "assignment_independent_xor_conclusion": "Any XOR combinations of seven latent 256-bit vectors have span rank at most 7; rank 35 therefore falsifies triple/four XOR under every assignment.",
            "xor_all_blocks_hex": f"{_fold_multiset(block_values, 35, 'xor')[0]:064x}",
            "natural_incidence_coefficient_rank_mod_n": coefficient_rank_mod_n,
            "natural_triple_sum_augmented_rank_mod_n": augmented_rank_mod_n,
            "natural_triple_sum_consistent": coefficient_rank_mod_n == augmented_rank_mod_n,
            "natural_incidence_coefficient_rank_gf2": coefficient_rank_gf2,
            "natural_triple_xor_inconsistent_bit_count": inconsistent_xor_bits,
            "natural_triple_xor_consistent": inconsistent_xor_bits == 0,
        },
        "latent_total_scalar_audit": {
            "candidate_records": len(latent_scalar_records),
            "records": latent_scalar_records,
            "target_matches": target_matches,
            "scope": "These totals are necessary consequences of additive subset models, not authenticated private-key derivations.",
        },
        "induced_block_scalar_search": {
            "performed": structural_assignment_supported,
            "reason": "No block order/sign scalar search is justified without a complete structural assignment." if not structural_assignment_supported else "Complete assignment found.",
        },
        "scope_note": "The GF(2) rank result is unconditional for every seven-latent-vector XOR model. Sum inconsistency is claimed only for natural lexicographic incidence; hash coverage applies only to the 48 explicit serialization models.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
