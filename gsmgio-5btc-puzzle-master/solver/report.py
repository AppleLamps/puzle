"""Run the complete verifier and emit binary, JSON, and Markdown deliverables."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .audit_claims import PUBLIC_OCCURRENCES, unresolved_frontier
from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze, base_digits_to_bytes
from .extract import COSMIC_SOURCE, README, ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion import derive_tokens
from .secp256k1_verify import addresses_for_x, p2pkh_address, wif


OUTPUT = ROOT / "artifacts"
BIN = OUTPUT / "bin"
JSON_PATH = ROOT / "artifacts.json"
REPORT_PATH = ROOT / "VERIFICATION_REPORT.md"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Ledger:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def add_bytes(
        self,
        name: str,
        data: bytes,
        source: str,
        derivation: str,
        *,
        write: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "name": name,
            "source": source,
            "derivation": derivation,
            "length": len(data),
            "sha256": sha256(data),
        }
        if len(data) <= 64:
            record["hex"] = data.hex()
        if write:
            filename = name.replace("/", "_").replace(" ", "_") + ".bin"
            path = BIN / filename
            path.write_bytes(data)
            record["path"] = str(path.relative_to(ROOT)).replace("\\", "/")
        if metadata:
            record["metadata"] = metadata
        self.records.append(record)

    def add_text(self, name: str, text: str, source: str, derivation: str) -> None:
        data = text.encode("utf-8")
        self.records.append(
            {
                "name": name,
                "source": source,
                "derivation": derivation,
                "length": len(data),
                "sha256": sha256(data),
                "text": text,
            }
        )


def _record_decryption(ledger: Ledger, prefix: str, result: Any, source: str) -> None:
    ledger.add_bytes(f"{prefix}_salt", result.salt, source, "bytes 8:16 of Salted__ envelope")
    ledger.add_bytes(f"{prefix}_password", result.password, source, "password bytes supplied to EVP_BytesToKey-MD5")
    ledger.add_bytes(f"{prefix}_aes_key", result.key, source, f"EVP_BytesToKey-{result.kdf_digest} AES-256 key")
    ledger.add_bytes(f"{prefix}_iv", result.iv, source, f"EVP_BytesToKey-{result.kdf_digest} CBC IV")
    ledger.add_bytes(
        f"{prefix}_padded_plaintext",
        result.padded_plaintext,
        source,
        "AES-256-CBC decryption before padding validation",
        metadata={"pkcs7_padding_length": result.padding_length},
    )
    ledger.add_bytes(
        f"{prefix}_plaintext",
        result.plaintext,
        source,
        "strict PKCS#7 validation and removal",
        metadata={"pkcs7_padding_length": result.padding_length},
    )


def run() -> dict[str, Any]:
    OUTPUT.mkdir(exist_ok=True)
    BIN.mkdir(exist_ok=True)
    ledger = Ledger()
    inputs = extract_all()
    sal = derive_tokens()
    chains = reconstruct(inputs, sal)
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)

    source_files = []
    for path in sorted(ROOT.iterdir(), key=lambda p: p.name.lower()):
        if path.is_file() and path.name not in {"artifacts.json", "VERIFICATION_REPORT.md"}:
            data = path.read_bytes()
            source_files.append({"path": path.name, "length": len(data), "sha256": sha256(data)})

    ledger.add_bytes("chain1_envelope", inputs.chain1_envelope, "README.md SalPhaseIon AES Blob", "parsed two blockquote lines")
    ledger.add_bytes("chain2_envelope", inputs.chain2_envelope, "README.md Phase 3.2 small AES blob", "parsed two base64 lines")
    ledger.add_bytes("phase32_envelope", inputs.phase32_envelope, "README.md Phase 3.2", "parsed 51 base64 lines")
    ledger.add_bytes(
        "cosmic_envelope",
        inputs.cosmic_envelope,
        "solver/data/cosmic_duality.txt",
        "strict base64 decode",
        metadata={
            "public_source": "https://github.com/jackdevs66/GSMG5_CDuality/blob/8f47839/cosmic_duality.txt",
            "source_text_sha256": sha256(COSMIC_SOURCE.read_bytes()),
            "source_commit": "8f47839",
        },
    )
    for index, (token, digest) in enumerate(zip(sal.tokens, sal.digests), 1):
        ledger.add_text(f"salphaseion_token_{index}", token, "README.md SalPhaseIon source", "direct alphabet decode or explicitly labeled semantic reading")
        ledger.add_bytes(f"salphaseion_token_{index}_sha256", digest, f"salphaseion_token_{index}", "SHA-256 of raw lowercase UTF-8 token")
    ledger.add_bytes("salphaseion_seven_digest_xor", sal.xor_password, "seven token SHA-256 digests", "bytewise XOR")

    _record_decryption(ledger, "chain1", chains.chain1_decryption, "chain1_envelope")
    for name, value in (("K_C1", chains.chain1.key1), ("K_C2", chains.chain1.key2), ("E_C", chains.chain1.extension)):
        ledger.add_bytes(name, value, "chain1_plaintext", "32+32+15 sibling-consistent split")
    ledger.add_text("K_C1_uncompressed_wif", chains.chain1_wif, "K_C1", "Base58Check(0x80 || K_C1)")

    _record_decryption(ledger, "chain2", chains.chain2_decryption, "chain2_envelope")
    for name, value in (("K_S1", chains.chain2.key1), ("K_S2", chains.chain2.key2), ("E_S", chains.chain2.extension)):
        ledger.add_bytes(name, value, "chain2_plaintext", "32+32+15 sibling-consistent split")

    _record_decryption(ledger, "cosmic", chains.cosmic_decryption, "cosmic_envelope")
    for name, value in (
        ("K_B1", chains.cosmic_b.key1), ("K_B2", chains.cosmic_b.key2), ("E_B", chains.cosmic_b.extension),
        ("K_H1", chains.cosmic_h.key1), ("K_H2", chains.cosmic_h.key2), ("E_H", chains.cosmic_h.extension),
    ):
        ledger.add_bytes(name, value, "cosmic_plaintext", "two repeated 32+32+15 layouts confirmed by Chains 1 and 2")
    ledger.add_bytes("cosmic_remainder_1169", chains.cosmic_remainder, "cosmic_plaintext", "bytes 158:1327")

    ledger.add_bytes("chain4_trimmed_remainder", chain4.trimmed_remainder, "cosmic_remainder_1169", "drop final byte")
    ledger.add_bytes("chain4_embedded_envelope", chain4.embedded_envelope, "chain4_trimmed_remainder", "XOR repeating b657264f2f6e6921")
    _record_decryption(ledger, "chain4", chain4.decryption, "chain4_embedded_envelope")
    ledger.add_bytes("chain4_marker", chain4.marker, "chain4_plaintext", "bytes 0:2")
    ledger.add_bytes("chain4_operand", chain4.operand, "chain4_plaintext", "bytes 2:31; 29-byte operand/header remainder")
    ledger.add_bytes("chain4_opcode_operand", chain4.opcode_operand, "chain4_plaintext", "bytes 1:31; alternate one-byte-opcode parse")
    ledger.add_bytes("chain4_structured_prefix", chain4.structured_prefix, "chain4_plaintext", "bytes 0:31")
    ledger.add_bytes("chain4_blocks_region", b"".join(chain4.blocks), "chain4_plaintext", "bytes 31:1151; 35 aligned 32-byte blocks")
    for index, block in enumerate(chain4.blocks):
        ledger.add_bytes(f"chain4_block_{index:02d}", block, "chain4_blocks_region", f"block {index}, bytes {31 + 32*index}:{31 + 32*(index+1)}")
    ledger.add_bytes("chain4_tail_905", chain4.tail_905, "chain4_plaintext", "bytes 246:1151; reported garbled-section boundary")

    rows_json = json.dumps(matrix.row_sums, separators=(",", ":")).encode("ascii")
    cols_json = json.dumps(matrix.column_sums, separators=(",", ":")).encode("ascii")
    ledger.add_bytes("cosmic_row_sums_json", rows_json, "cosmic_plaintext", "MSB-first 103x103 matrix row sums")
    ledger.add_bytes("cosmic_column_sums_json", cols_json, "cosmic_plaintext", "MSB-first 103x103 matrix column sums")
    ledger.add_bytes("cosmic_trailing_7_bits", bytes(matrix.trailing_bits), "cosmic_plaintext", "bits 10609:10616, one byte per bit")
    ledger.add_bytes("cosmic_secondary_shift7", matrix.selected.secondary, "row and column sums", "row[i] + column[(i+7) mod 103]")
    ledger.add_bytes("cosmic_base38_digits", bytes(matrix.digits), "cosmic_secondary_shift7", "subtract 80 from each byte")
    ledger.add_bytes("cosmic_base38_output", matrix.base38_bytes, "cosmic_base38_digits", "big-endian positional base-38 integer to minimal bytes")
    ledger.add_bytes("Half", matrix.half, "cosmic_base38_output", "bytes 0:32")
    ledger.add_bytes("Better_Half", matrix.better_half, "cosmic_base38_output", "bytes 32:64")
    ledger.add_bytes("trail1", matrix.trail1, "cosmic_base38_output", "bytes 64:68")

    half_addresses = {
        "compressed": p2pkh_address(matrix.half, True),
        "uncompressed": p2pkh_address(matrix.half, False),
    }
    better_addresses = {
        "compressed": p2pkh_address(matrix.better_half, True),
        "uncompressed": p2pkh_address(matrix.better_half, False),
    }
    target_x = bytes.fromhex("f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464")
    target_candidates = addresses_for_x(target_x)

    frontier_path = ROOT / "frontier_experiment.json"
    if not frontier_path.exists():
        raise ValueError("run `python -m solver.frontier_experiment` before generating the final report")
    frontier_experiment = json.loads(frontier_path.read_text(encoding="utf-8"))
    if frontier_experiment["chain4_sha256"] != sha256(chain4.decryption.plaintext):
        raise ValueError("frontier experiment was run against a different Chain 4 artifact")
    ledger.add_bytes(
        "frontier_experiment_json",
        frontier_path.read_bytes(),
        "verified Chain 4 plus matrix-derived Half/Better Half/trail1",
        "bounded exact-public-point candidate audit",
    )
    triangle_path = ROOT / "xor_triangle_audit.json"
    if not triangle_path.exists():
        raise ValueError("run `python -m solver.xor_triangle_audit` before generating the final report")
    triangle_audit = json.loads(triangle_path.read_text(encoding="utf-8"))
    if triangle_audit["chain4_sha256"] != sha256(chain4.decryption.plaintext):
        raise ValueError("XOR-triangle audit was run against a different Chain 4 artifact")
    ledger.add_bytes(
        "xor_triangle_audit_json",
        triangle_path.read_bytes(),
        "verified 35-block Chain 4 region",
        "exhaustive serialized T8 missing-node recurrence audit",
    )
    splice_path = ROOT / "trail1_splice_experiment.json"
    if not splice_path.exists():
        raise ValueError("run `python -m solver.trail1_splice_experiment` before generating the final report")
    splice_experiment = json.loads(splice_path.read_text(encoding="utf-8"))
    if splice_experiment["chain4_sha256"] != sha256(chain4.decryption.plaintext):
        raise ValueError("trail1 splice experiment was run against a different Chain 4 artifact")
    ledger.add_bytes(
        "trail1_splice_experiment_json",
        splice_path.read_bytes(),
        "verified Chain 4 prefix/blocks plus matrix-derived trail1",
        "contiguous trail-byte operand-completion audit with exact target gate",
    )
    permutation_path = ROOT / "trail1_permutation_experiment.json"
    completed_triangle_path = ROOT / "chain4_completed_triangle.json"
    door2_path = ROOT / "door2_formula_audit.json"
    split_path = ROOT / "chain4_split_audit.json"
    l4_crib_path = ROOT / "l4_crib_audit.json"
    l4_beaufort_path = ROOT / "l4_beaufort_audit.json"
    phase32_classical_path = ROOT / "phase32_classical.json"
    prime_reinsertion_path = ROOT / "prime_reinsertion_audit.json"
    matrixsumlist_path = ROOT / "matrixsumlist_audit.json"
    salphaseion_instruction_path = ROOT / "salphaseion_instruction_audit.json"
    sfield_reduction_path = ROOT / "sfield_reduction_audit.json"
    wayback_source_path = ROOT / "wayback_source_audit.json"
    wayback_early_asset_path = ROOT / "wayback_early_asset_audit.json"
    combinatorial_path = ROOT / "chain4_combinatorial_audit.json"
    mitm_path = ROOT / "chain4_mitm_audit.json"
    signed_mitm_path = ROOT / "chain4_signed_mitm_audit.json"
    blockchain_nonce_path = ROOT / "blockchain_nonce_audit.json"
    xcoordinate_path = ROOT / "chain4_xcoordinate_audit.json"
    xor_subset_path = ROOT / "chain4_xor_subset_audit.json"
    product_subset_path = ROOT / "chain4_product_subset_audit.json"
    aes_integer_path = ROOT / "chain4_aes_integer_audit.json"
    efragment_path = ROOT / "efragment_scalar_audit.json"
    plusminus_grammar_path = ROOT / "chain4_plusminus_grammar_audit.json"
    phase32_symbol_recovery_path = ROOT / "phase32_symbol_recovery.json"
    decentraland_audio_path = ROOT / "decentraland_audio_audit.json"
    extra_experiments = {}
    for name, path, source, derivation in (
        ("trail1_permutation_experiment", permutation_path, "verified Chain 4 prefix/blocks plus matrix-derived trail1", "ordered non-repeating trail-byte completion audit"),
        ("chain4_completed_triangle", completed_triangle_path, "verified 31-byte Chain 4 prefix, 35 blocks, and trail1", "exhaustive direct serialized T8 XOR-triangle audit"),
        ("door2_formula_audit", door2_path, "public Issue #92 formula plus verified Half/Better Half", "explicit-encoding reproduction and exact target audit"),
        ("chain4_split_audit", split_path, "verified Chain 4 plaintext", "fixed-size deterministic permutation test of the reported entropy boundary"),
        ("l4_crib_audit", l4_crib_path, "public Issue #87 plaintext claims plus verified Chain 4 plaintext", "exact repeating-XOR crib constraint audit"),
        ("l4_beaufort_audit", l4_beaufort_path, "public Issue #87 wording plus verified Chain 4 plaintext", "bounded byte-domain Beaufort/Vigenere crib audit"),
        ("phase32_classical", phase32_classical_path, "verified Phase 3.2 plaintext plus published README classical-cipher parameters", "symbol-map consistency, Beaufort, and VIC checkerboard reproduction"),
        ("prime_reinsertion_audit", prime_reinsertion_path, "README SalPhaseIon prefix plus original puzzle.png grid", "one-indexed prime-position reinsertion and exact prize-point candidate audit"),
        ("matrixsumlist_audit", matrixsumlist_path, "authenticated SalPhaseIon S91 field plus original puzzle.png grid", "bounded exploratory matrix/sum/list family with exact prize-point candidate audit"),
        ("salphaseion_instruction_audit", salphaseion_instruction_path, "authenticated SalPhaseIon S91/S570 fields, original puzzle.png, and three OpenSSL envelopes", "bounded instruction-style matrix, route, alphabet, insertion, hash, and downstream-structure audit"),
        ("sfield_reduction_audit", sfield_reduction_path, "authenticated SalPhaseIon S91/S570 fields plus verified Chain 4 operand and blocks", "legacy grid-reduction reproduction plus corrected 29-byte serialization audit"),
        ("wayback_source_audit", wayback_source_path, "Wayback CDX snapshot plus raw id_ replay bodies", "content-addressed sequential public-source retrieval and unresolved-artifact scan"),
        ("wayback_early_asset_audit", wayback_early_asset_path, "verified Wayback CDX snapshot plus every selected 2019-2021 puzzle-adjacent capture", "content-addressed early page, script, map, style, and image retrieval and scan"),
        ("chain4_combinatorial_audit", combinatorial_path, "verified Chain 4 blocks plus authenticated seven-password phrase and reconstructed records", "C(7,3)/C(7,4) hash, multiset, and linear-algebra audit"),
        ("chain4_mitm_audit", mitm_path, "verified Chain 4 blocks, prefix operands, recovered K values, and Half/Better Half points", "checkpointed exhaustive point-space additive subset search"),
        ("chain4_signed_mitm_audit", signed_mitm_path, "verified Chain 4 blocks, both prefix operands, and Half/Better Half", "checkpointed exhaustive point-space search over every 35-block sign assignment"),
        ("blockchain_nonce_audit", blockchain_nonce_path, "confirmed Blockstream Esplora histories and independently parsed raw Bitcoin transactions", "complete P2PKH signature reconstruction, sighash verification, and known-nonce audit"),
        ("chain4_xcoordinate_audit", xcoordinate_path, "verified Chain 4 blocks, prefix operands, and Half/Better Half", "distinct-block secp256k1 x-coordinate lift and bounded point-relation audit"),
        ("chain4_xor_subset_audit", xor_subset_path, "verified Chain 4 blocks and 30-byte opcode operand", "checkpointed exhaustive 3/4/7-block XOR subset scalar audit"),
        ("chain4_product_subset_audit", product_subset_path, "verified Chain 4 blocks and 30-byte opcode operand", "checkpointed exhaustive 3/4/7-block modular-product scalar audit"),
        ("chain4_aes_integer_audit", aes_integer_path, "verified Chain 4 blocks, recovered K values, token digests, passwords, and prefix forms", "bounded AES-256 layer, whole-integer, and selector audit"),
        ("efragment_scalar_audit", efragment_path, "four recovered 15-byte E fields, eight recovered K values, and verified Chain 4 forms", "deduplicated fragment serialization and scalar-operation audit"),
        ("chain4_plusminus_grammar_audit", plusminus_grammar_path, "verified Chain 4 envelope, four E fragments, marker, operand, and blocks", "bounded strict-padding and exact-point audit of the explicit plus-minus grammar family"),
        ("phase32_symbol_recovery", phase32_symbol_recovery_path, "authenticated Phase 3.2 raw symbol record and separately clued Beaufort key", "76-letter Architect crib plus generic English ranking of the six residual symbol assignments"),
        ("decentraland_audio_audit", decentraland_audio_path, "immutable Decentraland scene entity and original puzzlepiece.mp3 content IDs", "CID verification, active parcel association, stereo channel subtraction, and spectrogram reproduction"),
    ):
        if not path.exists():
            raise ValueError(f"run `python -m solver.{path.stem}` before generating the final report")
        experiment = json.loads(path.read_text(encoding="utf-8"))
        if experiment["chain4_sha256"] != sha256(chain4.decryption.plaintext) if "chain4_sha256" in experiment else False:
            raise ValueError(f"{name} was run against a different Chain 4 artifact")
        ledger.add_bytes(f"{name}_json", path.read_bytes(), source, derivation)
        extra_experiments[name] = experiment

    wayback_audit = extra_experiments["wayback_source_audit"]
    cdx_snapshot_path = ROOT / wayback_audit["cdx"]["snapshot_path"]
    cdx_snapshot = cdx_snapshot_path.read_bytes()
    if sha256(cdx_snapshot) != wayback_audit["cdx"]["snapshot_sha256"]:
        raise ValueError("Wayback CDX snapshot does not match the source-audit manifest")
    ledger.add_bytes(
        "wayback_cdx_snapshot",
        cdx_snapshot,
        wayback_audit["cdx"]["query_url"],
        "raw CDX JSON response used to select the 64 primary and five supplementary targets",
        write=False,
    )

    decentraland_audio = extra_experiments["decentraland_audio_audit"]
    audio_artifacts = (
        ("decentraland_entity", "artifacts/audio_audit/entity.json", decentraland_audio["entity"]["sha256"], decentraland_audio["entity"]["cid"]),
        ("decentraland_scene", "artifacts/audio_audit/scene.json", decentraland_audio["scene"]["sha256"], decentraland_audio["scene"]["cid"]),
        ("decentraland_game", "artifacts/audio_audit/game.js", decentraland_audio["game"]["sha256"], decentraland_audio["game"]["cid"]),
        ("decentraland_puzzlepiece_mp3", "artifacts/audio_audit/puzzlepiece.mp3", decentraland_audio["audio"]["sha256"], decentraland_audio["audio"]["cid"]),
        ("decentraland_channel_difference", decentraland_audio["reproduction"]["channel_difference_wav"], decentraland_audio["reproduction"]["channel_difference_sha256"], "left minus right channel"),
        ("decentraland_spectrogram", decentraland_audio["reproduction"]["spectrogram"], decentraland_audio["reproduction"]["spectrogram_sha256"], "full channel-difference spectrogram"),
        ("decentraland_text_spectrogram", decentraland_audio["reproduction"]["text_spectrogram"], decentraland_audio["reproduction"]["text_spectrogram_sha256"], "1-9 kHz channel-difference spectrogram"),
    )
    for name, relative_path, expected_sha256, derivation in audio_artifacts:
        path = ROOT / relative_path
        body = path.read_bytes()
        if sha256(body) != expected_sha256:
            raise ValueError(f"Decentraland audio artifact {name} differs from its audit manifest")
        ledger.add_bytes(
            name,
            body,
            decentraland_audio["official_content_server"],
            derivation,
            write=False,
        )

    mitm_audit = extra_experiments["chain4_mitm_audit"]
    checkpoint_manifests = {
        "synthetic_positive_control": mitm_audit["engine"]["synthetic_positive_control"],
        **mitm_audit["families"],
    }
    for checkpoint_name, expected_manifest in checkpoint_manifests.items():
        checkpoint_path = ROOT / "artifacts" / "mitm_checkpoints" / f"{checkpoint_name}.json"
        checkpoint_bytes = checkpoint_path.read_bytes()
        if json.loads(checkpoint_bytes) != expected_manifest:
            raise ValueError(f"MITM checkpoint {checkpoint_name} differs from the aggregate audit")
        ledger.add_bytes(
            f"mitm_checkpoint_{checkpoint_name}",
            checkpoint_bytes,
            "solver.chain4_mitm_audit",
            "terminal checkpoint with input digest, exact half-space counts, cursor, and collision manifest",
            write=False,
        )

    signed_mitm_audit = extra_experiments["chain4_signed_mitm_audit"]
    signed_checkpoint_manifests = {
        "signed_synthetic_positive_control": None,
        "S1_signed_blocks35_literal_constants": signed_mitm_audit["families"]["S1_literal"],
        "S2_signed_blocks35_half_better_constants": signed_mitm_audit["families"]["S2_cross_branch"],
    }
    for checkpoint_name, expected_manifest in signed_checkpoint_manifests.items():
        checkpoint_path = ROOT / "artifacts" / "mitm_checkpoints" / f"{checkpoint_name}.json"
        checkpoint_bytes = checkpoint_path.read_bytes()
        checkpoint_manifest = json.loads(checkpoint_bytes)
        if expected_manifest is not None and checkpoint_manifest != expected_manifest:
            raise ValueError(f"signed MITM checkpoint {checkpoint_name} differs from the aggregate audit")
        ledger.add_bytes(
            f"signed_mitm_checkpoint_{checkpoint_name}",
            checkpoint_bytes,
            "solver.chain4_signed_mitm_audit",
            "terminal checkpoint for the signed-block reduction and exact point-space gate",
            write=False,
        )

    xor_subset_audit = extra_experiments["chain4_xor_subset_audit"]
    for family_name, family in xor_subset_audit["families"].items():
        for expected_manifest in family["partitions"]:
            first = expected_manifest["first_block_index"]
            checkpoint_path = ROOT / "artifacts" / "xor_subset_checkpoints" / f"{family_name}_first_{first:02d}.json"
            checkpoint_bytes = checkpoint_path.read_bytes()
            if json.loads(checkpoint_bytes) != expected_manifest:
                raise ValueError(f"XOR-subset checkpoint {family_name}/{first} differs from the aggregate audit")
            ledger.add_bytes(
                f"xor_subset_checkpoint_{family_name}_{first:02d}",
                checkpoint_bytes,
                "solver.chain4_xor_subset_audit",
                "terminal first-index partition with exact combination count and candidate-stream digest",
                write=False,
            )

    product_subset_audit = extra_experiments["chain4_product_subset_audit"]
    for family_name, family in product_subset_audit["families"].items():
        for expected_manifest in family["partitions"]:
            first = expected_manifest["first_block_index"]
            checkpoint_path = ROOT / "artifacts" / "product_subset_checkpoints" / f"{family_name}_first_{first:02d}.json"
            checkpoint_bytes = checkpoint_path.read_bytes()
            if json.loads(checkpoint_bytes) != expected_manifest:
                raise ValueError(f"product-subset checkpoint {family_name}/{first} differs from the aggregate audit")
            ledger.add_bytes(
                f"product_subset_checkpoint_{family_name}_{first:02d}",
                checkpoint_bytes,
                "solver.chain4_product_subset_audit",
                "terminal first-index partition with exact combination count and candidate-stream digest",
                write=False,
            )

    blockchain_audit = extra_experiments["blockchain_nonce_audit"]
    for address, history in blockchain_audit["address_histories"].items():
        for page_index, record in enumerate([history["summary"], *history["pages"]]):
            body = (ROOT / record["path"]).read_bytes()
            if sha256(body) != record["sha256"]:
                raise ValueError(f"blockchain source-cache hash mismatch for {address} page {page_index}")
            ledger.add_bytes(
                f"blockchain_page_{address}_{page_index:02d}",
                body,
                record["request"],
                "content-addressed Esplora JSON response",
                write=False,
            )
    for raw_record in blockchain_audit["corpus"]["raw_transactions"]:
        raw = (ROOT / raw_record["path"]).read_bytes()
        if len(raw) != raw_record["length"] or sha256(raw) != raw_record["sha256"] or not raw_record["txid_verified"]:
            raise ValueError(f"raw transaction manifest mismatch for {raw_record['txid']}")
        ledger.add_bytes(
            f"bitcoin_raw_tx_{raw_record['txid']}",
            raw,
            f"{blockchain_audit['source']['api']}/tx/{raw_record['txid']}/raw",
            "immutable raw transaction with independently verified txid",
            write=False,
        )
    for signature_index, signature in enumerate(blockchain_audit["corpus"]["signatures"]):
        if signature["preimage_path"] is None:
            continue
        preimage = (ROOT / signature["preimage_path"]).read_bytes()
        if len(preimage) != signature["preimage_length"] or sha256(preimage) != signature["preimage_sha256"]:
            raise ValueError(f"sighash preimage manifest mismatch for {signature['txid']}:{signature['vin']}")
        ledger.add_bytes(
            f"bitcoin_sighash_preimage_{signature_index:03d}",
            preimage,
            f"{signature['txid']} input {signature['vin']} plus validated prevout {signature['prev_txid']}:{signature['prev_vout']}",
            f"legacy sighash type {signature['sighash_type']} serialization",
            write=False,
        )

    phase32_password = b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
    phase32 = decrypt_salted_aes256_cbc(inputs.phase32_envelope, phase32_password, digest="sha256")
    if not phase32.plaintext.startswith(b"I've been waiting for you."):
        raise ValueError("earlier Phase 3.2 positive control did not yield documented plaintext")
    _record_decryption(ledger, "phase32_positive_control", phase32, "phase32_envelope")

    # Base 39 is a concrete falsification control: it also yields 68 bytes, but not the known addresses.
    base39 = base_digits_to_bytes(matrix.digits, 39)
    base39_half = base39[:32]
    base39_control = {
        "length": len(base39),
        "sha256": sha256(base39),
        "half_compressed_address": p2pkh_address(base39_half, True),
        "matches_reported_half": p2pkh_address(base39_half, True) == half_addresses["compressed"],
    }

    payload = {
        "schema_version": 1,
        "generated_by": "python -m solver.report",
        "source_files": source_files,
        "artifacts": ledger.records,
        "salphaseion": {
            "directly_decoded": sal.directly_decoded,
            "semantic_or_fitted": sal.semantic_tokens,
            "tokens": sal.tokens,
        },
        "matrix": {
            "total_bits": len(matrix.bits),
            "matrix_bits": len(matrix.matrix_bits),
            "trailing_bits": matrix.trailing_bits,
            "S": matrix.total_ones,
            "Wr": matrix.weighted_rows,
            "Wc": matrix.weighted_columns,
            "range_80_117_shift_count": len(matrix.range_candidates),
            "range_80_117_shifts": [candidate.shift for candidate in matrix.range_candidates],
            "exact_80_117_shifts": [candidate.shift for candidate in matrix.exact_range_candidates],
            "selected_shift": matrix.selected.shift,
            "base38_is_minimal_valid_base": max(matrix.digits) == 37,
            "base39_68_byte_control": base39_control,
        },
        "addresses": {
            "Half": half_addresses,
            "Better_Half": better_addresses,
            "K_C1_uncompressed_wif": chains.chain1_wif,
            "target_x_coordinate_candidates": [
                {"y_parity": parity, "address": address, "y": y} for parity, address, y in target_candidates
            ],
        },
        "public_occurrences": PUBLIC_OCCURRENCES,
        "public_audit": {
            "audit_date": "2026-08-03",
            "canonical_remote": "https://github.com/puzzlehunt/gsmgio-5btc-puzzle",
            "canonical_master_commit": "fb92dd15487c6e2d275adb8c923698b7166c328e",
            "workspace_has_git_metadata": False,
            "pr_heads_inspected": {
                "68": "27ea50eb0544baa6b99f145e9ea51c110010abf4",
                "93": "2c97f4472bda49f983f3b2fb3da454e665d57e6e",
            },
            "public_forks_shallow_cloned_and_scanned": 70,
            "issue_attachment_urls_found": 61,
            "issue_attachments_downloaded": 60,
            "issue_attachment_unique_sha256": 32,
            "attachment_missing": "https://github.com/user-attachments/assets/767b648e-d6dc-4c1c-a135-c177d16f1df0",
            "raw_attachment_term_hits": 0,
            "wayback_cdx_collapsed_capture_rows": wayback_audit["cdx"]["collapsed_capture_rows"],
            "wayback_cdx_global_unique_digest_values": wayback_audit["cdx"]["global_unique_digest_values"],
            "wayback_cdx_unique_original_urls": wayback_audit["cdx"]["unique_original_urls"],
            "wayback_octet_streams": [
                "css/app.css.map",
                "fonts/lato-regular-webfont.woff2",
                "js/app.js.map",
                "js/manifest.js.map",
                "js/vendor.js.map",
            ],
            "archived_key_page_capture_dates_inspected": ["20230601222752", "20231127181947", "20241123015038", "20251112043757", "20260405154227"],
            "wayback_primary_targets": wayback_audit["cdx"]["primary_target_count"],
            "wayback_supplementary_targets": wayback_audit["cdx"]["supplementary_octet_stream_count"],
            "wayback_retrieval_successes": wayback_audit["retrieval"]["success_count"],
            "wayback_retrieval_failures": wayback_audit["retrieval"]["failure_count"],
            "wayback_cdx_digest_verified": wayback_audit["retrieval"]["cdx_digest_verified_count"],
            "wayback_early_capture_rows": extra_experiments["wayback_early_asset_audit"]["cdx"]["selected_capture_rows"],
            "wayback_early_unique_digests": extra_experiments["wayback_early_asset_audit"]["cdx"]["selected_unique_digests"],
            "wayback_early_digest_verified": extra_experiments["wayback_early_asset_audit"]["retrieval"]["cdx_digest_verified_count"],
            "archive_limit": None,
            "result": "No bytes, full hash, length, or derivation for cosmic_A/ca, row1-4, or K_I1 were located.",
        },
        "frontier_experiment": frontier_experiment,
        "xor_triangle_audit": triangle_audit,
        "trail1_splice_experiment": splice_experiment,
        **extra_experiments,
        "unresolved_frontier": unresolved_frontier(),
    }
    JSON_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    REPORT_PATH.write_text(_markdown(payload, chains, chain4, matrix, phase32), encoding="utf-8")
    return payload


def _markdown(payload: dict[str, Any], chains: Any, chain4: Any, matrix: Any, phase32: Any) -> str:
    target = next(item for item in payload["addresses"]["target_x_coordinate_candidates"] if item["address"] == "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
    return f"""# GSMG.IO 5 BTC Puzzle Verification Report

Generated deterministically by `python -m solver.report` from the checked-in README/images plus the provenance-recorded Cosmic ciphertext in `solver/data/cosmic_duality.txt`.

## Result

The public chain is reproduced through Chain 4 and the independent 103x103 interpretation. The prize private key is **not** derived. The precise public frontier remains the absence of reproducible bytes or rules for `cosmic_A`/`ca`, `row1-4`, and `K_I1`.

## Confirmed stages

| Stage | Length | SHA-256 / value |
|---|---:|---|
| Seven-token digest XOR | 32 | `{chains.cosmic_decryption.password.hex()}` |
| Chain 1 plaintext | {len(chains.chain1_decryption.plaintext)} | `{sha256(chains.chain1_decryption.plaintext)}` |
| K_C1 uncompressed WIF | 51 chars | `{chains.chain1_wif}` |
| Chain 2 plaintext | {len(chains.chain2_decryption.plaintext)} | `{sha256(chains.chain2_decryption.plaintext)}` |
| Cosmic plaintext | {len(chains.cosmic_decryption.plaintext)} | `{sha256(chains.cosmic_decryption.plaintext)}` |
| Cosmic remainder | {len(chains.cosmic_remainder)} | `{sha256(chains.cosmic_remainder)}` |
| Masked embedded envelope | {len(chain4.embedded_envelope)} | `{sha256(chain4.embedded_envelope)}` |
| Chain 4 plaintext | {len(chain4.decryption.plaintext)} | `{sha256(chain4.decryption.plaintext)}` |
| Chain 4 tail at byte 246 | {len(chain4.tail_905)} | `{sha256(chain4.tail_905)}` |
| Base-38 output | {len(matrix.base38_bytes)} | `{sha256(matrix.base38_bytes)}` |

The four advanced AES layers use the exact legacy OpenSSL convention: `Salted__`, an 8-byte salt, MD5 `EVP_BytesToKey`, AES-256-CBC, and strict PKCS#7 validation. The earlier Phase 3.2 blob is a version-sensitive positive control: it requires the OpenSSL 1.1.0+ SHA-256 EVP default and decrypts to {len(phase32.plaintext)} bytes beginning `I've been waiting for you.` The digest is therefore explicit at every call site.

## Phase 3.2 classical stages and layer ownership

The Phase 3.2 plaintext contains a 1,539-byte, 26-symbol record at offset 447 and a separate 149-digit record. The symbol layer is no longer accepted merely from the published table. A 76-letter Matrix Architect opening crib fixes {payload['phase32_symbol_recovery']['crib_fixed_symbol_count']}/26 assignments without conflict; only {payload['phase32_symbol_recovery']['residual_candidate_count']} residual permutations remain. A generic English trigram/quadgram model built from wordfreq {payload['phase32_symbol_recovery']['model']['version']} ranks the winning assignment by a score margin of {payload['phase32_symbol_recovery']['best_score_margin']:.3f}, before the published mapping is consulted. The recovered map then agrees {payload['phase32_symbol_recovery']['published_mapping_agreement']}/{payload['phase32_symbol_recovery']['published_mapping_size']} with the published map and yields plaintext SHA-256 `{payload['phase32_symbol_recovery']['plaintext_sha256']}`. From that independently recovered boundary onward the solver reproduces:

- Beaufort with key `THEMATRIXHASYOU`: 1,539 letters, SHA-256 `{payload['phase32_classical']['beaufort']['plaintext_sha256']}`.
- VIC straddling checkerboard with alphabet `{payload['phase32_classical']['vic']['alphabet']}` and row digits `1,4`: `{payload['phase32_classical']['vic']['plaintext']}`.

Crucially, `TAKE THE PRIVATE KEY`, `REINSERTING THE PRIME BASICS`, and final `CIAO BELLA O` belong to this authenticated Phase 3.2.1 Architect message. They are not newly recovered Chain 4 plaintext. Issue #87's “all of it” wording enumerates earlier puzzle stages and does not specify Beaufort as the Chain 4 cipher.

## SalPhaseIon evidence boundary

`matrixsumlist`, `enter`, `lastwordsbeforearchichoice`, and `thispassword` are decoded mechanically from the raw SalPhaseIon line in `README.md`. Reusing `matrixsumlist` as token 5 and reading `yourlastcommand` / `secondanswer` are semantic or fitted steps. Their combination gains strong downstream support because it produces two sibling 79-byte `32+32+15` structures, the documented WIF, another sibling 79-byte structure, a repeated pair of structures in Cosmic, and the Chain 4 embedded `Salted__` header and exact hash. This is substantially stronger than padding success alone, but it is not a creator-authored token proof.

The instruction-style hypothesis has now been tested directly rather than rejected semantically. First, its quoted original-grid transcription is incorrect: authenticated pixel sampling gives row sums `{payload['salphaseion_instruction_audit']['source_corrections']['verified_row_sums']}`, column sums `{payload['salphaseion_instruction_audit']['source_corrections']['verified_column_sums']}`, total {payload['salphaseion_instruction_audit']['source_corrections']['verified_total_ones']}, and blue=1/yellow=0 stream `{payload['salphaseion_instruction_audit']['source_corrections']['verified_colored_bits_blue1_yellow0']}` (`{payload['salphaseion_instruction_audit']['source_corrections']['verified_colored_hex']}`), not total 101 / `F73D92`. Both authentic and supplied variants were nevertheless retained. The bounded construction generated {payload['salphaseion_instruction_audit']['candidate_family']['unique_preimages']:,} unique preimages from S91/S570 layouts, row/column/diagonal sums, all rectangular symmetries and four route families, `matrixsumlist` column ordering/weighting, S570 indexing, the 26-character `lastwords...` key/alphabet readings, five checkerboard row-pairs, `enter` insertions, last-bit reuse, access-loop strings, and Half/Better-Half forms. Raw, SHA-256, hex, and double-hash spellings expand these to {payload['salphaseion_instruction_audit']['candidate_family']['unique_password_bytes']:,} distinct password byte strings, each tested under MD5 and SHA-256 against all three envelopes.

At this scale padding behaves exactly like noise: {payload['salphaseion_instruction_audit']['strict_padding_hit_counts']['chain1']:,} short-blob, {payload['salphaseion_instruction_audit']['strict_padding_hit_counts']['chain2-direct']:,} direct small-blob, and {payload['salphaseion_instruction_audit']['strict_padding_hit_counts']['cosmic']:,} Cosmic hits from {payload['salphaseion_instruction_audit']['candidate_family']['decryptions_per_envelope']:,} decryptions per envelope. Thirteen short-blob candidates also pass small-blob padding after WIF derivation. Only one reaches the exact 1151-byte `+-` plus 35-block Chain 4 structure: the already-published five-token MD5 password; zero non-control candidates do. Cosmic likewise has exactly one Chain 4 structure hit, the canonical seven-digest-XOR control, and zero non-control hits. No candidate SHA-256 or 32-byte spelling derives the prize point. Thus this enumerated instruction reading is negative, while the published path is demonstrably more than a padding-only false positive.

The seven-token XOR is `{chains.cosmic_decryption.password.hex()}`. The Cosmic AES key is `{chains.cosmic_decryption.key.hex()}` and IV is `{chains.cosmic_decryption.iv.hex()}`.

## Chain parsing

Chains 1 and 2 independently decrypt to 79 bytes, exactly `32 + 32 + 15`. The first 158 Cosmic bytes repeat that layout twice, leaving exactly 1169 bytes. This repeated byte structure and the fact that `E_C || E_S || E_B[:2]` exposes a valid embedded OpenSSL envelope justify the labels `K_C*`, `K_S*`, `K_B*`, and `K_H*`; they were not imposed merely because slices were printable.

Chain 4 has an exact 31-byte prefix followed by 35 aligned 32-byte blocks:

- marker `[0:2]`: `+-`
- operand/header remainder `[2:31]`: `{chain4.operand.hex()}` (29 bytes)
- alternate opcode parse: `+` at `[0:1]`, then `{chain4.opcode_operand.hex()}` at `[1:31]` (30 bytes)
- block region `[31:1151]`: 1120 bytes = 35 x 32

The offsets and alignment are exact; the semantics are not. Nothing public selects the two-byte `+-` marker plus 29-byte operand over the one-byte `+` opcode plus 30-byte operand. The often-reported 905-byte tail is a separate observed boundary at `[246:1151]`; it does not align with the 31-byte/32-byte structural split.

## 103x103 interpretation

The 1327 bytes are 10616 MSB-first bits: 10609 matrix bits and trailing bits `{''.join(map(str, matrix.trailing_bits))}`. Invariants reproduce as `S={matrix.total_ones}`, `Wr={matrix.weighted_rows}`, and `Wc={matrix.weighted_columns}`.

Exhausting all 103 cyclic column shifts finds {len(matrix.range_candidates)} shifts whose sums stay within 80..117: `{', '.join(str(candidate.shift) for candidate in matrix.range_candidates)}`. Shift 7 is the **only** shift that attains the full exact range 80..117. Thus `+7` is selected by a specific invariant, but the broader printable-range test alone is not unique.

Subtracting 80 produces digits 0..37, making 38 the smallest valid positional base. Base 39 also produces 68 bytes, so output length alone does not uniquely prove base 38; base 38 is the canonical minimal-base choice and is independently checked by both published addresses.

- Half: `{matrix.half.hex()}` -> `{payload['addresses']['Half']['compressed']}`
- Better Half: `{matrix.better_half.hex()}` -> `{payload['addresses']['Better_Half']['compressed']}`
- trailing bytes / `trail1`: `{matrix.trail1.hex()}`

## Prize public key

The reported x-coordinate is on secp256k1. Its odd-y root is `{target['y']}` and independently hashes as an uncompressed public key to the exact prize address `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`. This validates the public point, not knowledge of its private scalar.

## Failed or unavailable claims

- The older 79-byte SHA-256 claim `e2590f15...` is refuted for the README Chain 1 blob. The reproduced hash is `{sha256(chains.chain1_decryption.plaintext)}`.
- `cosmic_A` is known only by the reported prefix `cd3fea3d...`; no bytes, full SHA-256, length, or reproducible derivation were found.
- `ca[280:312]`, `row1-4`, and `K_I1` have no public reproducible definition in the inspected canonical history, PR material, or issue evidence.
- `k_new = cc[833:865] XOR ca[280:312]` is therefore not executable. A claimed vanity-prefix match is not accepted as evidence.
- No tested or reported step here yields a private scalar whose public key equals the prize point.
- The exact serialized eight-row missing-node recurrence `parent[j] = child[j] XOR child[j+1]` has been independently rerun over 18,432 layouts; it has zero internally consistent survivors. This falsifies that finite interpretation, not the undefined general phrase “XOR triangle.”
- Completing the raw 31-byte Chain 4 prefix with each single `trail1` byte creates exactly 36 words, but all {payload['chain4_completed_triangle']['attempted_layouts']} serialized T8 layouts violate the XOR recurrence; the best layouts still fail all {payload['chain4_completed_triangle']['minimum_nonzero_residuals']} equations.
- The July 2026 `Door-2 LCP7` comment is ambiguous. Its literal lowercase ASCII-hex-text interpretation reproduces target-x LCP{payload['door2_formula_audit']['literal_lowercase_ascii_hex_lcp']}, not LCP7, and no audited encoding matches the target.
- The reported 246/905 entropy contrast is not a structural discriminator: a 10,000-permutation fixed-split test gives one-sided `p={payload['chain4_split_audit']['one_sided_permutation_p_value']:.3f}`. The observed entropy gap is almost exactly the random-partition mean and byte 246 is not aligned to the 31+32-byte structure.
- As a bounded falsification despite the layer mismatch, the Issue #87 phrases were tested across every Chain 4 offset and periods 1..64 under repeating XOR and three byte-domain Beaufort/Vigenere conventions. Every model has zero pairs agreeing on four shared key bytes. This does not test the authentic alphabetic Phase 3.2 Beaufort stage, which is reproduced separately.

## Provenance of unresolved terms

- “XOR triangle”: earliest immutable public comment located, 2025-12-25, [PR #68 comment](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/pull/68#issuecomment-3691156333); no formula.
- `K_I1`: earliest visible occurrence located, 2026-03-13, [Issue #87](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/87); claimed but not disclosed.
- `cosmic_A`, `ca`, `row1-4`, and the slice formula: earliest currently visible occurrence located in the editable body of [Issue #88](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/88), timestamped 2026-03-29. Because issue bodies can be edited, that timestamp is an earliest-visible bound, not proof that every line appeared on creation.
- `trail1`: the same editable Issue #88 body is the earliest visible label occurrence. Unlike the other terms, its four bytes are independently reproduced as the tail of the 68-byte matrix output: `fc0c1b02`, SHA-256 `bbf54842988b73cba4273885954b9d9a95d736f0454b55d2d90942fabc6c5ca4`.

## Precise current frontier

The reproducible public state ends with two independently verified branches: Chain 4 (`e4269ed5...`) and the matrix-derived Half/Better Half pair. There is no public, complete operand connecting either branch to the prize scalar. `cosmic_A`/`ca`, the definition of `row1-4`, and the derivation of `K_I1` remain unavailable.

The new bounded cross-branch experiment tested every one of the {payload['frontier_experiment']['window_count']} contiguous 32-byte Chain 4 windows under direct, XOR, modular addition/subtraction, and ordered SHA-256 composition with {payload['frontier_experiment']['constant_count']} verified constants derived from Half, Better Half, `trail1`, and both prefix parses. It generated {payload['frontier_experiment']['generated_candidates']} candidates ({payload['frontier_experiment']['unique_nonzero_scalars']} unique nonzero scalars) and found zero exact target-point matches. This falsifies only that enumerated family.

The queued contiguous `trail1` splice experiment is also complete. It formed {payload['trail1_splice_experiment']['word_count']} exact 32-byte completions of the 29-byte and 30-byte prefix operands and tested them standalone and under four operations with all {payload['trail1_splice_experiment']['block_count']} aligned blocks. All {payload['trail1_splice_experiment']['generated_candidates']} generated candidates were unique nonzero scalars; none matched the full target point or address.

The ordered non-repeating extension formed {payload['trail1_permutation_experiment']['word_count']} prefix completions and tested {payload['trail1_permutation_experiment']['generated_candidates']} unique nonzero scalars, again with zero matches. The more structural one-byte completion produced an exact 36-word T8-sized record, but none of its {payload['chain4_completed_triangle']['attempted_layouts']} row-order/orientation layouts satisfies even one complete XOR-triangle recurrence.

The public L4 phrases `REINSERTING THE PRIME BASICS`, `please take the private key`, and `CIAO BELLA O` also fail as exact repeating-XOR cribs over the complete Chain 4 record: {payload['l4_crib_audit']['consistent_crib_pairs']} mutually consistent pairs and {payload['l4_crib_audit']['unique_full_period_keys']} recovered full-period keys.

All three literal byte-domain Beaufort/Vigenere modes likewise yield zero consistent crib pairs. More importantly, the phrases are now deterministically assigned to Phase 3.2 rather than Chain 4, removing the claimed L4 crib route from the evidence-backed frontier.

The literal authenticated prime-reinsertion route is now exhausted for its explicit finite family. The README supplies a {payload['prime_reinsertion_audit']['source']['prefix_length']}-symbol prefix, while direct image sampling finds {payload['prime_reinsertion_audit']['source']['blue_count']} blue and {payload['prime_reinsertion_audit']['source']['yellow_count']} yellow cells, exactly matching the {payload['prime_reinsertion_audit']['prime_count']} one-indexed prime positions in 1..91. As a positive control, the same sampled bit grid spirals to `{payload['prime_reinsertion_audit']['source']['spiral_ascii']}`. The audit generated {payload['prime_reinsertion_audit']['inserted_stream_records']} reinsertion records, {payload['prime_reinsertion_audit']['decoded_byte_records']} byte decodings, and {payload['prime_reinsertion_audit']['scalar_candidate_records']} scalar candidate records ({payload['prime_reinsertion_audit']['unique_nonzero_scalars']} unique nonzero scalars). None derives the full prize point; the instruction is authentic, but the enumerated stream/offset interpretations remain exploratory.

The bounded `matrixsumlist` model is also exact-gated. Its 8 grid symmetries, 3 row statistics, 6 pair/interval list constructions, 2 equivalent positive-integer mod-9 spellings, 6 triangle traversals, and 3 arithmetic combinations produce {payload['matrixsumlist_audit']['structural_hypotheses']} structural hypotheses and {payload['matrixsumlist_audit']['base9_output_records']} base-9 outputs. No generated key equals the authentic S91 field; the best agrees at only {payload['matrixsumlist_audit']['maximum_generated_key_equalities_of_91']}/91 positions. Hashing the explicit digit and byte serializations yields {payload['matrixsumlist_audit']['scalar_candidate_records']} scalar records ({payload['matrixsumlist_audit']['unique_nonzero_scalars']} unique nonzero scalars), with zero target-point matches. This family is exploratory: `matrixsumlist` is authentic, but these transformations are not creator-documented.

The unused authenticated S570 field is now extracted directly at symbols 195..764 before the first `z`: length {payload['sfield_reduction_audit']['authenticated_inputs']['s570_length']}, SHA-256 `{payload['sfield_reduction_audit']['authenticated_inputs']['s570_sha256']}`. The independent port exactly reproduces the prior {payload['sfield_reduction_audit']['legacy_reproduction']['R1_lists30']} 30-value lists and {payload['sfield_reduction_audit']['legacy_reproduction']['R2_unique_nonzero_scalars']} unique selector/sign-fold scalars. It also identifies two dead legacy branches: 30 selectors cannot permute all 35 blocks, and a 30-byte record cannot equal the 29-byte magnitude. The corrected audit therefore enumerates {payload['sfield_reduction_audit']['corrected_extension']['lists29']} properly sized lists and {payload['sfield_reduction_audit']['corrected_extension']['serialization_candidate_records']} direct/hash/prefix serialization records. Across both legacy and corrected families, {payload['sfield_reduction_audit']['combined_unique_nonzero_scalars']} unique nonzero scalars yield zero exact target-point matches.

The exact `35 = C(7,3) = C(7,4)` coincidence is now structurally audited against the authenticated “seven intertwined passwords” phrase. The 48 explicit raw-token/digest/separator/order models generate {payload['chain4_combinatorial_audit']['explicit_triple_hash_family']['generated_hash_records']} hashes, but none equals even one Chain 4 block; flexible bipartite coverage is {payload['chain4_combinatorial_audit']['explicit_triple_hash_family']['maximum_flexible_bipartite_assignment']}/35. After removing 18 duplicate digest-representation comparisons from the older loop, all {payload['chain4_combinatorial_audit']['legacy_multiset_reproduction']['unique_comparisons']} unique C(7,3)/C(7,4) sum/XOR multiset comparisons are negative. More decisively, the 35 blocks have GF(2) rank {payload['chain4_combinatorial_audit']['linear_algebra']['block_gf2_rank']} (rank {payload['chain4_combinatorial_audit']['linear_algebra']['block_plus_operand_gf2_rank']} with the operand), so they cannot be XOR combinations of any seven latent vectors under any assignment. The natural lexicographic triple-sum system is also inconsistent over the curve order: coefficient rank {payload['chain4_combinatorial_audit']['linear_algebra']['natural_incidence_coefficient_rank_mod_n']}, augmented rank {payload['chain4_combinatorial_audit']['linear_algebra']['natural_triple_sum_augmented_rank_mod_n']}. No block-order scalar search is inferred from a nonexistent structural assignment.

The additive-selection route is now independently closed in point space. A libsecp256k1 Gray-code MITM engine first agrees with the independent package scalar multiplier and recovers the planted synthetic subset `[0,3,7,11]`. Its terminal checkpoints then exhaust M1 (`2^35` block subsets x 7 prefix shifts), M2/M3 (each `2^36` with the operand or magnitude), M4 (`2^43` over blocks plus eight recovered K values), and M5 (`2^35` x 9 Half/Better-Half point shifts). These represent {payload['chain4_mitm_audit']['total_logical_candidate_space']} logical subset/shift evaluations; all half tables have zero point collisions and every family has zero matches. This is a complete negative certificate for additive subsets of those explicit scalar sets and shifts, not for non-additive operations.

The literal signed-block reading of the `+-` marker is also exhaustively closed. The identity `c + sum(s_i*b_i) = c - sum(b_i) + sum_{{i in A}}(2*b_i)` reduces every one of the `2^35` sign assignments to the same checkpointed point-space MITM. S1 tests all {payload['chain4_signed_mitm_audit']['literal_constant_count']} zero/prefix/operand constants ({payload['chain4_signed_mitm_audit']['families']['S1_literal']['logical_candidate_space']} logical assignments), while S2 tests all {payload['chain4_signed_mitm_audit']['cross_branch_constant_count']} signed Half/Better-Half combinations ({payload['chain4_signed_mitm_audit']['families']['S2_cross_branch']['logical_candidate_space']}). A planted signed pattern is recovered, both real families have zero point collisions, and neither reaches the prize point. This does not cover omitted blocks or an unavailable external operand.

## Blockchain signature and nonce audit

At Bitcoin tip `{payload['blockchain_nonce_audit']['chain_snapshot']['tip_height']}` (`{payload['blockchain_nonce_audit']['chain_snapshot']['tip_hash']}`), the confirmed histories of the prize address and the two component addresses independently yield {payload['blockchain_nonce_audit']['corpus']['signature_count']} P2PKH signatures in {payload['blockchain_nonce_audit']['corpus']['unique_spending_transactions']} spending transactions. The address counts are `{json.dumps(payload['blockchain_nonce_audit']['corpus']['counts_by_address'], sort_keys=True)}`. All {payload['blockchain_nonce_audit']['corpus']['raw_transaction_count']} required raw current/prevout transactions rederive their txids; every prevout script and value agrees with its history record; and all signatures verify against locally serialized legacy sighash preimages. The reconstructed core `(address, txid, vin, r, s)` inventory exactly reproduces SHA-256 `{payload['blockchain_nonce_audit']['source']['reconstructed_core_inventory_sha256']}`.

All {payload['blockchain_nonce_audit']['corpus']['signature_count']} signatures use sighash type 1 and all {payload['blockchain_nonce_audit']['corpus']['unique_r_count']} `r` values are distinct, so there is no repeated-`r` nonce recovery. The original six-target-signature x 35-block test is reproduced as {payload['blockchain_nonce_audit']['nonce_audit']['legacy_target_block_nonce_tests']} equations. The expanded exact audit tests {payload['blockchain_nonce_audit']['nonce_audit']['candidate_signed_nonces']} signed nonce scalars across the full corpus ({payload['blockchain_nonce_audit']['nonce_audit']['known_nonce_equation_tests']} equations), covering the 35 blocks, both prefix operands, eight recovered K values, and Half/Better Half. It finds zero matching `r` values, zero recovered prize scalars, and zero direct prize-scalar matches. This closes only those explicit nonce families; it is not a general ECDSA discrete-log attack.

The complementary x-coordinate interpretation is also reconstructed with a stricter combination model than the historical probe. Exactly {payload['chain4_xcoordinate_audit']['valid_x_coordinate_count']} of 35 blocks lift to curve points. Selecting distinct block indices before assigning either y parity, and applying no shift or either sign of the operand, magnitude, structured prefix, Half, and Better Half points, exhausts {payload['chain4_xcoordinate_audit']['total_candidate_relations']} singleton/pair/triple relations. A planted three-block-plus-Half relation is recovered by the same engine; the prize point has zero relations. Even a relation would not expose the lifted points' discrete logarithms, so this is a negative structural certificate and not a private-key recovery method.

The nonlinear XOR route is now independently closed for the clue-motivated subset sizes 3, 4, and 7. First-index terminal checkpoints cover {payload['chain4_xor_subset_audit']['families']['X3']['combination_count']:,}, {payload['chain4_xor_subset_audit']['families']['X4']['combination_count']:,}, and {payload['chain4_xor_subset_audit']['families']['X7']['combination_count']:,} subsets respectively. With the recorded plain, operand-XOR, operand-add, and operand-subtract variants, the engine performs {payload['chain4_xor_subset_audit']['total_candidate_scalars']:,} exact libsecp256k1 point gates and finds zero prize matches. Every partition records its candidate-stream digest, and a six-block fixture successfully rediscovers its planted three-block/operand-XOR scalar and uncompressed address. This certificate does not cover other subset sizes.

The parallel modular-product route is closed over the same subset sizes. Its Q3/Q4 families apply plain product and operand multiply, divide, add, and subtract; Q7 applies plain product and operand multiplication. Across {payload['chain4_product_subset_audit']['total_candidate_scalars']:,} exact point gates, all terminal partition streams are hashed and there are zero prize matches. The enumerated control rediscovers a planted three-block product divided by the operand and verifies its complete point and uncompressed address. These product results cannot be inferred from either the additive or XOR searches.

The bounded nested-AES and whole-integer probe is also independently reproduced without hard-coded recovered keys. It derives {payload['chain4_aes_integer_audit']['derived_key_count']} AES-256 keys from the eight K values, six unique token digests, Cosmic master value, Chain 4 password, and two operand paddings. The engine performs {payload['chain4_aes_integer_audit']['counts']['A1_ecb_block_decryptions']} ECB block decryptions, {payload['chain4_aes_integer_audit']['counts']['A2_cbc_body_decryptions']} CBC body decryptions with {payload['chain4_aes_integer_audit']['counts']['A2_chunk_scalar_gates']} chunk gates, {payload['chain4_aes_integer_audit']['counts']['B1_whole_integer_candidates']} whole-integer candidates, and {payload['chain4_aes_integer_audit']['counts']['B2_selector_candidates']} header-selected candidates. AES roundtrips and a known component-point gate pass; there are zero structural hits, component matches, or prize matches. Printable output is never treated as key evidence.

The four 15-byte E fragments are now covered by an independent scalar-family audit. It reproduces raw family counts F1={payload['efragment_scalar_audit']['raw_family_counts']['F1']}, F2={payload['efragment_scalar_audit']['raw_family_counts']['F2']}, F3={payload['efragment_scalar_audit']['raw_family_counts']['F3']}, and F4={payload['efragment_scalar_audit']['raw_family_counts']['F4']}: {payload['efragment_scalar_audit']['raw_attempt_count']:,} generated attempts in total. Global deduplication removes {payload['efragment_scalar_audit']['duplicate_attempt_count']} repeated values, exactly reproducing {payload['efragment_scalar_audit']['unique_scalar_count']:,} unique point gates. There are zero component or prize matches. The enumerated F2 control recovers its planted scalar through both equivalent left-pad and integer serializations, directly checking the deduplication boundary.

The more literal `+-` grammar audit is complete as well. It tests all {payload['chain4_plusminus_grammar_audit']['A_fragment_passwords']['tested']} `15+15+2` E-fragment passwords with strict PKCS#7 validation, {payload['chain4_plusminus_grammar_audit']['B_unstripped_integer_readings']['candidate_count']} whole/unstripped integer readings, {payload['chain4_plusminus_grammar_audit']['C_sign_windows']['candidate_count']:,} sign-window scalars, and {payload['chain4_plusminus_grammar_audit']['D_natural_sign_patterns']['candidate_count']} natural sign folds. Nine passwords pass padding by chance, but exactly one has the canonical `+-` plus 31+35x32 layout: the already-known `E_C || E_S || E_B[:2]` password and the verified Chain 4 plaintext. Every new scalar family has zero prize matches; C and D are additionally subsumed by the exhaustive signed-block certificate.

## Public-source audit boundary

The canonical history at `fb92dd1`, PR heads #68 and #93, 70 public forks, all issue/comment text, and 60 of 61 public attachment URLs were searched. The attachments collapse to 32 unique SHA-256 values; none has the reported `cd3fea3d...` prefix and no raw attachment metadata/body contains the unresolved terms. The sole unavailable attachment is recorded in `artifacts.json`.

The original Decentraland clue is now independently authenticated rather than accepted from a later reconstruction. The active scene entity `{payload['decentraland_audio_audit']['entity']['cid']}` at parcels `{', '.join(payload['decentraland_audio_audit']['entity']['pointers'])}` names `sounds/puzzlepiece.mp3` with CID `{payload['decentraland_audio_audit']['audio']['cid']}`. The downloaded {payload['decentraland_audio_audit']['audio']['length']:,}-byte MP3 exactly reproduces that CID/SHA-256, and the scene script references the same path. Subtracting the right channel from the left and rendering the spectrogram visibly yields `HASHTHETEXT`. Because this could alter the ambiguous SalPhaseIon phrase “our first hint is your last command,” the audit also places `HASHTHETEXT`, its lowercase form, and other source-grounded strings into both semantic token slots: {payload['decentraland_audio_audit']['salphaseion_substitution_audit']['tested_pairs']} pairs, exactly one strict-padding/1327-byte hit (`yourlastcommand`, `secondanswer`), and zero hits containing `HASHTHETEXT`. The authentic audio therefore validates the instruction that leads back to the first-page hash but does not replace the literal SalPhaseIon token or add a post-Chain-4 operand.

The refreshed Wayback CDX snapshot contains {payload['wayback_source_audit']['cdx']['collapsed_capture_rows']} URL-local digest-collapsed capture rows across {payload['wayback_source_audit']['cdx']['unique_original_urls']} original URLs and {payload['wayback_source_audit']['cdx']['global_unique_digest_values']} globally unique digest values. The previously reported 787 count was a collapsed-row count, not a globally distinct digest count. The first provenance-recovered selection yields exactly {payload['wayback_source_audit']['cdx']['primary_target_count']} primary SalPhaseIon/`app.js`/JSON targets plus {payload['wayback_source_audit']['cdx']['supplementary_octet_stream_count']} source-map/font controls. The broader early-site audit then covers every 2019-2021 puzzle-adjacent CDX row after excluding only account/shared/subscription surfaces: {payload['wayback_early_asset_audit']['cdx']['selected_capture_rows']} exact captures, {payload['wayback_early_asset_audit']['cdx']['selected_unique_digests']} unique bodies, all content-digest verified. This includes every captured home/page variant, `/Puzzle`, the exact lowercase `/puzzle` PNG (byte-identical to local `puzzle.png`), `/theseedisplanted`, its eight clue images, JavaScript, source maps, CSS, JSON, icons, and robots text. The broader corpus has zero unresolved-term hits, zero standalone 29/30/32-byte literals, zero `cd3fea3d` body-hash prefixes, and zero target-point candidates.

## Next required evidence

No further computational family is justified by the authenticated public bytes. The next productive step is acquisition, not another transformation search: obtain the actual `cosmic_A`/`ca` bytes (with full SHA-256 and length) or a creator/source-authenticated derivation of `ca[280:312]`, plus exact definitions for `row1-4` and `K_I1`. Any claimed final formula must then reproduce the complete prize point and address. Until one of those inputs appears, continuing to invent XOR triangles, ciphers, or block formulas would expand an unconstrained search rather than solve the documented puzzle.

Full byte-level provenance is in `artifacts.json`; generated binaries are under `artifacts/bin/`.
"""


if __name__ == "__main__":
    result = run()
    print(f"wrote {JSON_PATH.name}, {REPORT_PATH.name}, and {len(result['artifacts'])} artifact records")
