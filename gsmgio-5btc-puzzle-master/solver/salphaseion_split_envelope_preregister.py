"""Seal the split-envelope (env48 / raw48) audit manifest.

The archived SalPhaseIon first textarea carries two 64-character base64 runs
separated by the unique ``enter`` marker.  Run one decodes to a 48-byte OpenSSL
envelope (``Salted__`` + salt ``3ab585348552415d`` + two ciphertext blocks) and
run two decodes to 48 raw bytes (three AES-block-sized blocks with no header).
Every earlier sealed family (v1-v39, cross-stage, instruction audit) targeted
only the *glued* 96-byte envelope; the two halves were never sealed targets on
their own.  This manifest freezes them as independent decryption targets under
only authenticated key/IV/password material, plus an envelope-salt control
hunt.  Families:

- K1: direct AES-256-CBC key+IV on raw48 (no KDF); full key x IV cross product.
- K2: EVP_BytesToKey passwords on env48 standalone (finite authenticated set).
- K3: stage-two ``shabefanstoo`` rule: sha256 of every strict-padding stage-one
  plaintext (whole plaintext only) as (a) EVP password on env48 and (b) direct
  AES-256 key on raw48 under the frozen IV set.
- K4: raw48 byte grammar (non-AES): 32-byte windows as secp256k1 scalars
  against the prize gates, base58check, and the blind-evaluator format scan.
- K5: the four envelope salts, both endiannesses, hunted through the
  authenticated plaintexts, Architect record, S91/S570 base-9 streams, poster
  RGB streams, and the F73D92/A94021/5E7DB3 derivatives.

Out of scope: replaying historical password manifests, Cosmic/Chain-4 password
enumeration, and any new semantic tokens.
"""

from __future__ import annotations

import base64
import hashlib
import json

from PIL import Image

from .architect_source_prime_reinsertion_audit import _load_inputs
from .chain4 import reconstruct_chain4
from .chains import ChainsResult, reconstruct
from .creator_frontier_giveaway_audit import CREATOR_PIPELINE
from .extract import ROOT, extract_all
from .salphaseion import SalPhaseIonResult, derive_tokens
from .salphaseion_raw import (
    EARLIEST_CAPTURE_PATH,
    EARLIEST_CAPTURE_TIMESTAMP,
    RawSalPhaseIon,
    _decode_capture,
    _textareas,
    capture_stability,
    extract_raw,
    sha256_hex,
)
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "salphaseion_split_envelope_preregistered.json"
SEAL_PATH = ROOT / "salphaseion_split_envelope_preregistered.sha256"
RESULT_PATH = ROOT / "salphaseion_split_envelope_results.json"

STAGE_PASSWORDS_PATH = ROOT / "seven_stage_passwords_intertwine_audit.json"
RABBIT_IMAGE_PATH = ROOT.parent / "sources" / "follow_the_white_rabbit.png"
PUZZLE_IMAGE_PATH = ROOT / "puzzle.png"

# Pinned split targets (verified 2026-08-05 against the earliest capture).
ENV48_SHA256 = "f35efe2236bf60310e7b645ad297b70c6fd1670e5717d7601f5319e69d489b1b"
RAW48_SHA256 = "bab0c6d922a323c893f071b3b70885d00ae885914dbd70568dd6a032bc05ed70"
GLUED_SHA256 = "9e2831e1b34b5f34796df47ccaf6530d48d371c61a6bff84d60db1064fa7a258"

# Pinned positive-control plaintext digests.
CHAIN1_PLAINTEXT_SHA256 = "1449a2178eea7c0e3fabac8c1ad2afa294be4fc1800c594a025a056e88c626bf"
CHAIN2_PLAINTEXT_SHA256 = "b40fce72ef5638e4f79b3233e653f8a5dbdb0d4ae2009d2d3da2c98b70f4d004"
COSMIC_PLAINTEXT_SHA256 = "4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081"
CHAIN1_WIF = "5K2byJMssxFKuTgnk9YQjpBz5FhkwwF2LaZoAyTus8HjGEpz8AT"

# Prize gates.  These are the same bytes the sealed audits recorded; they now
# come from solver.targets so a single self-checked definition governs them.
HALF_UNCOMPRESSED_PUBKEY = HALF_PUBLIC_UNCOMPRESSED.hex()
BETTER_HALF_HASH160 = BETTER_H160.hex()

ENVELOPE_SALTS = (
    ("env48", "3ab585348552415d"),
    ("chain2", "b45a5e3d827593ca"),
    ("phase32", "eefc4c5befc1656a"),
    ("cosmic", "2d3f6fe06dc950e6"),
)


def split_envelope() -> tuple[bytes, bytes]:
    """Rebuild env48/raw48 from the earliest capture's token stream.

    This replays the frozen ``salphaseion_raw`` token logic but keeps the two
    base64 runs around the unique ``enter`` marker separate instead of gluing
    them.  Both pinned sha256 values and the glue identity are asserted.
    """

    html = _decode_capture(EARLIEST_CAPTURE_PATH)
    textarea1, _ = _textareas(html)
    tokens = textarea1.decode("ascii").split()
    if len(tokens) != 1075 or any(len(token) != 1 for token in tokens):
        raise ValueError("unexpected first-textarea token structure")

    enter_bits = "".join(f"{byte:08b}" for byte in b"enter").translate(
        str.maketrans("01", "ab")
    )
    enter_tokens = list(enter_bits)
    ending = list("shabefanstoo")
    if tokens[-len(ending):] != ending:
        raise ValueError("missing terminal shabefanstoo field")
    payload_end = len(tokens) - len(ending)

    cursor = 765
    if tokens[cursor] != "z":
        raise ValueError("missing first z delimiter")
    cursor += 1
    first_z = tokens.index("z", cursor)
    cursor = first_z + 1
    second_z = tokens.index("z", cursor)
    cursor = second_z + 1
    if tokens[cursor] != "s":
        raise ValueError("unexpected SHA first-hint field start")
    base64_start = tokens.index("U", cursor)
    matches = [
        index
        for index in range(base64_start, payload_end - len(enter_tokens) + 1)
        if tokens[index:index + len(enter_tokens)] == enter_tokens
    ]
    if len(matches) != 1:
        raise ValueError(f"expected unique enter marker, found {len(matches)}")
    enter_start = matches[0]

    run1 = "".join(tokens[base64_start:enter_start])
    run2 = "".join(tokens[enter_start + len(enter_tokens):payload_end])
    if len(run1) != 64 or len(run2) != 64:
        raise ValueError("base64 runs around the enter marker changed length")
    env48 = base64.b64decode(run1, validate=True)
    raw48 = base64.b64decode(run2, validate=True)
    if sha256_hex(env48) != ENV48_SHA256:
        raise ValueError("env48 half changed")
    if sha256_hex(raw48) != RAW48_SHA256:
        raise ValueError("raw48 half changed")
    if sha256_hex(env48 + raw48) != GLUED_SHA256:
        raise ValueError("env48 + raw48 no longer glues to the chain-1 envelope")
    return env48, raw48


def _base9_views(field: str) -> dict[str, bytes]:
    """S-field base-9 streams under both established page conventions.

    ``a0`` maps a->0..i->8; ``a1-i0`` maps a->1..h->8, i->0 (the same pair of
    conventions as ``salphaseion_preregister_v29._base9_bytes``).
    """

    views: dict[str, bytes] = {}
    for convention, digits in (
        ("a0", [ord(symbol) - 97 for symbol in field]),
        ("a1-i0", [(ord(symbol) - 96) % 9 for symbol in field]),
    ):
        number = 0
        for digit in digits:
            number = number * 9 + digit
        minimal = number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
        views[f"base9-bytes-{convention}"] = minimal
        views[f"decimal-digits-{convention}"] = "".join(map(str, digits)).encode("ascii")
    return views


def _rgb_stream(path) -> bytes:
    image = Image.open(path).convert("RGB")
    return image.tobytes()


def derive_key_material() -> dict[str, object]:
    """Derive every frozen input from the authenticated upstream artifacts."""

    raw: RawSalPhaseIon = extract_raw()
    sal: SalPhaseIonResult = derive_tokens()
    extracted = extract_all()
    chains: ChainsResult = reconstruct(extracted, sal)
    chain4 = reconstruct_chain4(chains)
    env48, raw48 = split_envelope()
    glued = env48 + raw48
    if glued != extracted.chain1_envelope:
        raise ValueError("split halves no longer glue to the README chain-1 envelope")

    if len(chains.chain1_decryption.plaintext) != 79:
        raise ValueError("chain-1 plaintext length changed")
    if sha256_hex(chains.chain1_decryption.plaintext) != CHAIN1_PLAINTEXT_SHA256:
        raise ValueError("chain-1 plaintext digest changed")
    if sha256_hex(chains.chain2_decryption.plaintext) != CHAIN2_PLAINTEXT_SHA256:
        raise ValueError("chain-2 plaintext digest changed")
    if sha256_hex(chains.cosmic_decryption.plaintext) != COSMIC_PLAINTEXT_SHA256:
        raise ValueError("Cosmic plaintext digest changed")
    if chains.chain1_wif != CHAIN1_WIF:
        raise ValueError("chain-1 WIF changed")

    k1_keys = [
        ("cosmic-evp-key", chains.cosmic_decryption.key,
         "Cosmic EVP_BytesToKey(md5) key from the seven-token-digest XOR password"),
        ("chain1-key1", chains.chain1.key1, "chain-1 79-byte triplet bytes 0:32"),
        ("chain1-key2", chains.chain1.key2, "chain-1 79-byte triplet bytes 32:64"),
        ("chain2-key1", chains.chain2.key1, "chain-2 79-byte triplet bytes 0:32"),
        ("chain2-key2", chains.chain2.key2, "chain-2 79-byte triplet bytes 32:64"),
    ]
    for index, (token, digest) in enumerate(zip(sal.tokens, sal.digests), 1):
        k1_keys.append((
            f"token-digest-{index}-{token}", digest,
            f"sha256 of SalPhaseIon token {index} ({token!r})",
        ))
    k1_keys.append((
        "token-digest-xor7", sal.xor_password,
        "XOR of the seven token sha256 digests (the Cosmic password)",
    ))
    k1_keys.append((
        "sha256-chain1-plaintext",
        hashlib.sha256(chains.chain1_decryption.plaintext).digest(),
        "sha256 of the whole 79-byte chain-1 plaintext",
    ))
    k1_keys.append((
        "sha256-chain2-plaintext",
        hashlib.sha256(chains.chain2_decryption.plaintext).digest(),
        "sha256 of the whole 79-byte chain-2 plaintext",
    ))
    if any(len(key) != 32 for _, key, _ in k1_keys):
        raise ValueError("K1 key material is not 32 bytes")

    k1_ivs = [
        ("zero", bytes(16), "16 zero bytes"),
        ("cosmic-evp-iv", chains.cosmic_decryption.iv,
         "Cosmic EVP_BytesToKey(md5) IV"),
        ("chain1-key1-prefix16", chains.chain1.key1[:16], "chain-1 key1 first 16 bytes"),
        ("chain1-key2-prefix16", chains.chain1.key2[:16], "chain-1 key2 first 16 bytes"),
        ("chain2-key1-prefix16", chains.chain2.key1[:16], "chain-2 key1 first 16 bytes"),
        ("chain2-key2-prefix16", chains.chain2.key2[:16], "chain-2 key2 first 16 bytes"),
        ("chain1-key3-leftpad", b"\0" + chains.chain1.extension,
         "15-byte chain-1 tail key3 left-padded with 0x00"),
        ("chain2-key3-leftpad", b"\0" + chains.chain2.extension,
         "15-byte chain-2 tail key3 left-padded with 0x00"),
    ]
    if any(len(iv) != 16 for _, iv, _ in k1_ivs):
        raise ValueError("K1 IV material is not 16 bytes")

    k2_passwords: list[tuple[str, bytes, str]] = []
    for index, token in enumerate(sal.tokens[:5], 1):
        k2_passwords.append((
            f"chain1-token-{index}", token.encode("utf-8"),
            f"chain-1 token {index} of five in frozen physical source order ({token!r})",
        ))
    k2_passwords.append((
        "chain1-glued-joke-password", "".join(sal.tokens[:5]).encode("ascii"),
        "the glued five-token joke password that opens the glued envelope",
    ))
    for name, literal in (
        ("matrixsumlist", raw.matrix_marker),
        ("lastwordsbeforearchichoice", raw.lastwords_marker),
        ("thispassword", raw.password_marker),
        ("shabefourfirsthintisyourlastcommand", raw.sha_first_hint),
        ("enter", raw.enter_marker),
        ("shabefanstoo", raw.sha_answer_too),
    ):
        k2_passwords.append((
            f"field-literal-{name}", literal.encode("ascii"),
            "one of the six decoded field literals from the archived page",
        ))
    k2_passwords.append((
        "HASHTHETEXT", b"HASHTHETEXT",
        "Decentraland audio difference-channel command (uppercase)",
    ))
    k2_passwords.append((
        "hashthetext", b"hashthetext",
        "Decentraland audio difference-channel command (lowercase)",
    ))
    for index, word in enumerate(CREATOR_PIPELINE, 1):
        k2_passwords.append((
            f"creator-pipeline-{index}", word.encode("utf-8"),
            "one of the seven 2023 creator-pipeline words "
            "(creator_frontier_giveaway_audit.CREATOR_PIPELINE)",
        ))
    stage_passwords_bytes = STAGE_PASSWORDS_PATH.read_bytes()
    stage_passwords = json.loads(stage_passwords_bytes)["passwords"]
    if len(stage_passwords) != 7:
        raise ValueError("seven authenticated stage passwords changed")
    for index, password in enumerate(stage_passwords, 1):
        k2_passwords.append((
            f"stage-password-{index}", password.encode("utf-8"),
            "one of the seven authenticated stage passwords "
            "(seven_stage_passwords_intertwine_audit.json)",
        ))

    architect = _load_inputs()
    s91_views = _base9_views(raw.s91)
    s570_views = _base9_views(raw.s570)
    marker_f73d92 = bytes.fromhex("F73D92")
    passport_a94021 = bytes.fromhex("A94021")
    marker_xor = bytes(left ^ right for left, right in zip(marker_f73d92, passport_a94021))
    if marker_xor.hex() != "5e7db3":
        raise ValueError("authenticated marker XOR changed")
    derivatives = bytearray()
    for value in (marker_f73d92, passport_a94021, marker_xor):
        derivatives.extend(value)
        derivatives.extend(f"{int.from_bytes(value, 'big'):024b}".encode("ascii"))
    rabbit_rgb = _rgb_stream(RABBIT_IMAGE_PATH)
    puzzle_rgb = _rgb_stream(PUZZLE_IMAGE_PATH)

    k5_corpora: dict[str, bytes] = {
        "chain1-plaintext": chains.chain1_decryption.plaintext,
        "chain2-plaintext": chains.chain2_decryption.plaintext,
        "cosmic-plaintext": chains.cosmic_decryption.plaintext,
        "chain4-plaintext": chain4.decryption.plaintext,
        "architect-raw-record": architect["raw"],
        "architect-transliteration": architect["transliteration"],
        "poster-follow-the-white-rabbit-rgb": rabbit_rgb,
        "poster-puzzle-rgb": puzzle_rgb,
        "marker-xor-derivatives": bytes(derivatives),
    }
    for field, views in (("s91", s91_views), ("s570", s570_views)):
        for view_name, blob in views.items():
            k5_corpora[f"{field}-{view_name}"] = blob

    return {
        "raw": raw,
        "sal": sal,
        "chains": chains,
        "chain4": chain4,
        "env48": env48,
        "raw48": raw48,
        "glued": glued,
        "k1_keys": k1_keys,
        "k1_ivs": k1_ivs,
        "k2_passwords": k2_passwords,
        "stage_passwords_file_sha256": sha256_hex(stage_passwords_bytes),
        "k5_corpora": k5_corpora,
        "image_files": {
            "follow_the_white_rabbit.png": RABBIT_IMAGE_PATH.read_bytes(),
            "puzzle.png": PUZZLE_IMAGE_PATH.read_bytes(),
        },
    }


def _dedup_passwords(
    entries: list[tuple[str, bytes, str]],
) -> tuple[list[tuple[str, bytes, str, list[str]]], int]:
    """Order-preserving dedup on password bytes; provenance labels are merged."""

    unique: dict[bytes, tuple[str, bytes, str, list[str]]] = {}
    duplicates = 0
    for password_id, password, provenance in entries:
        if password in unique:
            duplicates += 1
            first_id, _, first_provenance, merged = unique[password]
            merged.append(password_id)
            continue
        unique[password] = (password_id, password, provenance, [])
    return list(unique.values()), duplicates


def build_manifest() -> dict[str, object]:
    material = derive_key_material()
    raw: RawSalPhaseIon = material["raw"]
    env48: bytes = material["env48"]
    raw48: bytes = material["raw48"]
    glued: bytes = material["glued"]

    k1_keys = [
        {"key_id": key_id, "hex": key.hex(), "sha256": sha256_hex(key),
         "provenance": provenance}
        for key_id, key, provenance in material["k1_keys"]
    ]
    k1_ivs = [
        {"iv_id": iv_id, "hex": iv.hex(), "sha256": sha256_hex(iv),
         "provenance": provenance}
        for iv_id, iv, provenance in material["k1_ivs"]
    ]
    k1_pairs: list[dict[str, str]] = []
    k1_seen: set[tuple[str, str]] = set()
    k1_duplicates = 0
    for key in k1_keys:
        for iv in k1_ivs:
            identity = (key["hex"], iv["hex"])
            if identity in k1_seen:
                k1_duplicates += 1
                continue
            k1_seen.add(identity)
            k1_pairs.append({
                "pair_id": f"k1p{len(k1_pairs):04d}",
                "key_id": key["key_id"],
                "iv_id": iv["iv_id"],
            })

    unique_passwords, duplicates = _dedup_passwords(material["k2_passwords"])
    k2_passwords = [
        {"password_id": password_id, "hex": password.hex(),
         "sha256": sha256_hex(password), "provenance": provenance,
         "merged_duplicate_ids": merged}
        for password_id, password, provenance, merged in unique_passwords
    ]

    k5_corpora = [
        {"corpus_id": corpus_id, "length": len(blob), "sha256": sha256_hex(blob)}
        for corpus_id, blob in material["k5_corpora"].items()
    ]
    salts = [
        {"name": name, "hex": hex_value, "bytes": 8}
        for name, hex_value in ENVELOPE_SALTS
    ]

    return {
        "schema": "salphaseion-split-envelope-audit-v1",
        "status": "SEALED_BEFORE_DECRYPTION",
        "sealed_on": "2026-08-05",
        "purpose": (
            "Test the two 48-byte halves of the SalPhaseIon short blob as "
            "independent decryption targets under only authenticated key/IV/"
            "password material, plus an envelope-salt control hunt."
        ),
        "source": {
            "wayback_capture": str(EARLIEST_CAPTURE_PATH.relative_to(ROOT)).replace("\\", "/"),
            "capture_timestamp": EARLIEST_CAPTURE_TIMESTAMP,
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "split_rule": (
                "first-textarea base64 split around the unique 'enter' marker: "
                "run 1 (64 chars) -> env48, run 2 (64 chars) -> raw48"
            ),
            "stage_passwords_file": STAGE_PASSWORDS_PATH.name,
            "stage_passwords_file_sha256": material["stage_passwords_file_sha256"],
            "image_files": {
                name: {"sha256": sha256_hex(blob), "length": len(blob)}
                for name, blob in material["image_files"].items()
            },
        },
        "targets": {
            "env48": {
                "length": len(env48), "sha256": sha256_hex(env48),
                "kind": "openssl-envelope", "salt_hex": env48[8:16].hex(),
            },
            "raw48": {
                "length": len(raw48), "sha256": sha256_hex(raw48),
                "kind": "raw-3-block-candidate",
            },
            "chain1-glued": {
                "length": len(glued), "sha256": sha256_hex(glued),
                "kind": "openssl-envelope", "salt_hex": glued[8:16].hex(),
                "role": "positive-control-only",
            },
        },
        "positive_controls": {
            "chain1_glued_with_joke_password": {
                "plaintext_length": 79, "plaintext_sha256": CHAIN1_PLAINTEXT_SHA256,
            },
            "chain1_wif": CHAIN1_WIF,
            "chain2_with_wif": {
                "plaintext_length": 79, "plaintext_sha256": CHAIN2_PLAINTEXT_SHA256,
            },
            "cosmic_with_xor_password": {
                "plaintext_length": 1327, "plaintext_sha256": COSMIC_PLAINTEXT_SHA256,
            },
        },
        "prize_gates": {
            "half_uncompressed_pubkey": HALF_UNCOMPRESSED_PUBKEY,
            "better_half_hash160": BETTER_HALF_HASH160,
        },
        "families": {
            "K1": {
                "rule": "direct AES-256-CBC key+IV on raw48 (no KDF)",
                "target": "raw48",
                "keys": k1_keys,
                "ivs": k1_ivs,
                "pairs": k1_pairs,
                "pair_count": len(k1_pairs),
                "duplicates_removed": k1_duplicates,
            },
            "K2": {
                "rule": "EVP_BytesToKey passwords on env48 standalone, strict PKCS#7",
                "target": "env48",
                "passwords": k2_passwords,
                "unique_password_count": len(k2_passwords),
                "duplicates_removed": duplicates,
                "password_forms": ["raw-bytes", "sha256-lowercase-hex"],
                "kdf_digests": ["md5", "sha256"],
            },
            "K3": {
                "rule": (
                    "stage-two shabefanstoo: sha256 of every whole strict-padding "
                    "stage-one plaintext from K1/K2; (a) raw digest and lowercase "
                    "hex as EVP password on env48 under md5/sha256, (b) raw digest "
                    "as direct AES-256 key on raw48 under the frozen K1 IV set"
                ),
                "stage_one_sources": ["K1", "K2"],
                "whole_plaintext_only": True,
                "a_evp_password_forms": ["raw-digest", "lowercase-hex"],
                "a_kdf_digests": ["md5", "sha256"],
                "b_direct_key_form": "raw-digest",
                "b_iv_set": "K1 frozen IVs",
            },
            "K4": {
                "rule": (
                    "raw48 byte grammar (non-AES): every 32-byte window "
                    "(offsets 0-16) as secp256k1 scalar against the prize gates; "
                    "base58check on the whole blob and each window; blind-evaluator "
                    "format scan on the whole blob and each window"
                ),
                "window_length": 32,
                "window_offsets_inclusive": [0, 16],
                "scalar_gates": [
                    "half-exact-uncompressed-point",
                    "better-half-hash160-both-serializations",
                ],
                "base58check_scopes": ["whole-blob", "32-byte-windows"],
                "format_scan": "salphaseion_blind_eval._formats",
            },
            "K5": {
                "rule": (
                    "envelope-salt control hunt: every salt needle form searched "
                    "in every frozen corpus; any hit is a designed-link candidate "
                    "and is reported verbatim"
                ),
                "salts": salts,
                "needle_forms": [
                    "big-endian-bytes",
                    "little-endian-bytes",
                    "lowercase-hex",
                    "little-endian-lowercase-hex",
                ],
                "corpora": k5_corpora,
            },
        },
        "acceptance": {
            "padding_alone_never_suffices": True,
            "readable_text_rule": "salphaseion_blind_eval._readable",
            "format_rule": "salphaseion_blind_eval._formats",
            "cross_blob_rule": (
                "same stage-two sha256 material accepted on both env48 and raw48"
            ),
            "prize_gate": (
                "every 32-byte output slice of every K1/K2/K3 plaintext and every "
                "K4 window is tested as a secp256k1 scalar against Half's exact "
                "uncompressed point and Better Half's hash160 under both "
                "serializations"
            ),
        },
    }


def main() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({
        "manifest": str(MANIFEST_PATH),
        "seal_sha256": sha256_hex(encoded),
        "k1_pairs": manifest["families"]["K1"]["pair_count"],
        "k2_unique_passwords": manifest["families"]["K2"]["unique_password_count"],
        "k2_duplicates_removed": manifest["families"]["K2"]["duplicates_removed"],
        "k5_corpora": len(manifest["families"]["K5"]["corpora"]),
    }, indent=2))


if __name__ == "__main__":
    main()
