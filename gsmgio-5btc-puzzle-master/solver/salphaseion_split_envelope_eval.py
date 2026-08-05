"""Evaluate the sealed split-envelope (env48 / raw48) manifest.

Re-derives every input from the authenticated upstream artifacts and fails
loudly on any drift, runs the three positive controls, then executes the
sealed K1-K5 families.  Acceptance gates are identical to the blind evaluator
(strict padding alone never suffices; readable-text rule; exact
parser/checksum formats; cross-blob rule) plus the prize gates on every
32-byte output slice.
"""

from __future__ import annotations

import base64
import hashlib
import json

from coincurve import PrivateKey
from Crypto.Cipher import AES

from .openssl_compat import (
    decrypt_salted_aes256_cbc,
    pkcs7_pad,
    strict_pkcs7_unpad,
)
from .salphaseion_blind_eval import _base58check, _formats, _readable
from .salphaseion_raw import sha256_hex
from .salphaseion_split_envelope_preregister import (
    BETTER_HALF_HASH160,
    CHAIN1_PLAINTEXT_SHA256,
    CHAIN1_WIF,
    CHAIN2_PLAINTEXT_SHA256,
    COSMIC_PLAINTEXT_SHA256,
    ENVELOPE_SALTS,
    HALF_UNCOMPRESSED_PUBKEY,
    MANIFEST_PATH,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    derive_key_material,
)
from .secp256k1_verify import N, hash160


HALF_PUBLIC = bytes.fromhex(HALF_UNCOMPRESSED_PUBKEY)
BETTER_H160 = bytes.fromhex(BETTER_HALF_HASH160)
PLANTED_MESSAGE = b"planted split envelope recovery control"
K2_FORMS = ("raw-bytes", "sha256-lowercase-hex")
K2_DIGESTS = ("md5", "sha256")
K3_A_FORMS = ("raw-digest", "lowercase-hex")


def _prize_gate_slice(slice32: bytes) -> dict[str, object]:
    scalar = int.from_bytes(slice32, "big")
    if not 1 <= scalar < N:
        return {"valid_scalar": False, "match": False}
    public = PrivateKey(slice32).public_key
    uncompressed = public.format(compressed=False)
    compressed = public.format(compressed=True)
    half = uncompressed == HALF_PUBLIC
    better_compressed = hash160(compressed) == BETTER_H160
    better_uncompressed = hash160(uncompressed) == BETTER_H160
    return {
        "valid_scalar": True,
        "match": half or better_compressed or better_uncompressed,
        "half_exact_public_key": half,
        "better_hash160_compressed": better_compressed,
        "better_hash160_uncompressed": better_uncompressed,
    }


def evaluate(manifest_path=MANIFEST_PATH, seal_path=SEAL_PATH, result_path=RESULT_PATH) -> dict[str, object]:
    encoded = manifest_path.read_bytes()
    expected_seal = seal_path.read_text(encoding="ascii").strip()
    actual_seal = hashlib.sha256(encoded).hexdigest()
    if actual_seal != expected_seal:
        raise ValueError("candidate manifest does not match its pre-decryption seal")
    manifest = json.loads(encoded)
    if manifest.get("status") != "SEALED_BEFORE_DECRYPTION":
        raise ValueError("manifest is not marked sealed")

    # Drift gate: re-derive the full manifest from the authenticated upstream
    # artifacts; any upstream change must fail here, before any decryption.
    if build_manifest() != manifest:
        raise ValueError("re-derived manifest differs from the sealed manifest")
    material = derive_key_material()
    env48: bytes = material["env48"]
    raw48: bytes = material["raw48"]
    glued: bytes = material["glued"]
    for name, blob in (("env48", env48), ("raw48", raw48), ("chain1-glued", glued)):
        if sha256_hex(blob) != manifest["targets"][name]["sha256"]:
            raise ValueError(f"sealed target changed: {name}")

    # Positive controls (must all pass before evaluation).
    chains = material["chains"]
    controls = {
        "chain1_glued_with_joke_password": {
            "plaintext_length": len(chains.chain1_decryption.plaintext),
            "plaintext_sha256": sha256_hex(chains.chain1_decryption.plaintext),
            "pass": len(chains.chain1_decryption.plaintext) == 79
            and sha256_hex(chains.chain1_decryption.plaintext) == CHAIN1_PLAINTEXT_SHA256,
        },
        "chain1_wif": {
            "wif": chains.chain1_wif,
            "pass": chains.chain1_wif == CHAIN1_WIF,
        },
        "chain2_with_wif": {
            "plaintext_length": len(chains.chain2_decryption.plaintext),
            "plaintext_sha256": sha256_hex(chains.chain2_decryption.plaintext),
            "pass": len(chains.chain2_decryption.plaintext) == 79
            and sha256_hex(chains.chain2_decryption.plaintext) == CHAIN2_PLAINTEXT_SHA256,
        },
        "cosmic_with_xor_password": {
            "plaintext_length": len(chains.cosmic_decryption.plaintext),
            "plaintext_sha256": sha256_hex(chains.cosmic_decryption.plaintext),
            "pass": len(chains.cosmic_decryption.plaintext) == 1327
            and sha256_hex(chains.cosmic_decryption.plaintext) == COSMIC_PLAINTEXT_SHA256,
        },
    }
    if not all(control["pass"] for control in controls.values()):
        raise ValueError("positive controls failed")

    k1_family = manifest["families"]["K1"]
    keys_by_id = {entry["key_id"]: bytes.fromhex(entry["hex"]) for entry in k1_family["keys"]}
    ivs_by_id = {entry["iv_id"]: bytes.fromhex(entry["hex"]) for entry in k1_family["ivs"]}
    k2_passwords = manifest["families"]["K2"]["passwords"]

    stream = hashlib.sha256()
    padding_hits: list[dict[str, object]] = []
    accepted: list[dict[str, object]] = []
    prize_matches: list[dict[str, object]] = []
    prize_slices = 0
    prize_valid_scalars = 0
    stage_one_plaintexts: dict[str, bytes] = {}
    counts = {
        "K1": {"attempts": 0},
        "K2": {"attempts": 0},
        "K3": {"attempts": 0, "stage_two_a_attempts": 0, "stage_two_b_attempts": 0},
    }

    def record_plaintext(
        family: str,
        candidate_id: str,
        target: str,
        plaintext: bytes,
        padding_length: int,
        extra: dict[str, object],
    ) -> None:
        nonlocal prize_slices, prize_valid_scalars
        readable, metrics = _readable(plaintext)
        formats = _formats(plaintext)
        record = {
            "family": family,
            "candidate_id": candidate_id,
            "target": target,
            "plaintext_length": len(plaintext),
            "plaintext_sha256": sha256_hex(plaintext),
            "padding_length": padding_length,
            "readable_text": readable,
            "text_metrics": metrics,
            "formats": formats,
            **extra,
        }
        padding_hits.append(record)
        if family in ("K1", "K2"):
            stage_one_plaintexts.setdefault(record["plaintext_sha256"], plaintext)
        if readable or formats:
            accepted.append({
                **record,
                "plaintext_base64": base64.b64encode(plaintext).decode("ascii"),
            })
        for offset in range(0, len(plaintext) - 31):
            window = plaintext[offset:offset + 32]
            gate = _prize_gate_slice(window)
            prize_slices += 1
            if gate["valid_scalar"]:
                prize_valid_scalars += 1
            if gate["match"]:
                prize_matches.append({
                    "family": family,
                    "candidate_id": candidate_id,
                    "target": target,
                    "slice_offset": offset,
                    "scalar_hex": window.hex(),
                    **gate,
                })

    def run_direct(pairs, target_name: str, blob: bytes, family: str) -> None:
        for pair in pairs:
            key = keys_by_id[pair["key_id"]]
            iv = ivs_by_id[pair["iv_id"]]
            counts[family]["attempts"] += 1
            stream.update(b"K1\0" + key + b"\0" + iv + b"\0" + target_name.encode("ascii"))
            padded = AES.new(key, AES.MODE_CBC, iv).decrypt(blob)
            try:
                plaintext, padding_length = strict_pkcs7_unpad(padded)
            except ValueError:
                continue
            record_plaintext(family, pair["pair_id"], target_name, plaintext, padding_length, {
                "key_id": pair["key_id"],
                "iv_id": pair["iv_id"],
            })

    # K1 — direct AES-256-CBC key+IV on raw48 (no KDF).
    run_direct(k1_family["pairs"], "raw48", raw48, "K1")

    # K2 — EVP passwords on env48 standalone.
    for entry in k2_passwords:
        password = bytes.fromhex(entry["hex"])
        forms = (
            ("raw-bytes", password),
            ("sha256-lowercase-hex", hashlib.sha256(password).hexdigest().encode("ascii")),
        )
        for form_name, form in forms:
            for digest in K2_DIGESTS:
                counts["K2"]["attempts"] += 1
                stream.update(b"K2\0" + form + b"\0" + digest.encode("ascii"))
                try:
                    decrypted = decrypt_salted_aes256_cbc(env48, form, digest=digest)
                except ValueError:
                    continue
                record_plaintext(
                    "K2", entry["password_id"], "env48",
                    decrypted.plaintext, decrypted.padding_length,
                    {"password_form": form_name, "kdf_digest": digest},
                )

    # K3 — stage-two shabefanstoo rule on the split blobs (whole plaintexts).
    stage_two_groups: dict[str, set[str]] = {}
    for pt_sha, stage_one in stage_one_plaintexts.items():
        digest = hashlib.sha256(stage_one).digest()
        a_forms = (
            ("raw-digest", digest),
            ("lowercase-hex", digest.hex().encode("ascii")),
        )
        for form_name, form in a_forms:
            for kdf_digest in K2_DIGESTS:
                counts["K3"]["attempts"] += 1
                counts["K3"]["stage_two_a_attempts"] += 1
                stream.update(b"K3a\0" + form + b"\0" + kdf_digest.encode("ascii"))
                try:
                    decrypted = decrypt_salted_aes256_cbc(env48, form, digest=kdf_digest)
                except ValueError:
                    continue
                before = len(accepted)
                record_plaintext(
                    "K3", f"sha256:{pt_sha}", "env48",
                    decrypted.plaintext, decrypted.padding_length,
                    {"stage_one_plaintext_sha256": pt_sha,
                     "password_form": form_name, "kdf_digest": kdf_digest},
                )
                if len(accepted) > before:
                    stage_two_groups.setdefault(pt_sha, set()).add("env48")
        for iv_id, iv in ivs_by_id.items():
            counts["K3"]["attempts"] += 1
            counts["K3"]["stage_two_b_attempts"] += 1
            stream.update(b"K3b\0" + digest + b"\0" + iv + b"\0" + iv_id.encode("ascii"))
            padded = AES.new(digest, AES.MODE_CBC, iv).decrypt(raw48)
            try:
                plaintext, padding_length = strict_pkcs7_unpad(padded)
            except ValueError:
                continue
            before = len(accepted)
            record_plaintext(
                "K3", f"sha256:{pt_sha}", "raw48", plaintext, padding_length,
                {"stage_one_plaintext_sha256": pt_sha, "iv_id": iv_id},
            )
            if len(accepted) > before:
                stage_two_groups.setdefault(pt_sha, set()).add("raw48")
    cross_blob = [
        {"stage_one_plaintext_sha256": pt_sha, "targets": sorted(targets)}
        for pt_sha, targets in stage_two_groups.items()
        if len(targets) >= 2
    ]

    # K4 — raw48 byte grammar (non-AES).
    k4_windows = [raw48[offset:offset + 32] for offset in range(17)]
    k4_scalar_gates = 0
    k4_base58check_hits: list[dict[str, object]] = []
    k4_format_hits: list[dict[str, object]] = []
    for offset, window in enumerate(k4_windows):
        k4_scalar_gates += 1
        stream.update(b"K4\0" + window)
        gate = _prize_gate_slice(window)
        if gate["match"]:
            prize_matches.append({
                "family": "K4",
                "candidate_id": f"raw48-window-{offset}",
                "target": "raw48",
                "slice_offset": offset,
                "scalar_hex": window.hex(),
                **gate,
            })
    for scope, value in (
        [("whole-blob", raw48)] + [(f"window-{offset}", window) for offset, window in enumerate(k4_windows)]
    ):
        if 26 <= len(value) <= 60 and _base58check(value):
            k4_base58check_hits.append({"scope": scope, "value_hex": value.hex()})
        formats = _formats(value)
        if formats:
            k4_format_hits.append({
                "scope": scope,
                "length": len(value),
                "sha256": sha256_hex(value),
                "formats": formats,
                "value_base64": base64.b64encode(value).decode("ascii"),
            })
    k4_accepted = [
        {**hit, "rule": "base58check"} for hit in k4_base58check_hits
    ] + [
        {**hit, "rule": "format-scan"} for hit in k4_format_hits
    ]

    # K5 — envelope-salt control hunt.
    k5_corpora: dict[str, bytes] = material["k5_corpora"]
    needles: list[tuple[str, str, bytes]] = []
    for salt_name, salt_hex in ENVELOPE_SALTS:
        salt = bytes.fromhex(salt_hex)
        needles.append((salt_name, "big-endian-bytes", salt))
        needles.append((salt_name, "little-endian-bytes", salt[::-1]))
        needles.append((salt_name, "lowercase-hex", salt_hex.encode("ascii")))
        needles.append((salt_name, "little-endian-lowercase-hex", salt[::-1].hex().encode("ascii")))
    k5_searches = 0
    salt_hits: list[dict[str, object]] = []
    for corpus_id, blob in k5_corpora.items():
        if sha256_hex(blob) != next(
            corpus["sha256"] for corpus in manifest["families"]["K5"]["corpora"]
            if corpus["corpus_id"] == corpus_id
        ):
            raise ValueError(f"sealed K5 corpus changed: {corpus_id}")
        for salt_name, form, needle in needles:
            k5_searches += 1
            stream.update(b"K5\0" + needle + b"\0" + corpus_id.encode("ascii"))
            start = 0
            while True:
                index = blob.find(needle, start)
                if index < 0:
                    break
                salt_hits.append({
                    "salt": salt_name,
                    "needle_form": form,
                    "needle_hex": needle.hex(),
                    "corpus": corpus_id,
                    "offset": index,
                    "matched_hex": blob[index:index + len(needle)].hex(),
                })
                start = index + 1

    # Planted K1 positive control: a synthetic raw48 built with the first
    # sealed (key, IV) pair must be recovered through the same engine.
    planted_pair = k1_family["pairs"][0]
    planted_key = keys_by_id[planted_pair["key_id"]]
    planted_iv = ivs_by_id[planted_pair["iv_id"]]
    planted_blob = AES.new(planted_key, AES.MODE_CBC, planted_iv).encrypt(
        pkcs7_pad(PLANTED_MESSAGE)
    )
    if len(planted_blob) != 48:
        raise ValueError("planted fixture is not 48 bytes")
    planted_hits: list[dict[str, object]] = []
    planted_attempts = 0
    for pair in k1_family["pairs"]:
        planted_attempts += 1
        padded = AES.new(keys_by_id[pair["key_id"]], AES.MODE_CBC, ivs_by_id[pair["iv_id"]]).decrypt(planted_blob)
        try:
            plaintext, _ = strict_pkcs7_unpad(padded)
        except ValueError:
            continue
        readable, _ = _readable(plaintext)
        if plaintext == PLANTED_MESSAGE:
            planted_hits.append({
                "pair_id": pair["pair_id"],
                "key_id": pair["key_id"],
                "iv_id": pair["iv_id"],
                "plaintext_sha256": sha256_hex(plaintext),
                "readable_text": readable,
            })
    planted_control = {
        "planted_pair": planted_pair,
        "message": PLANTED_MESSAGE.decode("ascii"),
        "message_sha256": sha256_hex(PLANTED_MESSAGE),
        "planted_blob_sha256": sha256_hex(planted_blob),
        "attempts": planted_attempts,
        "recoveries": planted_hits,
        "recovered": any(
            hit["pair_id"] == planted_pair["pair_id"] for hit in planted_hits
        ),
    }
    if not planted_control["recovered"]:
        raise ValueError("planted K1 control failed")
    controls["planted_k1_recovery"] = planted_control

    family_counts = {
        "K1": {
            "attempts": counts["K1"]["attempts"],
            "padding_hits": sum(1 for hit in padding_hits if hit["family"] == "K1"),
            "accepted": sum(1 for record in accepted if record["family"] == "K1"),
        },
        "K2": {
            "attempts": counts["K2"]["attempts"],
            "padding_hits": sum(1 for hit in padding_hits if hit["family"] == "K2"),
            "accepted": sum(1 for record in accepted if record["family"] == "K2"),
        },
        "K3": {
            "stage_one_unique_plaintexts": len(stage_one_plaintexts),
            "attempts": counts["K3"]["attempts"],
            "stage_two_a_attempts": counts["K3"]["stage_two_a_attempts"],
            "stage_two_b_attempts": counts["K3"]["stage_two_b_attempts"],
            "padding_hits": sum(1 for hit in padding_hits if hit["family"] == "K3"),
            "accepted": sum(1 for record in accepted if record["family"] == "K3"),
        },
        "K4": {
            "windows": len(k4_windows),
            "scalar_gates": k4_scalar_gates,
            "base58check_tests": 1 + len(k4_windows),
            "format_scans": 1 + len(k4_windows),
            "accepted": len(k4_accepted),
        },
        "K5": {
            "needles": len(needles),
            "corpora": len(k5_corpora),
            "searches": k5_searches,
            "hits": len(salt_hits),
        },
    }
    dedup_counts = {
        "k1_duplicate_pairs_removed": k1_family["duplicates_removed"],
        "k2_duplicate_passwords_removed": manifest["families"]["K2"]["duplicates_removed"],
        "k3_duplicate_stage_one_plaintexts": (
            family_counts["K1"]["padding_hits"] + family_counts["K2"]["padding_hits"]
            - len(stage_one_plaintexts)
        ),
    }
    accepted_all = accepted + [
        {"family": "K4", **record} for record in k4_accepted
    ]
    if prize_matches:
        status = "ACCEPTED_PRIZE_MATCH"
    elif accepted_all or cross_blob or salt_hits:
        status = "ACCEPTED_STRUCTURED_OR_LINKED_OUTPUT"
    else:
        status = "NO_ACCEPTED_OUTPUT"

    result = {
        "schema": "salphaseion-split-envelope-audit-results-v1",
        "manifest_sha256": actual_seal,
        "controls": controls,
        "family_counts": family_counts,
        "dedup_counts": dedup_counts,
        "candidate_stream_sha256": stream.hexdigest(),
        "prize_gate": {
            "output_slices_tested": prize_slices,
            "valid_scalars": prize_valid_scalars,
            "matches": prize_matches,
        },
        "accepted_count": len(accepted_all),
        "accepted": accepted_all,
        "cross_blob": cross_blob,
        "salt_hits": salt_hits,
        "status": status,
        "padding_hits_without_plaintext": padding_hits,
        "important": (
            "Strict padding hits are recorded by hash and metrics only and are "
            "never accepted without a preregistered validator."
        ),
    }
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    result = evaluate()
    print(json.dumps({
        "manifest_sha256": result["manifest_sha256"],
        "controls_pass": all(
            control["pass"] for key, control in result["controls"].items()
            if key != "planted_k1_recovery"
        ),
        "planted_control_recovered": result["controls"]["planted_k1_recovery"]["recovered"],
        "family_counts": result["family_counts"],
        "dedup_counts": result["dedup_counts"],
        "candidate_stream_sha256": result["candidate_stream_sha256"],
        "prize_matches": len(result["prize_gate"]["matches"]),
        "accepted_count": result["accepted_count"],
        "cross_blob": len(result["cross_blob"]),
        "salt_hits": len(result["salt_hits"]),
        "status": result["status"],
    }, indent=2))


if __name__ == "__main__":
    main()
