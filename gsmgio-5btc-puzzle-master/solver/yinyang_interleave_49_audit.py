"""Evaluate sealed v64: yin-yang 49-wide interleave audit."""

from __future__ import annotations

import hashlib
import json

from . import targets
from .extract import extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import PHASE32_PASSWORD
from .pipeline_operand_split_envelope_audit import _gate_plaintext, _password_bytes
from .salphaseion_split_envelope_preregister import split_envelope
from .yinyang_interleave_49_preregister import (
    COMPOSITIONS,
    ENVELOPES,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    RESULT_PATH,
    SEAL_PATH,
    build_manifest,
    expected_aes_trials,
    expected_scalar_gates,
)
from .yinyang_prime_dual_preregister import prime_lists
from .yinyang_rot180_partition_preregister import partition
from .youwon_middle_block_preregister import difference_state


def _compose(name: str) -> bytes:
    part = partition()
    streams = part["streams"]
    mask98 = str(streams["rot180_inversion_mask98"])
    yin_first = str(streams["pair_first_member_bits98"])[:49]
    mask49 = mask98[:49]
    middle49 = difference_state()["middle49"]
    primes = "".join(str(v) for v in prime_lists()["blue15_zero5"])

    if name == "mod26_add_mask49":
        out = "".join(
            chr((ord(a) - ord("A") + int(b)) % 26 + ord("A")) for a, b in zip(middle49, mask49)
        )
        return out.encode("ascii")
    if name == "mod26_add_yin_first49":
        out = "".join(
            chr((ord(a) - ord("A") + int(b)) % 26 + ord("A")) for a, b in zip(middle49, yin_first)
        )
        return out.encode("ascii")
    if name == "ascii_mask_then_middle":
        return (mask49 + middle49).encode("ascii")
    if name == "prime24_interleave_mask":
        bits = (mask98 * 2)[: max(len(primes), len(mask98))]
        merged = "".join(p + b for p, b in zip(primes, bits[: len(primes)]))
        return merged.encode("ascii")
    raise ValueError(name)


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    env48, _ = split_envelope()
    chain1 = extract_all().chain1_envelope
    blobs = {"chain1": chain1, "env48": env48}
    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")

    aes_results = []
    scalar_results = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches = []

    for composition in COMPOSITIONS:
        material = _compose(composition)
        for derivation in ("sha256", "double_sha256"):
            digest = hashlib.sha256(material).digest()
            if derivation == "double_sha256":
                digest = hashlib.sha256(digest).digest()
            hit = targets.gate_scalar_bytes(digest)
            scalar_results.append({"composition": composition, "derivation": derivation, "prize_match": hit})
            if hit:
                prize_matches.append({"kind": "scalar", "composition": composition, **hit})

        for form in PASSWORD_FORMS:
            password = _password_bytes(material, form)
            for digest in KDF_DIGESTS:
                for target, blob in blobs.items():
                    try:
                        plaintext = decrypt_salted_aes256_cbc(blob, password, digest=digest).plaintext
                    except ValueError:
                        aes_results.append({"composition": composition, "target": target, "form": form, "kdf": digest, "padding_valid": False})
                        continue
                    padding_hits += 1
                    gate = _gate_plaintext(plaintext)
                    record = {"composition": composition, "target": target, "form": form, "kdf": digest, "padding_valid": True, **gate}
                    if gate["legible"]:
                        legible_outputs += 1
                    if gate["prize_matches"]:
                        prize_matches.extend({"kind": f"aes_{target}", "composition": composition, **m} for m in gate["prize_matches"])
                    aes_results.append(record)

    if len(aes_results) != expected_aes_trials():
        raise ValueError("aes drift")
    if len(scalar_results) != expected_scalar_gates():
        raise ValueError("scalar drift")

    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "controls": {"phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you.")},
        "counts": {
            "aes_trials": len(aes_results),
            "scalar_gates": len(scalar_results),
            "padding_hits": padding_hits,
            "legible_outputs": legible_outputs,
            "prize_matches": len(prize_matches),
        },
        "prize_matches": prize_matches,
        "legible_records": [r for r in aes_results if r.get("legible")],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import json as _json

    print(_json.dumps(run()["counts"], indent=2))
