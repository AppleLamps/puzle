"""Seal the completed 15-row dual-matrix construction before evaluation.

Physical source order gives 91 S symbols followed by the 104 a/b source bits
that spell ``matrixsumlist``.  Together they are 195=15*13 symbols.  The next
S field is 570=15*38 symbols, while the next two decoded phrases have 26+12=38
characters.  This round registers the column sum lists of those two source
matrices and only length-matched key arithmetic.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v23 import SEAL_PATH as V23_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v24.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v24.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v24.json"


def _columns(values: list[int], width: int) -> list[int]:
    if len(values) % width:
        raise ValueError("incomplete matrix")
    rows = [values[offset : offset + width] for offset in range(0, len(values), width)]
    return [sum(row[column] for row in rows) for column in range(width)]


def _forms(values: list[int]) -> dict[str, bytes]:
    return {
        "raw-byte-list": bytes(values),
        "decimal-concatenated": "".join(map(str, values)).encode("ascii"),
        "decimal-spaces": " ".join(map(str, values)).encode("ascii"),
        "decimal-commas": ",".join(map(str, values)).encode("ascii"),
        "compact-json": json.dumps(values, separators=(",", ":")).encode("ascii"),
        "mod9-symbols": bytes(97 + value % 9 for value in values),
        "mod26-a0": bytes(97 + value % 26 for value in values),
        "mod26-a1": bytes(97 + (value - 1) % 26 for value in values),
    }


def _key_variants(values: list[int], key_text: str) -> dict[str, list[int]]:
    key0 = [ord(character) - 97 for character in key_text]
    if len(values) != len(key0):
        raise ValueError("key width mismatch")
    return {
        "direct": values,
        "plus-key-mod26": [(value + key0[index]) % 26 for index, value in enumerate(values)],
        "minus-key-mod26": [(value - key0[index]) % 26 for index, value in enumerate(values)],
        "key-minus-mod26": [(key0[index] - value) % 26 for index, value in enumerate(values)],
    }


def build_manifest() -> dict[str, object]:
    raw = extract_raw()
    extracted = extract_all()
    first_symbols = raw.s91 + raw.matrix_marker_bits
    key13 = raw.matrix_marker
    key38 = raw.lastwords_marker + raw.password_marker
    if len(first_symbols) != 195 or len(raw.s570) != 570:
        raise ValueError("dual matrix lengths changed")
    if len(key13) != 13 or len(key38) != 38:
        raise ValueError("adjacent key widths changed")

    marker_start = len(raw.s91)
    first_conventions = {
        "uniform-a0": [ord(symbol) - 97 for symbol in first_symbols],
        "uniform-a1": [ord(symbol) - 96 for symbol in first_symbols],
        "source-native-s-a1-marker-binary": [
            (ord(symbol) - 96) if index < marker_start else (ord(symbol) - 97)
            for index, symbol in enumerate(first_symbols)
        ],
    }
    second_conventions = {
        "a0": [ord(symbol) - 97 for symbol in raw.s570],
        "a1": [ord(symbol) - 96 for symbol in raw.s570],
    }

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes) -> None:
        if value:
            preimages[value].add(f"dual15-row-matrix/{label}")

    records: list[dict[str, object]] = []
    for first_name, first_values in first_conventions.items():
        sums13 = _columns(first_values, 13)
        for first_variant, first_output in _key_variants(sums13, key13).items():
            for serialization, value in _forms(first_output).items():
                add(f"first/{first_name}/{first_variant}/{serialization}", value)
        for second_name, second_values in second_conventions.items():
            sums38 = _columns(second_values, 38)
            first_variants = _key_variants(sums13, key13)
            second_variants = _key_variants(sums38, key38)
            for second_variant, second_output in second_variants.items():
                for serialization, value in _forms(second_output).items():
                    add(f"second/{second_name}/{second_variant}/{serialization}", value)
            for first_variant, first_output in first_variants.items():
                for second_variant, second_output in second_variants.items():
                    joined = first_output + second_output
                    for serialization, value in _forms(joined).items():
                        add(
                            f"joined/{first_name}/{second_name}/{first_variant}/{second_variant}/{serialization}",
                            value,
                        )
            records.append({
                "first_convention": first_name,
                "second_convention": second_name,
                "sum13": sums13,
                "sum38": sums38,
                "joined_raw_sha256": sha256_hex(bytes(sums13 + sums38)),
            })

    candidates: list[dict[str, object]] = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v24c{len(candidates):05d}",
                "preimage_hex": preimage.hex(),
                "password_expansion": expansion,
                "password_hex": password.hex(),
                "password_sha256": sha256_hex(password),
                "provenance": sorted(preimages[preimage]),
            })

    blobs = {
        "salphaseion-short": extracted.chain1_envelope,
        "phase32-small": extracted.chain2_envelope,
        "cosmic-duality": extracted.cosmic_envelope,
    }
    return {
        "schema": "salphaseion-source-only-preregistration-v24-dual15-row-matrix",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v23_manifest_sha256": V23_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "physical_equations": [
                "len(S91)+len(matrixsumlist source bits)=91+104=195=15*13",
                "len(S570)=570=15*38",
                "len(matrixsumlist)=13",
                "len(lastwordsbeforearchichoice)+len(thispassword)=26+12=38",
            ],
            "matrix_rule": "source-order 15-row matrices; column sums only",
            "records": records,
        },
        "blobs": {
            name: {
                "length": len(envelope),
                "sha256": sha256_hex(envelope),
                "salt_hex": envelope[8:16].hex(),
                "ciphertext_length": len(envelope) - 16,
            }
            for name, envelope in blobs.items()
        },
        "declared_crypto": {
            "cipher": "AES-256-CBC",
            "password_to_key": "OpenSSL EVP_BytesToKey",
            "kdf_digests": ["md5", "sha256"],
            "padding": "strict PKCS#7",
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
        },
        "declared_acceptance": {
            "inherits_v1_rules_verbatim": True,
            "padding_alone": False,
            "forbidden_evidence": [
                "expected padding length", "plus/minus block grammar", "Half/Better Half",
                "target point or address", "community plaintext hashes",
            ],
        },
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def main() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({
        "manifest": str(MANIFEST_PATH),
        "candidate_count": manifest["candidate_count"],
        "seal_sha256": sha256_hex(encoded),
    }, indent=2))


if __name__ == "__main__":
    main()
