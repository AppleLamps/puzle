"""Seal Architect-key transformations of the completed matrix sum lists.

The raw page orders the authenticated instructions as ``matrixsumlist`` and
then ``lastwordsbeforearchichoice``.  The verified Architect speech contains
two occurrences of "choice".  This manifest therefore fixes exact suffixes of
the words preceding each occurrence as keys for the three reciprocal modular
alphabet operations already established by the puzzle's Beaufort stage.
Nothing decrypted is inspected while this manifest is built.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v29 import SEAL_PATH as V29_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v30.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v30.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v30.json"

ARCHITECT_WINDOWS = {
    "first-choice": "as long as they were given a",
    "second-choice": "even if they were only aware of the",
}


def _matrix_values(text: str, width: int, convention: str, marker_start: int | None = None) -> list[list[int]]:
    values = []
    for index, symbol in enumerate(text):
        if convention == "a0":
            value = ord(symbol) - 97
        elif convention == "a1":
            value = ord(symbol) - 96
        elif convention == "native" and marker_start is not None:
            value = ord(symbol) - (97 if index >= marker_start else 96)
        else:
            raise ValueError(convention)
        values.append(value)
    rows = [values[offset : offset + width] for offset in range(0, len(values), width)]
    if not rows or any(len(row) != width for row in rows):
        raise ValueError("incomplete matrix")
    return rows


def _column_sums(matrix: list[list[int]]) -> list[int]:
    return [sum(row[column] for row in matrix) for column in range(len(matrix[0]))]


def _apply(values: list[int], key: str, operation: str) -> bytes:
    left = [value % 26 for value in values]
    right = [(ord(key[index % len(key)]) - 97) % 26 for index in range(len(values))]
    if operation == "cipher-minus-key":
        output = [(a - b) % 26 for a, b in zip(left, right)]
    elif operation == "key-minus-cipher":
        output = [(b - a) % 26 for a, b in zip(left, right)]
    elif operation == "cipher-plus-key":
        output = [(a + b) % 26 for a, b in zip(left, right)]
    else:
        raise ValueError(operation)
    return bytes(97 + value for value in output)


def build_manifest():
    raw = extract_raw()
    extracted = extract_all()
    completed = raw.s91 + raw.matrix_marker_bits
    sum_vectors: dict[str, list[int]] = {}
    for convention in ("a0", "a1", "native"):
        matrix = _matrix_values(completed, 13, convention, marker_start=91)
        sum_vectors[f"A-15x13/{convention}"] = _column_sums(matrix)
    for convention in ("a0", "a1"):
        matrix = _matrix_values(raw.s570, 38, convention)
        sum_vectors[f"B-15x38/{convention}"] = _column_sums(matrix)

    keys = {}
    for occurrence, window in ARCHITECT_WINDOWS.items():
        words = window.split()
        for count in range(1, len(words) + 1):
            keys[f"{occurrence}/last-{count}-words"] = "".join(words[-count:])

    preimages: dict[bytes, set[str]] = defaultdict(set)

    def add(label: str, value: bytes):
        if value:
            preimages[value].add(f"architect-keyed-matrix-sums/{label}")

    records = []
    vector_sets = dict(sum_vectors)
    for a_name in [name for name in sum_vectors if name.startswith("A-")]:
        for b_name in [name for name in sum_vectors if name.startswith("B-")]:
            vector_sets[f"joined/{a_name}+{b_name}"] = sum_vectors[a_name] + sum_vectors[b_name]

    for vector_name, values in vector_sets.items():
        for direction, routed in (("forward", values), ("reverse", values[::-1])):
            direct = bytes(97 + (value % 26) for value in routed)
            add(f"{vector_name}/{direction}/direct-mod26", direct)
            add(f"{vector_name}/{direction}/direct-mod26-upper", direct.upper())
            for key_name, key in keys.items():
                for operation in ("cipher-minus-key", "key-minus-cipher", "cipher-plus-key"):
                    output = _apply(routed, key, operation)
                    label = f"{vector_name}/{direction}/{key_name}/{operation}"
                    add(f"{label}/lower", output)
                    add(f"{label}/upper", output.upper())
                    records.append({
                        "label": label,
                        "output_sha256": sha256_hex(output),
                    })

    candidates = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v30c{len(candidates):05d}",
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
        "schema": "salphaseion-source-only-preregistration-v30-architect-keyed-matrix-sums",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v29_manifest_sha256": V29_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(),
            "textarea1_sha256": sha256_hex(raw.textarea1),
            "physical_instruction_order": ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword"],
            "architect_windows": ARCHITECT_WINDOWS,
            "key_rule": "every compact whole-word suffix before each authenticated occurrence of choice",
            "matrix_outputs": {name: values for name, values in sum_vectors.items()},
            "operations": ["cipher-minus-key", "key-minus-cipher", "cipher-plus-key"],
            "output_records_without_plaintext": records,
        },
        "blobs": {
            name: {"length": len(value), "sha256": sha256_hex(value), "salt_hex": value[8:16].hex(), "ciphertext_length": len(value) - 16}
            for name, value in blobs.items()
        },
        "declared_crypto": {
            "cipher": "AES-256-CBC",
            "password_to_key": "OpenSSL EVP_BytesToKey",
            "kdf_digests": ["md5", "sha256"],
            "padding": "strict PKCS#7",
            "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"],
        },
        "declared_acceptance": {
            "aes": "existing v1 readable/exact-format rule",
            "padding_alone": False,
            "forbidden_evidence": ["expected padding length", "Half/Better Half", "target point", "community plaintext hashes"],
        },
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def main():
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"], "seal_sha256": sha256_hex(encoded)}, indent=2))


if __name__ == "__main__":
    main()
