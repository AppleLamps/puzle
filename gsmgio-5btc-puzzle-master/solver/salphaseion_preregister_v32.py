"""Seal authenticated spiral routes on the completed Z/9Z matrices."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v31 import SEAL_PATH as V31_SEAL, _base9, _decimal_to_hex
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v32.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v32.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v32.json"


def _rotate(matrix):
    return [list(row) for row in zip(*matrix[::-1])]


def _spiral_right(matrix):
    work = [row[:] for row in matrix]
    output = []
    while work:
        output.extend(work.pop(0))
        if work and work[0]:
            for row in work:
                output.append(row.pop())
        if work:
            output.extend(reversed(work.pop()))
        if work and work[0]:
            for row in reversed(work):
                output.append(row.pop(0))
    return output


def _spiral_routes(matrix):
    current = matrix
    routes = {}
    for rotation in range(4):
        for reflected, grid in ((False, current), (True, [row[::-1] for row in current])):
            name = f"rotation-{rotation * 90}{'-mirror' if reflected else ''}"
            route = _spiral_right(grid)
            routes[name] = route
            routes[name + "-reverse"] = route[::-1]
        current = _rotate(current)
    return routes


def build_manifest():
    raw = extract_raw()
    extracted = extract_all()
    first = raw.s91 + raw.matrix_marker_bits
    a_values = [((ord(symbol) - 96) % 9) if index < 91 else ord(symbol) - 97 for index, symbol in enumerate(first)]
    a = [a_values[offset : offset + 13] for offset in range(0, 195, 13)]
    b_values = [(ord(symbol) - 96) % 9 for symbol in raw.s570]
    rows38 = [b_values[offset : offset + 38] for offset in range(0, 570, 38)]
    b1, b2, b3 = ([row[start:end] for row in rows38] for start, end in ((0, 13), (13, 26), (26, 38)))
    matrices = {"A": a, "B-15x38": rows38, "B1": b1, "B2": b2, "B3": b3}

    preimages = defaultdict(set)
    records = []

    def add(label, value):
        if value:
            preimages[value].add(f"completed-matrix-spiral/{label}")

    for matrix_name, matrix in matrices.items():
        for route_name, values in _spiral_routes(matrix).items():
            base = f"{matrix_name}/{route_name}"
            add(f"{base}/digits", "".join(map(str, values)).encode("ascii"))
            add(f"{base}/symbols-a0", bytes(97 + value for value in values))
            add(f"{base}/raw-residue-bytes", bytes(values))
            add(f"{base}/base9", _base9(values))
            add(f"{base}/decimal-to-hex", _decimal_to_hex(values))
            records.append({"label": base, "base9_sha256": sha256_hex(_base9(values))})

    candidates = []
    for preimage in sorted(preimages):
        for expansion, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-raw-digest", hashlib.sha256(preimage).digest()),
        ):
            candidates.append({
                "candidate_id": f"v32c{len(candidates):04d}", "preimage_hex": preimage.hex(),
                "password_expansion": expansion, "password_hex": password.hex(),
                "password_sha256": sha256_hex(password), "provenance": sorted(preimages[preimage]),
            })

    blobs = {"salphaseion-short": extracted.chain1_envelope, "phase32-small": extracted.chain2_envelope, "cosmic-duality": extracted.cosmic_envelope}
    return {
        "schema": "salphaseion-source-only-preregistration-v32-completed-matrix-spirals",
        "status": "SEALED_BEFORE_DECRYPTION",
        "extends_v31_manifest_sha256": V31_SEAL.read_text(encoding="ascii").strip(),
        "source": {
            "capture_stability": capture_stability(), "textarea1_sha256": sha256_hex(raw.textarea1),
            "mapping": "S fields a..i -> 1..8,0; appended marker a,b -> 0,1",
            "route_rule": "all eight rectangular dihedral views of an upper-left right-first spiral and their reversals; includes the published down-first route by symmetry",
            "records_without_plaintext": records,
        },
        "blobs": {name: {"length": len(value), "sha256": sha256_hex(value), "salt_hex": value[8:16].hex(), "ciphertext_length": len(value) - 16} for name, value in blobs.items()},
        "declared_crypto": {"cipher": "AES-256-CBC", "password_to_key": "OpenSSL EVP_BytesToKey", "kdf_digests": ["md5", "sha256"], "padding": "strict PKCS#7", "password_expansions": ["raw", "sha256-lowerhex", "sha256-raw-digest"]},
        "declared_acceptance": {"aes": "existing v1 readable/exact-format rule", "padding_alone": False, "forbidden_evidence": ["expected padding length", "Half/Better Half", "target point", "community plaintext hashes"]},
        "candidate_count": len(candidates), "candidates": candidates,
    }


def main():
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")
    print(json.dumps({"manifest": str(MANIFEST_PATH), "candidate_count": manifest["candidate_count"], "seal_sha256": sha256_hex(encoded)}, indent=2))


if __name__ == "__main__":
    main()
