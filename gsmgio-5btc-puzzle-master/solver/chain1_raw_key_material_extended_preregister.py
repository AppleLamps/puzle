"""Seal v74: exhaustive chain1 non-AES scalar material (all tiers).

Extends v73 with four sealed tiers in one manifest:

* **Tier A** — v73 combine rules with full sliding windows (v73 gated offset 0 only).
* **Tier B** — five additional derivations on every view.
* **Tier C** — ten new byte transforms beyond v73.
* **Tier D** — Cartesian product of all transforms × all derivations × windows.
* **Tier E** — decrypted 79-byte chain1 triplet (joke-password AES output) as key
  material: sliding windows plus key1/key2/extension/xor/add direct views.

No AES password attempts in tiers A–D.  Tier E uses the authenticated five-token
decrypt only to obtain the 79-byte blob, then applies the same scalar gate.
"""

from __future__ import annotations

import json

from .chain1_scalar_material import (
    ALL_DERIVATIONS,
    EXTENDED_DERIVATIONS,
    EXTENDED_TRANSFORMS,
    V73_COMBINE_RULES,
    V73_DERIVATIONS,
    all_transforms,
    expected_gates_for_transforms,
    expected_triplet_gates,
)
from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "chain1_raw_key_material_extended_preregistered.json"
SEAL_PATH = ROOT / "chain1_raw_key_material_extended_preregistered.sha256"
RESULT_PATH = ROOT / "chain1_raw_key_material_extended_audit.json"

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def expected_tier_counts() -> dict[str, int]:
    tier_a = expected_gates_for_transforms(
        V73_COMBINE_RULES,
        V73_DERIVATIONS,
        include_prefix32=False,
        include_glued_triplet_slices=False,
    )
    tier_b_extra = expected_gates_for_transforms(
        all_transforms(),
        EXTENDED_DERIVATIONS,
        include_prefix32=True,
        include_glued_triplet_slices=True,
    )
    tier_d = expected_gates_for_transforms(
        all_transforms(),
        ALL_DERIVATIONS,
        include_prefix32=True,
        include_glued_triplet_slices=True,
    )
    tier_e = expected_triplet_gates(ALL_DERIVATIONS)
    return {
        "tier_a_combine_slide_v73_derivations": tier_a,
        "tier_b_extended_derivations_delta": tier_b_extra,
        "tier_d_cartesian_all": tier_d,
        "tier_e_triplet79": tier_e,
        "total_scalar_gates": tier_d + tier_e,
    }


def build_manifest() -> dict[str, object]:
    tiers = expected_tier_counts()
    return {
        "schema": "chain1-raw-key-material-extended-v74",
        "status": "SEALED_BEFORE_SCALAR_EVALUATION",
        "id": "v74_chain1_raw_key_material_extended",
        "date": "2026-08-07",
        "hypothesis": (
            "The remaining non-AES chain1 scalar gates — combine sliding, "
            "extended derivations, new transforms, full cartesian coverage, "
            "and the decrypted 79-byte triplet — still miss both prize targets."
        ),
        "tiers": {
            "A": "v73 combine rules, full sliding, three derivations",
            "B": "five extended derivations on all transforms",
            "C": "ten transforms beyond v73 base/combine set",
            "D": "cartesian: 17 transforms × 8 derivations × windows + prefix32 + glued 32+32+32",
            "E": "79-byte joke-password decrypt triplet path",
        },
        "transforms": list(all_transforms()),
        "derivations": list(ALL_DERIVATIONS),
        "expected_counts": tiers,
        "acceptance": "solver.targets.gate_scalar_bytes only",
        "scope_note": (
            "Superset of v73. Tier D intentionally re-covers v73 windows under "
            "extended derivations. Tier E is the decrypted-79-byte hypothesis "
            "explicitly excluded from v73. Does not reopen AES password search."
        ),
        "control_scalar_hex": CONTROL_SCALAR_HEX,
        "targets": {
            "half_uncompressed_pubkey": HALF_PUBLIC_UNCOMPRESSED.hex(),
            "better_half_hash160": BETTER_H160.hex(),
        },
    }


def seal() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")


if __name__ == "__main__":
    seal()
    counts = expected_tier_counts()
    print(f"sealed {MANIFEST_PATH.name}")
    print(json.dumps(counts, indent=2))
