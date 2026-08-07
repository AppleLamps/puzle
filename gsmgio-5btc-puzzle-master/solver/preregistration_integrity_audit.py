"""Check that every sealed preregistration in this package still binds.

The preregistration discipline is what separates a bounded negative from a
post-hoc story, so the seals have to be checkable from committed bytes alone.
Three distinct ways for that to break were found on 2026-08-06, and only one
of them shows up as a seal mismatch:

1. **Seal mismatch** -- a manifest file no longer hashes to its ``.sha256``.
   None were found; this check is the cheap regression guard.
2. **Unresolvable digest** -- a result JSON records a ``manifest_sha256`` that
   no committed manifest produces, so the family behind the negative cannot be
   inspected.  Two sub-cases matter and they are very different: a manifest
   that is merely absent but regenerates bit-exactly from committed code is
   recoverable, while a digest that nothing in the repository reproduces is
   not.
3. **Drift-gate failure** -- the manifest hashes correctly and the evaluator
   still refuses to run, because re-deriving the manifest from the current
   artifacts produces different bytes.  This is the strongest signal: the
   sealed family was built from inputs that were never committed.

Run ``python -m solver.preregistration_integrity_audit``.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from pathlib import Path

from .extract import ROOT


RESULT_PATH = ROOT / "preregistration_integrity_audit.json"

DIGEST_KEYS = ("manifest_sha256", "preregistration_sha256")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")

# Manifests deliberately excluded from version control by size.  Each entry is
# the module whose ``build_manifest`` regenerates it; the audit records whether
# the regeneration still reproduces the sealed digest, because that is what
# keeps the corresponding negative auditable.  Regenerating both costs roughly
# 30 seconds and 1.3 GB, so it is opt-in.
LARGE_REGENERABLE = {
    "salphaseion_preregistered_candidates_v38.json": "solver.salphaseion_preregister_v38",
    "salphaseion_preregistered_candidates_v39.json": "solver.salphaseion_preregister_v39",
}

# Modules whose evaluator re-derives its manifest before decrypting anything.
DRIFT_GATED = (
    "solver.salphaseion_split_envelope_preregister",
    "solver.salphaseion_split_envelope_reseal",
    "solver.sfield_base9_substitution_preregister",
    "solver.sfield_cipher_preregister",
    "solver.youwon_middle_block_preregister",
    "solver.fae_paired_list_preregister",
    "solver.yinyang_prime_dual_preregister",
    "solver.yinyang_rot180_partition_preregister",
    "solver.matrixsumlist_instruction_preregister",
    "solver.cipher_catalogue_23_16_7_preregister",
)

# A drift that has been diagnosed and superseded by a re-sealed copy.  The
# original stays untouched as the historical record, so its gate keeps failing
# on purpose; what matters is that the negative is reachable somewhere.
REPAIRED_DRIFT = {
    "solver.salphaseion_split_envelope_preregister": {
        "repaired_by": "solver.salphaseion_split_envelope_reseal",
        "repaired_result": "salphaseion_split_envelope_results_v2.json",
        "cause": "sealed against an uncommitted copy of seven_stage_passwords_intertwine_audit.json",
    },
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_seals() -> list[dict[str, object]]:
    records = []
    for seal_path in sorted(ROOT.rglob("*.sha256")):
        manifest_path = seal_path.parent / (seal_path.name[: -len(".sha256")] + ".json")
        expected = seal_path.read_text(encoding="ascii").strip().split()[0]
        if not manifest_path.exists():
            records.append(
                {
                    "seal": str(seal_path.relative_to(ROOT)),
                    "manifest_present": False,
                    "sealed_digest": expected,
                    "status": "MANIFEST_ABSENT",
                }
            )
            continue
        actual = _sha256(manifest_path)
        records.append(
            {
                "seal": str(seal_path.relative_to(ROOT)),
                "manifest_present": True,
                "sealed_digest": expected,
                "actual_digest": actual,
                "status": "OK" if actual == expected else "SEAL_MISMATCH",
            }
        )
    return records


def _digest_index() -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for path in ROOT.rglob("*.json"):
        try:
            index.setdefault(_sha256(path), []).append(str(path.relative_to(ROOT)))
        except OSError:
            continue
    return index


def _check_result_digests(index: dict[str, list[str]]) -> list[dict[str, object]]:
    records = []
    for path in sorted(ROOT.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        for key in DIGEST_KEYS:
            value = payload.get(key)
            if not isinstance(value, str) or not HEX64.match(value):
                continue
            resolved = index.get(value, [])
            name = str(path.relative_to(ROOT))
            record = {
                "result": name,
                "key": key,
                "digest": value,
                "resolves_to": resolved,
                "status": "RESOLVED" if resolved else "UNRESOLVED",
            }
            if not resolved:
                expected_manifest = next(
                    (
                        manifest
                        for manifest, module in LARGE_REGENERABLE.items()
                        if (ROOT / (manifest[: -len(".json")] + ".sha256")).exists()
                        and (ROOT / (manifest[: -len(".json")] + ".sha256")).read_text(encoding="ascii").strip() == value
                    ),
                    None,
                )
                if expected_manifest:
                    record["status"] = "UNRESOLVED_BUT_REGENERABLE"
                    record["regenerating_module"] = LARGE_REGENERABLE[expected_manifest]
                    record["manifest"] = expected_manifest
            records.append(record)
    return records


def _check_drift_gates() -> list[dict[str, object]]:
    records = []
    for module_name in DRIFT_GATED:
        module = importlib.import_module(module_name)
        manifest_path: Path = module.MANIFEST_PATH
        record: dict[str, object] = {"module": module_name, "manifest": str(manifest_path.relative_to(ROOT))}
        try:
            sealed = json.loads(manifest_path.read_bytes())
            # Round-trip the re-derivation so tuples compare equal to the lists
            # a manifest necessarily holds; only real drift should be reported.
            rederived = json.loads(json.dumps(module.build_manifest()))
            record["passes"] = rederived == sealed
            if not record["passes"]:
                record["differing_paths"] = _diff_paths(sealed, rederived)[:8]
        except Exception as error:  # pragma: no cover - reported, never raised
            record["passes"] = False
            record["error"] = f"{type(error).__name__}: {error}"
        if not record["passes"] and module_name in REPAIRED_DRIFT:
            record["repair"] = REPAIRED_DRIFT[module_name]
        records.append(record)
    return records


def _diff_paths(left: object, right: object, prefix: str = "") -> list[str]:
    if isinstance(left, dict) and isinstance(right, dict):
        found: list[str] = []
        for key in sorted(set(left) | set(right)):
            found.extend(_diff_paths(left.get(key), right.get(key), f"{prefix}/{key}"))
        return found
    if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        found = []
        for index, (a, b) in enumerate(zip(left, right)):
            found.extend(_diff_paths(a, b, f"{prefix}[{index}]"))
        return found
    return [] if left == right else [prefix or "/"]


def regenerate_large_manifests() -> list[dict[str, object]]:
    """Rebuild the two gitignored manifests in memory and check their digests."""
    records = []
    for manifest, module_name in LARGE_REGENERABLE.items():
        seal_path = ROOT / (manifest[: -len(".json")] + ".sha256")
        module = importlib.import_module(module_name)
        encoded = (json.dumps(module.build_manifest(), indent=2, sort_keys=True) + "\n").encode("utf-8")
        records.append(
            {
                "manifest": manifest,
                "module": module_name,
                "bytes": len(encoded),
                "sealed_digest": seal_path.read_text(encoding="ascii").strip(),
                "regenerated_digest": hashlib.sha256(encoded).hexdigest(),
                "reproduces_seal": hashlib.sha256(encoded).hexdigest() == seal_path.read_text(encoding="ascii").strip(),
            }
        )
    return records


def run(*, regenerate_large: bool = False) -> dict[str, object]:
    seals = _check_seals()
    digests = _check_result_digests(_digest_index())
    drift = _check_drift_gates()

    seal_mismatches = [record for record in seals if record["status"] == "SEAL_MISMATCH"]
    absent = [record for record in seals if record["status"] == "MANIFEST_ABSENT"]
    unresolved = [record for record in digests if record["status"] == "UNRESOLVED"]
    regenerable = [record for record in digests if record["status"] == "UNRESOLVED_BUT_REGENERABLE"]
    failed_gates = [record for record in drift if not record["passes"]]
    unrepaired_gates = [record for record in failed_gates if "repair" not in record]

    result = {
        "schema": "preregistration-integrity-audit-v1",
        "status": "CLEAN"
        if not (seal_mismatches or unresolved or unrepaired_gates)
        else "DEFECTS_PRESENT",
        "summary": {
            "seals_checked": len(seals),
            "seal_mismatches": len(seal_mismatches),
            "manifests_absent": len(absent),
            "result_digests_checked": len(digests),
            "unresolved_digests": len(unresolved),
            "unresolved_but_regenerable": len(regenerable),
            "drift_gates_checked": len(drift),
            "drift_gates_failing": len(failed_gates),
            "drift_gates_failing_unrepaired": len(unrepaired_gates),
        },
        "seals": seals,
        "result_digests": digests,
        "drift_gates": drift,
        "large_regenerable_manifests": regenerate_large_manifests() if regenerate_large else {
            "checked": False,
            "note": "Pass regenerate_large=True; rebuilding both costs roughly 30 s and 1.3 GB.",
        },
        "scope_note": (
            "This checks that sealed families remain auditable from committed bytes. "
            "It says nothing about whether any family was a good hypothesis, and a "
            "CLEAN status is not evidence about the puzzle."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import sys

    outcome = run(regenerate_large="--regenerate-large" in sys.argv)
    print(json.dumps({"status": outcome["status"], "summary": outcome["summary"]}, indent=2))
    for entry in outcome["drift_gates"]:
        if not entry["passes"]:
            print("DRIFT", entry)
    for entry in outcome["result_digests"]:
        if entry["status"] != "RESOLVED":
            print(entry["status"], entry["result"], entry["digest"])
