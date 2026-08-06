"""Re-seal the split-envelope manifest so its evaluator runs on committed bytes.

The 2026-08-05 split-envelope audit closed open-frontier item 3 (the
independent 48-byte SalPhaseIon envelope) with ``NO_ACCEPTED_OUTPUT``.  Its
seal is intact -- ``salphaseion_split_envelope_preregistered.json`` still
hashes to its ``.sha256`` -- but the evaluator's drift gate rejects it, because
the manifest records

    "stage_passwords_file_sha256": "e9cc5043..."

for ``seven_stage_passwords_intertwine_audit.json``, while every committed
version of that file hashes to ``be85c87d...``.  The manifest was therefore
sealed against a working-tree copy that was never checked in, and the audit
could not be re-executed by anyone else.

Nothing else in the manifest differs: the drift report names exactly one path,
so the candidate families themselves re-derive unchanged.  The original
manifest and seal are left untouched as the historical record.  This module
writes a v2 manifest from the committed artifacts, seals it, and re-runs the
same evaluator against it, which restores re-derivability of the negative.

Run ``python -m solver.salphaseion_split_envelope_reseal``.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_split_envelope_eval import evaluate
from .salphaseion_split_envelope_preregister import (
    MANIFEST_PATH as V1_MANIFEST_PATH,
    build_manifest,
)


MANIFEST_PATH = ROOT / "salphaseion_split_envelope_preregistered_v2.json"
SEAL_PATH = ROOT / "salphaseion_split_envelope_preregistered_v2.sha256"
RESULT_PATH = ROOT / "salphaseion_split_envelope_results_v2.json"


def drift_report() -> dict[str, object]:
    """Name every manifest path where v1 and the committed artifacts disagree."""
    sealed = json.loads(V1_MANIFEST_PATH.read_bytes())
    rederived = json.loads(json.dumps(build_manifest()))

    def walk(left: object, right: object, prefix: str = "") -> list[dict[str, object]]:
        if isinstance(left, dict) and isinstance(right, dict):
            found: list[dict[str, object]] = []
            for key in sorted(set(left) | set(right)):
                found.extend(walk(left.get(key), right.get(key), f"{prefix}/{key}"))
            return found
        if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
            found = []
            for index, (a, b) in enumerate(zip(left, right)):
                found.extend(walk(a, b, f"{prefix}[{index}]"))
            return found
        if left == right:
            return []
        return [{"path": prefix or "/", "sealed": left, "rederived": right}]

    differences = walk(sealed, rederived)
    return {
        "v1_manifest": str(V1_MANIFEST_PATH.relative_to(ROOT)),
        "v1_seal_intact": hashlib.sha256(V1_MANIFEST_PATH.read_bytes()).hexdigest()
        == (ROOT / "salphaseion_split_envelope_preregistered.sha256").read_text(encoding="ascii").strip(),
        "differing_path_count": len(differences),
        "differences": differences,
    }


def reseal() -> str:
    encoded = (json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    SEAL_PATH.write_text(digest + "\n", encoding="ascii")
    return digest


def run() -> dict[str, object]:
    report = drift_report()
    digest = reseal()
    result = evaluate(manifest_path=MANIFEST_PATH, seal_path=SEAL_PATH, result_path=RESULT_PATH)
    payload = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    payload["reseal"] = {
        "reason": "the v1 manifest was sealed against an uncommitted copy of seven_stage_passwords_intertwine_audit.json",
        "v1_drift": report,
        "v2_manifest_sha256": digest,
        "note": "v1 manifest and seal are unchanged; this is an added re-derivable copy, not an edit.",
    }
    RESULT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return {"status": result.get("status"), "v2_manifest_sha256": digest, "v1_drift": report}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
