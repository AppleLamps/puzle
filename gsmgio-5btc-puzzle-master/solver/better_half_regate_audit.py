"""Re-gate the Half-only audit families against Better Half's hash160.

Five older audit modules define their own ``_target_match`` against Half's
exact public point only and never test Better Half's ``hash160``:

- ``prime_reinsertion_audit.py``
- ``frontier_experiment.py``
- ``trail1_splice_experiment.py``
- ``trail1_permutation_experiment.py``
- ``page140_key_test.py`` (no result JSON on disk; skipped)

Their recorded negatives certify only that no candidate matched Half's exact
public key.  The authenticated VIC plaintext reads "THE PRIVATE KEYS BELONG TO
HALF AND BETTER HALF" (plural keys), and ``HALF_AND_BETTER_HALF.md`` flagged
the Half-only certificate concern before talking itself out of it.  This
module re-runs each audit's candidate generation with its ``_target_match``
replaced by ``solver.targets.gate_scalar``, which tests **both** targets on
every candidate: Half's exact public key, Half's hash160, and Better Half's
hash160 under both serializations.

This is a bounded re-gating pass, not a new search: the candidate families are
exactly those of the original audits, regenerated from the same committed code
and inputs.  The only change is the gate function.

Run ``python -m solver.better_half_regate_audit``.
"""

from __future__ import annotations

import json

from .extract import ROOT
from . import targets


RESULT_PATH = ROOT / "better_half_regate_audit.json"


def _patch_and_run(module_name: str) -> dict[str, object]:
    """Replace a module's _target_match with targets.gate_scalar and re-run."""
    import importlib
    module = importlib.import_module(module_name)

    if not hasattr(module, "_target_match"):
        return {"name": module_name, "status": "NO_TARGET_MATCH_FUNCTION"}

    original = module._target_match
    half_matches: list[dict[str, str]] = []
    better_matches: list[dict[str, str]] = []

    def full_gate(candidate: int) -> bool:
        hit = targets.gate_scalar(candidate)
        if hit is None:
            return False
        record = {
            "scalar": f"{candidate % targets.N:064x}",
            "target": hit.get("target", "unknown"),
        }
        if "better" in str(hit.get("target", "")).lower():
            better_matches.append(record)
        else:
            half_matches.append(record)
        return True

    module._target_match = full_gate
    try:
        outcome = module.run()
    finally:
        module._target_match = original

    return {
        "name": module_name,
        "status": "GATED",
        "original_status": outcome.get("status"),
        "unique_nonzero_scalars": outcome.get("unique_nonzero_scalars",
                                                outcome.get("generated_candidates", "?")),
        "original_matches": len(outcome.get("matches", [])),
        "half_matches": half_matches,
        "better_half_matches": better_matches,
    }


def run() -> dict[str, object]:
    targets.self_check()

    # Negative control: a random scalar should not match either target.
    control_scalar = 0x0000000000000000000000000000000000000000000000000000000000000001
    control_hit = targets.gate_scalar(control_scalar)
    assert control_hit is None, "negative control failed: gate accepted scalar=1"

    half_only_modules = [
        "solver.prime_reinsertion_audit",
        "solver.frontier_experiment",
        "solver.trail1_splice_experiment",
        "solver.trail1_permutation_experiment",
    ]

    per_audit: list[dict[str, object]] = []
    all_half: list[dict[str, str]] = []
    all_better: list[dict[str, str]] = []

    for name in half_only_modules:
        result = _patch_and_run(name)
        per_audit.append(result)
        all_half.extend(result.get("half_matches", []))
        all_better.extend(result.get("better_half_matches", []))

    outcome = {
        "schema": "better-half-regate-audit-v1",
        "status": (
            "BETTER_HALF_MATCH" if all_better
            else "HALF_MATCH" if all_half
            else "NO_MATCH_IN_REGATED_FAMILY"
        ),
        "summary": {
            "audits_regated": len([a for a in per_audit if a.get("status") == "GATED"]),
            "half_matches": len(all_half),
            "better_half_matches": len(all_better),
        },
        "per_audit": per_audit,
        "half_matches": all_half,
        "better_half_matches": all_better,
        "controls": {
            "negative_control_scalar_1_rejected": control_hit is None,
            "targets_self_check_passed": True,
        },
        "scope_note": (
            "Re-runs four Half-only audit modules with their _target_match "
            "replaced by solver.targets.gate_scalar, which tests both Half "
            "(exact pubkey + hash160) and Better Half (hash160 under both "
            "serializations) on every candidate. The candidate families are "
            "exactly those of the original audits, regenerated from the same "
            "committed code. A NO_MATCH result means none of the candidates "
            "matched Better Half's hash160; it does not mean Better Half is "
            "not a target — only that these specific bounded families did not "
            "produce a Better Half key."
        ),
    }
    RESULT_PATH.write_text(json.dumps(outcome, indent=2) + "\n", encoding="utf-8")
    return outcome


if __name__ == "__main__":
    result = run()
    print(json.dumps({"status": result["status"], "summary": result["summary"]}, indent=2))
