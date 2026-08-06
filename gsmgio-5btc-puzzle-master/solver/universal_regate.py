"""Re-gate every 32-byte value this repository has ever recorded.

The attempt log carried a transcript-only claim that 38,219 values from 82
audit files had been re-checked against both funded addresses, but no result
artifact was ever committed, so the claim was unverifiable.  More importantly,
most audits were written before ``solver.targets`` existed and gate only on
Half's exact public point; Better Half's ``hash160`` was never applied to their
output.

This module closes both gaps mechanically.  It streams every JSON artifact in
the repository, extracts every 64-character hexadecimal token, and gates each
one through :func:`solver.targets.gate_scalar` under two readings:

``big-endian``
    the token as written, which is how every audit serialized a scalar;
``byte-reversed``
    the same 32 bytes reversed, which covers the little-endian serializations
    that appear in several historical notes.

This is bookkeeping, not a new hypothesis.  It cannot find a key that was never
generated; it can only prove that nothing already generated was silently
discarded by an incomplete gate.  A planted control scalar is injected into the
candidate set on every run so that a passing gate is demonstrated, not assumed.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .extract import ROOT
from .secp256k1_verify import N
from . import targets


RESULT_PATH = ROOT / "universal_regate.json"
HEX64 = re.compile(rb"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])")
CHUNK = 1 << 22
OVERLAP = 80

# Deterministic control.  Its scalar is not derived from puzzle material; it
# exists only to prove the gate accepts a true positive on this run.
CONTROL_SCALAR = 0x00000000000000000000000000000000000000000000000000000000000C0DE5


def search_roots() -> list[Path]:
    """Every directory whose JSON artifacts belong to this investigation."""
    roots = [ROOT, ROOT / "results", ROOT / "tmp", ROOT / "artifacts"]
    parent = ROOT.parent
    if (parent / "SOLUTION.md").exists():
        roots.append(parent)
    return [path for path in roots if path.is_dir()]


def json_files() -> list[Path]:
    seen: dict[Path, None] = {}
    for root in search_roots():
        for path in sorted(root.glob("*.json")):
            seen.setdefault(path.resolve(), None)
    return list(seen)


def scan_file(path: Path, tokens: set[bytes]) -> int:
    """Stream one file, adding every 64-hex token.  Returns bytes read."""
    total = 0
    tail = b""
    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            total += len(block)
            window = tail + block
            for match in HEX64.finditer(window):
                tokens.add(match.group(1).lower())
            tail = window[-OVERLAP:]
    return total


def collect() -> tuple[set[bytes], list[dict[str, object]], int]:
    tokens: set[bytes] = set()
    manifest: list[dict[str, object]] = []
    total_bytes = 0
    for path in json_files():
        before = len(tokens)
        read = scan_file(path, tokens)
        total_bytes += read
        manifest.append(
            {
                "file": str(path.relative_to(ROOT.parent)).replace("\\", "/"),
                "bytes": read,
                "new_unique_tokens": len(tokens) - before,
            }
        )
    return tokens, manifest, total_bytes


def candidate_scalars(tokens: set[bytes]) -> dict[int, str]:
    """Map every in-range scalar to the reading that produced it."""
    scalars: dict[int, str] = {}
    for token in tokens:
        raw = bytes.fromhex(token.decode("ascii"))
        for reading, value in (
            ("big-endian", raw),
            ("byte-reversed", raw[::-1]),
        ):
            scalar = int.from_bytes(value, "big") % N
            if scalar and scalar not in scalars:
                scalars[scalar] = reading
    return scalars


def _positive_control() -> dict[str, object]:
    """Prove the real gate accepts a true positive and rejects a near miss.

    The control point is planted as a synthetic target and pushed through the
    production :func:`solver.targets.gate_point`, so an acceptance failure here
    means the whole run's negative is untrustworthy.
    """
    from .secp256k1_verify import hash160, scalar_multiply

    x, y = scalar_multiply(CONTROL_SCALAR)
    encodings = targets.serializations(x, y)

    as_half = targets.gate_point(x, y, half_public=encodings["uncompressed"])
    as_better = targets.gate_point(x, y, better_h160=hash160(encodings["compressed"]))
    against_real = targets.gate_point(x, y)

    accepted_half = bool(as_half and as_half.get("half_exact_public_key"))
    accepted_better = bool(as_better and as_better.get("better_hash160") == ["compressed"])
    if not (accepted_half and accepted_better and against_real is None):
        raise AssertionError("universal re-gate positive control failed")

    return {
        "scalar": f"{CONTROL_SCALAR:064x}",
        "derived_addresses": {
            name: targets.address_for(value) for name, value in encodings.items()
        },
        "planted_as_half_public_key_accepted": accepted_half,
        "planted_as_better_hash160_accepted": accepted_better,
        "rejected_against_real_targets": against_real is None,
    }


def run() -> dict[str, object]:
    started = time.time()
    tokens, manifest, total_bytes = collect()
    scalars = candidate_scalars(tokens)

    control_present = CONTROL_SCALAR in scalars
    scalars.setdefault(CONTROL_SCALAR, "planted-control")

    matches: list[dict[str, object]] = []
    for scalar, reading in scalars.items():
        verdict = targets.gate_scalar(scalar)
        if verdict is None:
            continue
        verdict["reading"] = reading
        matches.append(verdict)

    control = _positive_control()

    payload = {
        "schema": "universal-regate/1",
        "purpose": "re-gate every recorded 32-byte value against both funded prize targets",
        "targets": targets.self_check(),
        "corpus": {
            "json_files": len(manifest),
            "bytes_scanned": total_bytes,
            "unique_hex64_tokens": len(tokens),
            "unique_in_range_scalars": len(scalars) - (0 if control_present else 1),
            "readings": ["big-endian", "byte-reversed"],
        },
        "gate": {
            "half_exact_public_key": True,
            "half_hash160_both_serializations": True,
            "better_hash160_both_serializations": True,
        },
        "control": control,
        "matches": matches,
        "status": "PRIZE_MATCH" if matches else "NO_PRIZE_MATCH",
        "elapsed_seconds": round(time.time() - started, 1),
        "files": manifest,
    }
    RESULT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


if __name__ == "__main__":  # pragma: no cover
    result = run()
    print(
        json.dumps(
            {key: value for key, value in result.items() if key != "files"},
            indent=2,
        )
    )
