"""Decisive test: hash faithful page-140 text units of The Heart of Sufism
(1999 Shambhala, ISBN 9781570624025) and check each resulting scalar against
the complete GSMG prize public key.

This is a bounded, source-grounded test.  It does not enumerate dictionaries;
it tests only the exact page-defined text units and faithful normalizations.
"""

from __future__ import annotations

import hashlib
import re

from solver.secp256k1_verify import N, public_key, p2pkh_address
from solver.targets import HALF_ADDRESS, HALF_X, HALF_Y

TARGET_X = HALF_X
TARGET_Y = HALF_Y
TARGET_ADDRESS = HALF_ADDRESS


def _target_match(scalar: int) -> bool:
    scalar %= N
    if not scalar:
        return False
    pub = public_key(scalar.to_bytes(32, "big"), compressed=False)
    x = int.from_bytes(pub[1:33], "big")
    y = int.from_bytes(pub[33:], "big")
    return x == TARGET_X and y == TARGET_Y


# Exact page-140 text units recovered from the confirmed 1999 edition via
# Google Books search-within-volume (ISBN 9781570624025, id P3N92HA0PJgC).
PAGE140_UNITS = [
    "a breath which comes directly from the source seeks a body an accommodation in which to function",
    "a breath which comes directly from the source seeks a body, an accommodation in which to function",
    "a breath which comes directly from the source seeks a body an accommodation in which to function a thought is as a body",
    "the breath which runs from the source as a ray of the spirit which may be likened to the sun makes the thought an entity it lives as an entity",
    "a word expressed at such a moment must live and carry out its purpose",
    "a word expressed at such a moment must live and carry out its purpose it is like",
    "the breath which runs from the source",
    "a breath which comes directly from the source",
    "seeks a body an accommodation in which to function",
    "a thought is as a body",
    "makes the thought an entity it lives as an entity",
    "must live and carry out its purpose",
    "directly from the source",
    "in which to function",
    "carry out its purpose",
    "the source seeks a body",
    "a body an accommodation in which to function",
    "the thought an entity it lives as an entity",
]

# The Architect's own paraphrase (the puzzle's rewrite of this source).
ARCHITECT_UNITS = [
    "return to the source codes",
    "the function of the you",
    "the code you hopefully carry",
    "reinserting the prime basics",
    "return to the source",
    "the function of the you is now to return to the source codes",
    "allowing a temporary dissemination of the code you hopefully carry",
    "the function of the you is now to return to the source codes allowing a temporary dissemination of the code you hopefully carry",
]

# The seed metaphor (page 139, "The Life of Thought").
SEED_UNITS = [
    "a traveler who is journeying and who on his way has some seeds in his hands which he throws on the ground",
    "a traveler who is journeying and who, on his way, has some seeds in his hands, which he throws on the ground",
    "he just threw the seeds and they are there the earth has taken them the water has reared them and the sun and the air have helped them to grow",
    "the earth has taken them the water has reared them and the sun and the air have helped them to grow",
    "he just threw the seeds and they are there",
]


def _normalizations(text: str) -> list[tuple[str, str]]:
    """Faithful normalizations: raw, lower, upper, no-punct, no-space, etc."""
    forms = []
    forms.append(("raw", text))
    forms.append(("lower", text.lower()))
    forms.append(("upper", text.upper()))
    forms.append(("title", text.title()))
    no_punct = re.sub(r"[^A-Za-z0-9 ]", "", text)
    forms.append(("no-punct", no_punct))
    forms.append(("no-punct-lower", no_punct.lower()))
    no_space = re.sub(r"\s+", "", text)
    forms.append(("no-space", no_space))
    forms.append(("no-space-lower", no_space.lower()))
    no_punct_nospace = re.sub(r"[^A-Za-z0-9]", "", text)
    forms.append(("compact", no_punct_nospace))
    forms.append(("compact-lower", no_punct_nospace.lower()))
    return forms


def run() -> dict[str, object]:
    all_units = {
        "page140": PAGE140_UNITS,
        "architect": ARCHITECT_UNITS,
        "seed139": SEED_UNITS,
    }
    records: list[dict[str, object]] = []
    matches: list[dict[str, object]] = []
    seen_scalars: set[int] = set()

    for group, units in all_units.items():
        for unit in units:
            for norm_name, norm in _normalizations(unit):
                # SHA-256 of the normalized text -> scalar
                digest = hashlib.sha256(norm.encode("utf-8")).digest()
                scalar = int.from_bytes(digest, "big") % N
                matched = scalar not in seen_scalars and _target_match(scalar)
                if matched:
                    seen_scalars.add(scalar)
                    matches.append({
                        "group": group,
                        "unit": unit,
                        "normalization": norm_name,
                        "scalar": scalar.to_bytes(32, "big").hex(),
                        "address": p2pkh_address(scalar.to_bytes(32, "big"), compressed=False),
                    })
                records.append({
                    "group": group,
                    "unit": unit,
                    "normalization": norm_name,
                    "scalar_sha256": digest.hex(),
                    "matched": matched,
                })

    return {
        "target_address": TARGET_ADDRESS,
        "unit_count": sum(len(u) for u in all_units.values()),
        "normalization_count": len(records),
        "matches": matches,
        "match_count": len(matches),
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
