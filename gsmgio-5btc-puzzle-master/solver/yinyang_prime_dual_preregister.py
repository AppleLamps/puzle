"""Seal the v46 family over the balanced prime pair itself.

``CREATOR_SOURCED.md`` leaves the second door under ``yellowblueprimes`` +
primes + zeroing as its first still-open item, and the creator has said three
times that reaching ``yinyang`` ends the puzzle within hours.  The one
reproducible object that literally earns the name is the balanced pair the
poster produces:

    24 markers ``BBBBYBBBYYBBBBYBBYYBYYBY`` against consecutive primes 2..89
    blue = 484, yellow = 479, the imbalance is the blue prime 5
    zero it: 479 = 479

Every audit so far has used that balance as an *index* -- 479 into the
Architect plaintext -- or has hashed poster streams and quote text at prime
positions.  The two prime lists have never been used as key material in their
own right.  ``yinyang_479_continuation_audit.json`` confirms this: its
prime-reinsertion family operates on quote letters, not on the value lists.

This manifest freezes the twelve lists the dual reading defines, in source
marker order, over the nine serialisations the sealed F-A-E audit already used
and four fixed byte derivations, plus the two phrase-anchored forms that the
creator's own word ``yinyang`` supplies.  The only acceptance gate is
:mod:`solver.targets`; padding is never acceptance.

This is a bounded test of one reading.  It is not a claim that the 479 balance
is the intended step 4 -- that remains fitted, and the creator's position as of
2026-03-03 is that ``yinyang`` has not been reached.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "yinyang_prime_dual_preregistered.json"
SEAL_PATH = ROOT / "yinyang_prime_dual_preregistered.sha256"
RESULT_PATH = ROOT / "yinyang_prime_dual_audit.json"

# The 24 spiral marker colours, as pinned by three existing audit modules.
MARKERS = "BBBBYBBBYYBBBBYBBYYBYYBY"

SERIALIZATIONS = (
    "raw_value_bytes",
    "ascii_decimal_concat",
    "ascii_two_digit_concat",
    "ascii_csv",
    "ascii_space",
    "mod10_ascii",
    "mod9_zero_ascii",
    "mod9_zero_to9_ascii",
    "mod26_A0_ascii",
)
DERIVATIONS = ("sha256", "double_sha256", "sha256^0x7f", "sha256_reversed")
PHRASE = "yinyang"
PHRASE_FORMS = ("phrase_prefix_sha256", "phrase_suffix_sha256")
AES_DIGESTS = ("md5", "sha256")
AES_PASSWORD_FORMS = ("literal", "sha256_lowercase_hex")

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def _primes(count: int) -> list[int]:
    found: list[int] = []
    candidate = 2
    while len(found) < count:
        if all(candidate % prime for prime in found if prime * prime <= candidate):
            found.append(candidate)
        candidate += 1
    return found


def prime_lists() -> dict[str, list[int]]:
    """The twelve lists the balanced yin-yang reading defines."""
    primes = _primes(24)
    if len(MARKERS) != 24:
        raise ValueError("the marker string must carry 24 colours")
    yellow = [prime for prime, colour in zip(primes, MARKERS) if colour == "Y"]
    blue = [prime for prime, colour in zip(primes, MARKERS) if colour == "B"]
    if sum(blue) != 484 or sum(yellow) != 479 or sum(blue) - sum(yellow) != 5 or 5 not in blue:
        raise ValueError("the 484/479 balance did not reproduce; upstream drift")
    blue_zero5 = [0 if prime == 5 else prime for prime in blue]
    return {
        "all24": primes,
        "all24_zero5": [0 if prime == 5 else prime for prime in primes],
        "yellow9": yellow,
        "blue15": blue,
        "blue15_zero5": blue_zero5,
        "blue14_drop5": [prime for prime in blue if prime != 5],
        "yin_yang_pair": yellow + blue_zero5,
        "yang_yin_pair": blue_zero5 + yellow,
        "mirror_pair": yellow + blue_zero5[::-1],
        "mask_yellow_zeroed": [0 if colour == "Y" else prime for prime, colour in zip(primes, MARKERS)],
        "mask_blue_zeroed": [0 if colour == "B" else prime for prime, colour in zip(primes, MARKERS)],
        "sums_pair": [sum(yellow), sum(blue_zero5)],
    }


def build_manifest() -> dict[str, object]:
    lists = prime_lists()
    return {
        "schema": "yinyang-prime-dual-preregistration-v46",
        "status": "SEALED_BEFORE_SCALAR_OR_AES_EVALUATION",
        "hypothesis": (
            "The balanced pair itself -- yellow 479 against blue-with-5-zeroed 479 -- "
            "is the yin-yang object, and its two prime lists are key material rather "
            "than only an index into the Architect plaintext."
        ),
        "distinct_from": {
            "yinyang_479_continuation_audit.json": "uses 479 as a text index; its prime-reinsertion family hashes quote letters at prime positions, not the value lists",
            "second_door_yellowblueprimes_audit.json": "operates on the URL and poster marker streams; its own scope note excludes the 15/9 colour-count reinsertion",
            "architect_source_prime_reinsertion_audit.json": "reinserts primes into the 1,539-byte Architect record",
        },
        "frozen_inputs": {
            "poster_marker_colors": MARKERS,
            "consecutive_primes_2_89": _primes(24),
            "blue_sum": 484,
            "yellow_sum": 479,
            "imbalance": 5,
            "balanced_after_zeroing": True,
        },
        "lists": {
            name: {"length": len(values), "sum": sum(values), "sha256": sha256_hex(",".join(map(str, values)).encode("ascii"))}
            for name, values in sorted(lists.items())
        },
        "expansion": {
            "serializations": list(SERIALIZATIONS),
            "derivations": list(DERIVATIONS),
            "phrase": PHRASE,
            "phrase_forms": list(PHRASE_FORMS),
            "logical_scalar_candidates": len(lists) * len(SERIALIZATIONS) * (len(DERIVATIONS) + len(PHRASE_FORMS)),
        },
        "aes_family": {
            "target": "the authenticated SalPhaseIon short envelope",
            "password_forms": list(AES_PASSWORD_FORMS),
            "kdf_digests": list(AES_DIGESTS),
            "logical_trials": len(lists) * len(SERIALIZATIONS) * len(AES_PASSWORD_FORMS) * len(AES_DIGESTS),
        },
        "acceptance": {
            "only_gate": "solver.targets.gate_scalar_bytes",
            "half": {"exact_public_key": HALF_PUBLIC_UNCOMPRESSED.hex()},
            "better_half": {"hash160": BETTER_H160.hex()},
            "explicitly_not_acceptance": [
                "valid PKCS#7 padding",
                "readable English fragments",
                "a sum that works out to 479",
            ],
            "planted_control_scalar": CONTROL_SCALAR_HEX,
        },
        "out_of_scope": [
            "any Cosmic, Chain 4 or base-38 operand",
            "prime assignments other than the 24 consecutive primes 2..89",
            "zeroing rules other than the single balancing blue 5",
            "free-parameter ciphers keyed by anything not on this list",
        ],
    }


def seal() -> str:
    encoded = (json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    SEAL_PATH.write_text(digest + "\n", encoding="ascii")
    return digest


if __name__ == "__main__":
    print(seal())
