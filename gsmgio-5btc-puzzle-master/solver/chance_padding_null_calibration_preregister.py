"""Seal v79: null calibration for the three recorded post-3.2 envelope opens.

The repository records three envelopes as "opened" after phase 3.2:

* ``chain1`` under the five SalPhaseIon tokens, giving 79 bytes read as 32+32+15
* ``chain2`` under the uncompressed WIF of ``chain1`` bytes 0..32, giving 79 bytes
* ``cosmic`` under the seven-token digest XOR, giving 1327 bytes

None is legible, and ``SOLUTION.md`` defends the first two with the claim that
"two independent routes meeting on the same bytes is not padding luck".  This
manifest tests that defence directly rather than adding another password family.

Every one of the three strips **exactly one** PKCS#7 byte, which is the only
padding length a wrong key can produce with appreciable probability.  The one
envelope whose password is creator-derived and whose plaintext reads as English
-- phase 3.2 -- strips ten.  The null hypothesis is therefore that all three are
chance padding hits and that the 32+32+15 "triplet grammar" is an artifact of
the ciphertext length rather than a designed record layout.

Predictions are analytic, fixed here before the sealed run, and each one is a
falsifier: if the measured value lands outside its band the null is wrong and
the recorded opens gain support.

P1  Random-password strict-unpad rate on chain1 is ~1/256.
P2  Given a chance unpad, plaintext length is exactly ``len(ciphertext) - 1``
    (79 bytes) in the overwhelming majority of cases.  If chance unpads were
    usually some other length, 79 bytes would be evidence of design.
P3  Given a chance unpad, the canonical cascade rule -- uncompressed WIF of
    bytes 0..32 as the chain2 password -- opens chain2 at ~1/256.  A rate far
    below that would make the observed cascade meaningful.
P4  Given a chance unpad, *some* member of the natural serialisation menu a
    solver would try opens chain2 at ~``menu/256``.  This is the false-positive
    rate of the procedure that discovered the cascade, as opposed to the rate
    of a single pre-committed guess.
P5  The authenticated phase 3.2 open strips a padding length other than 1,
    which is what a designed payload looks like.

A 200,000-trial pilot preceded this seal and produced 0.389% / 99.36% / 0.00% /
8.02%.  The predictions above are derived from the block cipher, not from that
pilot, and the sealed run uses a different trial count and a fixed seed.
"""

from __future__ import annotations

import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex


MANIFEST_PATH = ROOT / "chance_padding_null_calibration_preregistered.json"
SEAL_PATH = ROOT / "chance_padding_null_calibration_preregistered.sha256"
RESULT_PATH = ROOT / "chance_padding_null_calibration_audit.json"

# Deterministic so the recorded result re-derives bit-exactly from committed code.
TRIALS = 2_000_000
SEED = 20260807

# Password shape of the null draws: 32 lowercase hex characters, the same shape
# as every authenticated password in this puzzle.
PASSWORD_FORM = "32-lowercase-hex-characters-from-16-random-bytes"

# The serialisations of a 79-byte 32+32+15 record a solver would plausibly try
# as the next envelope's password.  Order matters: index 0 is the canonical
# rule that the recorded cascade uses.
CASCADE_MENU = (
    "wif_key1_uncompressed",
    "wif_key1_compressed",
    "key1_hex",
    "key1_raw",
    "key1_sha256_hex",
    "wif_key2_uncompressed",
    "wif_key2_compressed",
    "key2_hex",
    "key2_raw",
    "key2_sha256_hex",
    "extension_raw",
    "plaintext_raw",
)
CASCADE_KDFS = ("md5", "sha256")

# Prediction bands.  Wide enough that sampling noise cannot flip a conclusion,
# narrow enough that a real signal would break them.
PREDICTIONS = {
    "P1_chain1_unpad_rate": {"low": 0.0030, "high": 0.0050, "analytic": 1 / 256},
    "P2_len79_share_of_unpads": {"low": 0.95, "high": 1.0, "analytic": None},
    "P3_cascade_single_rule_rate": {"low": 0.0015, "high": 0.0070, "analytic": 1 / 256},
    "P4_cascade_menu_rate": {
        "low": 0.05,
        "high": 0.14,
        "analytic": len(CASCADE_MENU) * len(CASCADE_KDFS) / 256,
    },
}

# Padding lengths of the four recorded opens, as they stand in the repository.
RECORDED_PADDING_LENGTHS = {
    "chain1": 1,
    "chain2": 1,
    "cosmic": 1,
    "phase32": 10,
}


def build_manifest() -> dict[str, object]:
    return {
        "schema": "chance-padding-null-calibration-v79",
        "status": "SEALED_BEFORE_EVALUATION",
        "id": "v79_chance_padding_null_calibration",
        "date": "2026-08-07",
        "hypothesis": (
            "The three recorded post-3.2 envelope opens (chain1 under the five "
            "SalPhaseIon tokens, chain2 under the derived WIF, cosmic under the "
            "seven-token digest XOR) are chance PKCS#7 hits, and the 32+32+15 "
            "triplet grammar is an artifact of ciphertext length."
        ),
        "method": (
            "Draw random passwords, strictly unpad chain1, and for each chance "
            "unpad apply the cascade menu to chain2.  Measure the unpad rate, "
            "the plaintext-length distribution, and both cascade rates."
        ),
        "trials": TRIALS,
        "seed": SEED,
        "password_form": PASSWORD_FORM,
        "cascade_menu": list(CASCADE_MENU),
        "cascade_kdfs": list(CASCADE_KDFS),
        "cascade_menu_size": len(CASCADE_MENU) * len(CASCADE_KDFS),
        "predictions": PREDICTIONS,
        "recorded_padding_lengths": RECORDED_PADDING_LENGTHS,
        "acceptance": (
            "This manifest cannot accept a prize candidate; it is a "
            "falsification study.  The null survives only if every prediction "
            "lands inside its band.  Any prediction outside its band is "
            "recorded as evidence for the recorded opens being genuine."
        ),
        "scope_note": (
            "Calibrates the evidential value of the three recorded opens.  It "
            "does not test any new password, does not gate any scalar, and "
            "says nothing about whether the envelopes have a real password -- "
            "all three are creator-published ciphertexts either way."
        ),
    }


def seal() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(sha256_hex(encoded) + "\n", encoding="ascii")


if __name__ == "__main__":
    seal()
    print(f"sealed {MANIFEST_PATH.name} ({TRIALS} trials, seed {SEED})")
