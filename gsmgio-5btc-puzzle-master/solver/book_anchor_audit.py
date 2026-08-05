"""Audit the four reported Architect book-cipher anchors.

The authenticated Phase 3.2 plaintext has one-based word positions
121=WISEMAN, 142=ACCOMPLISH, 182=FINISH, and 237=SOURCE.  A public solver
reported these four anchors without publishing the selection rule.  This
module tests only the finite direct consequences of that report; it does not
treat the report as authenticated puzzle evidence.
"""

from __future__ import annotations

import hashlib
import itertools
import json

from coincurve import PrivateKey

from .architect_substitution_audit import _puzzle_text, _words
from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "book_anchor_audit.json"
WORDS = ("wiseman", "accomplish", "finish", "source")
INDICES = (121, 142, 182, 237)


def _target(value: bytes) -> bool:
    scalar = int.from_bytes(value, "big") % N
    if not scalar:
        return False
    public = PrivateKey.from_int(scalar).public_key.format(compressed=False)
    return (
        public[1:33] == TARGET_X.to_bytes(32, "big")
        and public[33:] == TARGET_Y.to_bytes(32, "big")
        and base58check(b"\0" + hash160(public)) == TARGET_ADDRESS
    )


def run() -> dict[str, object]:
    architect = _words(_puzzle_text())
    recovered = tuple(architect[index - 1].lower() for index in INDICES)
    if recovered != WORDS:
        raise ValueError(f"book anchors changed: {recovered!r}")

    preimages: dict[bytes, set[str]] = {}

    def add(label: str, value: bytes) -> None:
        preimages.setdefault(value, set()).add(label)

    for order in itertools.permutations(range(4)):
        ordered_words = [WORDS[index] for index in order]
        ordered_decimal = [str(INDICES[index]) for index in order]
        ordered_bytes = bytes(INDICES[index] for index in order)
        order_label = "".join(str(index + 1) for index in order)
        for separator_name, separator in (("empty", ""), ("space", " "), ("colon", ":"), ("comma", ",")):
            for case_name, case in (("lower", str.lower), ("upper", str.upper), ("title", str.title)):
                add(
                    f"words/{order_label}/{separator_name}/{case_name}",
                    separator.join(case(word) for word in ordered_words).encode("ascii"),
                )
            add(
                f"indices-decimal/{order_label}/{separator_name}",
                separator.join(ordered_decimal).encode("ascii"),
            )
        add(f"indices-byte/{order_label}", ordered_bytes)
        add(f"indices-hex/{order_label}", ordered_bytes.hex().encode("ascii"))

    inputs = extract_all()
    blobs = {
        "salphaseion-short": inputs.chain1_envelope,
        "phase32-small": inputs.chain2_envelope,
        "cosmic-duality": inputs.cosmic_envelope,
    }
    accepted: list[dict[str, object]] = []
    padding_hits = 0
    scalar_matches: list[dict[str, object]] = []
    attempts = 0
    for preimage, labels in preimages.items():
        forms = {
            "raw": preimage,
            "sha256-lowerhex": hashlib.sha256(preimage).hexdigest().encode("ascii"),
            "sha256-digest": hashlib.sha256(preimage).digest(),
        }
        for form_name, password in forms.items():
            digest = hashlib.sha256(password).digest()
            if _target(digest):
                scalar_matches.append({"labels": sorted(labels), "form": form_name, "password_hex": password.hex()})
            for blob_name, envelope in blobs.items():
                attempts += 1
                try:
                    plaintext = decrypt_salted_aes256_cbc(envelope, password).plaintext
                except ValueError:
                    continue
                padding_hits += 1
                printable = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in plaintext) / len(plaintext)
                semantic = printable >= 0.90
                if semantic:
                    accepted.append({
                        "labels": sorted(labels), "form": form_name, "blob": blob_name,
                        "plaintext_length": len(plaintext), "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
                        "printable_ratio": printable,
                    })

    result = {
        "schema": "architect-four-book-anchor-audit-v1",
        "status": "MATCH" if accepted or scalar_matches else "COMPLETE_NO_ACCEPT",
        "source": {
            "anchors": dict(zip(WORDS, INDICES)),
            "verification": "one-based indexing into authenticated Phase 3.2 Architect plaintext",
            "evidence_boundary": "anchor selection was reported publicly without a derivation",
        },
        "unique_preimages": len(preimages),
        "aes_attempts": attempts,
        "strict_padding_hits": padding_hits,
        "semantic_accepts": accepted,
        "target_scalar_matches": scalar_matches,
        "scope_note": "Exhausts direct word/index concatenations, not an unknown book-cipher selection rule.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
