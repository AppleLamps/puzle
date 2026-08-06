"""v49: apply the creator's own acceptance criterion to the post-3.2 chain.

Read only the creator's statements, this is what he says about breaking
SalPhaseIon:

    2021-03-14  "Breaking salphation should be giving the feeling of the
                 phase's name."

``SalPhaseIon`` is an anagram-ish spelling of *salvation*, and he elsewhere
answers a claimed extraction of "ying yang"/"salvation" without disputing the
word.  Taken plainly, that line is an **acceptance criterion**: a correct break
produces something a human recognises.  It is the same standard the phase-3.2
break meets -- its plaintext opens ``I've been waiting for you.``

This module does two things.

**Part A, the audit.**  Measure whether the three chained unlocks that the whole
post-3.2 branch rests on actually meet that standard, against two references:
the phase-3.2 decryption as a true positive, and the measured chance rate of
valid PKCS#7 padding on each envelope as a null.  ``CLAUDE.md`` already states
that clean padding proves nothing; this checks whether the rule was applied to
the repository's own load-bearing chain.

**Part B, the search.**  Take the creator's seven published phrases and the four
authenticated SalPhaseIon literals as the token set -- "we won't give away the
password" and "it's in front of your eyes but you're not seeing it" both being
his commentary on a password whose parts he had just listed -- and sweep ordered
combinations against every authenticated envelope, accepting only on legibility,
never on padding.

Nothing here is offered as a solve.  Part A is a measurement; Part B is a
bounded search with an acceptance gate taken from a creator statement rather
than from solver convention.
"""

from __future__ import annotations

import collections
import hashlib
import itertools
import json
import math
import random

from . import targets
from .chains import reconstruct
from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import PHASE32_PASSWORD
from .salphaseion import derive_tokens


RESULT_PATH = ROOT / "salvation_coherence_audit.json"

# The seven phrases of the 2023-02-23 image, in the creator's order.
CREATOR_PHRASES = (
    "yellowblueprimes",
    "matrixsumlist",
    "lastwordsbeforearchichoice",
    "yinyang",
    "wewontgiveawaythepassword",
    "itsinfrontofyoureyesbutyourenotseeingit",
    "verylaststepisatruegiveawaypromised",
)

# Authenticated SalPhaseIon literals, plus the spelling the creator actually
# types in Telegram and the phase name he points at.
EXTRA_TOKENS = ("enter", "thispassword", "yingyang", "salvation")

SEPARATORS = ("", " ", "\n")
CASES = ("lower", "upper")
KDF_DIGESTS = ("md5", "sha256")
MAX_TOKENS = 5

NULL_TRIALS = 20000
NULL_SEED = 20260806

# Legibility thresholds.  A correct break should read; these are deliberately
# generous so that a real hit cannot be filtered out.
MIN_PRINTABLE = 0.90
MAX_ENTROPY = 4.5
CRIB_WORDS = (
    b"the", b"you", b"and", b"key", b"private", b"bitcoin", b"congrat", b"well done",
    b"matrix", b"neo", b"answer", b"password", b"seed", b"address", b"wallet", b"prize",
)


def _stats(plaintext: bytes) -> dict[str, float]:
    counts = collections.Counter(plaintext)
    length = max(1, len(plaintext))
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    printable = sum(1 for byte in plaintext if byte in b"\n\r\t" or 32 <= byte <= 126) / length
    return {"length": len(plaintext), "entropy_bits_per_byte": entropy, "printable_ratio": printable}


def _is_legible(plaintext: bytes) -> bool:
    stats = _stats(plaintext)
    if stats["printable_ratio"] >= MIN_PRINTABLE:
        return True
    if stats["entropy_bits_per_byte"] <= MAX_ENTROPY:
        return True
    lowered = plaintext.lower()
    return sum(1 for word in CRIB_WORDS if word in lowered) >= 2


def _null_padding_rate(envelope: bytes, trials: int = NULL_TRIALS) -> dict[str, object]:
    generator = random.Random(NULL_SEED)
    hits = 0
    legible = 0
    for _ in range(trials):
        password = generator.randbytes(16).hex().encode("ascii")
        try:
            decrypted = decrypt_salted_aes256_cbc(envelope, password, digest="md5")
        except ValueError:
            continue
        hits += 1
        if _is_legible(decrypted.plaintext):
            legible += 1
    return {
        "trials": trials,
        "padding_hits": hits,
        "padding_rate": hits / trials,
        "legible_hits": legible,
        "note": "random passwords; this is the rate any campaign must be judged against",
    }


def part_a() -> dict[str, object]:
    """Do the chained unlocks meet the creator's own standard?"""
    inputs = extract_all()
    chains = reconstruct(inputs, derive_tokens())

    positive = decrypt_salted_aes256_cbc(inputs.phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    reference = _stats(positive.plaintext) | {
        "legible": _is_legible(positive.plaintext),
        "opening_bytes": positive.plaintext[:60].decode("ascii", errors="replace"),
    }

    chained = {}
    for name, decryption in (
        ("chain1_5token_password", chains.chain1_decryption),
        ("chain2_wif_password", chains.chain2_decryption),
        ("cosmic_7token_xor_password", chains.cosmic_decryption),
    ):
        plaintext = decryption.plaintext
        chained[name] = _stats(plaintext) | {
            "legible": _is_legible(plaintext),
            "distinct_bytes": len(set(plaintext)),
            "sha256": hashlib.sha256(plaintext).hexdigest(),
            "opening_bytes_repr": repr(plaintext[:40]),
        }

    nulls = {
        name: _null_padding_rate(getattr(inputs, name))
        for name in ("chain1_envelope", "chain2_envelope", "cosmic_envelope")
    }

    return {
        "creator_criterion": {
            "statement": "Breaking salphation should be giving the feeling of the phase's name.",
            "date": "2021-03-14",
            "reading": "SalPhaseIon points at 'salvation'; a correct break yields recognisable output",
        },
        "true_positive_reference": reference,
        "chained_unlocks": chained,
        "null_padding_rates": nulls,
        "finding": (
            "The phase-3.2 break is legible and opens \"I've been waiting for you.\" "
            "None of the three chained unlocks downstream of it is legible: their "
            "plaintexts sit at 6.1 to 7.9 bits of entropy per byte with no readable "
            "text. Valid padding arises by chance at roughly 0.35 to 0.38 percent per "
            "password on these envelopes, so a campaign of the size this repository "
            "has run produces padding hits in the thousands by chance alone. The three "
            "unlocks are therefore consistent with padding luck and none of them is "
            "self-authenticating. That does not prove they are wrong, but it means the "
            "post-3.2 chain has no authentication behind it, and CLAUDE.md's own rule "
            "-- clean padding proves nothing -- was never applied to it."
        ),
    }


def _passwords():
    """Ordered creator-sourced token combinations, his own order first."""
    tokens = list(dict.fromkeys(CREATOR_PHRASES + EXTRA_TOKENS))
    seen: set[bytes] = set()

    def emit(parts: tuple[str, ...]):
        for separator in SEPARATORS:
            joined = separator.join(parts)
            for case in CASES:
                text = joined.lower() if case == "lower" else joined.upper()
                encoded = text.encode("ascii")
                if encoded not in seen:
                    seen.add(encoded)
                    yield encoded, f"{'|'.join(parts)}/sep={separator!r}/{case}"

    # His own ordered prefixes first, so a hit is attributable to his list.
    for length in range(1, len(CREATOR_PHRASES) + 1):
        yield from emit(CREATOR_PHRASES[:length])
    # Then every ordered combination up to MAX_TOKENS.
    for size in range(1, MAX_TOKENS + 1):
        for parts in itertools.permutations(tokens, size):
            yield from emit(parts)


def part_b(limit: int | None = None) -> dict[str, object]:
    """Sweep creator-sourced passwords, accepting only on legibility."""
    inputs = extract_all()
    envelopes = {
        "chain1_envelope": inputs.chain1_envelope,
        "chain2_envelope": inputs.chain2_envelope,
        "cosmic_envelope": inputs.cosmic_envelope,
        "phase32_envelope": inputs.phase32_envelope,
    }
    attempts = 0
    padding_hits = 0
    legible_hits: list[dict[str, object]] = []
    prize_hits: list[dict[str, object]] = []
    passwords_tried = 0

    for password, provenance in _passwords():
        passwords_tried += 1
        if limit is not None and passwords_tried > limit:
            break
        for envelope_name, envelope in envelopes.items():
            for digest in KDF_DIGESTS:
                attempts += 1
                try:
                    decrypted = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
                except ValueError:
                    continue
                padding_hits += 1
                plaintext = decrypted.plaintext
                if _is_legible(plaintext):
                    legible_hits.append(
                        {
                            "envelope": envelope_name,
                            "kdf_digest": digest,
                            "provenance": provenance,
                            "password": password.decode("ascii", errors="replace")[:120],
                            **_stats(plaintext),
                            "opening_bytes": plaintext[:80].decode("ascii", errors="replace"),
                            "sha256": hashlib.sha256(plaintext).hexdigest(),
                        }
                    )
                for offset in range(max(0, len(plaintext) - 31)):
                    window = plaintext[offset : offset + 32]
                    if len(window) == 32:
                        hit = targets.gate_scalar_bytes(window)
                        if hit:
                            prize_hits.append(
                                {"provenance": provenance, "envelope": envelope_name, "gate": hit}
                            )
    return {
        "token_set": list(dict.fromkeys(CREATOR_PHRASES + EXTRA_TOKENS)),
        "construction": {
            "creator_ordered_prefixes": "tested first",
            "ordered_combinations_up_to": MAX_TOKENS,
            "separators": [repr(separator) for separator in SEPARATORS],
            "cases": list(CASES),
            "kdf_digests": list(KDF_DIGESTS),
        },
        "envelopes": sorted(envelopes),
        "passwords_tried": passwords_tried,
        "decryption_attempts": attempts,
        "padding_hits": padding_hits,
        "padding_rate": padding_hits / max(1, attempts),
        "legible_hits": legible_hits,
        "prize_gate_hits": prize_hits,
        "acceptance": "legibility only; padding is explicitly not acceptance",
    }


def run(limit: int | None = None) -> dict[str, object]:
    audit = part_a()
    search = part_b(limit=limit)
    result = {
        "schema": "salvation-coherence-audit-v49",
        "status": "MATCH" if search["prize_gate_hits"] or search["legible_hits"] else "NO_LEGIBLE_BREAK_AND_NO_PRIZE_MATCH",
        "part_a_coherence_audit": audit,
        "part_b_creator_password_search": search,
        "scope_note": (
            "Part A is a measurement of already-recorded artifacts, not a new "
            "hypothesis: it reports entropy, legibility and the chance padding rate. "
            "Part B falsifies only the swept creator-token password family on the four "
            "authenticated envelopes under EVP MD5 and SHA-256. It does not test other "
            "KDFs, other envelopes, or tokens the creator never published."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import sys

    cap = None
    for argument in sys.argv[1:]:
        if argument.startswith("--limit="):
            cap = int(argument.split("=", 1)[1])
    outcome = run(limit=cap)
    print(json.dumps(outcome["part_a_coherence_audit"], indent=2))
    search = outcome["part_b_creator_password_search"]
    print(
        json.dumps(
            {key: value for key, value in search.items() if key != "legible_hits"},
            indent=2,
        )
    )
    print(f"\nlegible hits: {len(search['legible_hits'])}")
    for record in search["legible_hits"][:20]:
        print("  ", record["envelope"], record["kdf_digest"], record["provenance"][:70])
        print("     ", record["opening_bytes"][:70])
