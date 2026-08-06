"""v50: the "seven intertwined passwords" family, gated on legibility.

This extends v49 (``salvation_coherence_audit``) in the two directions it left
open, both taken from creator-authenticated text rather than solver convention.

Two creator statements motivate it:

*   The Architect plaintext -- which *decrypts* from a creator-published
    ciphertext, so it is tier 1 -- says the finisher must "SELECT FROM OVER
    TWENTYTHREE CIPHERS SIXTEEN ENCRYPTIONS ANDOR **SEVEN INTERTWINED
    PASSWORDS**".  Every prior "intertwine" audit in this repository braided the
    seven *stage answers* (``seven_stage_passwords_intertwine_audit.json``,
    ``chain4_intertwined_results.json``); none braided the seven *phrases* of
    the 2023-02-23 image, whose order is the strongest structural constraint in
    the puzzle.

*   The only *authenticated* password in the whole puzzle -- phase 3.2's
    ``250f3772…`` -- is the lowercase SHA-256 **hex digest** of a phrase, used as
    ASCII with the ``-md sha256`` KDF.  That is the puzzle's proven password
    *format*.  v49 swept raw phrase text only; it never applied that format.

So this module sweeps two families against the three unsolved envelopes
(chain1, chain2, cosmic):

  A. **sha256-hex-format passwords.**  For each creator-sourced text (the seven
     phrases, the seven SalPhaseIon tokens, the Architect slices, the S-fields,
     and the other authenticated strings), use its lowercase / uppercase SHA-256
     hex digest, its double-SHA-256 hex, and its raw 32-byte digest as the
     password.

  B. **intertwined passwords.**  Braid (round-robin, one character at a time,
     continuing past exhausted parts) and zip (stop at the shortest part) every
     ordered arrangement of a non-empty subset of the seven phrases, and of the
     seven tokens with the two placeholder tokens substituted by their
     creator-sourced readings.  Test each braid raw and as its SHA-256 hex.

Acceptance is taken from the creator, never from padding: a candidate is
accepted only if its plaintext is legible (v49's gate) **or** some 32-byte
window gates to a prize target via ``solver.targets``.  Valid PKCS#7 padding is
counted and compared to the chance rate, and is explicitly *not* acceptance.

Result: ``NO_LEGIBLE_BREAK_AND_NO_PRIZE_MATCH``.  The padding-hit rate matches
the ~0.36% chance rate v49 measured, i.e. every clean unpad here is noise.  This
is a bounded negative that closes the phrase-intertwine and sha256-format
password families for the post-3.2 envelopes; it is not offered as a solve.
"""

from __future__ import annotations

import collections
import hashlib
import itertools
import json
import math
import re

from . import targets
from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import BEAUFORT_KEY, PHASE32_PASSWORD, README, _beaufort
from .salphaseion import derive_tokens
from .salphaseion_raw import extract_raw


RESULT_PATH = ROOT / "intertwined_password_coherence_audit.json"

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

# The two SalPhaseIon tokens whose marker text is a placeholder ("your last
# command", "second answer") get their creator-sourced readings substituted.
LASTCOMMAND_SUBS = ("yourlastcommand", "HASHTHETEXT", "hashthetext")
SECONDANSWER_SUBS = (
    "secondanswer",
    "giveitjustonesecond",
    "causality",
    "heisenbergsuncertaintyprinciple",
    "jacquefresco",
)

KDF_DIGESTS = ("md5", "sha256")
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


def _architect_plaintext() -> str:
    readme = README.read_text(encoding="utf-8-sig")
    match = re.search(
        r"- phase 3\.2\.1\s+The first blob.*?converted to letters:\s*\n\s*([a-z]+)",
        readme,
        re.DOTALL,
    )
    if match is None:
        raise ValueError("published Phase 3.2.1 ciphertext not found")
    return _beaufort(match.group(1), BEAUFORT_KEY)


def _creator_texts() -> dict[str, bytes]:
    """Named creator-sourced byte strings for the sha256-format family."""
    raw = extract_raw()
    tokens = derive_tokens().tokens
    architect = _architect_plaintext()
    texts: dict[str, bytes] = {}

    def add(name: str, value) -> None:
        if isinstance(value, str):
            value = value.encode("ascii", errors="ignore")
        if value and name not in texts:
            texts[name] = value

    add("architect_upper", architect)
    add("architect_lower", architect.lower())
    add("architect_479_on", architect[479:])
    add("architect_first_479", architect[:479])
    add("s91", raw.s91)
    add("s570", raw.s570)
    add("lastwords_numeric", raw.lastwords_numeric)
    add("password_numeric", raw.password_numeric)
    add("sha_first_hint", raw.sha_first_hint)
    add("sha_answer_too", raw.sha_answer_too)
    for index, phrase in enumerate(CREATOR_PHRASES):
        add(f"phrase_{index + 1}", phrase)
    add("phrases_1to4", "".join(CREATOR_PHRASES[:4]))
    add("phrases_all7", "".join(CREATOR_PHRASES))
    for index, token in enumerate(tokens):
        add(f"token_{index}", token)
    add("tokens_first5", "".join(tokens[:5]))
    add("tokens_all7", "".join(tokens))
    add("heisenberg_preimage", "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple")
    add("flower", "theflowerblossomsthroughwhatseemstobeaconcretesurface")
    add("phase3_url_text", "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
    add("hashthetext", "HASHTHETEXT")
    add("yinyang", "yinyang")
    add("yin", "yin")
    add("yang", "yang")
    return texts


def _sha256_format_passwords():
    for name, text in _creator_texts().items():
        digest = hashlib.sha256(text).digest()
        hex_lower = hashlib.sha256(text).hexdigest()
        yield hex_lower.encode("ascii"), f"{name}/sha256-hex-lower"
        yield hex_lower.upper().encode("ascii"), f"{name}/sha256-hex-upper"
        yield hashlib.sha256(digest).hexdigest().encode("ascii"), f"{name}/sha256d-hex-lower"
        yield digest, f"{name}/sha256-raw-digest"


def _braid(parts: tuple[str, ...]) -> str:
    out: list[str] = []
    for index in range(max(len(part) for part in parts)):
        for part in parts:
            if index < len(part):
                out.append(part[index])
    return "".join(out)


def _zip_shortest(parts: tuple[str, ...]) -> str:
    shortest = min(len(part) for part in parts)
    return "".join(part[index] for index in range(shortest) for part in parts)


def _phrase_intertwines():
    seen: set[str] = set()
    for size in range(1, len(CREATOR_PHRASES) + 1):
        for combo in itertools.permutations(range(len(CREATOR_PHRASES)), size):
            parts = tuple(CREATOR_PHRASES[i] for i in combo)
            label = "-".join(str(i + 1) for i in combo)
            for form, function in (("braid", _braid), ("zip", _zip_shortest)):
                material = function(parts)
                if material not in seen:
                    seen.add(material)
                    yield material, f"phrases/{label}/{form}"


def _token_intertwines():
    base = list(derive_tokens().tokens)
    seen: set[str] = set()
    for lastcommand in LASTCOMMAND_SUBS:
        for secondanswer in SECONDANSWER_SUBS:
            tokens = base[:5] + [lastcommand, secondanswer]
            for combo in itertools.permutations(range(7)):
                parts = tuple(tokens[i] for i in combo)
                for form, function in (("braid", _braid), ("zip", _zip_shortest)):
                    material = function(parts)
                    if material not in seen:
                        seen.add(material)
                        yield material, f"tokens/{lastcommand[:4]}.{secondanswer[:4]}/{form}"


def _scan(envelopes, password, provenance, digests, accumulator):
    accumulator["attempts"] += len(envelopes) * len(digests)
    for envelope_name, envelope in envelopes.items():
        for digest in digests:
            try:
                decrypted = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
            except ValueError:
                continue
            accumulator["padding_hits"] += 1
            plaintext = decrypted.plaintext
            if _is_legible(plaintext):
                accumulator["legible_hits"].append(
                    {
                        "envelope": envelope_name,
                        "kdf_digest": digest,
                        "provenance": provenance,
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
                        accumulator["prize_gate_hits"].append(
                            {"provenance": provenance, "envelope": envelope_name, "gate": hit}
                        )


def run(limit: int | None = None) -> dict[str, object]:
    inputs = extract_all()
    envelopes = {
        "chain1_envelope": inputs.chain1_envelope,
        "chain2_envelope": inputs.chain2_envelope,
        "cosmic_envelope": inputs.cosmic_envelope,
    }

    families: dict[str, dict[str, object]] = {}

    # Family A: sha256-hex-format passwords, plus scalar gate on sha256(text).
    acc_a = {"attempts": 0, "padding_hits": 0, "legible_hits": [], "prize_gate_hits": []}
    tried_a = 0
    for password, provenance in _sha256_format_passwords():
        if limit is not None and tried_a >= limit:
            break
        tried_a += 1
        _scan(envelopes, password, provenance, KDF_DIGESTS, acc_a)
        scalar = targets.gate_scalar_bytes(password) if len(password) == 32 else None
        if scalar:
            acc_a["prize_gate_hits"].append({"provenance": provenance, "as": "scalar", "gate": scalar})
    acc_a["passwords_tried"] = tried_a
    families["A_sha256_format"] = acc_a

    # Family B: intertwined passwords (phrases and tokens), raw + sha256-hex.
    acc_b = {"attempts": 0, "padding_hits": 0, "legible_hits": [], "prize_gate_hits": []}
    tried_b = 0
    for source in (_phrase_intertwines(), _token_intertwines()):
        for material, provenance in source:
            if limit is not None and tried_b >= limit:
                break
            tried_b += 1
            raw = material.encode("ascii")
            _scan(envelopes, raw, f"{provenance}/raw", KDF_DIGESTS, acc_b)
            _scan(
                envelopes,
                hashlib.sha256(raw).hexdigest().encode("ascii"),
                f"{provenance}/sha256hex",
                KDF_DIGESTS,
                acc_b,
            )
            digest = hashlib.sha256(raw).digest()
            scalar = targets.gate_scalar_bytes(digest)
            if scalar:
                acc_b["prize_gate_hits"].append({"provenance": provenance, "as": "scalar", "gate": scalar})
    acc_b["passwords_tried"] = tried_b
    families["B_intertwined"] = acc_b

    total_attempts = sum(f["attempts"] for f in families.values())
    total_padding = sum(f["padding_hits"] for f in families.values())
    total_legible = sum(len(f["legible_hits"]) for f in families.values())
    total_prize = sum(len(f["prize_gate_hits"]) for f in families.values())

    result = {
        "schema": "intertwined-password-coherence-audit-v50",
        "status": "MATCH" if (total_legible or total_prize) else "NO_LEGIBLE_BREAK_AND_NO_PRIZE_MATCH",
        "creator_grounding": {
            "architect_instruction": "SELECT FROM OVER TWENTYTHREE CIPHERS SIXTEEN ENCRYPTIONS ANDOR SEVEN INTERTWINED PASSWORDS",
            "authenticated_password_format": "phase 3.2 password 250f3772... is the lowercase sha256 hex of a phrase, used as ascii with -md sha256",
            "why_new": "prior intertwine audits braided the seven STAGE ANSWERS; this braids the seven 2023-02-23 PHRASES and the seven SalPhaseIon TOKENS, and applies the authenticated sha256-hex password format that v49 never tried",
        },
        "envelopes": {name: {"length": len(env), "sha256": hashlib.sha256(env).hexdigest()} for name, env in envelopes.items()},
        "families": families,
        "totals": {
            "decryption_attempts": total_attempts,
            "padding_hits": total_padding,
            "padding_rate": total_padding / max(1, total_attempts),
            "chance_padding_rate_reference": 0.0036,
            "legible_hits": total_legible,
            "prize_gate_hits": total_prize,
        },
        "acceptance": "legibility (v49 gate) OR a 32-byte window gating to a prize target; padding is NOT acceptance",
        "scope_note": (
            "Falsifies two password families on the three post-3.2 envelopes under "
            "EVP MD5 and SHA-256: (A) sha256-hex / double-sha256-hex / raw-digest of "
            "named creator texts, and (B) round-robin braid and zip intertwines of "
            "every ordered subset of the seven 2023-02-23 phrases and of the seven "
            "SalPhaseIon tokens (with the two placeholder tokens substituted), each "
            "raw and as its sha256 hex. It does NOT test other KDFs, other envelopes, "
            "non-round-robin interleavings, or phrases the creator never published. A "
            "NEGATIVE here means these bounded families missed, not that intertwining "
            "is the wrong reading."
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
    print(json.dumps({key: value for key, value in outcome.items() if key != "families"}, indent=2))
    for name, family in outcome["families"].items():
        print(
            f"{name}: tried={family['passwords_tried']} attempts={family['attempts']} "
            f"padding={family['padding_hits']} legible={len(family['legible_hits'])} "
            f"prize={len(family['prize_gate_hits'])}"
        )
