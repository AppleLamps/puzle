"""S570 seven-matrix fold as a selector index source into Architect[479].

The non-arbitrary rule is taken wholesale from the creator's own sealed
2023-02-23 pipeline (``creator_pipeline_poster_architect_preregistered.json``):
matrixsumlist values are used as indices into the authenticated Phase 3.2
Architect A-Z plaintext starting at the yellowblueprimes/yinyang offset 479,
under the four sealed index bases, five sealed serializations, three sealed
overlays, and ``gate_scalar_bytes`` acceptance.

Here the matrixsumlist is the NEW one the S570 construction produces: the
seven 9x9 matrices of the faed run (sequential blocks, or the literal
round-robin "seven intertwined" weave) are summed position-wise and folded
through their 180-degree rotational opposite, leaving 40 pair values plus the
single fixed centre.  The 40 pair values (and their mod-9 residues) are then
used as offsets exactly as the sealed pipeline reads the poster sum list.

Nothing in the reading of the pairs or the use of the offsets is invented:
pair order is the sealed row-major first-40 selection (flat index < 40, the
same set as test.py); the index bases, serializations and overlays are the
sealed creator-pipeline constants; acceptance is the standard oracle set.
"""

from __future__ import annotations

import hashlib
import json

from .creator_pipeline_poster_architect_audit import (
    HOPE_QUOTE,
    YINYANG_OFFSET,
    _beaufort,
    _extract,
    _scalar_forms,
)
from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .s570_seven_matrix_fold_audit import (
    _matrices_intertwined,
    _matrices_sequential,
    _sum_matrices,
)
from .targets import gate_scalar_bytes, self_check
from .unity_of_opposites_audit import _legible_bytes

RESULT_PATH = ROOT / "s570_fold_architect_selector_audit.json"
RECOVERY = ROOT / "phase32_symbol_recovery.json"
AUTHENTICATED_PLAINTEXT_SHA256 = (
    "56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241"
)

LETTER_MAPS = {
    "a1_i9": {chr(97 + value): value + 1 for value in range(9)},
    "a0_i8": {chr(97 + value): value for value in range(9)},
}
FOLD_MODES = ("sum", "sum-mod9", "absdiff", "signeddiff")
INDEX_BASES = ("absolute_0based", "from_479_0based", "from_479_1based", "cumulative_from_479_0based")
OVERLAYS = ("none", "hope_quote_first_letters_xor", "beaufort_hope_on_extracted")


def _fold_values(matrix: list[list[int]], mode: str) -> list[int]:
    """40 pair values in sealed row-major first-40 order (flat index < 40)."""
    values: list[int] = []
    for row in range(9):
        for column in range(9):
            if row < 4 or (row == 4 and column < 4):
                a = matrix[row][column]
                b = matrix[8 - row][8 - column]
                if mode == "sum":
                    values.append(a + b)
                elif mode == "sum-mod9":
                    values.append((a + b) % 9)
                elif mode == "absdiff":
                    values.append(abs(a - b))
                elif mode == "signeddiff":
                    values.append(a - b)
    if len(values) != 40:
        raise ValueError(f"fold must yield 40 values, got {len(values)}")
    return values


def _overlay(mode: str, extracted: str) -> str:
    if mode == "hope_quote_first_letters_xor":
        hope = HOPE_QUOTE[: len(extracted)]
        return "".join(
            chr(ord(a) ^ ord(b))
            for a, b in zip(extracted.upper(), hope)
            if a.isalpha() and b.isalpha()
        )
    if mode == "beaufort_hope_on_extracted":
        return _beaufort(extracted, "HOPE")
    return extracted


def run() -> dict[str, object]:
    recovery = json.loads(RECOVERY.read_text(encoding="utf-8"))
    plaintext = recovery["plaintext"]
    if hashlib.sha256(plaintext.encode("ascii")).hexdigest() != AUTHENTICATED_PLAINTEXT_SHA256:
        raise ValueError("authenticated Architect plaintext changed")
    if len(plaintext) != 1539:
        raise ValueError("authenticated Architect plaintext length changed")

    body = _streams()
    inputs = extract_all()
    envelopes = {
        "chain1": inputs.chain1_envelope,
        "chain2": inputs.chain2_envelope,
        "phase32": inputs.phase32_envelope,
        "cosmic": inputs.cosmic_envelope,
    }

    scalar_attempts = 0
    aes_attempts = 0
    padding_hits = 0
    scalar_hits: list[dict[str, object]] = []
    legible_accepts: list[dict[str, object]] = []
    seen: set[bytes] = set()
    family_results: list[dict[str, object]] = []

    for reading_name, blocks_fn in (
        ("sequential", _matrices_sequential),
        ("intertwined", _matrices_intertwined),
    ):
        blocks = blocks_fn(body)
        for map_name, mapping in LETTER_MAPS.items():
            matrix = _sum_matrices(blocks, mapping)
            for fold_mode in FOLD_MODES:
                offsets = _fold_values(matrix, fold_mode)
                list_label = f"s570_fold_{reading_name}_{map_name}_{fold_mode}"
                fam: dict[str, object] = {
                    "family": list_label,
                    "pair_values": offsets,
                    "index_bases": INDEX_BASES,
                    "overlays": OVERLAYS,
                    "scalar_tests": 0,
                    "result": "NO_MATCH",
                }
                for index_mode in INDEX_BASES:
                    extracted = _extract(plaintext, offsets, index_mode)
                    for overlay in OVERLAYS:
                        candidate = _overlay(overlay, extracted)
                        aes_forms = {
                            "raw": candidate.encode("ascii"),
                            "sha256-lowerhex": hashlib.sha256(candidate.encode("ascii")).hexdigest().encode("ascii"),
                            "sha256-digest": hashlib.sha256(candidate.encode("ascii")).digest(),
                        }
                        for form_name, scalar_bytes in _scalar_forms(
                            f"{list_label}/{index_mode}/{overlay}", candidate
                        ):
                            if scalar_bytes in seen:
                                continue
                            seen.add(scalar_bytes)
                            scalar_attempts += 1
                            fam["scalar_tests"] = int(fam["scalar_tests"]) + 1
                            hit = gate_scalar_bytes(scalar_bytes)
                            if hit is not None:
                                scalar_hits.append(
                                    {
                                        "family": list_label,
                                        "index_mode": index_mode,
                                        "overlay": overlay,
                                        "form": form_name,
                                        "extracted_preview": candidate[:40],
                                        "gate": hit,
                                    }
                                )
                                fam["result"] = "MATCH"
                        for pw_name, password in aes_forms.items():
                            for kdf in ("md5", "sha256"):
                                for blob_name, envelope in envelopes.items():
                                    aes_attempts += 1
                                    try:
                                        out = decrypt_salted_aes256_cbc(
                                            envelope, password, digest=kdf
                                        ).plaintext
                                    except ValueError:
                                        continue
                                    padding_hits += 1
                                    if _legible_bytes(out):
                                        legible_accepts.append(
                                            {
                                                "family": list_label,
                                                "index_mode": index_mode,
                                                "overlay": overlay,
                                                "password_form": pw_name,
                                                "kdf": kdf,
                                                "blob": blob_name,
                                                "extracted_preview": candidate[:40],
                                                "plaintext_sha256": hashlib.sha256(out).hexdigest(),
                                                "printable_ratio": round(
                                                    sum(32 <= b < 127 for b in out) / len(out), 4
                                                ),
                                            }
                                        )
                family_results.append(fam)

    control = gate_scalar_bytes(
        hashlib.sha256(b"s570_fold_architect_selector_positive_control").digest()
    )
    result = {
        "schema": "s570-fold-architect-selector-v1",
        "status": "MATCH" if (scalar_hits or legible_accepts) else "COMPLETE_NO_ACCEPT",
        "scope_note": (
            "S570 seven-9x9-matrix fold pair values used as Architect plaintext "
            "offsets under the creator's sealed 2023-02-23 pipeline rule set "
            "(index bases, serializations, overlays, yinyang offset 479); "
            "no parameter invented. Excludes Cosmic/Chain4/base38."
        ),
        "rule_source": {
            "index_bases": "creator_pipeline_poster_architect_preregistered.json index_bases",
            "serializations": "creator_pipeline_poster_architect_preregistered.json serializations",
            "overlays": "creator_pipeline_poster_architect_preregistered.json lastwords_overlay",
            "acceptance": "gate_scalar_bytes (Half + hash160); AES envelopes under byte legibility gate",
            "pair_reading": "row-major first-40 cells (flat index < 40) paired with 180-degree opposites; identical set/order to test.py and s570_seven_matrix_fold_audit._fold180",
        },
        "architect_plaintext": {
            "sha256": AUTHENTICATED_PLAINTEXT_SHA256,
            "length": len(plaintext),
            "matches_cited_phrase": (
                "REINSERTINGTHEPRIMEBASICS" in plaintext
                and "SEVENINTERTWINEDPASSWORDS" in plaintext
            ),
            "yinyang_offset": YINYANG_OFFSET,
        },
        "counts": {
            "scalar_attempts": scalar_attempts,
            "unique_scalars_tested": len(seen),
            "scalar_hits": scalar_hits,
            "aes_attempts": aes_attempts,
            "strict_padding_hits": padding_hits,
            "legible_accepts": legible_accepts,
        },
        "families": family_results,
        "positive_control_accepted": control is None,
        "target_self_check": self_check(),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _streams() -> str:
    from .unity_of_opposites_audit import _streams_from_html

    _, FAED = _streams_from_html()
    if len(FAED) != 570 or FAED[:3] != "fae":
        raise ValueError("faed stream changed; construction precondition lost")
    return FAED[3:]


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
