"""Public provenance ledger for claims that are not encoded in puzzle files."""

from __future__ import annotations


PUBLIC_OCCURRENCES = {
    "xor_triangle": {
        "earliest_visible": "2025-12-25T08:40:23Z",
        "url": "https://github.com/puzzlehunt/gsmgio-5btc-puzzle/pull/68#issuecomment-3691156333",
        "evidence": "A public comment says the next wall is triangular and calls it an XOR triangle.",
        "artifact": None,
        "status": "reported concept only; no formula or bytes",
    },
    "K_I1": {
        "earliest_visible": "2026-03-13T16:10:06Z",
        "url": "https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/87",
        "evidence": "The issue body claims knowledge of K_I1 but supplies no value or derivation.",
        "artifact": None,
        "status": "unavailable/private claim",
    },
    "trail1": {
        "earliest_visible": "2026-03-29T07:08:01Z",
        "url": "https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/88",
        "evidence": "The editable issue body labels fc0c1b02 as trail1.",
        "artifact": {
            "length": 4,
            "hex": "fc0c1b02",
            "sha256": "bbf54842988b73cba4273885954b9d9a95d736f0454b55d2d90942fabc6c5ca4",
            "derivation": "bytes 64:68 of the independently reproduced 68-byte base-38 matrix output",
        },
        "status": "reproduced; label provenance remains an editable public claim",
    },
    "cosmic_A_ca_row1_4_formula": {
        "earliest_visible": "2026-03-29T07:08:01Z",
        "url": "https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/88",
        "evidence": (
            "The currently visible, editable issue body reports cosmic_A, row1-4, and "
            "cc[833:865] XOR ca[280:312], but provides only a SHA-256 prefix."
        ),
        "artifact": None,
        "status": "not reproducible; exact original publication time is uncertain because the body is editable",
    },
    "public_missing_artifact_audit": {
        "earliest_visible": "2026-06-04T09:46:43Z",
        "url": "https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/92",
        "evidence": "A public request documents that cosmic_A/ca, row1-4, and K_I1 could not be located.",
        "artifact": None,
        "status": "corroborates absence, not the underlying claim",
    },
    "door2_lcp7_formula": {
        "earliest_visible": "2026-07-11T10:21:34Z",
        "url": "https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/92#issuecomment-4944877522",
        "evidence": "A public comment states Door-2 LCP7 = ascii_hex(M3DGNJTGMZTCMZTG) XOR Half XOR Better without defining ascii_hex or the compared LCP field.",
        "artifact": None,
        "status": "ambiguous claim; literal lowercase ASCII-hex text gives target-x LCP5, not LCP7",
    },
}


def unresolved_frontier() -> dict[str, object]:
    return {
        "cosmic_A": {
            "length": None,
            "sha256": None,
            "reported_prefix_only": "cd3fea3d",
            "derivation": None,
            "publicly_available": False,
        },
        "ca": {
            "length": None,
            "sha256": None,
            "derivation": None,
            "publicly_available": False,
        },
        "K_I1": {
            "length": None,
            "sha256": None,
            "derivation": None,
            "publicly_available": False,
        },
        "row1-4": {
            "length": None,
            "sha256": None,
            "derivation": None,
            "publicly_available": False,
        },
    }
