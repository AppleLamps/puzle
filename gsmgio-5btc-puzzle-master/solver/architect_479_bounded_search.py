"""Creator-bounded key search around the authenticated Architect offset 479.

This deliberately excludes Cosmic/Chain 4.  It tests only literal material
named by the 479/484/472/140 breakthrough, the Architect's own words, and the
23/16/7 Matrix counts.  Every scalar is checked against the exact Half point
and both P2PKH serializations of Half and Better Half.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path

from coincurve import PrivateKey, PublicKey

from .extract import ROOT
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "architect_479_bounded_search.json"
PLAINTEXT_PATH = ROOT / "phase32_symbol_recovery.json"
NONCE_CORPUS_PATH = ROOT / "blockchain_nonce_audit.json"

HALF_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER_ADDRESS = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
HALF_H160 = bytes.fromhex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")
BETTER_H160 = bytes.fromhex("4bc468447fe1b048ad030a2f9a125478eabc4ed6")
HALF_PUBLIC = bytes.fromhex(
    "04"
    "f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)
HALF_COMPRESSED = PublicKey(HALF_PUBLIC).format(compressed=True)
AUTHENTICATED_PLAINTEXT_SHA256 = "56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241"
BREAKTHROUGH_POSITIONS = (479, 484, 472, 140)
WINDOW_MODES = {
    "start-0based": lambda position: position,
    "start-1based": lambda position: position - 1,
    "center-0based": lambda position: position - 16,
    "center-1based": lambda position: position - 17,
    "end-0based": lambda position: position - 31,
    "end-1based": lambda position: position - 32,
}


def _sha(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _primes(limit: int) -> list[int]:
    return [
        value
        for value in range(2, limit + 1)
        if all(value % divisor for divisor in range(2, math.isqrt(value) + 1))
    ]


def _serializations(public: PublicKey) -> dict[str, bytes]:
    return {
        "compressed": public.format(compressed=True),
        "uncompressed": public.format(compressed=False),
    }


def _h160s(public: PublicKey) -> dict[str, bytes]:
    return {name: hash160(encoded) for name, encoded in _serializations(public).items()}


def _address(h160_value: bytes) -> str:
    return base58check(b"\0" + h160_value)


def _point_gate(public: PublicKey) -> dict[str, object]:
    serializations = _serializations(public)
    h160s = {name: hash160(encoded) for name, encoded in serializations.items()}
    return {
        "half_exact_pubkey": serializations["uncompressed"] == HALF_PUBLIC,
        "half_hash160": {name: value == HALF_H160 for name, value in h160s.items()},
        "better_hash160": {name: value == BETTER_H160 for name, value in h160s.items()},
        "addresses": {name: _address(value) for name, value in h160s.items()},
    }


def _add_material(
    materials: dict[str, tuple[bytes, str]], label: str, value: bytes, family: str
) -> None:
    if not value:
        return
    previous = materials.get(label)
    if previous is not None and previous != (value, family):
        raise ValueError(f"material label collision: {label}")
    materials[label] = (value, family)


def _window_material(plaintext: str) -> tuple[dict[str, tuple[bytes, str]], dict[str, str]]:
    materials: dict[str, tuple[bytes, str]] = {}
    diagnostics: dict[str, str] = {}
    forms = {
        "raw-upper": plaintext,
        "normalized-upper": "".join(character for character in plaintext if "A" <= character <= "Z"),
        "normalized-lower": "".join(character.lower() for character in plaintext if "A" <= character <= "Z"),
    }
    if forms["raw-upper"] != forms["normalized-upper"]:
        raise ValueError("authenticated plaintext is no longer its own A-Z normalization")
    for form_name, text in forms.items():
        for position in BREAKTHROUGH_POSITIONS:
            for mode_name, start_fn in WINDOW_MODES.items():
                start = start_fn(position)
                value = text[start : start + 32].encode("ascii")
                if len(value) != 32:
                    raise ValueError("breakthrough window is truncated")
                label = f"window/{form_name}/position-{position}/{mode_name}"
                _add_material(materials, label, value, "exact-32-window")
                diagnostics[label] = value.decode("ascii")
    return materials, diagnostics


def _privatekey_chunks(
    plaintext: str, materials: dict[str, tuple[bytes, str]]
) -> dict[str, object]:
    offsets: list[int] = []
    cursor = 0
    while True:
        offset = plaintext.find("PRIVATEKEY", cursor)
        if offset < 0:
            break
        offsets.append(offset)
        suffix = plaintext[offset + len("PRIVATEKEY") :]
        for chunk_index, start in enumerate(range(0, len(suffix) - 31, 32)):
            chunk = suffix[start : start + 32].encode("ascii")
            _add_material(
                materials,
                f"after-privatekey-{offset}/chunk-{chunk_index:02d}",
                chunk,
                "post-PRIVATEKEY-32-byte-chunk",
            )
        cursor = offset + 1
    return {"PRIVATEKEY_offsets_0based": offsets, "first_offset_1based": offsets[0] + 1}


def _phrase_material(
    plaintext: str, materials: dict[str, tuple[bytes, str]]
) -> dict[str, object]:
    raw_phrases = {
        "take-private-key": "TAKETHEPRIVATEKEY",
        "earned": "YOUVEEARNEDIT",
        "take-heart": "BUTPLEASETAKETHISTOHEART",
        "wise-man-140": (
            "THATWHATAWISEMANABOVEHINTEDATISWORTHHUNDREDFOURTYOFTHEINVESTMENT"
        ),
        "key-through-investment": (
            "TAKETHEPRIVATEKEYYOUVEEARNEDITBUTPLEASETAKETHISTOHEART"
            "THATWHATAWISEMANABOVEHINTEDATISWORTHHUNDREDFOURTYOFTHEINVESTMENT"
        ),
        "matrix-counts": (
            "SELECTFROMOVERTWENTYTHREECIPHERSSIXTEENENCRYPTIONSANDOR"
            "SEVENINTERTWINEDPASSWORDS"
        ),
    }
    restored_phrases = {
        "take-private-key": "Take the private key.",
        "earned": "You've earned it.",
        "take-heart": "But please take this to heart:",
        "wise-man-140": (
            "that what a wise man above hinted at is worth hundred fourty "
            "of the investment."
        ),
        "key-through-investment": (
            "Take the private key. You've earned it. But please take this to heart: "
            "that what a wise man above hinted at is worth hundred fourty of the investment."
        ),
        "matrix-counts": (
            "select from over twenty three ciphers, sixteen encryptions and/or "
            "seven intertwined passwords"
        ),
    }
    records: dict[str, object] = {}
    for name, phrase in raw_phrases.items():
        if phrase not in plaintext:
            raise ValueError(f"authenticated phrase missing: {name}")
        restored = restored_phrases[name]
        spellings = {
            "raw-upper": phrase.encode("ascii"),
            "raw-lower": phrase.lower().encode("ascii"),
            "punctuation-restored": restored.encode("ascii"),
        }
        for spelling, value in spellings.items():
            _add_material(
                materials,
                f"sha256/phrase/{name}/{spelling}",
                _sha(value),
                "SHA256-exact-phrase",
            )
        records[name] = {
            "raw": phrase,
            "punctuation_restored": restored,
            "raw_offset_0based": plaintext.index(phrase),
            "sha256": {spelling: _sha(value).hex() for spelling, value in spellings.items()},
        }
    return records


def _heart_and_center_material(
    plaintext: str, materials: dict[str, tuple[bytes, str]]
) -> dict[str, object]:
    records: dict[str, object] = {}
    streams = {
        "plaintext": plaintext,
        "after-first-PRIVATEKEY": plaintext[plaintext.index("PRIVATEKEY") + len("PRIVATEKEY") :],
        "heart-clause": (
            "BUTPLEASETAKETHISTOHEART"
            "THATWHATAWISEMANABOVEHINTEDATISWORTHHUNDREDFOURTYOFTHEINVESTMENT"
        ),
    }
    for name, stream in streams.items():
        left_start = (len(stream) - 32) // 2
        right_start = len(stream) // 2 - 16
        starts = sorted({left_start, right_start})
        records[name] = []
        for start in starts:
            value = stream[start : start + 32].encode("ascii")
            label = f"heart-center/{name}/start-{start}"
            _add_material(materials, label, value, "heart-center-32")
            records[name].append({"start_0based": start, "text": value.decode("ascii")})
    for occurrence, heart_offset in enumerate(
        index for index in range(len(plaintext)) if plaintext.startswith("HEART", index)
    ):
        for side, start in (("left-center", heart_offset - 14), ("right-center", heart_offset - 13)):
            value = plaintext[start : start + 32].encode("ascii")
            label = f"heart-literal/occurrence-{occurrence}/{side}"
            _add_material(materials, label, value, "heart-literal-32")
            records[label] = {"heart_offset_0based": heart_offset, "text": value.decode("ascii")}
    return records


def _prime_material(
    plaintext: str, materials: dict[str, tuple[bytes, str]]
) -> dict[str, object]:
    records: dict[str, object] = {}
    suffix = plaintext[plaintext.index("PRIVATEKEY") + len("PRIVATEKEY") :]
    for name, stream in (("plaintext", plaintext), ("after-first-PRIVATEKEY", suffix)):
        primes = _primes(len(stream))
        variants = {
            "one-based": "".join(stream[position - 1] for position in primes),
            "zero-based": "".join(stream[position] for position in primes if position < len(stream)),
        }
        records[name] = {}
        for indexing, selected in variants.items():
            encoded = selected.encode("ascii")
            _add_material(
                materials,
                f"prime-index/{name}/{indexing}/first32",
                encoded[:32],
                "prime-index-first-32",
            )
            _add_material(
                materials,
                f"prime-index/{name}/{indexing}/sha256",
                _sha(encoded),
                "SHA256-prime-index-stream",
            )
            records[name][indexing] = {
                "length": len(selected),
                "first32": selected[:32],
                "sha256": _sha(encoded).hex(),
            }
    return records


def _zero_fifth_character(
    materials: dict[str, tuple[bytes, str]]
) -> dict[str, object]:
    sources = {
        label: value
        for label, (value, family) in materials.items()
        if len(value) == 32
        and family in {
            "exact-32-window",
            "post-PRIVATEKEY-32-byte-chunk",
            "heart-center-32",
            "heart-literal-32",
            "prime-index-first-32",
        }
    }
    generated = 0
    for label, value in sources.items():
        for indexing, index in (("offset5-0based", 5), ("character5-1based", 4)):
            for replacement_name, replacement in (("ascii-zero", b"0"), ("nul-byte", b"\0")):
                zeroed = value[:index] + replacement + value[index + 1 :]
                _add_material(
                    materials,
                    f"zero-char-5/{label}/{indexing}/{replacement_name}",
                    zeroed,
                    "zero-character-5",
                )
                generated += 1
    return {"source_count": len(sources), "generated_count": generated}


def _numeric_and_matrix_material(
    materials: dict[str, tuple[bytes, str]]
) -> dict[str, object]:
    values = {
        "yellow-sum": 479,
        "blue-sum": 484,
        "take-offset": 472,
        "page-number": 140,
        "zeroed-difference": 5,
        "matrix-ciphers": 23,
        "matrix-encryptions": 16,
        "matrix-passwords": 7,
    }
    for name, value in values.items():
        _add_material(materials, f"integer/{name}/be32", value.to_bytes(32, "big"), "literal-integer")
        _add_material(
            materials,
            f"integer/{name}/sha256-decimal",
            _sha(str(value).encode("ascii")),
            "SHA256-literal-integer",
        )
    for label, encoding in {
        "matrix-counts/23-16-7/ascii": b"23167",
        "matrix-counts/23,16,7/ascii": b"23,16,7",
        "matrix-counts/bytes": bytes((23, 16, 7)),
        "breakthrough/479,484,5,140/ascii": b"479,484,5,140",
        "breakthrough/479-484-472-140/ascii": b"479,484,472,140",
    }.items():
        _add_material(materials, f"{label}/sha256", _sha(encoding), "SHA256-exact-number-list")
    return values


def _half_better_combinations(
    materials: dict[str, tuple[bytes, str]]
) -> dict[str, object]:
    pairs: list[tuple[str, bytes, bytes]] = []
    for form in ("raw-upper", "normalized-lower"):
        for mode in WINDOW_MODES:
            yellow = materials[f"window/{form}/position-479/{mode}"][0]
            blue = materials[f"window/{form}/position-484/{mode}"][0]
            pairs.append((f"{form}/{mode}", yellow, blue))
    generated = 0
    for label, half, better in pairs:
        left = int.from_bytes(half, "big")
        right = int.from_bytes(better, "big")
        candidates = {
            "xor": left ^ right,
            "sum-mod-n": (left + right) % N,
            "half-minus-better-mod-n": (left - right) % N,
            "better-minus-half-mod-n": (right - left) % N,
        }
        for operation, scalar in candidates.items():
            if scalar:
                _add_material(
                    materials,
                    f"half-better/{label}/{operation}",
                    scalar.to_bytes(32, "big"),
                    "Half-Better-combination",
                )
                generated += 1
        for operation, value in (
            ("sha256-half||better", half + better),
            ("sha256-better||half", better + half),
        ):
            _add_material(
                materials,
                f"half-better/{label}/{operation}",
                _sha(value),
                "Half-Better-combination",
            )
            generated += 1
    return {"paired_window_count": len(pairs), "generated_count": generated}


def _gate_scalars(
    materials: dict[str, tuple[bytes, str]]
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[int, list[str]]]:
    scalar_labels: dict[int, list[str]] = {}
    for label, (value, _) in materials.items():
        if len(value) != 32:
            raise ValueError(f"non-scalar-width material survived: {label}")
        scalar = int.from_bytes(value, "big") % N
        if scalar:
            scalar_labels.setdefault(scalar, []).append(label)

    manifest: list[dict[str, object]] = []
    matches: list[dict[str, object]] = []
    for scalar, labels in sorted(scalar_labels.items()):
        private = scalar.to_bytes(32, "big")
        public = PrivateKey(private).public_key
        gate = _point_gate(public)
        record = {
            "labels": sorted(labels),
            "family": sorted({materials[label][1] for label in labels}),
            "candidate_hex": private.hex(),
            "gate": gate,
        }
        manifest.append(record)
        if (
            gate["half_exact_pubkey"]
            or any(gate["half_hash160"].values())
            or any(gate["better_hash160"].values())
        ):
            matches.append(record)
    return manifest, matches, scalar_labels


def _half_point_offsets(
    scalar_labels: dict[int, list[str]]
) -> tuple[dict[str, int], list[dict[str, object]]]:
    half_point = PublicKey(HALF_PUBLIC)
    tests = Counter()
    matches: list[dict[str, object]] = []
    for scalar, labels in scalar_labels.items():
        t_point = PrivateKey.from_int(scalar).public_key
        negative_t = PublicKey(
            b"\x04"
            + t_point.format(compressed=False)[1:33]
            + (int.from_bytes(t_point.format(compressed=False)[33:], "big") * -1
               % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2).to_bytes(32, "big")
        )
        for operation, operand in (("P_H+tG", t_point), ("P_H-tG", negative_t)):
            tests[operation] += 1
            combined = PublicKey.combine_keys((half_point, operand))
            gate = _point_gate(combined)
            if any(gate["better_hash160"].values()) or gate["half_exact_pubkey"]:
                matches.append(
                    {
                        "labels": sorted(labels),
                        "operation": operation,
                        "t_hex": f"{scalar:064x}",
                        "gate": gate,
                    }
                )
    return dict(tests), matches


def _candidate_nonce_recovery(
    scalar_labels: dict[int, list[str]]
) -> dict[str, object]:
    corpus = json.loads(NONCE_CORPUS_PATH.read_text(encoding="utf-8"))
    signatures = [
        record
        for record in corpus["corpus"]["signatures"]
        if record["address"] == HALF_ADDRESS
    ]
    if len(signatures) != 6 or not all(record["signature_verified"] for record in signatures):
        raise ValueError("expected six verified Half signatures")
    r_map: dict[int, list[tuple[int, list[str]]]] = {}
    for scalar, labels in scalar_labels.items():
        for sign, nonce in (("positive", scalar), ("negative", (-scalar) % N)):
            if not nonce:
                continue
            point = PrivateKey.from_int(nonce).public_key.format(compressed=False)
            r_value = int.from_bytes(point[1:33], "big") % N
            signed_labels = [f"{label}/{sign}" for label in labels]
            r_map.setdefault(r_value, []).append((nonce, signed_labels))

    r_matches: list[dict[str, object]] = []
    accepted: list[dict[str, object]] = []
    recovery_tests = 0
    for signature in signatures:
        for nonce, labels in r_map.get(int(signature["r"]), []):
            for s_sign in (1, -1):
                recovery_tests += 1
                private = (
                    (s_sign * int(signature["s"]) * nonce - int(signature["z"]))
                    * pow(int(signature["r"]), -1, N)
                ) % N
                if not private:
                    continue
                gate = _point_gate(PrivateKey.from_int(private).public_key)
                record = {
                    "txid": signature["txid"],
                    "vin": signature["vin"],
                    "nonce_labels": sorted(labels),
                    "s_sign": s_sign,
                    "recovered_private_hex": f"{private:064x}",
                    "gate": gate,
                }
                r_matches.append(record)
                if gate["half_exact_pubkey"] or any(gate["better_hash160"].values()):
                    accepted.append(record)
    return {
        "verified_half_signatures": len(signatures),
        "signed_nonce_candidates": sum(len(values) for values in r_map.values()),
        "r_comparisons": len(signatures) * sum(len(values) for values in r_map.values()),
        "r_matches": r_matches,
        "recovery_equation_tests": recovery_tests,
        "accepted": accepted,
    }


def run() -> dict[str, object]:
    source = json.loads(PLAINTEXT_PATH.read_text(encoding="utf-8"))
    plaintext = source["plaintext"]
    plaintext_sha = _sha(plaintext.encode("ascii")).hex()
    if (
        source["status"] != "RECOVERED"
        or len(plaintext) != 1539
        or plaintext_sha != AUTHENTICATED_PLAINTEXT_SHA256
    ):
        raise ValueError("authenticated Architect plaintext anchor changed")
    if plaintext[479:].startswith("PRIVATEKEY") is False:
        raise ValueError("the zero-based 479 PRIVATEKEY breakthrough is absent")
    if 484 - 479 != 5:
        raise ValueError("blue/yellow difference is no longer five")

    materials, windows = _window_material(plaintext)
    privatekey = _privatekey_chunks(plaintext, materials)
    phrases = _phrase_material(plaintext, materials)
    centers = _heart_and_center_material(plaintext, materials)
    prime = _prime_material(plaintext, materials)
    zeroing = _zero_fifth_character(materials)
    numeric = _numeric_and_matrix_material(materials)
    combinations = _half_better_combinations(materials)

    manifest, direct_matches, scalar_labels = _gate_scalars(materials)
    point_test_counts, offset_matches = _half_point_offsets(scalar_labels)
    nonce = _candidate_nonce_recovery(scalar_labels)
    family_counts = Counter(
        family for _, family in materials.values()
    )
    commitment_input = b"\n".join(
        label.encode("utf-8") + b"\0" + value
        for label, (value, _) in sorted(materials.items())
    )
    matches = {
        "direct_scalar": direct_matches,
        "half_point_offset": offset_matches,
        "candidate_nonce_recovery": nonce["accepted"],
    }
    has_match = any(matches.values())
    result: dict[str, object] = {
        "schema": "architect-479-creator-bounded-search-v1",
        "status": "MATCH" if has_match else "NO_MATCH",
        "scope": {
            "creator_bounded": True,
            "excluded": ["Cosmic", "Chain 4", "base-38"],
            "plaintext_path": str(PLAINTEXT_PATH.relative_to(ROOT)),
            "plaintext_length": len(plaintext),
            "plaintext_sha256": plaintext_sha,
            "breakthrough": {
                "yellow_sum_and_PRIVATEKEY_offset_0based": 479,
                "blue_sum": 484,
                "difference_zeroed": 5,
                "TAKETHE_offset_0based": 472,
                "page_number": 140,
                "matrix_counts": [23, 16, 7],
            },
        },
        "targets": {
            "Half": {
                "address": HALF_ADDRESS,
                "hash160": HALF_H160.hex(),
                "pubkey_uncompressed": HALF_PUBLIC.hex(),
                "pubkey_compressed": HALF_COMPRESSED.hex(),
            },
            "Better": {"address": BETTER_ADDRESS, "hash160": BETTER_H160.hex()},
            "serializations_gated": ["compressed", "uncompressed"],
        },
        "derivations": {
            "windows": windows,
            "privatekey_chunks": privatekey,
            "phrases": phrases,
            "heart_centers": centers,
            "prime_index": prime,
            "zero_character_5": zeroing,
            "numeric_inputs": numeric,
            "half_better_combinations": combinations,
        },
        "candidate_summary": {
            "material_records": len(materials),
            "unique_nonzero_scalars": len(scalar_labels),
            "family_counts": dict(sorted(family_counts.items())),
            "candidate_set_sha256": _sha(commitment_input).hex(),
            "manifest": manifest,
        },
        "point_offset_tests": {
            "counts": point_test_counts,
            "matches": offset_matches,
        },
        "nonce_tests": nonce,
        "matches": matches,
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(
        json.dumps(
            {
                "status": output["status"],
                "candidate_summary": {
                    key: value
                    for key, value in output["candidate_summary"].items()
                    if key != "manifest"
                },
                "point_offset_tests": output["point_offset_tests"],
                "nonce_tests": {
                    key: value
                    for key, value in output["nonce_tests"].items()
                    if key != "r_matches"
                },
                "matches": output["matches"],
            },
            indent=2,
            sort_keys=True,
        )
    )
