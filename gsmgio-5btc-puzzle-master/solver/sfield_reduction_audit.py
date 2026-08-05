"""Reproduce and correct the bounded S91/S570-to-Chain-4 reduction audit."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import math
import re

from coincurve import PrivateKey, PublicKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import README, ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "sfield_reduction_audit.json"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")


def _extract_sfields() -> tuple[str, str, str]:
    line = next(
        value
        for value in README.read_text(encoding="utf-8-sig").splitlines()
        if value.startswith("> d b b i b f")
    )
    before_first_z = line.split("**z**", 1)[0]
    symbols = re.findall(r"(?<![A-Za-z])[a-i](?![A-Za-z])", before_first_z)
    if len(symbols) != 765:
        raise ValueError(f"expected 765 symbols before the first z separator, found {len(symbols)}")
    s91 = "".join(symbols[:91])
    binary104 = "".join(symbols[91:195])
    s570 = "".join(symbols[195:765])
    if set(binary104) - {"a", "b"} or len(s91) != 91 or len(s570) != 570:
        raise ValueError("SalPhaseIon S-field boundaries failed structural validation")
    return s91, binary104, s570


def _factor_grids(values: list[int], label: str):
    for divisor in range(1, math.isqrt(len(values)) + 1):
        if len(values) % divisor:
            continue
        quotient = len(values) // divisor
        for rows, columns in ((divisor, quotient), (quotient, divisor)):
            if rows == columns and (rows, columns) != (divisor, quotient):
                continue
            grid = [values[offset : offset + columns] for offset in range(0, len(values), columns)]
            yield f"{label}_{rows}x{columns}", grid, rows, columns


def _serpentine(grid: list[list[int]], rows: int, columns: int) -> tuple[list[int], list[int]]:
    row_stream = [
        value
        for row_index, row in enumerate(grid)
        for value in (row if row_index % 2 == 0 else row[::-1])
    ]
    column_stream: list[int] = []
    for column in range(columns):
        values = [grid[row][column] for row in range(rows)]
        column_stream.extend(values if column % 2 == 0 else values[::-1])
    return row_stream, column_stream


def _window_lists(s91: list[int], s570: list[int], width: int):
    records: list[tuple[str, list[int]]] = []
    for values, label in ((s91, "s91"), (s570, "s570"), ([value - 1 for value in s91], "s91z"), ([value - 1 for value in s570], "s570z")):
        for grid_name, grid, rows, columns in _factor_grids(values, label):
            row_sums = [sum(row) for row in grid]
            column_sums = [sum(grid[row][column] for row in range(rows)) for column in range(columns)]
            row_serpentine, column_serpentine = _serpentine(grid, rows, columns)
            for stream_name, stream in (("rowserp", row_serpentine), ("colserp", column_serpentine)):
                records.extend(
                    (f"{grid_name}/{stream_name}@{offset}", stream[offset : offset + width])
                    for offset in range(len(stream) - width + 1)
                )
            for sum_name, sums in (("rows", row_sums), ("cols", column_sums)):
                # The legacy script emitted a named direct list and an identical
                # @0 window when the sum-list length equaled the requested width.
                if len(sums) == width:
                    records.append((f"{grid_name}/{sum_name}", sums))
                records.extend(
                    (f"{grid_name}/{sum_name}+{sum_name}@{offset}", sums[offset : offset + width])
                    for offset in range(len(sums) - width + 1)
                )
    return records


def _fast_target_match(scalar: int) -> bool:
    return PrivateKey((scalar % N).to_bytes(32, "big")).public_key.format(compressed=True) == TARGET_COMPRESSED


def run() -> dict[str, object]:
    s91_text, binary104, s570_text = _extract_sfields()
    s91 = [ord(symbol) - ord("a") + 1 for symbol in s91_text]
    s570 = [ord(symbol) - ord("a") + 1 for symbol in s570_text]
    chain4 = reconstruct_chain4(reconstruct(extract_all(), derive_tokens()))
    plaintext = chain4.decryption.plaintext
    operand30 = chain4.opcode_operand
    magnitude29 = chain4.operand
    blocks = chain4.blocks
    block_scalars = [int.from_bytes(block, "big") for block in blocks]

    target_uncompressed = PublicKey(TARGET_COMPRESSED).format(compressed=False)
    if base58check(b"\0" + hash160(target_uncompressed)) != TARGET_ADDRESS:
        raise ValueError("target compressed point does not reproduce the prize address")

    legacy30 = _window_lists(s91, s570, 30)
    corrected29 = _window_lists(s91, s570, 29)
    if len(legacy30) != 40456:
        raise ValueError(f"legacy R1 cardinality changed: {len(legacy30)}")

    operand_matches: list[dict[str, object]] = []
    magnitude_matches: list[dict[str, object]] = []
    for width, records, target, matches in (
        (30, legacy30, operand30, operand_matches),
        (29, corrected29, magnitude29, magnitude_matches),
    ):
        for name, values in records:
            encoded = bytes(value & 0xFF for value in values)
            if encoded == target:
                matches.append({"list": name, "encoding": "mod256", "offset": 0})
            offset = (target[0] - encoded[0]) & 0xFF
            if all(((value + offset) & 0xFF) == expected for value, expected in zip(encoded, target)):
                matches.append({"list": name, "encoding": "constant-offset-mod256", "offset": offset})

    # Reproduce legacy R2 exactly. A 30-element list can never be a
    # permutation of all 35 indices; the old perm_* branch is therefore dead.
    r2_generated_records = 0
    r2_sources: dict[int, str] = {}
    for name, values in legacy30:
        selectors = [value % 35 for value in values]
        folds = {
            "sel30_xor": 0,
            "sel30_sum": sum(block_scalars[index] for index in selectors),
            "sign30_sum": sum(
                (1 if value % 2 else -1) * scalar
                for value, scalar in zip(values, block_scalars[:30])
            ),
        }
        for index in selectors:
            folds["sel30_xor"] ^= block_scalars[index]
        for fold_name, value in folds.items():
            r2_generated_records += 1
            scalar = value % N
            if scalar:
                r2_sources.setdefault(scalar, f"{name}/{fold_name}")
    if len(r2_sources) != 54792:
        raise ValueError(f"legacy R2 unique-scalar cardinality changed: {len(r2_sources)}")

    # Reproduce legacy R3: the two seven-value S91 reductions, seven direct
    # values each, plus first/last-seven signed block folds.
    r3_records = 0
    r3_sources: dict[int, str] = {}
    for grid_name, grid, rows, columns in _factor_grids(s91, "s91"):
        row_sums = [sum(row) for row in grid]
        column_sums = [sum(grid[row][column] for row in range(rows)) for column in range(columns)]
        for list_name, values in (("rows", row_sums), ("cols", column_sums)):
            if len(values) != 7:
                continue
            for index, value in enumerate(values):
                r3_records += 1
                r3_sources.setdefault(value % N, f"{grid_name}/{list_name}/value-{index}")
            signs = [1 if value % 2 else -1 for value in values]
            for segment_name, segment in (("first7", block_scalars[:7]), ("last7", block_scalars[-7:])):
                r3_records += 1
                scalar = sum(sign * value for sign, value in zip(signs, segment)) % N
                if scalar:
                    r3_sources.setdefault(scalar, f"{grid_name}/{list_name}/{segment_name}/signed-sum")
    if r3_records != 18:
        raise ValueError(f"legacy R3 cardinality changed: {r3_records}")

    # Correct the old length mismatch with explicit direct/hash serializations
    # for both the 30-byte signed operand and its 29-byte magnitude.
    extension_records = 0
    extension_sources: dict[int, str] = {}

    def extension_submit(value: bytes | int, provenance: str) -> None:
        nonlocal extension_records
        extension_records += 1
        scalar = (value if isinstance(value, int) else int.from_bytes(value, "big")) % N
        if scalar:
            extension_sources.setdefault(scalar, provenance)

    for width, records in ((30, legacy30), (29, corrected29)):
        for name, values in records:
            raw = bytes(value & 0xFF for value in values)
            constructions: list[tuple[str, bytes | int]] = [
                ("raw-leftpad32", raw.rjust(32, b"\0")),
                ("raw-rightpad32", raw.ljust(32, b"\0")),
                ("sha256-raw", hashlib.sha256(raw).digest()),
                ("negative-raw-integer", -int.from_bytes(raw, "big")),
            ]
            if width == 30:
                prefixed = b"+" + raw
                constructions.extend((
                    ("plus-prefix-leftpad32", prefixed.rjust(32, b"\0")),
                    ("plus-prefix-rightpad32", prefixed.ljust(32, b"\0")),
                    ("sha256-plus-prefix", hashlib.sha256(prefixed).digest()),
                ))
            else:
                signed = b"-" + raw
                structured = b"+-" + raw
                constructions.extend((
                    ("minus-prefix-leftpad32", signed.rjust(32, b"\0")),
                    ("minus-prefix-rightpad32", signed.ljust(32, b"\0")),
                    ("structured-prefix-leftpad32", structured.rjust(32, b"\0")),
                    ("structured-prefix-rightpad32", structured.ljust(32, b"\0")),
                    ("sha256-minus-prefix", hashlib.sha256(signed).digest()),
                    ("sha256-structured-prefix", hashlib.sha256(structured).digest()),
                ))
            for construction, candidate in constructions:
                extension_submit(candidate, f"width{width}/{name}/{construction}")

    families: dict[int, set[str]] = defaultdict(set)
    provenance: dict[int, str] = {}
    for family, sources in (("legacy_R2", r2_sources), ("legacy_R3", r3_sources), ("corrected_serialization", extension_sources)):
        for scalar, source in sources.items():
            families[scalar].add(family)
            provenance.setdefault(scalar, source)

    matches: list[dict[str, object]] = []
    for scalar, family_names in families.items():
        if _fast_target_match(scalar):
            public_uncompressed = PrivateKey(scalar.to_bytes(32, "big")).public_key.format(compressed=False)
            address = base58check(b"\0" + hash160(public_uncompressed))
            matches.append({
                "families": sorted(family_names),
                "derivation": provenance[scalar],
                "private_hex": f"{scalar:064x}",
                "address": address,
                "address_verified": address == TARGET_ADDRESS,
            })

    result: dict[str, object] = {
        "status": "MATCH" if matches else "NO_MATCH_IN_ENUMERATED_FAMILY",
        "chain4_sha256": hashlib.sha256(plaintext).hexdigest(),
        "authenticated_inputs": {
            "s91_length": len(s91_text),
            "s91_sha256": hashlib.sha256(s91_text.encode("ascii")).hexdigest(),
            "binary104_length": len(binary104),
            "binary104_sha256": hashlib.sha256(binary104.encode("ascii")).hexdigest(),
            "s570_length": len(s570_text),
            "s570_sha256": hashlib.sha256(s570_text.encode("ascii")).hexdigest(),
            "field_boundary_rule": "single-letter a-i tokens before the first highlighted z separator: S91[0:91], binary104[91:195], S570[195:765]",
            "chain4_sha256": hashlib.sha256(plaintext).hexdigest(),
            "operand30_hex": operand30.hex(),
            "magnitude29_hex": magnitude29.hex(),
            "block_count": len(blocks),
        },
        "legacy_reproduction": {
            "R1_lists30": len(legacy30),
            "R1_operand_matches": operand_matches,
            "R2_generated_fold_records": r2_generated_records,
            "R2_unique_nonzero_scalars": len(r2_sources),
            "R3_generated_records": r3_records,
            "R3_unique_nonzero_scalars": len(r3_sources),
            "dead_permutation_branch_records": 0,
            "dead_permutation_reason": "The candidate order has 30 entries, so it cannot contain all 35 distinct block indices.",
            "dead_magnitude_comparison_reason": "The old R1 compared a 30-byte encoding with magnitude[:30], but magnitude is only 29 bytes; equality is impossible by length.",
        },
        "corrected_extension": {
            "lists29": len(corrected29),
            "magnitude29_matches": magnitude_matches,
            "serialization_candidate_records": extension_records,
            "unique_nonzero_scalars": len(extension_sources),
            "serializations": [
                "raw left/right zero padding to 32 bytes",
                "literal +, -, and +- prefix completions left/right padded to 32 bytes",
                "SHA256 of raw and literal-prefix byte records",
                "negative raw integer modulo secp256k1 order",
            ],
        },
        "combined_unique_nonzero_scalars": len(families),
        "target": {"x": f"{TARGET_X:064x}", "y": f"{TARGET_Y:064x}", "address": TARGET_ADDRESS},
        "matches": matches,
        "scope_note": "This reproduces the prior finite grid-reduction/selector/sign family and adds only the enumerated correction for its 29-vs-30-byte mismatch. It is not a general S-field impossibility result.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
