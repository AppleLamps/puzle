"""Seal the v47 family over the poster's rot180 yin/yang partition.

A yin-yang is the one common symbol whose defining property is *180-degree
rotational symmetry with colour inversion*: rotate it half a turn and black
becomes white.  The repository has tested colour inversion, left/right,
top/bottom, diagonal and interleave rules on the poster
(`../derived/second_door_yinyang_joint_audit.json`, 1,794 materials), and eight
spiral symmetries (`salphaseion_blind_results_v28.json`), but not the partition
that the rotational-inversion property itself induces.

Measured here from `sources/follow_the_white_rabbit.png`, under the
authenticated URL bit convention (black/blue = 1, white/yellow = 0, off-white
counted as white because that is what reproduces the URL):

* the 196 cells form 98 rot180 pairs, with no fixed point on an even grid;
* **exactly 49 of the 98 pairs invert** -- a perfect half, which is the
  strongest sense in which this artifact "is a yin-yang" under the symbol's own
  defining symmetry;
* the 49 inverting pairs carry exactly 49 ones and 49 zeros, which is forced;
* the 49 non-inverting pairs split **26 dark-dark against 23 light-light**;
* all three rotations (90, 180, 270 degrees) split the 196 cell-to-image
  comparisons exactly 98 same / 98 different.

The perfect 49/98 split sits exactly at the chance expectation, so it is a
clean *construction* and not by itself surprising evidence.  What has never
been gated is the material it defines, which is what this manifest freezes.

Also recorded, because both were verified while building this and neither is a
free parameter: the off-white cell (7,4) has spiral index 163 and its rot180
partner (6,9) is black at spiral index 173; and the four innermost spiral
cells, the residual beyond the 192 URL bits, are all white, which is the
recorded `0000`.

The only acceptance gate is :mod:`solver.targets`.  Padding is never
acceptance, and neither is a count that happens to balance.
"""

from __future__ import annotations

import hashlib
import json

from .extract import ROOT
from .salphaseion_raw import sha256_hex
from .second_door_yellowblueprimes_audit import (
    BLACK,
    BLUE,
    FALLBACK_IMAGE,
    IMAGE,
    OFF_WHITE,
    _majority_grid,
    _spiral_positions,
)
from .targets import BETTER_H160, HALF_PUBLIC_UNCOMPRESSED


MANIFEST_PATH = ROOT / "yinyang_rot180_partition_preregistered.json"
SEAL_PATH = ROOT / "yinyang_rot180_partition_preregistered.sha256"
RESULT_PATH = ROOT / "yinyang_rot180_partition_audit.json"

SIZE = 14
SERIALIZATIONS = ("bit_string_ascii", "packed_bytes", "int_bigendian", "int_littleendian")
DERIVATIONS = ("sha256", "double_sha256", "sha256^0x7f", "sha256_reversed", "raw_32_bytes")
PHRASE = "yinyang"
PHRASE_FORMS = ("phrase_prefix_sha256", "phrase_suffix_sha256")
AES_DIGESTS = ("md5", "sha256")
AES_PASSWORD_FORMS = ("literal", "sha256_lowercase_hex")

CONTROL_SCALAR_HEX = "00000000000000000000000000000000000000000000000000000000000c0de5"


def _bit(colour: tuple[int, int, int]) -> int:
    return 1 if colour in (BLACK, BLUE) else 0


def partition() -> dict[str, object]:
    """Re-derive the rot180 pair partition and every object it defines."""
    image = IMAGE if IMAGE.exists() else FALLBACK_IMAGE
    grid = _majority_grid(image)
    order = _spiral_positions(SIZE)

    seen: set[tuple[int, int]] = set()
    pairs: list[tuple[tuple[int, int], tuple[int, int]]] = []
    for cell in order:
        partner = (SIZE - 1 - cell[0], SIZE - 1 - cell[1])
        if cell in seen or partner in seen:
            continue
        seen.add(cell)
        seen.add(partner)
        pairs.append((cell, partner))
    if len(pairs) != 98:
        raise ValueError(f"expected 98 rot180 pairs, got {len(pairs)}")

    inverting = [_bit(grid[a[0]][a[1]]) != _bit(grid[b[0]][b[1]]) for a, b in pairs]
    if sum(inverting) != 49:
        raise ValueError(f"the 49/98 rot180 balance changed: {sum(inverting)}")

    def spiral_sorted(cells: list[tuple[int, int]]) -> list[tuple[int, int]]:
        return sorted(cells, key=order.index)

    def bits_of(cells: list[tuple[int, int]]) -> str:
        return "".join(str(_bit(grid[row][col])) for row, col in cells)

    yin_cells = spiral_sorted([cell for (a, b), flag in zip(pairs, inverting) if flag for cell in (a, b)])
    yang_cells = spiral_sorted([cell for (a, b), flag in zip(pairs, inverting) if not flag for cell in (a, b)])
    dark_pairs = [(a, b) for (a, b), flag in zip(pairs, inverting) if not flag and _bit(grid[a[0]][a[1]]) == 1]
    light_pairs = [(a, b) for (a, b), flag in zip(pairs, inverting) if not flag and _bit(grid[a[0]][a[1]]) == 0]
    if (len(dark_pairs), len(light_pairs)) != (26, 23):
        raise ValueError(f"the 26/23 non-inverting split changed: {len(dark_pairs)}/{len(light_pairs)}")

    mask = "".join("1" if flag else "0" for flag in inverting)
    first_of_pair = "".join(str(_bit(grid[a[0]][a[1]])) for a, _ in pairs)

    off_white = [cell for cell in order if grid[cell[0]][cell[1]] == OFF_WHITE]
    if len(off_white) != 1:
        raise ValueError("expected exactly one off-white cell")
    off_white_cell = off_white[0]
    off_white_dual = (SIZE - 1 - off_white_cell[0], SIZE - 1 - off_white_cell[1])

    streams = {
        "yin_bits98": bits_of(yin_cells),
        "yang_bits98": bits_of(yang_cells),
        "rot180_inversion_mask98": mask,
        "rot180_inversion_mask98_complement": "".join("1" if character == "0" else "0" for character in mask),
        "pair_first_member_bits98": first_of_pair,
        "yin_then_yang_bits196": bits_of(yin_cells) + bits_of(yang_cells),
        "dark_dark_pair_bits52": "".join(bits_of([a, b]) for a, b in dark_pairs),
        "light_light_pair_bits46": "".join(bits_of([a, b]) for a, b in light_pairs),
    }
    return {
        "image": str(image.relative_to(ROOT.parent)) if image == IMAGE else str(image.relative_to(ROOT)),
        "streams": streams,
        "structure": {
            "pairs": len(pairs),
            "inverting_pairs": sum(inverting),
            "non_inverting_pairs": len(pairs) - sum(inverting),
            "non_inverting_dark_dark": len(dark_pairs),
            "non_inverting_light_light": len(light_pairs),
            "off_white_cell": list(off_white_cell),
            "off_white_spiral_index": order.index(off_white_cell),
            "off_white_rot180_partner": list(off_white_dual),
            "off_white_rot180_partner_spiral_index": order.index(off_white_dual),
            "off_white_rot180_partner_is_dark": _bit(grid[off_white_dual[0]][off_white_dual[1]]) == 1,
            "innermost_four_spiral_bits": "".join(str(_bit(grid[r][c])) for r, c in order[-4:]),
        },
    }


def build_manifest() -> dict[str, object]:
    derived = partition()
    streams: dict[str, str] = derived["streams"]  # type: ignore[assignment]
    return {
        "schema": "yinyang-rot180-partition-preregistration-v47",
        "status": "SEALED_BEFORE_SCALAR_OR_AES_EVALUATION",
        "hypothesis": (
            "The yin-yang the creator names is the poster's rot180 colour-inverting "
            "structure, and the partition it induces -- 49 inverting pairs against "
            "49 non-inverting -- carries the material for the next step."
        ),
        "distinct_from": {
            "../derived/second_door_yinyang_joint_audit.json": "colour inversion, L/R, top/bottom, diagonal and interleave rules; no rot180 pair-parity partition",
            "salphaseion_blind_results_v28.json": "the eight spiral symmetries as whole-grid re-readings, not a partition by pair parity",
            "second_door_frontier_derivations.json": "prime-index zeroing, 14x14 sum/product/determinant matrices and diagonal splits",
        },
        "measured_structure": derived["structure"],
        "streams": {
            name: {"length": len(value), "ones": value.count("1"), "sha256": sha256_hex(value.encode("ascii"))}
            for name, value in sorted(streams.items())
        },
        "expansion": {
            "serializations": list(SERIALIZATIONS),
            "derivations": list(DERIVATIONS),
            "phrase": PHRASE,
            "phrase_forms": list(PHRASE_FORMS),
        },
        "aes_family": {
            "target": "the authenticated SalPhaseIon short envelope",
            "password_forms": list(AES_PASSWORD_FORMS),
            "kdf_digests": list(AES_DIGESTS),
        },
        "acceptance": {
            "only_gate": "solver.targets.gate_scalar_bytes",
            "half": {"exact_public_key": HALF_PUBLIC_UNCOMPRESSED.hex()},
            "better_half": {"hash160": BETTER_H160.hex()},
            "explicitly_not_acceptance": [
                "valid PKCS#7 padding",
                "readable English fragments",
                "a count that balances, including the 49/98 split itself",
            ],
            "planted_control_scalar": CONTROL_SCALAR_HEX,
        },
        "out_of_scope": [
            "bit conventions other than the authenticated black/blue = 1 URL rule",
            "treating off-white as 1, already negative",
            "any Cosmic, Chain 4 or base-38 operand",
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
