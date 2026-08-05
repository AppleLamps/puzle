"""Audit instruction-style readings of the authentic SalPhaseIon material.

This is a bounded candidate construction, not a claim that the puzzle author
intended any one grammar.  It specifically tests the hypothesis that
``matrixsumlist``, ``enter``, ``lastwordsbeforearchichoice``, and
``thispassword`` are operations/key material rather than literal password
tokens.  Padding hits are reported, but acceptance requires the independent
short-blob -> WIF -> small-blob -> embedded Chain 4 structure.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from typing import Iterable

from coincurve import PrivateKey

from .chain4 import MASK
from .chains import reconstruct
from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import _vic_decode
from .prime_reinsertion_audit import (
    TARGET_ADDRESS,
    TARGET_X,
    TARGET_Y,
    _image_records,
    _spiral,
)
from .salphaseion import derive_tokens
from .secp256k1_verify import N, wif
from .sfield_reduction_audit import _extract_sfields


RESULT_PATH = ROOT / "salphaseion_instruction_audit.json"
PHRASE = "lastwordsbeforearchichoice"
MATRIX_KEY = "matrixsumlist"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")
KNOWN_CHAIN1_SHA256 = "1449a2178eea7c0e3fabac8c1ad2afa294be4fc1800c594a025a056e88c626bf"
KNOWN_CHAIN2_SHA256 = "b40fce72ef5638e4f79b3233e653f8a5dbdb0d4ae2009d2d3da2c98b70f4d004"
KNOWN_COSMIC_SHA256 = "4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081"
KNOWN_CHAIN4_SHA256 = "e4269ed5fbb202a81e5e1aa6b5190fdd1ea126b2c8547ea7cdbdf45387ea135b"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reshape(values: list[int], columns: int) -> list[list[int]]:
    if len(values) % columns:
        raise ValueError("matrix shape does not divide the source")
    return [values[offset : offset + columns] for offset in range(0, len(values), columns)]


def _rotate(grid: list[list[int]]) -> list[list[int]]:
    return [list(row) for row in zip(*grid[::-1])]


def _grid_variants(grid: list[list[int]]) -> Iterable[tuple[str, list[list[int]]]]:
    seen: set[tuple[tuple[int, ...], ...]] = set()
    current = grid
    for rotation in range(4):
        for reflected, value in ((False, current), (True, [row[::-1] for row in current])):
            frozen = tuple(tuple(row) for row in value)
            if frozen in seen:
                continue
            seen.add(frozen)
            suffix = "_mirror" if reflected else ""
            yield f"rot{rotation * 90}{suffix}", value
        current = _rotate(current)


def _spiral_right(grid: list[list[int]]) -> list[int]:
    """Conventional clockwise spiral, upper-left and right first."""

    top = left = 0
    bottom = len(grid) - 1
    right = len(grid[0]) - 1
    output: list[int] = []
    while left <= right and top <= bottom:
        output.extend(grid[top][left : right + 1])
        top += 1
        for row in range(top, bottom + 1):
            output.append(grid[row][right])
        right -= 1
        if top <= bottom:
            output.extend(reversed(grid[bottom][left : right + 1]))
            bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                output.append(grid[row][left])
            left += 1
    return output


def _diagonal_sums(grid: list[list[int]], reverse_columns: bool) -> list[int]:
    rows = len(grid)
    columns = len(grid[0])
    values = [row[::-1] for row in grid] if reverse_columns else grid
    return [
        sum(values[row][diagonal - row] for row in range(rows) if 0 <= diagonal - row < columns)
        for diagonal in range(rows + columns - 1)
    ]


def _list_serializations(values: list[int]) -> Iterable[tuple[str, bytes]]:
    decimal = [str(value) for value in values]
    for name, separator in (
        ("concat", ""),
        ("space", " "),
        ("comma", ","),
        ("hyphen", "-"),
        ("slash", "/"),
        ("colon", ":"),
    ):
        yield name, separator.join(decimal).encode("ascii")
    yield "json", ("[" + ",".join(decimal) + "]").encode("ascii")
    yield "hex2", "".join(f"{value & 0xff:02x}" for value in values).encode("ascii")
    if all(0 <= value <= 255 for value in values):
        yield "bytes", bytes(values)
    if all(0 <= value <= 65535 for value in values):
        yield "uint16be", b"".join(value.to_bytes(2, "big") for value in values)


def _stable_key_order(key: str) -> list[int]:
    return sorted(range(len(key)), key=lambda index: (key[index], index))


def _password_expansions(value: bytes) -> Iterable[tuple[str, bytes]]:
    first = hashlib.sha256(value).digest()
    second_digest = hashlib.sha256(first).digest()
    second_hex_text = hashlib.sha256(first.hex().encode("ascii")).digest()
    yield "raw", value
    yield "sha256-digest", first
    yield "sha256-lowerhex", first.hex().encode("ascii")
    yield "sha256-upperhex", first.hex().upper().encode("ascii")
    yield "sha256-of-digest", second_digest
    yield "sha256-of-digest-lowerhex", second_digest.hex().encode("ascii")
    yield "sha256-of-lowerhex", second_hex_text
    yield "sha256-of-lowerhex-lowerhex", second_hex_text.hex().encode("ascii")


def _try_decrypt(envelope: bytes, password: bytes, digest: str):
    try:
        return decrypt_salted_aes256_cbc(envelope, password, digest=digest)
    except ValueError:
        return None


def _chain4_gate(embedded: bytes, password: bytes) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for digest in ("md5", "sha256"):
        result = _try_decrypt(embedded, password, digest)
        if result is None:
            continue
        plaintext = result.plaintext
        structured = (
            len(plaintext) == 1151
            and plaintext[:2] == b"+-"
            and len(plaintext[31:]) == 35 * 32
        )
        hits.append({
            "kdf": digest,
            "plaintext_length": len(plaintext),
            "plaintext_sha256": _sha(plaintext),
            "marker_hex": plaintext[:2].hex(),
            "canonical_structure": structured,
            "known_chain4": _sha(plaintext) == KNOWN_CHAIN4_SHA256,
        })
    return hits


def run() -> dict[str, object]:
    inputs = extract_all()
    sal = derive_tokens()
    canonical = reconstruct(inputs, sal)
    s91_text, binary104, s570_text = _extract_sfields()
    s91_one = [ord(value) - ord("a") + 1 for value in s91_text]
    s91_zero = [value - 1 for value in s91_one]
    s570_one = [ord(value) - ord("a") + 1 for value in s570_text]
    s570_zero = [value - 1 for value in s570_one]

    preimages: dict[bytes, list[str]] = defaultdict(list)
    category_records: Counter[str] = Counter()

    def add(category: str, label: str, value: str | bytes) -> None:
        raw = value.encode("utf-8") if isinstance(value, str) else value
        if not raw:
            return
        provenance = f"{category}/{label}"
        category_records[category] += 1
        if provenance not in preimages[raw]:
            preimages[raw].append(provenance)

    # Literal checklist and exact positive controls.
    direct = (
        "matrixsumlist", "enter", PHRASE, "thispassword", "matrixsumlistenter",
        "matrixsumlistenterlastwordsbeforearchichoice",
        "matrixsumlistenterlastwordsbeforearchichoicethispassword",
        "matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist",
        "enterthispassword", "lastwordsbeforearchichoicethispassword",
        "thispasswordlastwordsbeforearchichoice",
    )
    for index, value in enumerate(direct):
        add("direct-token-checklist", str(index), value)
    add("positive-control", "canonical-chain1-password", "".join(sal.tokens[:5]))
    add("positive-control", "canonical-cosmic-password-bytes", sal.xor_password)

    access_text = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    access_hash = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
    for label, value in (
        ("audio-message", "HASHTHETEXT"),
        ("audio-message-lower", "hashthetext"),
        ("access-preimage", access_text),
        ("access-hash-lowerhex", access_hash),
        ("access-hash-upperhex", access_hash.upper()),
    ):
        add("access-loop", label, value)

    half_variants = (
        "HALF", "BETTERHALF", "HALFANDBETTERHALF", "HALF AND BETTER HALF",
        "half", "betterhalf", "halfandbetterhalf", "half and better half",
        "halfbetterhalf", "theyalsoneedfundstolive",
    )
    for index, value in enumerate(half_variants):
        add("half-message", str(index), value)

    vic_words = "IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE".split()
    add("vic-message", "first-letters", "".join(word[0] for word in vic_words))
    add("vic-message", "last-letters", "".join(word[-1] for word in vic_words))
    add("vic-message", "no-spaces", "".join(vic_words))
    add("vic-message", "spaces", " ".join(vic_words))

    # Authentic image-derived binary statistics.  The supplied F73D92/101
    # values are retained as a separately labeled transcription control.
    binary_grid, numbered_grid, colors, _, _ = _image_records()
    verified_rows = [sum(row) for row in binary_grid]
    verified_columns = [sum(binary_grid[row][column] for row in range(14)) for column in range(14)]
    actual_color_bits = [1 if value == 15 else 0 for value in colors]
    supplied_rows = [6, 10, 8, 7, 6, 6, 5, 4, 9, 9, 7, 8, 7, 9]
    supplied_columns = [8, 10, 8, 10, 8, 7, 3, 6, 7, 5, 9, 6, 6, 8]
    supplied_bits = [int(value) for value in "111101110011110110010010"]

    matrix_outputs: list[tuple[str, bytes]] = []

    def add_list(category: str, label: str, values: list[int], *, insertion_source: bool = False) -> None:
        for serialization, raw in _list_serializations(values):
            add(category, f"{label}/{serialization}", raw)
            if insertion_source and len(raw) <= 256:
                matrix_outputs.append((f"{category}/{label}/{serialization}", raw))

    for prefix, rows, columns, total in (
        ("verified", verified_rows, verified_columns, sum(verified_rows)),
        ("supplied-transcription", supplied_rows, supplied_columns, 101),
    ):
        add_list("original-grid", f"{prefix}/rows", rows, insertion_source=True)
        add_list("original-grid", f"{prefix}/columns", columns, insertion_source=True)
        add_list("original-grid", f"{prefix}/rows-plus-columns", [*rows, *columns], insertion_source=True)
        add("original-grid", f"{prefix}/total", str(total))
        add("original-grid", f"{prefix}/blue-yellow", "15 9")
        add("original-grid", f"{prefix}/blue-yellow-concat", "159")
        add("original-grid", f"{prefix}/yellow-blue-concat", "915")
    for prefix, bits in (("verified", actual_color_bits), ("supplied-transcription", supplied_bits)):
        for orientation, stream in (
            ("forward", bits),
            ("reverse", bits[::-1]),
            ("inverted", [1 - bit for bit in bits]),
            ("reverse-inverted", [1 - bit for bit in bits[::-1]]),
        ):
            bit_text = "".join(str(bit) for bit in stream)
            number = int(bit_text, 2)
            add("colored-cells", f"{prefix}/{orientation}/binary", bit_text)
            add("colored-cells", f"{prefix}/{orientation}/hex-upper", f"{number:06X}")
            add("colored-cells", f"{prefix}/{orientation}/hex-lower", f"{number:06x}")
            add("colored-cells", f"{prefix}/{orientation}/decimal", str(number))

    # The published spiral route is itself an authenticated positive control.
    spiral_bits = _spiral(binary_grid)
    add("original-grid", "spiral-url", b"gsmg.io/theseedisplanted")
    add("original-grid", "spiral-tail-bits", "".join(str(value) for value in spiral_bits[192:]))
    add_list("original-grid", "numbered-rows", [sum(row) for row in numbered_grid], insertion_source=True)
    add_list("original-grid", "numbered-columns", [sum(numbered_grid[row][column] for row in range(14)) for column in range(14)], insertion_source=True)

    # S91 sum lists and route variants, under both natural a=1..i=9 and
    # zero-based a=0..i=8 mappings.
    route_digit_streams: dict[str, str] = {}
    for mapping_name, values in (("one-based", s91_one), ("zero-based", s91_zero)):
        for columns in (13, 7):
            base = _reshape(values, columns)
            for transform_name, grid in _grid_variants(base):
                grid_label = f"S91/{mapping_name}/{len(grid)}x{len(grid[0])}/{transform_name}"
                lists = {
                    "rows": [sum(row) for row in grid],
                    "columns": [sum(grid[row][column] for row in range(len(grid))) for column in range(len(grid[0]))],
                    "diagonal-nwse": _diagonal_sums(grid, False),
                    "diagonal-nesw": _diagonal_sums(grid, True),
                }
                for list_name, vector in lists.items():
                    variants = {
                        "identity": vector,
                        "mod10": [value % 10 for value in vector],
                        "mod26": [value % 26 for value in vector],
                        "mod26-zero-to26": [value % 26 or 26 for value in vector],
                    }
                    if len(vector) == len(MATRIX_KEY):
                        order = _stable_key_order(MATRIX_KEY)
                        variants["matrixsumlist-order"] = [vector[index] for index in order]
                        variants["matrixsumlist-order-reverse"] = [vector[index] for index in reversed(order)]
                        weights = [ord(character) - ord("a") + 1 for character in MATRIX_KEY]
                        variants["matrixsumlist-weighted"] = [value * weight for value, weight in zip(vector, weights)]
                        variants["matrixsumlist-weighted-total"] = [sum(value * weight for value, weight in zip(vector, weights))]
                    for variant_name, variant in variants.items():
                        label = f"{grid_label}/{list_name}/{variant_name}"
                        add_list("s91-sum-list", label, variant, insertion_source=True)
                        for index_mode, indexes in (
                            ("one-based-direct", [value - 1 for value in variant]),
                            ("zero-based-direct", list(variant)),
                            ("one-based-mod570", [(value - 1) % 570 for value in variant]),
                            ("zero-based-mod570", [value % 570 for value in variant]),
                        ):
                            if all(0 <= index < 570 for index in indexes):
                                selected = "".join(s570_text[index] for index in indexes)
                                add("s91-index-s570", f"{label}/{index_mode}", selected)

                for route_name, stream in (
                    ("row-major", [value for row in grid for value in row]),
                    ("column-major", [grid[row][column] for column in range(len(grid[0])) for row in range(len(grid))]),
                    ("spiral-right", _spiral_right(grid)),
                    ("spiral-down", _spiral(grid)),
                ):
                    for direction, routed in (("forward", stream), ("reverse", stream[::-1])):
                        label = f"{grid_label}/{route_name}/{direction}"
                        add_list("s91-route", label, routed)
                        if all(1 <= value <= 9 for value in routed):
                            route_digit_streams[label] = "".join(str(value) for value in routed)

    add("s91-route", "literal-text", s91_text)
    add("s91-route", "literal-text-reverse", s91_text[::-1])

    # Column reads ordered by the 13-character matrixsumlist key.
    s91_chars = _reshape([ord(value) for value in s91_text], 13)
    key_order = _stable_key_order(MATRIX_KEY)
    for direction, order in (("ascending", key_order), ("descending", list(reversed(key_order)))):
        text = "".join(chr(s91_chars[row][column]) for column in order for row in range(7))
        add("s91-keyed-columns", direction, text)

    # S570 matrix/route variants.  These are tested as password preimages and
    # as checkerboard digit streams, not asserted to be plaintext.
    for mapping_name, values in (("one-based", s570_one), ("zero-based", s570_zero)):
        for columns in (19, 30):
            base = _reshape(values, columns)
            for transform_name, grid in _grid_variants(base):
                grid_label = f"S570/{mapping_name}/{len(grid)}x{len(grid[0])}/{transform_name}"
                for list_name, vector in (
                    ("rows", [sum(row) for row in grid]),
                    ("columns", [sum(grid[row][column] for row in range(len(grid))) for column in range(len(grid[0]))]),
                ):
                    add_list("s570-sum-list", f"{grid_label}/{list_name}", vector, insertion_source=True)
                for route_name, stream in (
                    ("row-major", [value for row in grid for value in row]),
                    ("column-major", [grid[row][column] for column in range(len(grid[0])) for row in range(len(grid))]),
                    ("spiral-right", _spiral_right(grid)),
                    ("spiral-down", _spiral(grid)),
                ):
                    for direction, routed in (("forward", stream), ("reverse", stream[::-1])):
                        label = f"{grid_label}/{route_name}/{direction}"
                        add_list("s570-route", label, routed)
                        if all(1 <= value <= 9 for value in routed):
                            route_digit_streams[label] = "".join(str(value) for value in routed)
    add("s570-route", "literal-text", s570_text)
    add("s570-route", "literal-text-reverse", s570_text[::-1])

    # Treat the 26-character phrase as alphabet/key material.
    unique = "".join(dict.fromkeys(PHRASE))
    missing = "".join(character for character in "abcdefghijklmnopqrstuvwxyz" if character not in unique)
    dotted = "".join(character if PHRASE.index(character) == index else "." for index, character in enumerate(PHRASE))
    alphabets = {
        "literal": PHRASE,
        "unique-plus-missing": unique + missing,
        "dotted-repeats": dotted,
        "unique-plus-missing-dot-slash": unique + missing + "./",
        "unique-plus-missing-slash-dot": unique + missing + "/.",
    }
    for label, value in alphabets.items():
        add("lastwords-alphabet", label, value)
        add("lastwords-alphabet", f"{label}-upper", value.upper())
        add("lastwords-alphabet", f"{label}-reverse", value[::-1])

    vic_failures = 0
    vic_outputs = 0
    for alphabet_name in ("unique-plus-missing-dot-slash", "unique-plus-missing-slash-dot"):
        alphabet = alphabets[alphabet_name].upper()
        for digits_name, digits in route_digit_streams.items():
            for row_digits in (("1", "4"), ("2", "5"), ("2", "6"), ("5", "6"), ("1", "0")):
                try:
                    decoded = _vic_decode(digits, alphabet, row_digits)
                except ValueError:
                    vic_failures += 1
                    continue
                vic_outputs += 1
                add("lastwords-vic", f"{alphabet_name}/{digits_name}/rows-{''.join(row_digits)}", decoded)

    # "enter" as bounded concatenation/insertion grammar.  Only sum-list
    # serializations enter this expansion; route strings remain direct/hash
    # candidates to keep the family finite and interpretable.
    insertion_positions = {
        "start": 0,
        "before-archi": PHRASE.index("archi"),
        "before-choice": PHRASE.index("choice"),
        "end": len(PHRASE),
    }
    for source, value in matrix_outputs:
        for position_name, position in insertion_positions.items():
            add("enter-insertion", f"{source}/{position_name}", PHRASE[:position].encode("ascii") + value + PHRASE[position:].encode("ascii"))
        add("enter-insertion", f"{source}/result-thispassword", value + b"thispassword")
        add("enter-insertion", f"{source}/thispassword-result", b"thispassword" + value)
        add("enter-insertion", f"{source}/lastwords-result-thispassword", PHRASE.encode("ascii") + value + b"thispassword")
        add("enter-insertion", f"{source}/matrixsumlist-result", b"matrixsumlist" + value)

    # Reapply "last bit" to the authentic instruction tokens.
    instruction_tokens = (MATRIX_KEY, "enter", PHRASE, "thispassword")
    add("last-bit-reuse", "last-characters", "".join(value[-1] for value in instruction_tokens))
    add("last-bit-reuse", "last-characters-reverse", "".join(value[-1] for value in reversed(instruction_tokens)))
    joined = "".join(instruction_tokens).encode("ascii")
    parity_bits = "".join(str(value & 1) for value in joined)
    add("last-bit-reuse", "character-lsb-bits", parity_bits)
    add("last-bit-reuse", "character-lsb-hex", f"{int(parity_bits, 2):x}")
    add("last-bit-reuse", "token-sum-parities", "".join(str(sum(value.encode('ascii')) & 1) for value in instruction_tokens))
    digest_last_bytes = bytes(hashlib.sha256(value.encode("ascii")).digest()[-1] for value in instruction_tokens)
    add("last-bit-reuse", "sha256-last-bytes", digest_last_bytes)
    add("last-bit-reuse", "sha256-last-bytes-hex", digest_last_bytes.hex())

    # Expand raw answers into the explicitly requested SHA-256 and double-hash
    # password spellings, then deduplicate by the actual password bytes.
    passwords: dict[bytes, list[str]] = defaultdict(list)
    for preimage, sources in preimages.items():
        for expansion, password in _password_expansions(preimage):
            for source in sources:
                provenance = f"{source}/{expansion}"
                if provenance not in passwords[password]:
                    passwords[password].append(provenance)

    stream_hasher = hashlib.sha256()
    for password in sorted(passwords):
        stream_hasher.update(len(password).to_bytes(4, "big"))
        stream_hasher.update(password)

    chain1_padding_hits: list[dict[str, object]] = []
    chain1_coupled_hits: list[dict[str, object]] = []
    chain2_direct_hits: list[dict[str, object]] = []
    cosmic_padding_hits: list[dict[str, object]] = []
    direct_scalar_matches: list[dict[str, object]] = []
    strict_counts = Counter()

    # Canonical Cosmic material is only used as an independent downstream
    # gate after a candidate passes both short blobs.
    canonical_cosmic = canonical.cosmic_decryption.plaintext
    canonical_embedded = bytes(
        value ^ MASK[index % len(MASK)]
        for index, value in enumerate(canonical.cosmic_remainder[:1168])
    )

    for password, sources in passwords.items():
        representative_sources = sources[:8]
        for kdf in ("md5", "sha256"):
            chain1 = _try_decrypt(inputs.chain1_envelope, password, kdf)
            if chain1 is not None:
                strict_counts["chain1"] += 1
                record: dict[str, object] = {
                    "password_sha256": _sha(password),
                    "password_length": len(password),
                    "sources": representative_sources,
                    "kdf": kdf,
                    "plaintext_length": len(chain1.plaintext),
                    "plaintext_sha256": _sha(chain1.plaintext),
                    "known_chain1": _sha(chain1.plaintext) == KNOWN_CHAIN1_SHA256,
                }
                chain1_padding_hits.append(record)
                if len(chain1.plaintext) == 79:
                    scalar = int.from_bytes(chain1.plaintext[:32], "big")
                    if 0 < scalar < N:
                        candidate_wif = wif(chain1.plaintext[:32], compressed=False).encode("ascii")
                        for chain2_kdf in ("md5", "sha256"):
                            chain2 = _try_decrypt(inputs.chain2_envelope, candidate_wif, chain2_kdf)
                            if chain2 is None:
                                continue
                            strict_counts["chain1-to-chain2"] += 1
                            chain4_password = chain1.plaintext[64:79] + chain2.plaintext[64:79] + canonical_cosmic[64:66]
                            chain4_hits = _chain4_gate(canonical_embedded, chain4_password) if len(chain2.plaintext) == 79 else []
                            chain1_coupled_hits.append({
                                **record,
                                "chain2_kdf": chain2_kdf,
                                "chain2_plaintext_length": len(chain2.plaintext),
                                "chain2_plaintext_sha256": _sha(chain2.plaintext),
                                "known_chain2": _sha(chain2.plaintext) == KNOWN_CHAIN2_SHA256,
                                "chain4_gates": chain4_hits,
                                "canonical_chain4_structure": any(hit["canonical_structure"] for hit in chain4_hits),
                            })

            chain2 = _try_decrypt(inputs.chain2_envelope, password, kdf)
            if chain2 is not None:
                strict_counts["chain2-direct"] += 1
                chain2_direct_hits.append({
                    "password_sha256": _sha(password),
                    "password_length": len(password),
                    "sources": representative_sources,
                    "kdf": kdf,
                    "plaintext_length": len(chain2.plaintext),
                    "plaintext_sha256": _sha(chain2.plaintext),
                    "known_chain2": _sha(chain2.plaintext) == KNOWN_CHAIN2_SHA256,
                })

            cosmic = _try_decrypt(inputs.cosmic_envelope, password, kdf)
            if cosmic is not None:
                strict_counts["cosmic"] += 1
                cosmic_record: dict[str, object] = {
                    "password_sha256": _sha(password),
                    "password_length": len(password),
                    "sources": representative_sources,
                    "kdf": kdf,
                    "plaintext_length": len(cosmic.plaintext),
                    "plaintext_sha256": _sha(cosmic.plaintext),
                    "known_cosmic": _sha(cosmic.plaintext) == KNOWN_COSMIC_SHA256,
                    "chain4_gates": [],
                }
                if len(cosmic.plaintext) == 1327:
                    remainder = cosmic.plaintext[158:]
                    embedded = bytes(value ^ MASK[index % len(MASK)] for index, value in enumerate(remainder[:1168]))
                    chain4_password = canonical.chain1.extension + canonical.chain2.extension + cosmic.plaintext[64:66]
                    cosmic_record["chain4_gates"] = _chain4_gate(embedded, chain4_password)
                cosmic_padding_hits.append(cosmic_record)

        if len(password) == 32:
            scalar = int.from_bytes(password, "big") % N
            if scalar and PrivateKey(scalar.to_bytes(32, "big")).public_key.format(compressed=True) == TARGET_COMPRESSED:
                direct_scalar_matches.append({
                    "password_sha256": _sha(password),
                    "sources": representative_sources,
                    "address": TARGET_ADDRESS,
                })

    # Hash each unexpanded answer once as the explicit brainwallet/direct
    # scalar interpretation.  (The 32-byte password test above also covers all
    # raw digest and double-digest password spellings.)
    brainwallet_matches: list[dict[str, object]] = []
    for preimage, sources in preimages.items():
        scalar_bytes = hashlib.sha256(preimage).digest()
        scalar = int.from_bytes(scalar_bytes, "big") % N
        if scalar and PrivateKey(scalar.to_bytes(32, "big")).public_key.format(compressed=True) == TARGET_COMPRESSED:
            brainwallet_matches.append({"preimage_sha256": _sha(preimage), "sources": sources[:8], "address": TARGET_ADDRESS})

    canonical_coupled = [hit for hit in chain1_coupled_hits if hit["canonical_chain4_structure"]]
    noncontrol_coupled = [
        hit for hit in canonical_coupled
        if not any(source.startswith("positive-control/") or "canonical-chain1-password" in source for source in hit["sources"])
    ]
    cosmic_structured = [
        hit for hit in cosmic_padding_hits
        if any(gate["canonical_structure"] for gate in hit["chain4_gates"])
    ]
    noncontrol_cosmic_structured = [
        hit for hit in cosmic_structured
        if not any(source.startswith("positive-control/") for source in hit["sources"])
    ]

    def padding_summary(records: list[dict[str, object]], known_field: str) -> dict[str, object]:
        lengths = Counter(int(record["plaintext_length"]) for record in records)
        known = [record for record in records if record[known_field]]
        # Keep deterministic examples of padding luck, plus every known hit.
        samples = list(records[:20])
        for record in known:
            if record not in samples:
                samples.append(record)
        return {
            "count": len(records),
            "plaintext_length_histogram": {str(length): count for length, count in sorted(lengths.items())},
            "known_plaintext_hits": known,
            "first_padding_luck_samples": samples,
        }

    per_envelope_trials = len(passwords) * 2

    result: dict[str, object] = {
        "status": "NEW_AUTHENTICATED_PATH" if noncontrol_coupled or noncontrol_cosmic_structured or direct_scalar_matches or brainwallet_matches else "NO_NEW_AUTHENTICATED_PATH",
        "evidence_boundary": "The source fields, image pixels, envelopes, and canonical downstream controls are authenticated. Candidate matrix layouts, sums, routes, alphabets, insertions, and hash spellings are an explicitly enumerated interpretation family, not creator-documented rules.",
        "source_corrections": {
            "verified_row_sums": verified_rows,
            "supplied_row_sums": supplied_rows,
            "verified_column_sums": verified_columns,
            "supplied_column_sums": supplied_columns,
            "verified_total_ones": sum(verified_rows),
            "supplied_total_ones": 101,
            "verified_colored_bits_blue1_yellow0": "".join(str(value) for value in actual_color_bits),
            "verified_colored_hex": f"{int(''.join(str(value) for value in actual_color_bits), 2):06X}",
            "supplied_colored_bits": "".join(str(value) for value in supplied_bits),
            "supplied_colored_hex": f"{int(''.join(str(value) for value in supplied_bits), 2):06X}",
            "both_verified_and_supplied_variants_tested": True,
        },
        "authenticated_inputs": {
            "chain1_salt": inputs.chain1_envelope[8:16].hex(),
            "chain2_salt": inputs.chain2_envelope[8:16].hex(),
            "cosmic_salt": inputs.cosmic_envelope[8:16].hex(),
            "s91_length": len(s91_text),
            "s91_sha256": _sha(s91_text.encode("ascii")),
            "binary104_length": len(binary104),
            "binary104_sha256": _sha(binary104.encode("ascii")),
            "s570_length": len(s570_text),
            "s570_sha256": _sha(s570_text.encode("ascii")),
            "lastwords_length": len(PHRASE),
            "lastwords_unique_letters": unique,
            "lastwords_missing_letters": missing,
        },
        "candidate_family": {
            "raw_generation_records_by_category": dict(sorted(category_records.items())),
            "unique_preimages": len(preimages),
            "password_expansions": [
                "raw", "SHA256 digest bytes", "SHA256 lower/upper hex ASCII",
                "SHA256 of digest bytes", "SHA256 of lower-hex text", "lower-hex spellings of both",
            ],
            "unique_password_bytes": len(passwords),
            "decryptions_per_envelope": per_envelope_trials,
            "random_strict_pkcs7_expected_approximately": per_envelope_trials / 255,
            "password_candidate_stream_sha256": stream_hasher.hexdigest(),
            "kdf_digests": ["md5", "sha256"],
            "tested_envelopes": ["SalPhaseIon short", "Phase 3.2 small", "Cosmic Duality"],
            "vic_decoded_outputs": vic_outputs,
            "vic_invalid_route_parameter_records": vic_failures,
            "matrix_outputs_used_by_enter_grammar": len(matrix_outputs),
        },
        "acceptance_gates": {
            "padding_is_not_acceptance": True,
            "short_blob": "strict PKCS#7, then exactly 79 bytes and a valid first-field scalar",
            "coupled_small_blob": "WIF(first 32 bytes) must strictly decrypt the independent small blob",
            "embedded_chain4": "extensions plus Cosmic E_B prefix must decrypt to 1151 bytes, '+-' marker, and 35 aligned 32-byte blocks",
            "prize": "candidate scalar must derive the exact compressed target point",
        },
        "strict_padding_hit_counts": dict(strict_counts),
        "chain1_padding_audit": padding_summary(chain1_padding_hits, "known_chain1"),
        "chain1_to_chain2_hits": chain1_coupled_hits,
        "chain1_to_chain2_to_chain4_structure_hits": canonical_coupled,
        "noncontrol_chain1_to_chain2_to_chain4_structure_hits": noncontrol_coupled,
        "chain2_direct_padding_audit": padding_summary(chain2_direct_hits, "known_chain2"),
        "cosmic_padding_audit": padding_summary(cosmic_padding_hits, "known_cosmic"),
        "cosmic_to_chain4_structure_hits": cosmic_structured,
        "noncontrol_cosmic_to_chain4_structure_hits": noncontrol_cosmic_structured,
        "direct_32_byte_scalar_matches": direct_scalar_matches,
        "sha256_brainwallet_matches": brainwallet_matches,
        "conclusion": "No instruction-style candidate is accepted unless it passes an independent downstream cryptographic structure gate. The literal five-token path remains a positive control and is not classified as padding-only.",
        "scope_note": "This closes the enumerated layouts, routes, serializations, alphabet/checkerboard variants, insertions, and hash spellings. It does not prove that no unenumerated SalPhaseIon grammar exists.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
