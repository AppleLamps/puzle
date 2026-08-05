"""Frontier audit for S91/S570, Witteveen/page-140 selectors, and short blob.

This script is intentionally bounded around creator-sourced leads that were not
the main target of the earlier creator_frontier_giveaway_audit:

* use the S91 colour stream and Witteveen/page-140 text as selectors into
  Cosmic and Chain4 byte domains;
* interpret S570 under Playfair, Vigenere, and Beaufort-style ciphers with the
  requested keys;
* turn the Phase 3.2 "One for one, four for one" number line into key material;
* test creator-pipeline alternate passwords against the 80-byte ciphertext in
  the SalPhaseIon OpenSSL envelope.

Every byte candidate is ultimately gated against both prize P2PKH targets.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import hashlib
import json
import re
from pathlib import Path
from typing import Iterable

from coincurve import PrivateKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .heart_page140_key_audit import PAGE_140_P1, PAGE_140_P2, PAGE_140_P3_VISIBLE
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion import derive_tokens
from .salphaseion_raw import extract_raw
from .secp256k1_verify import N, base58check, hash160, wif
from .witteveen_identity_audit import t23_components, unique_color_parse


RESULT_PATH = ROOT / "salphaseion_selector_frontier_audit.json"

HALF_ADDR = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER_ADDR = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
HALF_H160 = bytes.fromhex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")
BETTER_H160 = bytes.fromhex("4bc468447fe1b048ad030a2f9a125478eabc4ed6")
HALF_PUB = bytes.fromhex(
    "04"
    "f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)
PRIZES = {
    "Half": {"address": HALF_ADDR, "hash160": HALF_H160},
    "Better_Half": {"address": BETTER_ADDR, "hash160": BETTER_H160},
}

CREATOR_PIPELINE = (
    "yellowblueprimes",
    "matrixsumlist",
    "lastwordsbeforearchichoice",
    "yinyang",
    "wewontgiveawaythepassword",
    "itsinfrontofyoureyesbutyourenotseeingit",
    "verylaststepisatruegiveawaypromised",
)
CLASSICAL_KEYS = (
    "THEMATRIXHASYOU",
    "WITTEVEEN",
    "yellowblueprimes",
    "HASHTHETEXT",
    "yinyang",
)
DIAG_SUMS = (22, 34, 19, 21, 56, 30, 13)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def xor_bytes(items: Iterable[bytes]) -> bytes:
    out = bytearray(32)
    for item in items:
        block = item if len(item) == 32 else sha256(item)
        for index, value in enumerate(block[:32]):
            out[index] ^= value
    return bytes(out)


def base58_p2pkh(public_key: bytes) -> str:
    return base58check(b"\0" + hash160(public_key))


def lcp_nibbles(left: bytes, right: bytes) -> int:
    count = 0
    for a, b in zip(left.hex(), right.hex()):
        if a != b:
            break
        count += 1
    return count


def bit_distance(left: bytes, right: bytes) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def text_words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9]+", text.lower())


def a1(char: str) -> int:
    return ord(char.upper()) - ord("A") + 1


def a0_to_letter(value: int) -> str:
    return chr(ord("A") + value % 26)


def printable_sample(data: bytes, limit: int = 96) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in data[:limit])


@dataclass
class CandidateGate:
    seen_scalars: set[bytes] = field(default_factory=set)
    scalar_tests: int = 0
    family_scalar_tests: Counter[str] = field(default_factory=Counter)
    family_raw_candidates: Counter[str] = field(default_factory=Counter)
    matches: list[dict[str, object]] = field(default_factory=list)
    near_misses: list[dict[str, object]] = field(default_factory=list)
    max_near_misses: int = 30

    def add_material(self, family: str, label: str, material: bytes, *, windows: bool = True) -> None:
        if not material:
            return
        self.family_raw_candidates[family] += 1
        for variant_label, candidate in self._scalar_variants(label, material, windows=windows):
            scalar = int.from_bytes(candidate, "big") % N
            if scalar == 0:
                continue
            scalar_bytes = scalar.to_bytes(32, "big")
            if scalar_bytes in self.seen_scalars:
                continue
            self.seen_scalars.add(scalar_bytes)
            self.scalar_tests += 1
            self.family_scalar_tests[family] += 1
            self._test_scalar(family, variant_label, scalar_bytes)

    def _scalar_variants(self, label: str, material: bytes, *, windows: bool) -> Iterable[tuple[str, bytes]]:
        length = len(material)
        yield f"{label}/sha256", sha256(material)
        yield f"{label}/double-sha256", sha256(sha256(material))
        if length < 32:
            yield f"{label}/left-zero-pad", material.rjust(32, b"\0")
            yield f"{label}/right-zero-pad", material.ljust(32, b"\0")
        elif length == 32:
            yield label, material
            yield f"{label}/rev", material[::-1]
        else:
            yield f"{label}/first32", material[:32]
            yield f"{label}/last32", material[-32:]
            if windows:
                for offset in range(length - 31):
                    window = material[offset : offset + 32]
                    yield f"{label}/win[{offset}:{offset + 32}]", window
                    yield f"{label}/win[{offset}:{offset + 32}]/rev", window[::-1]

    def _test_scalar(self, family: str, label: str, scalar: bytes) -> None:
        private = PrivateKey(scalar)
        pub_uncompressed = private.public_key.format(compressed=False)
        pub_compressed = private.public_key.format(compressed=True)
        pubs = {
            "uncompressed": pub_uncompressed,
            "compressed": pub_compressed,
        }
        for serialization, public_key in pubs.items():
            public_h160 = hash160(public_key)
            address = base58_p2pkh(public_key)
            for prize_name, prize in PRIZES.items():
                exact = public_h160 == prize["hash160"] and address == prize["address"]
                if prize_name == "Half" and serialization == "uncompressed":
                    exact = exact and public_key == HALF_PUB
                if exact:
                    self.matches.append(
                        {
                            "family": family,
                            "label": label,
                            "prize": prize_name,
                            "serialization": serialization,
                            "address": address,
                            "private_key_hex": scalar.hex(),
                            "wif": wif(scalar, compressed=(serialization == "compressed")),
                        }
                    )
            self._record_near(family, label, scalar, serialization, public_key, public_h160, address)

    def _record_near(
        self,
        family: str,
        label: str,
        scalar: bytes,
        serialization: str,
        public_key: bytes,
        public_h160: bytes,
        address: str,
    ) -> None:
        best_target = None
        best_lcp = -1
        best_bits = 999
        for prize_name, prize in PRIZES.items():
            prefix = lcp_nibbles(public_h160, prize["hash160"])
            distance = bit_distance(public_h160, prize["hash160"])
            if prefix > best_lcp or (prefix == best_lcp and distance < best_bits):
                best_target = prize_name
                best_lcp = prefix
                best_bits = distance
        half_pub_lcp = lcp_nibbles(public_key, HALF_PUB) if serialization == "uncompressed" else 0
        record = {
            "family": family,
            "label": label[:180],
            "target": best_target,
            "serialization": serialization,
            "hash160_lcp_nibbles": best_lcp,
            "hash160_bit_distance": best_bits,
            "half_pubkey_lcp_nibbles": half_pub_lcp,
            "address": address,
            "private_key_hex": scalar.hex(),
        }
        self.near_misses.append(record)
        self.near_misses.sort(
            key=lambda item: (
                item["hash160_lcp_nibbles"],
                -item["hash160_bit_distance"],
                item["half_pubkey_lcp_nibbles"],
            ),
            reverse=True,
        )
        del self.near_misses[self.max_near_misses :]


def cycle_select(data: bytes, selectors: list[int], length: int = 32) -> bytes:
    if not data or not selectors:
        return b""
    out = bytearray()
    cursor = 0
    while len(out) < length:
        selector = selectors[cursor % len(selectors)]
        out.append(data[(selector + cursor // len(selectors)) % len(data)])
        cursor += 1
    return bytes(out)


def fold_selected_blocks(blocks: list[bytes], indexes: list[int]) -> dict[str, bytes]:
    selected = [blocks[index % len(blocks)] for index in indexes if blocks]
    if not selected:
        return {}
    xor_fold = bytearray(32)
    sum_fold = 0
    weighted_sum = 0
    for rank, block in enumerate(selected, 1):
        value = int.from_bytes(block, "big")
        sum_fold = (sum_fold + value) % N
        weighted_sum = (weighted_sum + rank * value) % N
        for offset, byte in enumerate(block):
            xor_fold[offset] ^= byte
    return {
        "xor": bytes(xor_fold),
        "sum-mod-n": sum_fold.to_bytes(32, "big"),
        "weighted-sum-mod-n": weighted_sum.to_bytes(32, "big"),
        "sha-concat": sha256(b"".join(selected)),
        "concat": b"".join(selected),
    }


def build_s570_structural_streams(s570: str, colors: str) -> dict[str, str]:
    values = [ord(symbol) - ord("a") for symbol in s570]
    for index in (474, 400):
        values[index] = 0
    combined = [left + right for left, right in zip(values[:285], reversed(values[285:]))]
    middle = combined[7:-2]
    t23, _ = t23_components(middle, colors)
    return {
        "s570-a-i": "".join(chr(ord("A") + ord(symbol) - ord("a")) for symbol in s570),
        "s570-folded-a0": "".join(a0_to_letter(value) for value in combined),
        "s570-folded-middle-a0": "".join(a0_to_letter(value) for value in middle),
        "s570-t23-compact": t23.replace("_", ""),
    }


def playfair_square(key: str) -> dict[str, tuple[int, int]]:
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    seen: list[str] = []
    for char in re.sub(r"[^A-Za-z]", "", key.upper()).replace("J", "I") + alphabet:
        if char not in seen and char in alphabet:
            seen.append(char)
    return {char: divmod(index, 5) for index, char in enumerate(seen)}


def playfair_decrypt(ciphertext: str, key: str) -> str:
    positions = playfair_square(key)
    square = [[""] * 5 for _ in range(5)]
    for char, (row, col) in positions.items():
        square[row][col] = char
    letters = re.sub(r"[^A-Za-z]", "", ciphertext.upper()).replace("J", "I")
    if len(letters) % 2:
        letters = letters[:-1]
    out: list[str] = []
    for left, right in zip(letters[::2], letters[1::2]):
        r1, c1 = positions[left]
        r2, c2 = positions[right]
        if r1 == r2:
            out.append(square[r1][(c1 - 1) % 5])
            out.append(square[r2][(c2 - 1) % 5])
        elif c1 == c2:
            out.append(square[(r1 - 1) % 5][c1])
            out.append(square[(r2 - 1) % 5][c2])
        else:
            out.append(square[r1][c2])
            out.append(square[r2][c1])
    return "".join(out)


def keyed_shift(text: str, key: str, mode: str) -> str:
    letters = re.sub(r"[^A-Za-z]", "", text.upper())
    key_values = [a1(char) - 1 for char in re.sub(r"[^A-Za-z]", "", key.upper())]
    if not key_values:
        return ""
    out = []
    for index, char in enumerate(letters):
        cipher = a1(char) - 1
        kval = key_values[index % len(key_values)]
        if mode == "vigenere-decrypt":
            plain = (cipher - kval) % 26
        elif mode == "vigenere-encrypt":
            plain = (cipher + kval) % 26
        elif mode == "beaufort":
            plain = (kval - cipher) % 26
        elif mode == "variant-beaufort":
            plain = (cipher - kval) % 26
        else:
            raise ValueError(mode)
        out.append(chr(ord("A") + plain))
    return "".join(out)


def classical_score(text: str) -> int:
    trigrams = (
        "THE",
        "AND",
        "ING",
        "ION",
        "ENT",
        "KEY",
        "HASH",
        "TEXT",
        "WIT",
        "VEEN",
        "YIN",
        "YANG",
        "HALF",
        "PRIME",
        "SOURCE",
        "FUNCTION",
        "PURPOSE",
        "UNAWARE",
    )
    return sum(text.count(token) * len(token) for token in trigrams)


def run_witteveen_page_selector_family(gate: CandidateGate, cosmic_pt: bytes, chain4_plain: bytes) -> dict[str, object]:
    page = "\n\n".join((PAGE_140_P1, PAGE_140_P2, PAGE_140_P3_VISIBLE))
    words = text_words(page)
    page_alnum = "".join(words).encode("ascii")
    matrix = analyze(cosmic_pt)
    raw = extract_raw()
    colors = unique_color_parse(raw.s91)
    chain4 = reconstruct_chain4(reconstruct(extract_all(), derive_tokens()))
    blocks = list(chain4.blocks)

    concept_positions: list[int] = []
    for concept in ("unaware", "source", "function", "purpose", "muwakkals", "elementals", "heart", "thought"):
        concept_positions.extend(index + 1 for index, word in enumerate(words) if word == concept)

    primes = [
        value
        for value in range(2, 84)
        if all(value % divisor for divisor in range(2, int(value**0.5) + 1))
    ]
    blue_primes = [prime for prime, color in zip(primes, colors) if color == "B"]
    yellow_primes = [prime for prime, color in zip(primes, colors) if color == "Y"]
    page_by_diag = [words[(value - 1) % len(words)] for value in DIAG_SUMS]
    page_word_lengths = [len(word) for word in page_by_diag]
    page_word_sums = [sum(a1(char) for char in word if char.isalpha()) for word in page_by_diag]
    witteveen_letters = [a1(char) for char in "WITTEVEEN"]

    selector_sets = {
        "diag-sums": list(DIAG_SUMS),
        "diag-page-word-lengths": page_word_lengths,
        "diag-page-word-a1-sums": page_word_sums,
        "witteveen-letters": witteveen_letters,
        "concept-word-positions": concept_positions,
        "s91-blue-prime-numbers": blue_primes,
        "s91-yellow-prime-numbers": yellow_primes,
        "s91-blue-prime-page-word-lengths": [len(words[(value - 1) % len(words)]) for value in blue_primes],
        "s91-yellow-prime-page-word-lengths": [len(words[(value - 1) % len(words)]) for value in yellow_primes],
        "page140-plus-prime-sums": [140, 400, 474, 140 + 400, 140 + 474, 474 - 400],
    }

    examples = {}
    for name, selectors in selector_sets.items():
        selectors = [value for value in selectors if value is not None]
        if not selectors:
            continue
        examples[name] = selectors[:16]
        for fold_name, material in fold_selected_blocks(blocks, selectors).items():
            gate.add_material("witteveen_page_selectors", f"{name}/chain4-blocks/{fold_name}", material)
        gate.add_material(
            "witteveen_page_selectors",
            f"{name}/page-alnum-selected-32",
            cycle_select(page_alnum, selectors, 32),
            windows=False,
        )
        gate.add_material(
            "witteveen_page_selectors",
            f"{name}/cosmic-plaintext-selected-32",
            cycle_select(cosmic_pt, selectors, 32),
            windows=False,
        )
        gate.add_material(
            "witteveen_page_selectors",
            f"{name}/chain4-plaintext-selected-32",
            cycle_select(chain4_plain, selectors, 32),
            windows=False,
        )
        gate.add_material(
            "witteveen_page_selectors",
            f"{name}/cosmic-base38-selected-32",
            cycle_select(matrix.base38_bytes, selectors, 32),
            windows=False,
        )
        row_col = bytes(
            (matrix.row_sums[value % 103] + matrix.column_sums[(value + rank) % 103]) & 0xFF
            for rank, value in enumerate(selectors)
        )
        gate.add_material("witteveen_page_selectors", f"{name}/cosmic-rowcol-bytes", row_col)
        selected_words = " ".join(words[(value - 1) % len(words)] for value in selectors).encode("ascii")
        gate.add_material("witteveen_page_selectors", f"{name}/selected-page-words", selected_words)
        mask = sha256(selected_words)
        gate.add_material(
            "witteveen_page_selectors",
            f"{name}/selected-words-sha-xor-cosmic-half",
            bytes(a ^ b for a, b in zip(mask, matrix.half)),
            windows=False,
        )
        gate.add_material(
            "witteveen_page_selectors",
            f"{name}/selected-words-sha-xor-cosmic-better",
            bytes(a ^ b for a, b in zip(mask, matrix.better_half)),
            windows=False,
        )

    return {
        "page_word_count": len(words),
        "page_alnum_length": len(page_alnum),
        "s91_color_parse": colors,
        "blue_prime_count": len(blue_primes),
        "yellow_prime_count": len(yellow_primes),
        "selector_sets": {key: len(value) for key, value in selector_sets.items()},
        "selector_examples": examples,
        "diag_selected_words": page_by_diag,
    }


def run_s570_classical_family(gate: CandidateGate) -> dict[str, object]:
    raw = extract_raw()
    colors = unique_color_parse(raw.s91)
    streams = build_s570_structural_streams(raw.s570, colors)
    digits = "".join(str(ord(symbol) - ord("a") + 1) for symbol in raw.s570)
    pair_mod = "".join(a0_to_letter(int(digits[index : index + 2]) - 1) for index in range(0, len(digits) - 1, 2))
    streams["s570-a1-digit-pairs-mod26"] = pair_mod
    modes = ("vigenere-decrypt", "vigenere-encrypt", "beaufort", "variant-beaufort")
    decode_records: list[dict[str, object]] = []

    for stream_name, stream in streams.items():
        clean = re.sub(r"[^A-Za-z]", "", stream.upper())
        for key in CLASSICAL_KEYS:
            for mode in modes:
                plaintext = keyed_shift(clean, key, mode)
                if not plaintext:
                    continue
                label = f"{stream_name}/{mode}/{key.upper()}"
                gate.add_material("s570_classical", label, plaintext.encode("ascii"))
                score = classical_score(plaintext)
                decode_records.append(
                    {
                        "stream": stream_name,
                        "mode": mode,
                        "key": key.upper(),
                        "length": len(plaintext),
                        "score": score,
                        "sha256": hashlib.sha256(plaintext.encode("ascii")).hexdigest(),
                        "sample": plaintext[:120],
                    }
                )
            playfair = playfair_decrypt(clean, key)
            if playfair:
                label = f"{stream_name}/playfair-decrypt/{key.upper()}"
                gate.add_material("s570_classical", label, playfair.encode("ascii"))
                decode_records.append(
                    {
                        "stream": stream_name,
                        "mode": "playfair-decrypt",
                        "key": key.upper(),
                        "length": len(playfair),
                        "score": classical_score(playfair),
                        "sha256": hashlib.sha256(playfair.encode("ascii")).hexdigest(),
                        "sample": playfair[:120],
                    }
                )

    decode_records.sort(key=lambda item: (item["score"], item["length"]), reverse=True)
    return {
        "streams": {name: len(value) for name, value in streams.items()},
        "keys": [key.upper() for key in CLASSICAL_KEYS],
        "modes_per_stream_key": len(modes) + 1,
        "decode_records": len(decode_records),
        "top_scored_decodes": decode_records[:20],
    }


def phase32_number_line() -> tuple[str, str]:
    text = Path("/workspace/phase32_plaintext.txt").read_text(encoding="utf-8")
    number_match = re.search(r"(?m)^(\d{80,})$", text)
    phrase_match = re.search(r"One for one, four for one\.", text)
    if number_match is None or phrase_match is None:
        raise ValueError("could not find Phase 3.2 number line and one/four phrase")
    return phrase_match.group(0), number_match.group(1)


def run_phase32_one_four_family(gate: CandidateGate, cosmic_pt: bytes, chain4_plain: bytes) -> dict[str, object]:
    phrase, digits = phase32_number_line()
    chunks4 = [digits[index : index + 4] for index in range(0, len(digits) - 3, 4)]
    chunk_values = [int(chunk) for chunk in chunks4]
    one_digits = [int(char) for char in digits]

    materials: dict[str, bytes] = {
        "phrase-lower-nospace": re.sub(r"[^a-z0-9]", "", phrase.lower()).encode("ascii"),
        "number-line-ascii": digits.encode("ascii"),
        "phrase-plus-number": (phrase + "\n" + digits).encode("ascii"),
        "single-digits-as-a0-letters": "".join(a0_to_letter(value - 1) for value in one_digits).encode("ascii"),
        "four-chunks-mod256": bytes(value % 256 for value in chunk_values),
        "four-chunks-u16be": b"".join((value % 65536).to_bytes(2, "big") for value in chunk_values),
        "four-chunks-u16le": b"".join((value % 65536).to_bytes(2, "little") for value in chunk_values),
        "four-chunks-a0-mod26": "".join(a0_to_letter(value - 1) for value in chunk_values).encode("ascii"),
        "entire-number-mod-n": (int(digits) % N).to_bytes(32, "big"),
    }

    def alternating_groups(widths: tuple[int, int]) -> tuple[bytes, bytes]:
        pos = 0
        values: list[int] = []
        letters: list[str] = []
        turn = 0
        while pos < len(digits):
            width = widths[turn % 2]
            piece = digits[pos : pos + width]
            if len(piece) < width:
                break
            value = int(piece)
            values.append(value % 256)
            letters.append(a0_to_letter(value - 1))
            pos += width
            turn += 1
        return bytes(values), "".join(letters).encode("ascii")

    for name, widths in (("one-then-four", (1, 4)), ("four-then-one", (4, 1))):
        as_bytes, as_letters = alternating_groups(widths)
        materials[f"{name}-mod256"] = as_bytes
        materials[f"{name}-a0-mod26"] = as_letters

    key = re.sub(r"[^A-Za-z]", "", phrase).upper()
    materials["four-chunks-vigenere-with-phrase"] = keyed_shift(
        materials["four-chunks-a0-mod26"].decode("ascii"), key, "vigenere-decrypt"
    ).encode("ascii")
    materials["four-chunks-beaufort-with-phrase"] = keyed_shift(
        materials["four-chunks-a0-mod26"].decode("ascii"), key, "beaufort"
    ).encode("ascii")

    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    for fold_name, material in fold_selected_blocks(list(chain4.blocks), chunk_values).items():
        materials[f"four-chunks-select-chain4/{fold_name}"] = material
    materials["four-chunks-select-cosmic-32"] = cycle_select(cosmic_pt, chunk_values, 32)
    materials["four-chunks-select-chain4-plain-32"] = cycle_select(chain4_plain, chunk_values, 32)

    for label, material in materials.items():
        gate.add_material("phase32_one_four", label, material)

    return {
        "phrase": phrase,
        "number_line_digits": len(digits),
        "four_chunks": len(chunks4),
        "materials": {label: len(material) for label, material in materials.items()},
        "first_four_chunks": chunks4[:12],
    }


def password_byte_variants(label: str, value: bytes) -> Iterable[tuple[str, bytes]]:
    yield f"{label}/raw", value
    yield f"{label}/sha256-digest", sha256(value)
    yield f"{label}/sha256-lowerhex", hashlib.sha256(value).hexdigest().encode("ascii")
    yield f"{label}/sha256-upperhex", hashlib.sha256(value).hexdigest().upper().encode("ascii")
    yield f"{label}/double-sha256-digest", sha256(sha256(value))


def creator_pipeline_passwords() -> dict[str, bytes]:
    texts: dict[str, str] = {}
    for token in CREATOR_PIPELINE:
        texts[f"token/{token}"] = token
    for end in range(1, len(CREATOR_PIPELINE) + 1):
        prefix = CREATOR_PIPELINE[:end]
        texts[f"prefix-{end}-concat"] = "".join(prefix)
        texts[f"prefix-{end}-space"] = " ".join(prefix)
    for start in range(len(CREATOR_PIPELINE)):
        suffix = CREATOR_PIPELINE[start:]
        texts[f"suffix-{start + 1}-concat"] = "".join(suffix)
    for yin in ("yinyang", "yingyang", "yin yang", "YinYang"):
        texts[f"yellowblueprimes-{yin}-witteveen"] = "yellowblueprimes" + yin + "witteveen"
        texts[f"witteveen-{yin}-unaware"] = "witteveen" + yin + "unaware"
        texts[f"heart-{yin}-giveaway"] = "theheartofsufism" + yin + "verylaststepisatruegiveawaypromised"
    for extra in (
        "WITTEVEEN",
        "HJWITTEVEEN",
        "KARIMBAKHSH",
        "THEHEARTOFSUFISM",
        "HEARTOFSUFISM",
        "unaware",
        "sourcefunctionpurpose",
        "oneforonefourforone",
        "HASHTHETEXT",
    ):
        texts[f"extra/{extra}"] = extra

    passwords: dict[str, bytes] = {}
    for label, text in texts.items():
        forms = {
            "as-is": text,
            "lower": text.lower(),
            "upper": text.upper(),
            "nospace-lower": re.sub(r"[^a-z0-9]", "", text.lower()),
        }
        for form_name, form in forms.items():
            if form:
                passwords[f"{label}/{form_name}"] = form.encode("utf-8")

    public_tokens = [
        "matrixsumlist",
        "enter",
        "lastwordsbeforearchichoice",
        "thispassword",
        "matrixsumlist",
        "yourlastcommand",
        "secondanswer",
    ]
    substitutions = {
        1: ("yellowblueprimes", "yinyang", "witteveen"),
        3: ("yinyang", "wewontgiveawaythepassword"),
        5: ("yellowblueprimes", "yinyang", "unaware", "HASHTHETEXT", "WITTEVEEN"),
        6: ("yellowblueprimes", "yinyang", "unaware", "HASHTHETEXT", "verylaststepisatruegiveawaypromised"),
    }
    for index, alternatives in substitutions.items():
        for alternative in alternatives:
            tokens = list(public_tokens)
            tokens[index] = alternative
            passwords[f"public-subst-{index}-{alternative}"] = "".join(tokens).encode("ascii")

    digest_items = [sha256(token.encode("ascii")) for token in CREATOR_PIPELINE]
    for end in range(1, len(digest_items) + 1):
        passwords[f"digest-xor-prefix-{end}"] = xor_bytes(digest_items[:end])
    passwords["digest-xor-all-reversed"] = xor_bytes(reversed(digest_items))
    return passwords


def run_short_blob_password_family(gate: CandidateGate) -> dict[str, object]:
    raw = extract_raw()
    envelope = raw.short_envelope
    canonical_password = b"matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist"
    canonical = decrypt_salted_aes256_cbc(envelope, canonical_password)
    if len(canonical.plaintext) != 79:
        raise ValueError("canonical SalPhaseIon short blob no longer decrypts to 79 bytes")

    passwords = creator_pipeline_passwords()
    aes_attempts = 0
    padding_hits: list[dict[str, object]] = []
    structural_hits: list[dict[str, object]] = []
    seen_passwords: set[tuple[bytes, str]] = set()
    for base_label, base_password in passwords.items():
        for variant_label, password in password_byte_variants(base_label, base_password):
            if password == canonical_password:
                continue
            for digest in ("md5", "sha256"):
                key = (password, digest)
                if key in seen_passwords:
                    continue
                seen_passwords.add(key)
                aes_attempts += 1
                try:
                    decrypted = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
                except ValueError:
                    continue
                record = {
                    "label": variant_label,
                    "digest": digest,
                    "plaintext_len": len(decrypted.plaintext),
                    "plaintext_sha256": hashlib.sha256(decrypted.plaintext).hexdigest(),
                    "printable_sample": printable_sample(decrypted.plaintext),
                }
                padding_hits.append(record)
                gate.add_material(
                    "salphaseion_short_blob_alt_passwords",
                    f"{variant_label}/aes-{digest}-plaintext",
                    decrypted.plaintext,
                )
                if len(decrypted.plaintext) == 79:
                    structural = {
                        **record,
                        "triplet_shape": "32+32+15",
                        "first_scalar_in_range": 1 <= int.from_bytes(decrypted.plaintext[:32], "big") < N,
                    }
                    structural_hits.append(structural)

    return {
        "envelope_len": len(envelope),
        "ciphertext_len": len(envelope) - 16,
        "salt_hex": envelope[8:16].hex(),
        "canonical_plaintext_sha256": hashlib.sha256(canonical.plaintext).hexdigest(),
        "alternate_base_passwords": len(passwords),
        "aes_attempts": aes_attempts,
        "padding_hits": padding_hits[:50],
        "padding_hit_count": len(padding_hits),
        "structural_hits": structural_hits[:20],
        "structural_hit_count": len(structural_hits),
    }


def run() -> dict[str, object]:
    extracted = extract_all()
    salphaseion = derive_tokens()
    chains = reconstruct(extracted, salphaseion)
    chain4 = reconstruct_chain4(chains)
    cosmic_pt = chains.cosmic_decryption.plaintext
    chain4_plain = chain4.decryption.plaintext

    gate = CandidateGate()
    meta = {
        "witteveen_page_selectors": run_witteveen_page_selector_family(gate, cosmic_pt, chain4_plain),
        "s570_classical": run_s570_classical_family(gate),
        "phase32_one_four": run_phase32_one_four_family(gate, cosmic_pt, chain4_plain),
        "salphaseion_short_blob_alt_passwords": run_short_blob_password_family(gate),
    }

    result = {
        "schema": "salphaseion-selector-frontier-audit-v1",
        "status": "MATCH" if gate.matches else "NO_MATCH",
        "prize_targets": {
            "Half": {
                "address": HALF_ADDR,
                "known_uncompressed_pubkey": HALF_PUB.hex(),
                "hash160_uncompressed": HALF_H160.hex(),
            },
            "Better_Half": {
                "address": BETTER_ADDR,
                "hash160": BETTER_H160.hex(),
            },
        },
        "counts": {
            "raw_candidates_by_family": dict(gate.family_raw_candidates),
            "scalar_tests_by_family": dict(gate.family_scalar_tests),
            "total_raw_candidates": sum(gate.family_raw_candidates.values()),
            "total_scalar_tests": gate.scalar_tests,
        },
        "matches": gate.matches,
        "strongest_near_misses": gate.near_misses,
        "meta": meta,
        "notes": [
            "S91/Witteveen/page-140 material is used as selectors into byte domains, not as direct brainwallet text.",
            "S570 classical tests cover Playfair, Vigenere, Beaufort, and variant-Beaufort with the requested keys.",
            "Phase 3.2 number-line tests include one/four grouping, 4-digit chunks, phrase-key shifts, and selector folds.",
            "The SalPhaseIon short envelope has 80 bytes of AES ciphertext; creator-pipeline alternatives exclude the canonical known password.",
        ],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    if output["matches"]:
        print("***** EXACT PRIZE PRIVATE KEY MATCH *****")
        for match in output["matches"]:
            print(f"{match['prize']} {match['serialization']}")
            print(f"HEX: {match['private_key_hex']}")
            print(f"WIF: {match['wif']}")
        print("*****************************************")
    print(
        json.dumps(
            {
                "status": output["status"],
                "counts": output["counts"],
                "matches": output["matches"],
                "strongest_near_misses": output["strongest_near_misses"][:10],
                "result_path": str(RESULT_PATH),
            },
            indent=2,
        )
    )
