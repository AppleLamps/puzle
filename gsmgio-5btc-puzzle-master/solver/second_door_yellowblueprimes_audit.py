"""Bounded second-door audit from the first image under creator hints.

Creator-motivated inputs only:
  - yellowblueprimes pipeline head
  - Yellow/Blue resistor numbers (Y=4, B=6)
  - primes required; characters need to be 'zeroed out'
  - authenticated spiral URL + F73D92 marker stream
  - Witteveen bridge F73D92//2+3 -> 7B9ECC
  - majority (101 ones) vs centre (102 ones); off-white cell (7,4)

Gates:
  A) alternate Cosmic Duality / Chain4 OpenSSL passwords (readable or
     alternate +- / 1151 structure, excluding the known published controls)
  B) exact P2PKH match to either prize address
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path

from PIL import Image

from .chain4 import MASK, reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion import derive_tokens
from .salphaseion_blind_eval import _formats, _readable
from .salphaseion_raw import extract_raw
from .secp256k1_verify import N, p2pkh_address


RESULT_PATH = ROOT / "second_door_yellowblueprimes_audit.json"
IMAGE = Path("/workspace/follow_the_white_rabbit.png")
FALLBACK_IMAGE = ROOT / "puzzle.png"

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)
OFF_WHITE = (254, 254, 254)

URL = b"gsmg.io/theseedisplanted"
GENESIS = 0xF73D92
HALF = GENESIS // 2
BETTER = HALF + 3
PRIZE = {
    "Half": "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "Better_Half": "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa",
}
KNOWN_COSMIC_SHA = None  # filled at runtime from published path
KNOWN_CHAIN4_SHA = None


def _primes(limit: int) -> list[int]:
    return [
        value
        for value in range(2, limit + 1)
        if all(value % divisor for divisor in range(2, math.isqrt(value) + 1))
    ]


def _spiral_positions(size: int) -> list[tuple[int, int]]:
    order: list[tuple[int, int]] = []
    top = left = 0
    bottom = right = size - 1
    while top <= bottom and left <= right:
        for row in range(top, bottom + 1):
            order.append((row, left))
        left += 1
        for col in range(left, right + 1):
            order.append((bottom, col))
        bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                order.append((row, right))
            right -= 1
        if top <= bottom:
            for col in range(right, left - 1, -1):
                order.append((top, col))
            top += 1
    return order


def _majority_grid(path: Path) -> list[list[tuple[int, int, int]]]:
    image = Image.open(path).convert("RGB")
    cell = image.width // 14
    pixels = image.load()
    grid = []
    for row in range(14):
        cells = []
        for col in range(14):
            counts = Counter(
                pixels[x, y]
                for y in range(row * cell, (row + 1) * cell)
                for x in range(col * cell, (col + 1) * cell)
            )
            cells.append(counts.most_common(1)[0][0])
        grid.append(cells)
    return grid


def _center_grid(path: Path) -> list[list[tuple[int, int, int]]]:
    image = Image.open(path).convert("RGB")
    # puzzle.png is 1048 wide for the grid; follow_the_white_rabbit is 350.
    width = min(image.width, image.height if image.height >= 1048 else image.width)
    if image.width == 350:
        cell = 25
        return [
            [image.getpixel((col * cell + cell // 2, row * cell + cell // 2)) for col in range(14)]
            for row in range(14)
        ]
    return [
        [
            image.getpixel((int((col + 0.5) * width / 14), int((row + 0.5) * width / 14)))
            for col in range(14)
        ]
        for row in range(14)
    ]


def _marker_stream(grid: list[list[tuple[int, int, int]]]) -> tuple[str, str, bytes]:
    order = _spiral_positions(14)
    colours = [grid[row][col] for row, col in order]
    markers = [colour for colour in colours if colour in (BLUE, YELLOW)]
    if len(markers) != 24:
        raise ValueError(f"expected 24 markers, got {len(markers)}")
    bits = "".join("1" if colour == BLUE else "0" for colour in markers)
    resistor = "".join("6" if colour == BLUE else "4" for colour in markers)
    letters = "".join("B" if colour == BLUE else "Y" for colour in markers)
    packed = int(bits, 2).to_bytes(3, "big")
    if packed.hex().upper() != "F73D92":
        raise ValueError(f"marker stream drifted: {packed.hex()}")
    body_bits = "".join(
        "1" if colour in (BLACK, BLUE) else "0" for colour in colours
    )
    spiral_bytes = bytes(
        int(body_bits[offset : offset + 8], 2) for offset in range(0, 192, 8)
    )
    if spiral_bytes != URL:
        raise ValueError(f"spiral URL drifted: {spiral_bytes!r}")
    return bits, resistor, letters.encode("ascii")


def _zero_chars(text: bytes, positions_one_based: set[int], mode: str) -> bytes:
    out = bytearray()
    for index, byte in enumerate(text, 1):
        if index in positions_one_based:
            if mode == "omit":
                continue
            if mode == "ascii-zero":
                out.append(ord("0"))
            elif mode == "nul":
                out.append(0)
            else:
                raise ValueError(mode)
        else:
            out.append(byte)
    return bytes(out)


def _fill_primes(length: int, nonprime_source: bytes, prime_values: bytes, primes: set[int]) -> bytes:
    source = iter(nonprime_source)
    insert = iter(prime_values)
    out = []
    for position in range(1, length + 1):
        if position in primes:
            out.append(next(insert))
        else:
            out.append(next(source))
    return bytes(out)


def _expansions(preimage: bytes) -> list[tuple[str, bytes]]:
    digest = hashlib.sha256(preimage).digest()
    return [
        ("raw", preimage),
        ("sha256-digest", digest),
        ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
        ("sha256-upperhex", hashlib.sha256(preimage).hexdigest().upper().encode("ascii")),
        ("double-sha256-digest", hashlib.sha256(digest).digest()),
    ]


def _addresses(private_key: bytes) -> dict[str, str]:
    return {
        "uncompressed": p2pkh_address(private_key, compressed=False),
        "compressed": p2pkh_address(private_key, compressed=True),
    }


def _prize_hit(private_key: bytes) -> str | None:
    if len(private_key) != 32:
        return None
    scalar = int.from_bytes(private_key, "big") % N
    if not scalar:
        return None
    key = scalar.to_bytes(32, "big")
    for address in _addresses(key).values():
        for role, target in PRIZE.items():
            if address == target:
                return role
    return None


def build_preimages() -> dict[bytes, set[str]]:
    image = IMAGE if IMAGE.exists() else FALLBACK_IMAGE
    majority = _majority_grid(image) if image == IMAGE else _center_grid(image)
    # Prefer the small rabbit image for majority; if using puzzle.png, centre == majority for markers.
    if image != IMAGE:
        majority = _center_grid(image)
    bits, resistor, letters = _marker_stream(majority)
    resistor_bytes = resistor.encode("ascii")
    yellow_digits = "".join(ch for ch in resistor if ch == "4").encode("ascii")
    blue_digits = "".join(ch for ch in resistor if ch == "6").encode("ascii")
    primes24 = set(_primes(24))
    primes91 = set(_primes(91))
    s91 = extract_raw().s91.encode("ascii")

    preimages: dict[bytes, set[str]] = {}

    def add(label: str, value: bytes) -> None:
        if not value:
            return
        preimages.setdefault(value, set()).add(label)

    # --- resistor streams (creator: Yellow/Blue have numbers; Y=4 B=6) ---
    add("resistor/spiral-digits", resistor_bytes)
    add("resistor/yellow-then-blue", yellow_digits + blue_digits)
    add("resistor/blue-then-yellow", blue_digits + yellow_digits)
    add("resistor/packed-nibbles", bytes(int(resistor[i : i + 2], 16) for i in range(0, 24, 2)))
    add("resistor/letter-stream", letters)
    add("resistor/bits-text", bits.encode("ascii"))
    add("resistor/F73D92-hex", f"{GENESIS:06X}".encode("ascii"))
    add("resistor/F73D92-hex-lower", f"{GENESIS:06x}".encode("ascii"))
    add("resistor/half-7B9EC9", f"{HALF:06X}".encode("ascii"))
    add("resistor/better-7B9ECC", f"{BETTER:06X}".encode("ascii"))
    add("resistor/better-bits", format(BETTER, "b").encode("ascii"))

    # yellowblueprimes literal concatenations with authenticated material
    for head in (b"yellowblueprimes", b"yellowblue", b"YellowBluePrimes"):
        add(f"pipe/{head.decode('ascii', 'ignore')}", head)
        add(f"pipe/{head.decode()}+resistor", head + resistor_bytes)
        add(f"pipe/{head.decode()}+url", head + URL)
        add(f"pipe/{head.decode()}+F73D92", head + f"{GENESIS:06X}".encode("ascii"))
        add(f"pipe/{head.decode()}+7B9ECC", head + f"{BETTER:06X}".encode("ascii"))
        add(f"pipe/resistor+{head.decode()}", resistor_bytes + head)

    # --- character zeroing on the URL (creator: characters need to be zeroed out) ---
    for mode in ("omit", "ascii-zero", "nul"):
        add(f"url/zero-primes24/{mode}", _zero_chars(URL, primes24, mode))
        yellow_pos = {i + 1 for i, bit in enumerate(bits) if bit == "0"}
        blue_pos = {i + 1 for i, bit in enumerate(bits) if bit == "1"}
        add(f"url/zero-yellow-slots/{mode}", _zero_chars(URL, yellow_pos, mode))
        add(f"url/zero-blue-slots/{mode}", _zero_chars(URL, blue_pos, mode))
        # off-white sits on byte index 20 (1-based 21) — spiral bit 163 = byte 20 zero-based
        add(f"url/zero-offwhite-byte21/{mode}", _zero_chars(URL, {21}, mode))
        # majority/centre residual difference is padding only; still record the ones counts
    add("url/ones-101-text", b"101")
    add("url/ones-102-text", b"102")
    add("url/coord-7-4", b"7,4")
    add("url/coord-7-6", b"7,6")

    # zero hex digits of F73D92 / 7B9ECC at prime indices among the 6 nybbles/chars
    for label, text in (
        ("F73D92", f"{GENESIS:06X}".encode("ascii")),
        ("7B9EC9", f"{HALF:06X}".encode("ascii")),
        ("7B9ECC", f"{BETTER:06X}".encode("ascii")),
    ):
        for mode in ("omit", "ascii-zero"):
            add(f"hex/{label}/zero-primes-in-6/{mode}", _zero_chars(text, set(_primes(6)), mode))

    # --- primes + resistor reinsertion into S91 / URL ---
    # Replace S91 prime symbols with resistor digit chars (yellowblueprimes).
    add(
        "s91/replace-primes-with-resistor-digits",
        _fill_primes(91, bytes(s91[i] for i in range(91) if (i + 1) not in primes91), resistor_bytes, primes91)
        if len(bytes(s91[i] for i in range(91) if (i + 1) not in primes91)) == 67
        else b"",
    )
    nonprimes = bytes(symbol for index, symbol in enumerate(s91, 1) if index not in primes91)
    add("s91/fill-primes-resistor", _fill_primes(91, nonprimes, resistor_bytes, primes91))
    add("s91/fill-primes-url", _fill_primes(91, nonprimes, URL, primes91))
    add("s91/fill-primes-yellowblue-digits", _fill_primes(91, nonprimes, yellow_digits + blue_digits, primes91))
    # Zero (omit / ascii-zero) S91 at primes — "zeroed out" reading of prime slots.
    for mode in ("omit", "ascii-zero"):
        add(f"s91/zero-primes/{mode}", _zero_chars(s91, primes91, mode))
        # zero non-primes, keep only prime symbols (then optionally pair with colors)
        nonprime_pos = set(range(1, 92)) - primes91
        add(f"s91/zero-nonprimes/{mode}", _zero_chars(s91, nonprime_pos, mode))

    # Pair prime-selected S91 symbols with resistor digits / colours, zero one colour.
    selected = bytes(s91[p - 1] for p in sorted(primes91))
    add("s91/prime-symbols-only", selected)
    y_keep = bytes(sym for sym, digit in zip(selected, resistor) if digit == "4")
    b_keep = bytes(sym for sym, digit in zip(selected, resistor) if digit == "6")
    add("s91/prime-symbols-yellow-kept", y_keep)
    add("s91/prime-symbols-blue-kept", b_keep)
    add("s91/yellow-then-blue-kept", y_keep + b_keep)
    add("s91/blue-then-yellow-kept", b_keep + y_keep)

    # resistor digits with primes ≤24 zeroed among the 24-digit stream
    for mode in ("omit", "ascii-zero"):
        add(f"resistor/zero-primes24/{mode}", _zero_chars(resistor_bytes, primes24, mode))

    # pipeline phrase + zeroed URL variants
    zeroed_url_omit = _zero_chars(URL, primes24, "omit")
    zeroed_url_zero = _zero_chars(URL, primes24, "ascii-zero")
    add("pipe/yellowblueprimes+zeroed-url-omit", b"yellowblueprimes" + zeroed_url_omit)
    add("pipe/yellowblueprimes+zeroed-url-ascii0", b"yellowblueprimes" + zeroed_url_zero)
    add("pipe/yellowblueprimes+yb-digits", b"yellowblueprimes" + yellow_digits + blue_digits)

    # numeric concatenations of resistor total / color sums (resistor and puzzle counts)
    add("resistor/digit-sum-decimal", str(sum(int(ch) for ch in resistor)).encode("ascii"))
    add("resistor/yellow4-sum", str(4 * resistor.count("4")).encode("ascii"))
    add("resistor/blue6-sum", str(6 * resistor.count("6")).encode("ascii"))
    # Witteveen prime-color sums already authenticated: B=474 Y=400
    add("witteveen/sums-474-400", b"474400")
    add("witteveen/sums-400-474", b"400474")
    add("witteveen/WITTEVEEN", b"WITTEVEEN")
    add("witteveen/H.J.WITTEVEEN", b"H.J.WITTEVEEN")

    # majority/centre ones with F73D92 bridge
    add("bridge/F73D92//2+3", f"{BETTER:06X}".encode("ascii"))
    add("bridge/F73D92|7B9ECC", f"{GENESIS:06X}{BETTER:06X}".encode("ascii"))
    add("bridge/101|F73D92", b"101" + f"{GENESIS:06X}".encode("ascii"))
    add("bridge/102|7B9ECC", b"102" + f"{BETTER:06X}".encode("ascii"))

    # --- full-grid resistor code (creator Yellow/Blue numbers; black0 white9) ---
    resistor_map = {BLACK: 0, WHITE: 9, YELLOW: 4, BLUE: 6, OFF_WHITE: 9}
    order = _spiral_positions(14)

    def grid_digits(zero_off: bool) -> list[int]:
        values = []
        for row in range(14):
            for col in range(14):
                colour = majority[row][col]
                if zero_off and colour == OFF_WHITE:
                    values.append(0)
                else:
                    values.append(resistor_map[colour])
        return values

    for zero_off, tag in ((False, "offwhite-as-white9"), (True, "offwhite-zeroed")):
        values = grid_digits(zero_off)
        grid = [values[index : index + 14] for index in range(0, 196, 14)]
        row_sums = [sum(row) for row in grid]
        col_sums = [sum(grid[row][col] for row in range(14)) for col in range(14)]
        spiral_digits = "".join(
            str(0 if (zero_off and majority[row][col] == OFF_WHITE) else resistor_map[majority[row][col]])
            for row, col in order
        )
        add(f"grid/{tag}/total-decimal", str(sum(values)).encode("ascii"))
        add(f"grid/{tag}/rowsums-concat", "".join(map(str, row_sums)).encode("ascii"))
        add(f"grid/{tag}/colsums-concat", "".join(map(str, col_sums)).encode("ascii"))
        add(f"grid/{tag}/rowsums-csv", ",".join(map(str, row_sums)).encode("ascii"))
        add(f"grid/{tag}/matrixsumlist-literal+rowsums", b"matrixsumlist" + "".join(map(str, row_sums)).encode("ascii"))
        add(f"grid/{tag}/yellowblueprimes+rowsums", b"yellowblueprimes" + "".join(map(str, row_sums)).encode("ascii"))
        add(f"grid/{tag}/spiral-digits", spiral_digits.encode("ascii"))
        # zero out the digit character '0' from the spiral (literal zeroing)
        add(f"grid/{tag}/spiral-digits-omit-zeros", spiral_digits.replace("0", "").encode("ascii"))
        add(f"grid/{tag}/spiral-digits-ascii-zero-kept", spiral_digits.encode("ascii"))
        # first 192 spiral digits -> 24 bytes if grouped in pairs? or as decimal chunks of 8
        # pack pairs of digits as bytes when each pair < 100
        packed_pairs = bytes(int(spiral_digits[i : i + 2]) for i in range(0, 196, 2))
        add(f"grid/{tag}/spiral-digit-pairs", packed_pairs)
        # 24 marker resistor digits as big integer bytes
    marker_int = int(resistor)
    add("resistor/marker-int-32be", marker_int.to_bytes(32, "big"))
    add("resistor/marker-int-mod-n-32be", (marker_int % N).to_bytes(32, "big"))
    # half of marker int ("the price is in half")
    add("resistor/marker-int-half-32be", (marker_int // 2).to_bytes(32, "big"))
    add("resistor/F73D92-int-32be", GENESIS.to_bytes(32, "big"))
    add("resistor/7B9ECC-int-32be", BETTER.to_bytes(32, "big"))
    add("resistor/F73D92-half-plus3-32be", BETTER.to_bytes(32, "big"))

    # XOR URL bytes with repeating resistor digits / F73D92
    rep = (resistor_bytes * ((24 // len(resistor_bytes)) + 1))[:24]
    add("xor/url^resistor-digits-ascii", bytes(a ^ b for a, b in zip(URL, rep)))
    f73 = bytes.fromhex(f"{GENESIS:06X}") * 8
    add("xor/url^F73D92-repeat", bytes(a ^ b for a, b in zip(URL, f73)))
    better_rep = bytes.fromhex(f"{BETTER:06X}") * 8
    add("xor/url^7B9ECC-repeat", bytes(a ^ b for a, b in zip(URL, better_rep)))

    # TOE-style zeroing of letter O/o in creator phrases and URL
    for phrase in (
        b"yellowblueprimes",
        b"theseedisplanted",
        URL,
        b"theoryofeverything",
        b"WITTEVEEN",
        b"HILLONE",
    ):
        add(f"zero-letter-o/omit/{phrase.decode('ascii', 'ignore')}", phrase.replace(b"o", b"").replace(b"O", b""))
        add(
            f"zero-letter-o/ascii0/{phrase.decode('ascii', 'ignore')}",
            phrase.replace(b"o", b"0").replace(b"O", b"0"),
        )

    # pipeline head then matrixsumlist over resistor totals
    add("pipe/yellowblueprimes+900", b"yellowblueprimes900")
    add("pipe/yellowblueprimes+891", b"yellowblueprimes891")
    add("pipe/yellowblueprimes+matrixsumlist+900", b"yellowblueprimesmatrixsumlist900")
    add("pipe/yellowblueprimes+matrixsumlist+891", b"yellowblueprimesmatrixsumlist891")
    add("pipe/full-creator-four-concat", b"yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang")

    # --- S91 prime symbols split yellow/blue then page-decoded (a=1..i=9) ---
    def page_decode(symbols: bytes) -> bytes:
        decimal = symbols.translate(bytes.maketrans(b"abcdefghi", b"123456789"))
        hexadecimal = format(int(decimal), "x")
        if len(hexadecimal) % 2:
            hexadecimal = "0" + hexadecimal
        return bytes.fromhex(hexadecimal)

    yellow_decoded = page_decode(y_keep)
    blue_decoded = page_decode(b_keep)
    add("s91/page-decode/yellow", yellow_decoded)
    add("s91/page-decode/blue", blue_decoded)
    add("s91/page-decode/yellow-then-blue", yellow_decoded + blue_decoded)
    add("s91/page-decode/blue-then-yellow", blue_decoded + yellow_decoded)
    add("s91/page-decode/yb-hextext", (yellow_decoded + blue_decoded).hex().encode("ascii"))
    add(
        "pipe/yellowblueprimes+page-decode-yb",
        b"yellowblueprimes" + yellow_decoded + blue_decoded,
    )
    combined = yellow_decoded + blue_decoded
    add("s91/page-decode/yb-leftpad32", combined.rjust(32, b"\0"))
    add("s91/page-decode/yb-rightpad32", combined.ljust(32, b"\0"))

    # resistor digits at prime-numbered spiral cells (off-white zeroed)
    spiral_resistor = [
        0 if majority[row][col] == OFF_WHITE else resistor_map[majority[row][col]]
        for row, col in order
    ]
    for limit in (91, 192, 196):
        prime_set = set(_primes(limit))
        digits = "".join(str(spiral_resistor[p - 1]) for p in sorted(prime_set) if p <= 196)
        add(f"spiral/resistor-at-primes-{limit}", digits.encode("ascii"))
        zeroed = "".join(
            str(spiral_resistor[i]) if (i + 1) in prime_set else "0" for i in range(196)
        )
        add(f"spiral/nonprimes-zeroed-{limit}", zeroed.encode("ascii"))

    return preimages


def run() -> dict[str, object]:
    extracted = extract_all()
    tokens = derive_tokens()
    chains = reconstruct(extracted, tokens)
    chain4 = reconstruct_chain4(chains)
    global KNOWN_COSMIC_SHA, KNOWN_CHAIN4_SHA
    KNOWN_COSMIC_SHA = hashlib.sha256(chains.cosmic_decryption.plaintext).hexdigest()
    KNOWN_CHAIN4_SHA = hashlib.sha256(chain4.decryption.plaintext).hexdigest()
    known_cosmic_password = tokens.xor_password
    known_chain4_password = chain4.password
    embedded = chain4.embedded_envelope

    blobs = {
        "cosmic-duality": extracted.cosmic_envelope,
        "chain4-embedded": embedded,
        "salphaseion-short": extracted.chain1_envelope,
    }

    preimages = build_preimages()

    # Also try substituting yellowblueprimes into the 7-token XOR (creator pipeline).
    creator_tokens = (
        "yellowblueprimes",
        "matrixsumlist",
        "lastwordsbeforearchichoice",
        "yinyang",
        "matrixsumlist",
        "yourlastcommand",
        "secondanswer",
    )
    creator_xor = bytes(
        a ^ b ^ c ^ d ^ e ^ f ^ g
        for a, b, c, d, e, f, g in zip(
            *(hashlib.sha256(token.encode("utf-8")).digest() for token in creator_tokens)
        )
    )
    preimages.setdefault(creator_xor, set()).add("pipe/creator-four-plus-semantic-xor")
    # Strict four-token XOR padded by repeating / zero
    four = ("yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang")
    digests = [hashlib.sha256(token.encode("utf-8")).digest() for token in four]
    four_xor = bytes(a ^ b ^ c ^ d for a, b, c, d in zip(*digests))
    preimages.setdefault(four_xor, set()).add("pipe/creator-four-xor")
    preimages.setdefault(four_xor + bytes(32 - len(four_xor)), set()).add("pipe/creator-four-xor-pad32")
    # Concat of four sha256 digests then reduce
    concat4 = b"".join(digests)
    preimages.setdefault(concat4, set()).add("pipe/creator-four-digest-concat")
    preimages.setdefault(hashlib.sha256(concat4).digest(), set()).add("pipe/creator-four-digest-concat-sha256")

    password_hits: list[dict[str, object]] = []
    semantic_hits: list[dict[str, object]] = []
    structure_hits: list[dict[str, object]] = []
    prize_matches: list[dict[str, object]] = []
    padding_hits = 0
    aes_attempts = 0
    scalar_attempts = 0
    seen_scalars: set[int] = set()

    for preimage, labels in preimages.items():
        for expansion, password in _expansions(preimage):
            # B) scalar gate
            for scalar_bytes, scalar_label in (
                (password if len(password) == 32 else None, f"{expansion}/as-password"),
                (hashlib.sha256(password).digest(), f"sha256({expansion})"),
                (hashlib.sha256(preimage).digest(), "sha256(preimage)"),
            ):
                if scalar_bytes is None:
                    continue
                scalar = int.from_bytes(scalar_bytes, "big") % N
                if not scalar or scalar in seen_scalars:
                    continue
                seen_scalars.add(scalar)
                scalar_attempts += 1
                key = scalar.to_bytes(32, "big")
                role = _prize_hit(key)
                if role:
                    prize_matches.append({
                        "labels": sorted(labels),
                        "expansion": expansion,
                        "scalar_form": scalar_label,
                        "private_hex": key.hex(),
                        "prize_role": role,
                        "address": PRIZE[role],
                        "addresses": _addresses(key),
                    })

            # A) AES gate
            for digest in ("md5", "sha256"):
                for blob_name, envelope in blobs.items():
                    if password == known_cosmic_password and blob_name == "cosmic-duality":
                        continue
                    if password == known_chain4_password and blob_name == "chain4-embedded":
                        continue
                    aes_attempts += 1
                    try:
                        decrypted = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
                    except ValueError:
                        continue
                    padding_hits += 1
                    plaintext = decrypted.plaintext
                    readable, metrics = _readable(plaintext)
                    formats = _formats(plaintext)
                    record = {
                        "labels": sorted(labels),
                        "expansion": expansion,
                        "kdf_digest": digest,
                        "blob": blob_name,
                        "plaintext_length": len(plaintext),
                        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
                        "padding_length": decrypted.padding_length,
                        "readable": readable,
                        "metrics": metrics,
                        "formats": formats,
                    }
                    password_hits.append(record)
                    if readable or formats:
                        # Exclude republishing the known cosmic plaintext via another spelling
                        if hashlib.sha256(plaintext).hexdigest() in {KNOWN_COSMIC_SHA, KNOWN_CHAIN4_SHA}:
                            continue
                        semantic_hits.append(record)
                    # Alternate Chain4-like structure from a *different* Cosmic decrypt
                    if blob_name == "cosmic-duality" and len(plaintext) >= 158 + 16:
                        rem = plaintext[158:158 + 1168]
                        if len(rem) == 1168:
                            cand_env = bytes(value ^ MASK[i % 8] for i, value in enumerate(rem))
                            if cand_env[:8] == b"Salted__":
                                for chain_pwd_label, chain_pwd in (
                                    ("same-password", password),
                                    ("known-chain4-password", known_chain4_password),
                                ):
                                    try:
                                        inner = decrypt_salted_aes256_cbc(cand_env, chain_pwd, digest="md5")
                                    except ValueError:
                                        try:
                                            inner = decrypt_salted_aes256_cbc(cand_env, chain_pwd, digest="sha256")
                                        except ValueError:
                                            continue
                                    if inner.plaintext.startswith(b"+-") and len(inner.plaintext) == 1151:
                                        if hashlib.sha256(inner.plaintext).hexdigest() != KNOWN_CHAIN4_SHA:
                                            structure_hits.append({
                                                **record,
                                                "alternate_chain4": True,
                                                "chain_password": chain_pwd_label,
                                                "inner_sha256": hashlib.sha256(inner.plaintext).hexdigest(),
                                            })
                    if blob_name == "chain4-embedded":
                        if plaintext.startswith(b"+-") and len(plaintext) == 1151:
                            if hashlib.sha256(plaintext).hexdigest() != KNOWN_CHAIN4_SHA:
                                structure_hits.append({**record, "alternate_chain4_direct": True})

    status = "MATCH" if prize_matches or semantic_hits or structure_hits else "NO_MATCH"
    result: dict[str, object] = {
        "schema": "second-door-yellowblueprimes-audit-v1",
        "status": status,
        "source": {
            "image": str(IMAGE if IMAGE.exists() else FALLBACK_IMAGE),
            "url": URL.decode("ascii"),
            "marker_hex": f"{GENESIS:06X}",
            "half_hex": f"{HALF:06X}",
            "better_half_hex": f"{BETTER:06X}",
            "resistor": {"yellow": 4, "blue": 6},
            "known_cosmic_plaintext_sha256": KNOWN_COSMIC_SHA,
            "known_chain4_plaintext_sha256": KNOWN_CHAIN4_SHA,
        },
        "families": [
            "resistor Y=4/B=6 spiral digit streams",
            "yellowblueprimes concatenations with URL/F73D92/7B9ECC",
            "URL/S91 character zeroing at primes and color slots",
            "prime-slot resistor/URL reinsertion into S91",
            "creator four-token XOR variants",
            "Witteveen name / 474/400 sums",
            "101/102 and off-white coordinate literals",
            "full-grid resistor sums 900/891 and spiral digit readings",
            "URL XOR resistor/F73D92; letter-O zeroing; pipeline+matrixsumlist",
            "S91 yellow/blue page-decode (a=1..i=9) and prime-indexed spiral resistor digits",
            "creator-pipeline token substitutions into the 7-digest Cosmic XOR (sidecar)",
        ],
        "unique_preimages": len(preimages),
        "aes_attempts": aes_attempts,
        "strict_padding_hits": padding_hits,
        "scalar_attempts_unique": scalar_attempts,
        "password_padding_hit_count": len(password_hits),
        "semantic_or_format_hits": semantic_hits,
        "alternate_structure_hits": structure_hits,
        "prize_matches": prize_matches,
        "prize_addresses": PRIZE,
        "scope_note": (
            "Finite creator-motivated family only. Does not re-enumerate plain spiral bit "
            "orders, the published 15/9 color-count reinsertion, or unconstrained password search."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    out = run()
    summary = {
        "status": out["status"],
        "unique_preimages": out["unique_preimages"],
        "aes_attempts": out["aes_attempts"],
        "strict_padding_hits": out["strict_padding_hits"],
        "scalar_attempts_unique": out["scalar_attempts_unique"],
        "semantic_hits": len(out["semantic_or_format_hits"]),
        "structure_hits": len(out["alternate_structure_hits"]),
        "prize_matches": out["prize_matches"],
    }
    print(json.dumps(summary, indent=2))
