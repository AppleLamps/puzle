#!/usr/bin/env python3
"""Second-door audit: yellow-LSB-flip spiral + red resistor + prime zeroing.

Creator-aligned only. Does NOT touch Cosmic Duality.

Gates:
  - secp256k1 scalars → Half uncompressed pubkey / Better hash160
  - AES-256-CBC OpenSSL passwords → chain1 + chain2 + phase32 envelopes only
"""

from __future__ import annotations

import hashlib
import json
import math
import string
import sys
from collections import Counter
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent / "gsmgio-5btc-puzzle-master"))

from solver.extract import extract_all
from solver.openssl_compat import decrypt_salted_aes256_cbc
from solver.secp256k1_verify import N, base58check, hash160, public_key

IMAGE = Path("/workspace/follow_the_white_rabbit.png")
POSTER = Path("/workspace/gsmgio-5btc-puzzle-master/puzzle.png")
OUT = Path("/workspace/second_door_yellow_red_audit.json")

CELL = 25
SIZE = 14
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)
OFF_WHITE = (254, 254, 254)
RED = (237, 28, 36)

HALF_ADDR = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER_ADDR = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
HALF_H160 = bytes.fromhex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")
BETTER_H160 = bytes.fromhex("4bc468447fe1b048ad030a2f9a125478eabc4ed6")
HALF_PUB = bytes.fromhex(
    "04"
    "f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)

RESISTOR = {BLACK: 0, RED: 2, YELLOW: 4, BLUE: 6, WHITE: 9, OFF_WHITE: 9}


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def primes_upto(limit: int) -> set[int]:
    return {
        n
        for n in range(2, limit + 1)
        if all(n % d for d in range(2, math.isqrt(n) + 1))
    }


def spiral(size: int) -> list[tuple[int, int]]:
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


def read_grid(path: Path) -> list[list[tuple[int, int, int]]]:
    pixels = Image.open(path).convert("RGB").load()
    grid = []
    for row in range(SIZE):
        cells = []
        for col in range(SIZE):
            counts = Counter(
                pixels[x, y]
                for y in range(row * CELL, (row + 1) * CELL)
                for x in range(col * CELL, (col + 1) * CELL)
            )
            cells.append(counts.most_common(1)[0][0])
        grid.append(cells)
    return grid


def bits_to_bytes(bits: str) -> bytes:
    body = bits[: 8 * (len(bits) // 8)]
    return bytes(int(body[i : i + 8], 2) for i in range(0, len(body), 8))


def decode_spiral(colours: list[tuple[int, int, int]], one: set) -> tuple[str, str, bytes]:
    bits = "".join("1" if c in one else "0" for c in colours)
    raw = bits_to_bytes(bits[:192])
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return text, bits[192:], raw


def zero_prime_indices(bits: str, prime_set: set[int], one_based: bool = False) -> str:
    out = list(bits)
    for i in range(len(out)):
        idx = i + 1 if one_based else i
        if idx in prime_set:
            out[i] = "0"
    return "".join(out)


def xor_bytes(data: bytes, value: int) -> bytes:
    return bytes(b ^ value for b in data)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(32 <= b < 127 or b in (9, 10, 13) for b in data) / len(data)


def scalar_from_bytes(data: bytes) -> int | None:
    if not data:
        return None
    value = int.from_bytes(data[:32].rjust(32, b"\0") if len(data) < 32 else data[:32], "big")
    if not 1 <= value < N:
        return None
    return value


def addresses_for_scalar(scalar: int) -> dict[str, object]:
    key = scalar.to_bytes(32, "big")
    pub_u = public_key(key, compressed=False)
    pub_c = public_key(key, compressed=True)
    return {
        "uncompressed": base58check(b"\0" + hash160(pub_u)),
        "compressed": base58check(b"\0" + hash160(pub_c)),
        "pub_u": pub_u,
        "h160_u": hash160(pub_u),
        "h160_c": hash160(pub_c),
    }


def add_text_material(bank: dict[str, bytes], label: str, text: str) -> None:
    raw = text.encode("utf-8", errors="ignore")
    variants = {
        f"{label}/raw": raw,
        f"{label}/lower": text.lower().encode(),
        f"{label}/upper": text.upper().encode(),
        f"{label}/path-only": text.split("/")[-1].encode() if "/" in text else raw,
        f"{label}/with-gsmg-io": (
            text.encode() if text.startswith("gsmg") else f"gsmg.io/{text}".encode()
        ),
        f"{label}/slash-lead": ("/" + text.lstrip("/")).encode(),
    }
    # door-shaped slash fix: gsmg/io/... → gsmg.io/...
    if text.startswith("gsmg/io/"):
        variants[f"{label}/dot-fix"] = text.replace("gsmg/io/", "gsmg.io/", 1).encode()
        variants[f"{label}/dot-fix-path"] = text.split("/", 2)[-1].encode()
    for key, value in variants.items():
        bank[key] = value


def expand_preimages(bank: dict[str, bytes]) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for label, data in bank.items():
        out[label] = data
        out[f"{label}/sha256"] = sha256(data)
        out[f"{label}/dsha256"] = sha256(sha256(data))
        digest_hex = sha256(data).hex().encode()
        out[f"{label}/sha256-hex-ascii"] = digest_hex
        out[f"{label}/sha256-of-hex"] = sha256(digest_hex)
        # HASHTHETEXT style: hex digest digits drawn as decimal pairs → already ascii hex
        out[f"{label}/sha256||yellowblueprimes"] = sha256(data + b"yellowblueprimes")
        out[f"{label}/yellowblueprimes||sha256"] = sha256(b"yellowblueprimes" + data)
        out[f"{label}/sha256||yinyang"] = sha256(data + b"yinyang")
        out[f"{label}/red2-xor"] = xor_bytes(data, 2) if data else data
        out[f"{label}/red2-xor/sha256"] = sha256(xor_bytes(data, 2)) if data else sha256(data)
    return out


def try_aes(envelope: bytes, password: bytes, digest: str) -> dict | None:
    try:
        result = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
    except Exception:
        return None
    pt = result.plaintext
    return {
        "digest": digest,
        "padding_length": result.padding_length,
        "plaintext_len": len(pt),
        "printable_ratio": round(printable_ratio(pt), 4),
        "sha256": sha256(pt).hex(),
        "head_hex": pt[:32].hex(),
        "head_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in pt[:64]),
        "structured": printable_ratio(pt) >= 0.85 or pt.startswith((b"Salted__", b"-----")),
    }


def poster_red_facts() -> dict[str, object]:
    im = Image.open(POSTER).convert("RGB")
    w, h = im.size
    red_rows = []
    for y in range(h):
        # sample every pixel on a few x; red band is solid
        pix = im.getpixel((w // 2, y))
        if pix == RED:
            red_rows.append(y)
    thickness = len(red_rows)
    return {
        "rgb": list(RED),
        "resistor": 2,
        "thickness_px": thickness,
        "first_row": red_rows[0] if red_rows else None,
        "width": w,
        "bunny_edge": 3 * 349,  # 3x of 350-1? actual crop 1047
        "hex": "ED1C24",
    }


def main() -> None:
    grid = read_grid(IMAGE)
    order = spiral(SIZE)
    colours = [grid[r][c] for r, c in order]
    prime_set = primes_upto(196)
    red_facts = poster_red_facts()

    readings: dict[str, dict] = {}

    def record(name: str, one: set, post_bits=None) -> None:
        text, pad, raw = decode_spiral(colours, one)
        bits = "".join("1" if c in one else "0" for c in colours)
        if post_bits is not None:
            bits = post_bits(bits)
            raw = bits_to_bytes(bits[:192])
            try:
                text = raw.decode("ascii")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
            pad = bits[192:]
        readings[name] = {
            "text": text,
            "padding": pad,
            "raw_hex": raw.hex(),
            "printable": all(32 <= b < 127 for b in raw),
        }

    # Door 1 control
    record("door1_blackblue1", {BLACK, BLUE})
    # Yellow forced to 1 (creator yellow number + LSB flip)
    record("yellow_forced_1", {BLACK, BLUE, YELLOW})
    # Off-white as 1
    record("offwhite_as_1", {BLACK, BLUE, OFF_WHITE})
    # Blue only as 1 (yellow+black as 0) — extreme
    record("blue_only_1", {BLUE})
    # Black only
    record("black_only_1", {BLACK})
    # Yellow+black as 1, blue as 0 (invert color roles on markers)
    record("yellow_black_1_blue0", {BLACK, YELLOW})

    # Prime-index zeroing on door1 and yellow-flip (0- and 1-based)
    for base_name, one in (
        ("door1", {BLACK, BLUE}),
        ("yellow1", {BLACK, BLUE, YELLOW}),
    ):
        for one_based in (False, True):
            label = f"{base_name}_primezero_{'1based' if one_based else '0based'}"

            def make_post(ob=one_based):
                return lambda bits: zero_prime_indices(bits, prime_set, one_based=ob)

            record(label, one, post_bits=make_post())

    # Resistor digit stream along spiral (includes red only if present in grid — it isn't)
    digits = [RESISTOR.get(c, -1) for c in colours]
    readings["resistor_digit_stream"] = {
        "text": "".join(str(d) for d in digits),
        "padding": "",
        "raw_hex": "",
        "printable": True,
        "note": "grid has no red cells; red lives on poster divider only",
    }

    # Build material bank from readings + red facts
    bank: dict[str, bytes] = {}
    for name, info in readings.items():
        text = info["text"]
        add_text_material(bank, name, text)
        if info["raw_hex"]:
            bank[f"{name}/raw-bytes"] = bytes.fromhex(info["raw_hex"])
            # XOR red resistor into spiral bytes
            bank[f"{name}/xor-red2"] = xor_bytes(bytes.fromhex(info["raw_hex"]), 2)
            bank[f"{name}/xor-red2-ascii"] = xor_bytes(bytes.fromhex(info["raw_hex"]), 2)

    # Explicit yellow-flip focus strings
    yflip = readings["yellow_forced_1"]["text"]
    add_text_material(bank, "yflip", yflip)
    add_text_material(bank, "yflip_dot", yflip.replace("gsmg/io/", "gsmg.io/", 1))

    # Red divider material joined with yellow-flip / door1
    red_tokens = [
        "2",
        "red",
        "ED1C24",
        "ed1c24",
        str(red_facts["thickness_px"]),
        "rosesarewhitebutoftenred",
        "RosesareWhitebutoftenRed",
    ]
    for token in red_tokens:
        bank[f"red/{token}"] = token.encode()
        for base_label, base in (
            ("yflip", yflip.encode()),
            ("yflip_dot", yflip.replace("gsmg/io/", "gsmg.io/", 1).encode()),
            ("door1", b"gsmg.io/theseedisplanted"),
            ("door1_path", b"theseedisplanted"),
            ("yflip_path", yflip.split("/")[-1].encode()),
        ):
            bank[f"{base_label}+red/{token}"] = base + token.encode()
            bank[f"red/{token}+{base_label}"] = token.encode() + base
            bank[f"{base_label}|red/{token}"] = base + b"|" + token.encode()

    # April 2021 door hint coordinates
    for coords in ("1,4,21", "1 4 21", "1421", "{1},{4},{21}"):
        bank[f"doorhint/{coords}"] = coords.encode()
        bank[f"yflip+doorhint/{coords}"] = yflip.encode() + coords.encode()

    # Pipeline head with yellow-flip
    for phrase in (
        "yellowblueprimes",
        "yellowblueprimes" + yflip,
        yflip + "yellowblueprimes",
        "yellowblueprimes" + yflip.replace("gsmg/io/", "gsmg.io/", 1),
    ):
        bank[f"pipeline/{phrase[:40]}"] = phrase.encode()

    expanded = expand_preimages(bank)

    # Prize gate
    prize_matches = []
    scalar_attempts = 0
    seen_scalars: set[int] = set()
    for label, data in expanded.items():
        for candidate in (data, data[:32], sha256(data)):
            scalar = scalar_from_bytes(candidate if len(candidate) >= 32 else sha256(candidate))
            # Prefer direct 32-byte interpret when len>=32
            if len(candidate) >= 32:
                scalar = int.from_bytes(candidate[:32], "big")
                if not 1 <= scalar < N:
                    continue
            else:
                digest = sha256(candidate)
                scalar = int.from_bytes(digest, "big")
                if not 1 <= scalar < N:
                    continue
            if scalar in seen_scalars:
                continue
            seen_scalars.add(scalar)
            scalar_attempts += 1
            addrs = addresses_for_scalar(scalar)
            hit = None
            if addrs["pub_u"] == HALF_PUB or addrs["uncompressed"] == HALF_ADDR:
                hit = "Half"
            elif addrs["h160_u"] == BETTER_H160 or addrs["h160_c"] == BETTER_H160:
                hit = "Better_Half"
            elif addrs["compressed"] == BETTER_ADDR or addrs["uncompressed"] == BETTER_ADDR:
                hit = "Better_Half"
            if hit:
                prize_matches.append(
                    {
                        "label": label,
                        "prize": hit,
                        "scalar_hex": f"{scalar:064x}",
                        "address_uncompressed": addrs["uncompressed"],
                        "address_compressed": addrs["compressed"],
                    }
                )

    # AES gate — authenticated envelopes only (no Cosmic)
    extracted = extract_all()
    envelopes = {
        "chain1": extracted.chain1_envelope,
        "chain2": extracted.chain2_envelope,
        "phase32": extracted.phase32_envelope,
    }
    aes_hits = []
    aes_attempts = 0
    # Passwords: original bank texts + a few sha256 hex digests (not every expanded label)
    password_labels = [k for k in bank if not k.endswith("/raw-bytes")]
    for label in password_labels:
        password = bank[label]
        if not password or len(password) > 200:
            continue
        for env_name, envelope in envelopes.items():
            for digest in ("md5", "sha256"):
                aes_attempts += 1
                hit = try_aes(envelope, password, digest)
                if hit is None:
                    continue
                # Record structured hits always; padding-only only for yellow-flip family
                if hit["structured"] or label.startswith(("yflip", "yellow_forced", "red/", "door1")):
                    aes_hits.append({"label": label, "envelope": env_name, **hit})

    # Also try sha256(hex) of yellow-flip as password (HASHTHETEXT echo)
    for label in (
        "yflip",
        "yflip_dot",
        "yflip/dot-fix",
        "yellow_forced_1",
        "yellow_forced_1/dot-fix",
    ):
        if label not in bank and label not in expanded:
            continue
        data = bank.get(label) or expanded.get(label)
        if not data:
            continue
        for pw_label, pw in (
            (f"{label}/sha256-hex", sha256(data).hex().encode()),
            (f"{label}/sha256-bytes", sha256(data)),
        ):
            for env_name, envelope in envelopes.items():
                for digest in ("md5", "sha256"):
                    aes_attempts += 1
                    hit = try_aes(envelope, pw, digest)
                    if hit is not None:
                        aes_hits.append({"label": pw_label, "envelope": env_name, **hit})

    structured_aes = [h for h in aes_hits if h.get("structured")]
    # Filter known chain1 password false-interest: we only care about NEW structured
    known_chain1_pw = (
        b"matrixsumlistenterlastwordsbeforearchichoicethispasswordmatrixsumlist"
    )

    output = {
        "schema": "second-door-yellow-red-audit-v1",
        "status": "HIT" if prize_matches or structured_aes else "NO_PRIZE_MATCH",
        "scope": {
            "image": str(IMAGE),
            "poster_red": red_facts,
            "envelopes": list(envelopes),
            "excludes": ["cosmic_envelope", "base38", "chain4"],
        },
        "control_door1": readings["door1_blackblue1"]["text"],
        "yellow_lsb_flip": readings["yellow_forced_1"]["text"],
        "readings": {
            k: {kk: vv for kk, vv in v.items() if kk != "raw_hex" or v.get("printable")}
            for k, v in readings.items()
        },
        "material_count": len(bank),
        "expanded_count": len(expanded),
        "scalar_attempts_unique": scalar_attempts,
        "prize_matches": prize_matches,
        "aes_attempts": aes_attempts,
        "aes_padding_hits_recorded": len(aes_hits),
        "aes_structured_hits": structured_aes,
        "aes_note": "Padding hits are common under MD5-EVP; structured=high printable or Salted__/PEM head",
        "known_chain1_password_sha256": sha256(known_chain1_pw).hex(),
    }
    OUT.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({
        "status": output["status"],
        "yellow_lsb_flip": output["yellow_lsb_flip"],
        "control_door1": output["control_door1"],
        "scalar_attempts_unique": scalar_attempts,
        "prize_matches": len(prize_matches),
        "aes_attempts": aes_attempts,
        "aes_structured_hits": len(structured_aes),
        "aes_padding_hits_recorded": len(aes_hits),
        "out": str(OUT),
    }, indent=2))
    if prize_matches:
        print("PRIZE MATCHES:", json.dumps(prize_matches, indent=2))
    if structured_aes:
        print("STRUCTURED AES:", json.dumps(structured_aes[:20], indent=2))


if __name__ == "__main__":
    main()
