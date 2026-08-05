#!/usr/bin/env python3
"""Joint yin-yang rule on the first rabbit grid.

Creator-aligned materials only:
  - 86 black == 86 white/off-white
  - off-white eye at (7,4); rot180 dual is black at (6,9)
  - resistor red=2 (poster), yellow=4, blue=6
  - L/R halves are 44/42 vs 42/44; main diagonal 7+7

Gates: Half uncompressed pubkey / Better hash160;
AES on chain1, chain2, phase32 only. Cosmic excluded.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent / "gsmgio-5btc-puzzle-master"))

from solver.extract import extract_all
from solver.openssl_compat import decrypt_salted_aes256_cbc
from solver.secp256k1_verify import N, base58check, hash160, public_key

IMAGE = Path("/workspace/follow_the_white_rabbit.png")
OUT = Path("/workspace/second_door_yinyang_joint_audit.json")

CELL = 25
SIZE = 14
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (63, 72, 204)
YELLOW = (255, 242, 0)
OFF_WHITE = (254, 254, 254)

HALF_ADDR = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER_ADDR = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
HALF_H160 = bytes.fromhex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")
BETTER_H160 = bytes.fromhex("4bc468447fe1b048ad030a2f9a125478eabc4ed6")
HALF_PUB = bytes.fromhex(
    "04"
    "f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464"
    "9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559"
)

RESISTOR = {BLACK: 0, YELLOW: 4, BLUE: 6, WHITE: 9, OFF_WHITE: 9}


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


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
    return [
        [
            Counter(
                pixels[x, y]
                for y in range(row * CELL, (row + 1) * CELL)
                for x in range(col * CELL, (col + 1) * CELL)
            ).most_common(1)[0][0]
            for col in range(SIZE)
        ]
        for row in range(SIZE)
    ]


def bits_to_bytes(bits: str) -> bytes:
    bits = bits[: len(bits) // 8 * 8]
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(32 <= b < 127 or b in (9, 10, 13) for b in data) / len(data)


def bw_bit(color, color_rule: str) -> str:
    if color == BLACK:
        return "1"
    if color in (WHITE, OFF_WHITE):
        return "0"
    if color_rule == "0":
        return "0"
    if color_rule == "1":
        return "1"
    if color_rule == "blue1":
        return "1" if color == BLUE else "0"
    if color_rule == "yellow1":
        return "1" if color == YELLOW else "0"
    if color_rule == "resistor_lsb":
        return str(RESISTOR[color] & 1)
    if color_rule == "resistor_bit1":
        return str((RESISTOR[color] >> 1) & 1)
    raise ValueError(color_rule)


def invert_color(color, mode: str):
    """Yin-yang color dual."""
    if mode == "swap_bw":
        if color == BLACK:
            return WHITE
        if color == WHITE:
            return BLACK
        if color == OFF_WHITE:
            return BLACK  # eye flips to yin
        return color
    if mode == "swap_bw_keep_eye":
        if color == BLACK:
            return WHITE
        if color == WHITE:
            return BLACK
        return color  # off-white and markers stay
    if mode == "swap_all":
        if color == BLACK:
            return WHITE
        if color == WHITE:
            return BLACK
        if color == OFF_WHITE:
            return BLACK
        if color == BLUE:
            return YELLOW
        if color == YELLOW:
            return BLUE
    return color


def spiral_decode(grid, order, one_colors) -> tuple[str, bytes]:
    bits = "".join("1" if grid[r][c] in one_colors else "0" for r, c in order)
    raw = bits_to_bytes(bits[:192])
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return text, raw


def addresses_for_scalar(scalar: int) -> dict:
    key = scalar.to_bytes(32, "big")
    pub_u = public_key(key, compressed=False)
    pub_c = public_key(key, compressed=True)
    return {
        "pub_u": pub_u,
        "h160_u": hash160(pub_u),
        "h160_c": hash160(pub_c),
        "addr_u": base58check(b"\0" + hash160(pub_u)),
        "addr_c": base58check(b"\0" + hash160(pub_c)),
    }


def try_aes(envelope: bytes, password: bytes, digest: str) -> dict | None:
    try:
        result = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
    except Exception:
        return None
    pt = result.plaintext
    return {
        "digest": digest,
        "plaintext_len": len(pt),
        "printable_ratio": round(printable_ratio(pt), 4),
        "head_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in pt[:48]),
        "sha256": sha256(pt).hex(),
        "structured": printable_ratio(pt) >= 0.85 or pt.startswith((b"Salted__", b"-----")),
    }


def expand(label: str, data: bytes, bank: dict[str, bytes]) -> None:
    if not data:
        return
    bank[label] = data
    bank[f"{label}/sha256"] = sha256(data)
    bank[f"{label}/dsha256"] = sha256(sha256(data))
    hx = sha256(data).hex().encode()
    bank[f"{label}/sha256hex"] = hx
    bank[f"{label}/sha256ofhex"] = sha256(hx)
    bank[f"{label}/YBP||"] = sha256(b"yellowblueprimes" + data)
    bank[f"{label}/||YBP"] = sha256(data + b"yellowblueprimes")
    bank[f"{label}/||yinyang"] = sha256(data + b"yinyang")
    bank[f"{label}/yinyang||"] = sha256(b"yinyang" + data)
    bank[f"{label}/||red2"] = sha256(data + b"2")
    bank[f"{label}/red2||"] = sha256(b"2" + data)
    # XOR red resistor into bytes
    bank[f"{label}/xor2"] = bytes(b ^ 2 for b in data)
    bank[f"{label}/xor2/sha256"] = sha256(bytes(b ^ 2 for b in data))


def main() -> None:
    grid = read_grid(IMAGE)
    order = spiral(SIZE)
    facts = {
        "black": sum(grid[r][c] == BLACK for r in range(14) for c in range(14)),
        "white": sum(grid[r][c] == WHITE for r in range(14) for c in range(14)),
        "offwhite": (7, 4),
        "offwhite_rot180_dual": ((6, 9), "BLACK" if grid[6][9] == BLACK else str(grid[6][9])),
        "blue": 15,
        "yellow": 9,
        "resistor": {"red": 2, "yellow": 4, "blue": 6},
        "left_bw": (
            sum(grid[r][c] == BLACK for r in range(14) for c in range(7)),
            sum(grid[r][c] in (WHITE, OFF_WHITE) for r in range(14) for c in range(7)),
        ),
        "right_bw": (
            sum(grid[r][c] == BLACK for r in range(14) for c in range(7, 14)),
            sum(grid[r][c] in (WHITE, OFF_WHITE) for r in range(14) for c in range(7, 14)),
        ),
        "diag_bw": (
            sum(grid[i][i] == BLACK for i in range(14)),
            sum(grid[i][i] in (WHITE, OFF_WHITE) for i in range(14)),
        ),
    }
    assert facts["black"] == 86
    assert facts["white"] + 1 == 86  # + off-white

    bank: dict[str, bytes] = {}
    readings: dict[str, object] = {}

    # --- Family A: color-inverted spiral (yin-yang flip) ---
    for mode in ("swap_bw", "swap_bw_keep_eye", "swap_all"):
        inv = [[invert_color(grid[r][c], mode) for c in range(14)] for r in range(14)]
        for one_name, ones in (
            ("blackblue", {BLACK, BLUE}),
            ("blackyellow", {BLACK, YELLOW}),
            ("black", {BLACK}),
        ):
            text, raw = spiral_decode(inv, order, ones)
            label = f"invert/{mode}/{one_name}"
            readings[label] = {"text": text, "printable": all(32 <= b < 127 for b in raw)}
            expand(label, text.encode("latin-1"), bank)
            expand(f"{label}/raw", raw, bank)

    # door1 + yellow-flip controls (not re-tested as URLs; only as dual operands)
    door1, door1_raw = spiral_decode(grid, order, {BLACK, BLUE})
    yflip, yflip_raw = spiral_decode(grid, order, {BLACK, BLUE, YELLOW})
    readings["control/door1"] = door1
    readings["control/yflip"] = yflip

    # --- Family B: L⊕R and T⊕B half duals ---
    half_results = {}
    for rule in ("0", "1", "blue1", "yellow1", "resistor_lsb"):
        L = "".join(bw_bit(grid[r][c], rule) for r in range(14) for c in range(7))
        R = "".join(bw_bit(grid[r][c], rule) for r in range(14) for c in range(7, 14))
        T = "".join(bw_bit(grid[r][c], rule) for r in range(7) for c in range(14))
        Btm = "".join(bw_bit(grid[r][c], rule) for r in range(7, 14) for c in range(14))
        for name, bits in (
            (f"LR_xor/{rule}", "".join(str(int(a) ^ int(b)) for a, b in zip(L, R))),
            (f"TB_xor/{rule}", "".join(str(int(a) ^ int(b)) for a, b in zip(T, Btm))),
            (f"LR_concat/{rule}", L + R),
            (f"RL_concat/{rule}", R + L),
            (f"TB_concat/{rule}", T + Btm),
            (f"interleave_LR/{rule}", "".join(a + b for a, b in zip(L, R))),
            (f"interleave_TB/{rule}", "".join(a + b for a, b in zip(T, Btm))),
        ):
            raw = bits_to_bytes(bits)
            half_results[name] = {
                "len_bits": len(bits),
                "printable": round(printable_ratio(raw), 3),
                "head": "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:24]),
                "hex": raw.hex(),
            }
            expand(name, raw, bank)
            if printable_ratio(raw) >= 0.75:
                try:
                    expand(f"{name}/ascii", raw.decode("ascii").encode(), bank)
                except UnicodeDecodeError:
                    pass

    # --- Family C: diagonal 7+7 axis + below/above XOR ---
    diag = [grid[i][i] for i in range(14)]
    diag_bits = "".join(bw_bit(c, "0") for c in diag)
    expand("diag/bits", bits_to_bytes(diag_bits + "00"), bank)  # 14 bits -> pad
    expand("diag/bits14", diag_bits.encode(), bank)
    below = "".join(
        bw_bit(grid[r][c], "0") for r in range(14) for c in range(14) if r > c
    )
    above = "".join(
        bw_bit(grid[r][c], "0") for r in range(14) for c in range(14) if r < c
    )
    # unequal lengths possible — zip
    expand(
        "diag_halves_xor",
        bits_to_bytes("".join(str(int(a) ^ int(b)) for a, b in zip(below, above))),
        bank,
    )
    expand("diag_below", bits_to_bytes(below), bank)
    expand("diag_above", bits_to_bytes(above), bank)

    # --- Family D: off-white eye joint with dual + RGB resistors ---
    eye = (7, 4)
    dual = (6, 9)
    eye_materials = {
        "eye_rc": b"7,4",
        "eye_rc_compact": b"74",
        "dual_rc": b"6,9",
        "dual_rc_compact": b"69",
        "eye_spiral_idx": str(order.index(eye)).encode(),
        "eye_spiral_idx_1based": str(order.index(eye) + 1).encode(),
        "eye_rowmajor_0": str(7 * 14 + 4).encode(),
        "eye_rowmajor_1": str(7 * 14 + 4 + 1).encode(),
        "yin86yang86": b"8686",
        "86": b"86",
        "ryb_246": b"246",
        "ryb_4_6_2": b"462",
        "ryb_sum12": b"12",
        "ryb_product48": b"48",
        "ryb_hex": bytes([2, 4, 6]),
        "roses_red": b"RosesareWhitebutoftenRed",
        "yinyang": b"yinyang",
        "yingyang": b"yingyang",
        "doorhint_1421": b"1,4,21",
        "RAB_18_1_2": b"18,1,2",
        "RAB_sum21": b"21",
    }
    for k, v in eye_materials.items():
        expand(f"token/{k}", v, bank)

    # joint concatenations of the key dual facts
    joints = [
        b"8686" + b"74" + b"69",
        b"8686" + b"74" + b"246",
        b"74" + b"69" + b"246",
        b"yellowblueprimes" + b"8686",
        b"8686" + b"yinyang",
        b"yinyang" + b"8686",
        yflip.encode() + b"8686",
        door1.encode() + b"8686",
        b"8686" + yflip.encode(),
        b"8686" + door1.encode(),
        bytes([86, 86, 7, 4, 6, 9, 2, 4, 6]),
        bytes([86, 86, 2, 4, 6]),
        bytes([7, 4, 6, 9]),
        # eye bit flip on door1 raw
        door1_raw,
        bytes(door1_raw[i] ^ (0x10 if i == 20 else 0) for i in range(len(door1_raw))),  # bit3 of byte20
        yflip_raw,
        bytes(b ^ 2 for b in door1_raw),
        bytes(b ^ 2 for b in yflip_raw),
        bytes(a ^ b for a, b in zip(door1_raw, yflip_raw)),  # marker dual delta
    ]
    for i, data in enumerate(joints):
        expand(f"joint/{i}", data, bank)

    # --- Family E: yin path (black cells) vs yang path (white/off) along spiral ---
    yin_cells = [(r, c) for r, c in order if grid[r][c] == BLACK]
    yang_cells = [(r, c) for r, c in order if grid[r][c] in (WHITE, OFF_WHITE)]
    assert len(yin_cells) == len(yang_cells) == 86

    def coords_bits(cells):
        return "".join(format(r, "04b") + format(c, "04b") for r, c in cells)

    yin_bits = coords_bits(yin_cells)
    yang_bits = coords_bits(yang_cells)
    expand("path/yin_coords", bits_to_bytes(yin_bits), bank)
    expand("path/yang_coords", bits_to_bytes(yang_bits), bank)
    expand(
        "path/yin_xor_yang_coords",
        bits_to_bytes("".join(str(int(a) ^ int(b)) for a, b in zip(yin_bits, yang_bits))),
        bank,
    )
    expand(
        "path/interleave_coords",
        bits_to_bytes("".join(a + b for a, b in zip(yin_bits, yang_bits))),
        bank,
    )
    # index lists
    yin_idx = [order.index((r, c)) for r, c in yin_cells]
    yang_idx = [order.index((r, c)) for r, c in yang_cells]
    expand("path/yin_idx_bytes", bytes(yin_idx), bank)  # values <196 fit in byte
    expand("path/yang_idx_bytes", bytes(yang_idx), bank)
    expand(
        "path/yin_xor_yang_idx",
        bytes(a ^ b for a, b in zip(yin_idx, yang_idx)),
        bank,
    )
    expand(
        "path/yin_yang_idx_delta",
        bytes((a - b) % 256 for a, b in zip(yin_idx, yang_idx)),
        bank,
    )

    # marker dual: yellow vs blue as yang-eye / yin-eye
    yellow_idx = [i for i, (r, c) in enumerate(order) if grid[r][c] == YELLOW]
    blue_idx = [i for i, (r, c) in enumerate(order) if grid[r][c] == BLUE]
    expand("markers/yellow_idx", bytes(yellow_idx), bank)
    expand("markers/blue_idx", bytes(blue_idx), bank)
    expand("markers/F73D92", bytes.fromhex("F73D92"), bank)
    # yellow digits 4 and blue 6 stream
    mark_digits = "".join(
        str(RESISTOR[grid[r][c]])
        for r, c in order
        if grid[r][c] in (YELLOW, BLUE)
    )
    expand("markers/digit_stream", mark_digits.encode(), bank)
    expand("markers/digit_stream+red2", ("2" + mark_digits).encode(), bank)
    expand("markers/digit_stream+red2suf", (mark_digits + "2").encode(), bank)

    # --- Family F: sha256(yin) XOR sha256(yang) style duals ---
    yin_raw = bits_to_bytes(yin_bits)
    yang_raw = bits_to_bytes(yang_bits)
    for a_lab, a, b_lab, b in (
        ("yin", yin_raw, "yang", yang_raw),
        ("door1", door1_raw, "yflip", yflip_raw),
        ("left0", bits_to_bytes("".join(bw_bit(grid[r][c], "0") for r in range(14) for c in range(7))),
         "right0", bits_to_bytes("".join(bw_bit(grid[r][c], "0") for r in range(14) for c in range(7, 14)))),
    ):
        sa, sb = sha256(a), sha256(b)
        expand(f"dualhash/{a_lab}_xor_{b_lab}", bytes(x ^ y for x, y in zip(sa, sb)), bank)
        expand(f"dualhash/{a_lab}||{b_lab}", sa + sb, bank)
        expand(f"dualhash/{b_lab}||{a_lab}", sb + sa, bank)
        expand(f"dualhash/{a_lab}+{b_lab}", sha256(a + b), bank)

    # literal creator words with dual numbers
    for phrase in (
        b"yinyang",
        b"yingyang",
        b"ying yang",
        b"yellowblueprimes",
        b"yellowblueprimesyinyang",
        b"itsinfrontofyoureyesbutyourenotseeingit",
        b"wewontgiveawaythepassword",
    ):
        expand(f"phrase/{phrase.decode()[:40]}", phrase, bank)
        expand(f"phrase/{phrase.decode()[:20]}+8686", phrase + b"8686", bank)

    # --- Prize gate ---
    prize_matches = []
    seen: set[int] = set()
    for label, data in bank.items():
        cands = []
        if len(data) >= 32:
            cands.append(("raw32", data[:32]))
        if len(data) == 64:  # possible concat of two digests
            cands.append(("first32", data[:32]))
            cands.append(("second32", data[32:64]))
        cands.append(("sha256", sha256(data)))
        for tag, cand in cands:
            sc = int.from_bytes(cand[:32], "big")
            if not 1 <= sc < N or sc in seen:
                continue
            seen.add(sc)
            addrs = addresses_for_scalar(sc)
            hit = None
            if addrs["pub_u"] == HALF_PUB or addrs["addr_u"] == HALF_ADDR:
                hit = "Half"
            elif (
                addrs["h160_u"] == BETTER_H160
                or addrs["h160_c"] == BETTER_H160
                or addrs["addr_u"] == BETTER_ADDR
                or addrs["addr_c"] == BETTER_ADDR
            ):
                hit = "Better_Half"
            if hit:
                prize_matches.append(
                    {
                        "label": label,
                        "tag": tag,
                        "prize": hit,
                        "scalar_hex": f"{sc:064x}",
                        "addr_u": addrs["addr_u"],
                        "addr_c": addrs["addr_c"],
                    }
                )

    # --- AES gate (auth only) ---
    extracted = extract_all()
    envelopes = {
        "chain1": extracted.chain1_envelope,
        "chain2": extracted.chain2_envelope,
        "phase32": extracted.phase32_envelope,
    }
    # passwords: compact set — raw materials + select hashes, not every expansion
    pw_items: list[tuple[str, bytes]] = []
    for label, data in bank.items():
        if label.endswith("/sha256") or label.endswith("/dsha256") or label.endswith("/sha256ofhex"):
            continue
        if label.endswith("/xor2/sha256") or "/YBP" in label or "/yinyang" in label or "/red2" in label:
            # keep these — small and on-theme
            if len(data) <= 64:
                pw_items.append((label, data))
            continue
        if len(data) <= 96:
            pw_items.append((label, data))
        if label.startswith(("joint/", "token/", "phrase/", "dualhash/", "path/yin_xor", "markers/digit")):
            pw_items.append((f"{label}/sha256hex", sha256(data).hex().encode()))

    # dedupe passwords
    seen_pw: set[bytes] = set()
    uniq_pw: list[tuple[str, bytes]] = []
    for lab, pw in pw_items:
        if pw in seen_pw or not pw:
            continue
        seen_pw.add(pw)
        uniq_pw.append((lab, pw))

    aes_structured = []
    aes_padding = []
    aes_attempts = 0
    for lab, pw in uniq_pw:
        for env_name, env in envelopes.items():
            for digest in ("md5", "sha256"):
                aes_attempts += 1
                hit = try_aes(env, pw, digest)
                if hit is None:
                    continue
                rec = {"label": lab, "envelope": env_name, **hit}
                if hit["structured"]:
                    aes_structured.append(rec)
                else:
                    aes_padding.append(rec)

    # Collect high-print half readings for the report
    printable_halves = {
        k: v for k, v in half_results.items() if v["printable"] >= 0.75
    }
    printable_inverts = {
        k: v for k, v in readings.items() if isinstance(v, dict) and v.get("printable")
    }

    output = {
        "schema": "second-door-yinyang-joint-audit-v1",
        "status": "HIT" if prize_matches or aes_structured else "NO_PRIZE_MATCH",
        "facts": facts,
        "control": {"door1": door1, "yflip": yflip},
        "material_count": len(bank),
        "unique_scalars": len(seen),
        "prize_matches": prize_matches,
        "aes_attempts": aes_attempts,
        "aes_structured_hits": aes_structured,
        "aes_padding_count": len(aes_padding),
        "aes_padding_sample": aes_padding[:15],
        "printable_half_streams": printable_halves,
        "printable_invert_spirals": printable_inverts,
        "scope_excludes": ["cosmic_envelope", "base38", "chain4"],
    }
    OUT.write_text(json.dumps(output, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": output["status"],
                "facts": facts,
                "door1": door1,
                "yflip": yflip,
                "materials": len(bank),
                "unique_scalars": len(seen),
                "prize_matches": len(prize_matches),
                "aes_attempts": aes_attempts,
                "aes_structured": len(aes_structured),
                "aes_padding": len(aes_padding),
                "printable_halves": list(printable_halves),
                "printable_inverts": {k: v.get("text") if isinstance(v, dict) else v for k, v in printable_inverts.items()},
                "out": str(OUT),
            },
            indent=2,
        )
    )
    if prize_matches:
        print("PRIZE", json.dumps(prize_matches, indent=2))
    if aes_structured:
        print("AES", json.dumps(aes_structured, indent=2))


if __name__ == "__main__":
    main()
