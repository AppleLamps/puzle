"""Test direct password/key readings of the 24 colored-cell stream."""

from __future__ import annotations

import hashlib
import json

from coincurve import PrivateKey
from PIL import Image

from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .prime_reinsertion_audit import BLUE, YELLOW, TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion_preregister_v12 import _spiral_positions
from .secp256k1_verify import N, base58check, hash160


RESULT = ROOT / "color_stream_password_audit.json"


def _target(data: bytes) -> bool:
    scalar = int.from_bytes(data, "big") % N
    if not scalar:
        return False
    public = PrivateKey.from_int(scalar).public_key.format(compressed=False)
    return (public[1:33] == TARGET_X.to_bytes(32, "big") and
            public[33:] == TARGET_Y.to_bytes(32, "big") and
            base58check(b"\0" + hash160(public)) == TARGET_ADDRESS)


def run() -> dict[str, object]:
    image = Image.open(ROOT / "puzzle.png").convert("RGB")
    grid = [[image.getpixel((int((column + .5) * image.width / 14), int((row + .5) * image.width / 14)))
             for column in range(14)] for row in range(14)]
    routes = {
        "row-major": [(row, column) for row in range(14) for column in range(14)],
        "authenticated-spiral": _spiral_positions(14),
    }
    preimages: dict[bytes, set[str]] = {}

    def add(label: str, value: bytes) -> None:
        preimages.setdefault(value, set()).add(label)

    route_records = []
    for route, order in routes.items():
        colors = [grid[row][column] for row, column in order if grid[row][column] in (BLUE, YELLOW)]
        for reverse_name, sequence in (("forward", colors), ("reverse", list(reversed(colors)))):
            for blue_bit in (0, 1):
                bits = "".join(str(blue_bit if color == BLUE else 1 - blue_bit) for color in sequence)
                packed = int(bits, 2).to_bytes(3, "big")
                add(f"{route}/{reverse_name}/bits-blue{blue_bit}/packed", packed)
                add(f"{route}/{reverse_name}/bits-blue{blue_bit}/text", bits.encode("ascii"))
                add(f"{route}/{reverse_name}/bits-blue{blue_bit}/hex-text", packed.hex().encode("ascii"))
            counts = [15 if color == BLUE else 9 for color in sequence]
            nibbles = bytes.fromhex("".join(format(value, "x") for value in counts))
            add(f"{route}/{reverse_name}/count-nibbles/packed", nibbles)
            add(f"{route}/{reverse_name}/count-nibbles/hex-text", nibbles.hex().encode("ascii"))
            add(f"{route}/{reverse_name}/count-decimal", "".join(map(str, counts)).encode("ascii"))
            letters = "".join("o" if color == BLUE else "i" for color in sequence).encode("ascii")
            add(f"{route}/{reverse_name}/count-a1z26", letters)
        route_records.append({"route": route, "color_count": len(colors)})

    blobs = {
        "salphaseion-short": extract_all().chain1_envelope,
        "phase32-small": extract_all().chain2_envelope,
        "cosmic-duality": extract_all().cosmic_envelope,
    }
    padding_hits = 0
    semantic = []
    target_matches = []
    attempts = 0
    for preimage, labels in preimages.items():
        for form, password in (
            ("raw", preimage),
            ("sha256-lowerhex", hashlib.sha256(preimage).hexdigest().encode("ascii")),
            ("sha256-digest", hashlib.sha256(preimage).digest()),
        ):
            if _target(hashlib.sha256(password).digest()):
                target_matches.append({"labels": sorted(labels), "form": form})
            for blob_name, envelope in blobs.items():
                attempts += 1
                try:
                    plaintext = decrypt_salted_aes256_cbc(envelope, password).plaintext
                except ValueError:
                    continue
                padding_hits += 1
                ratio = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in plaintext) / len(plaintext)
                if ratio >= .9:
                    semantic.append({"labels": sorted(labels), "form": form, "blob": blob_name,
                                     "length": len(plaintext), "sha256": hashlib.sha256(plaintext).hexdigest(),
                                     "printable_ratio": ratio})

    result = {
        "schema": "first-grid-color-direct-password-audit-v1",
        "status": "MATCH" if semantic or target_matches else "COMPLETE_NO_ACCEPT",
        "routes": route_records,
        "representations": ["packed bits", "bit text", "hex text", "count nibbles", "decimal counts", "A1Z26 o/i"],
        "unique_preimages": len(preimages),
        "aes_attempts": attempts,
        "strict_padding_hits": padding_hits,
        "semantic_accepts": semantic,
        "target_scalar_matches": target_matches,
        "scope_note": "Direct color-stream readings only; no fitted transform or target-prefix scoring.",
    }
    RESULT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
