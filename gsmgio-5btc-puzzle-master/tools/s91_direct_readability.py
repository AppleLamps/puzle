from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
from pathlib import Path

from wordfreq import zipf_frequency

from solver.extract import ROOT
from solver.salphaseion_preregister_v12 import _color_letters
from solver.salphaseion_raw import extract_raw, sha256_hex


OUT = ROOT / "artifacts" / "s91_direct_readability"
PREREG = OUT / "preregistered.json"
SEAL = OUT / "preregistered.sha256"
RESULT = OUT / "result.json"


def primes(limit: int) -> list[int]:
    return [n for n in range(2, limit + 1) if all(n % d for d in range(2, math.isqrt(n) + 1))]


def page_decode(symbols: str) -> bytes:
    decimal = symbols.translate(str.maketrans("abcdefghi", "123456789"))
    hexadecimal = format(int(decimal), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def pipeline(s91: str, positions: list[int], colors: str) -> dict[str, object]:
    selected = "".join(s91[position - 1] for position in positions)
    if len(selected) != len(colors) != 24:
        raise ValueError("cardinality changed")
    # _color_letters encodes yellow as i and blue as o. Selection is the
    # literal zeroing operation: symbols assigned the other color are omitted.
    yellow = "".join(symbol for symbol, color in zip(selected, colors) if color == "i")
    blue = "".join(symbol for symbol, color in zip(selected, colors) if color == "o")
    if (len(yellow), len(blue)) != (9, 15):
        raise ValueError("authenticated yellow/blue split changed")
    yellow_bytes = page_decode(yellow)
    blue_bytes = page_decode(blue)
    # The master hint itself fixes the concatenation order: yellow, then blue.
    combined = yellow_bytes + blue_bytes
    return {
        "positions": positions,
        "selected_symbols": selected,
        "yellow_symbols": yellow,
        "blue_symbols": blue,
        "yellow_bytes_hex": yellow_bytes.hex(),
        "blue_bytes_hex": blue_bytes.hex(),
        "combined_hex": combined.hex(),
        "combined": combined,
    }


def dictionary_coverage(data: bytes) -> dict[str, object]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return {"score": 0.0, "text": None, "segmentation": [], "fully_printable": False}
    fully_printable = all(character in "\t\n\r" or 32 <= ord(character) <= 126 for character in text)
    if not fully_printable or not re.fullmatch(r"[A-Za-z ]*", text):
        return {"score": 0.0, "text": text, "segmentation": [], "fully_printable": fully_printable}
    compact = text.lower().replace(" ", "")
    if not compact:
        return {"score": 0.0, "text": text, "segmentation": [], "fully_printable": True}
    n = len(compact)
    best: list[tuple[int, list[str]]] = [(-1, []) for _ in range(n + 1)]
    best[0] = (0, [])
    for start in range(n):
        covered, words = best[start]
        if covered < 0:
            continue
        # An uncovered character remains reachable but contributes no coverage.
        if best[start + 1][0] < covered:
            best[start + 1] = (covered, words)
        for stop in range(start + 2, min(n, start + 20) + 1):
            word = compact[start:stop]
            if zipf_frequency(word, "en") >= 3.0:
                candidate = covered + len(word)
                if candidate > best[stop][0]:
                    best[stop] = (candidate, words + [word])
    covered, words = best[n]
    return {
        "score": covered / n,
        "text": text,
        "segmentation": words,
        "fully_printable": True,
    }


def prepare() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    raw = extract_raw()
    colors, image_sha256 = _color_letters()
    spiral = colors["counterclockwise-spiral"]
    manifest = {
        "schema": "s91-direct-readability-v1",
        "status": "SEALED_BEFORE_EVALUATION",
        "one_sentence_gate": "This can solve the puzzle only if yellowblueprimes plus zeroed out pairs the 24 one-based prime positions of S91 with the 24 colored cells in the authenticated door-one spiral order and decodes directly through the page mapping.",
        "sources": {
            "s91_sha256": sha256_hex(raw.s91.encode("ascii")),
            "s91_length": len(raw.s91),
            "puzzle_image_sha256": image_sha256,
            "prime_positions_one_based": primes(91),
            "spiral_color_mask_yellow_i_blue_o": spiral,
            "yellow_count": spiral.count("i"),
            "blue_count": spiral.count("o"),
        },
        "pipeline": [
            "select S91 at the 24 one-based prime positions <=91, ascending",
            "pair selected symbols with colored cells encountered by the published upper-left down-first counterclockwise spiral",
            "zero/omit blue to form yellow stream and zero/omit yellow to form blue stream",
            "decode each stream separately by a=1..i=9 decimal integer -> lowercase base16 -> bytes",
            "concatenate decoded yellow bytes then decoded blue bytes, following literal yellowblue order",
        ],
        "null": {
            "draws": 10000,
            "seed_hex": hashlib.sha256(b"GSMG S91 direct-readability null v1").hexdigest(),
            "method": "uniform random 24-subsets of positions 1..91, sorted, through the identical pipeline and score",
        },
        "score": "strict ASCII letters/spaces only; dynamic-programming maximum character coverage by wordfreq 3.1.1 English words length 2..20 with Zipf >=3.0; any other byte gives score 0",
        "acceptance": {
            "readable_english_required": True,
            "minimum_dictionary_coverage": 0.75,
            "null_equal_or_better_count_required": 0,
            "forbidden": ["AES", "padding", "scalars", "target address", "variant orderings", "exceptions"],
        },
    }
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    PREREG.write_bytes(encoded)
    SEAL.write_text(hashlib.sha256(encoded).hexdigest() + "\n", encoding="ascii")
    print(json.dumps({"seal_sha256": hashlib.sha256(encoded).hexdigest(), "null_draws": 10000}))


def run() -> None:
    manifest = json.loads(PREREG.read_text(encoding="utf-8"))
    raw = extract_raw()
    colors, _ = _color_letters()
    observed = pipeline(raw.s91, manifest["sources"]["prime_positions_one_based"], colors["counterclockwise-spiral"])
    observed_score = dictionary_coverage(observed.pop("combined"))
    seed = int(manifest["null"]["seed_hex"], 16)
    rng = random.Random(seed)
    scores = []
    best = []
    for draw in range(manifest["null"]["draws"]):
        positions = sorted(rng.sample(range(1, 92), 24))
        record = pipeline(raw.s91, positions, colors["counterclockwise-spiral"])
        score = dictionary_coverage(record.pop("combined"))
        scores.append(score["score"])
        if score["score"] > 0:
            best.append({"draw": draw, "positions": positions, "combined_hex": record["combined_hex"], **score})
    best.sort(key=lambda row: row["score"], reverse=True)
    equal_or_better = sum(score >= observed_score["score"] for score in scores)
    success = (
        observed_score["fully_printable"]
        and observed_score["score"] >= manifest["acceptance"]["minimum_dictionary_coverage"]
        and equal_or_better == 0
    )
    result = {
        "preregistered_sha256": hashlib.sha256(PREREG.read_bytes()).hexdigest(),
        "observed": {**observed, "readability": observed_score},
        "null": {
            "draws": len(scores),
            "nonzero_score_count": sum(score > 0 for score in scores),
            "maximum_score": max(scores),
            "equal_or_better_than_observed": equal_or_better,
            "top_records": best[:20],
        },
        "accepted": success,
        "interpretation": "READABLE_ENGLISH" if success else "NO_READABLE_ENGLISH",
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["prepare", "run"])
    args = parser.parse_args()
    prepare() if args.mode == "prepare" else run()
