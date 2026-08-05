"""Test the authenticated nine-symbol fields as a globally consistent T9 code."""

from __future__ import annotations

import heapq
import itertools
import json
import re

from wordfreq import top_n_list, zipf_frequency

from .extract import ROOT
from .salphaseion_raw import extract_raw, sha256_hex


RESULT_PATH = ROOT / "sfield_t9_audit.json"
KEYS = "23456789"
GROUPS = {
    "2": "abc", "3": "def", "4": "ghi", "5": "jkl",
    "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz",
}


def _t9(word: str) -> str:
    reverse = {letter: key for key, letters in GROUPS.items() for letter in letters}
    return "".join(reverse[letter] for letter in word)


def _lexicon(limit: int = 500_000) -> dict[str, tuple[str, float]]:
    best: dict[str, tuple[str, float]] = {}
    for word in top_n_list("en", limit):
        lowered = word.lower()
        if not re.fullmatch(r"[a-z]+", lowered):
            continue
        code = _t9(lowered)
        score = zipf_frequency(lowered, "en")
        if code not in best or score > best[code][1]:
            best[code] = (lowered, score)
    return best


def run() -> dict[str, object]:
    raw = extract_raw()
    lexicon = _lexicon()
    symbols = "abcdefghi"
    top: list[tuple[tuple[int, int, float], dict[str, object]]] = []

    for separator in symbols:
        encrypted_words = [part for part in raw.s570.split(separator) if part]
        cipher_symbols = "".join(symbol for symbol in symbols if symbol != separator)
        for digit_order in itertools.permutations(KEYS):
            mapping = dict(zip(cipher_symbols, digit_order))
            decoded: list[str] = []
            covered_characters = 0
            covered_words = 0
            language_score = 0.0
            for encrypted in encrypted_words:
                code = "".join(mapping[symbol] for symbol in encrypted)
                match = lexicon.get(code)
                if match is None:
                    decoded.append("?")
                    continue
                word, score = match
                decoded.append(word)
                covered_characters += len(encrypted)
                covered_words += 1
                language_score += score * len(encrypted)

            rank = (covered_characters, covered_words, language_score)
            record = {
                "separator": separator,
                "mapping": mapping,
                "encrypted_word_count": len(encrypted_words),
                "covered_characters": covered_characters,
                "covered_words": covered_words,
                "language_score": language_score,
                "decoded": " ".join(decoded),
            }
            item = (rank, json.dumps(mapping, sort_keys=True), record)
            if len(top) < 20:
                heapq.heappush(top, item)
            elif item[:2] > top[0][:2]:
                heapq.heapreplace(top, item)

    ranked = [item[2] for item in sorted(top, reverse=True)]
    result: dict[str, object] = {
        "status": "T9_WORD_LAYER" if ranked[0]["covered_characters"] >= 400 else "NO_CONVINCING_T9_LAYER",
        "source": {
            "s91_length": len(raw.s91),
            "s91_sha256": sha256_hex(raw.s91.encode("ascii")),
            "s570_length": len(raw.s570),
            "s570_sha256": sha256_hex(raw.s570.encode("ascii")),
            "alphabet": symbols,
        },
        "model": {
            "separator": "each of nine symbols exhaustively",
            "key_assignment": "all 8! bijections to standard T9 keys 2 through 9",
            "lexicon": "wordfreq English top 500000; exact full-word T9-code matches only",
            "ranking": "covered characters, then covered words, then length-weighted Zipf score",
            "assignments_tested": 9 * 40320,
        },
        "top": ranked,
        "acceptance_note": (
            "A genuine word-separated T9 layer should cover most of the 570-symbol field "
            "under one mapping. Isolated dictionary matches are expected by chance."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
