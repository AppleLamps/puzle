"""Recover the Phase 3.2 26-symbol alphabet without importing its README map.

The decrypted preamble identifies the Matrix/Architect context and the
separately clued Beaufort key.  A well-known Architect sentence supplies only
the opening crib through ``...PROGRAMMING OF``.  That fixes 23 of the 26 raw
symbol assignments.  The remaining three assignments have only 3! = 6
possibilities and are selected with a generic English trigram/quadgram model
built from wordfreq, before comparison with the published community mapping.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import importlib.metadata
import itertools
import json
import math
import re

from wordfreq import top_n_list

from .extract import README, ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .phase32_classical import BEAUFORT_KEY, PHASE32_PASSWORD


RESULT_PATH = ROOT / "phase32_symbol_recovery.json"
ARCHITECT_CRIB = "YOURLIFEISTHESUMOFAREMAINDEROFANUNBALANCEDEQUATIONINHERENTTOTHEPROGRAMMINGOF"
WORD_COUNT = 50_000


def _raw_symbol_record() -> bytes:
    plaintext = decrypt_salted_aes256_cbc(
        extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256"
    ).plaintext
    marker = b"One for one, four for one.\r\n\r\n"
    start = plaintext.index(marker) + len(marker)
    end = plaintext.index(b"\r\n\r\n151659", start)
    return plaintext[start:end]


def _build_model() -> tuple[dict[int, tuple[dict[str, float], float]], str]:
    words = top_n_list("en", WORD_COUNT)
    corpus_hash = hashlib.sha256("\n".join(words).encode("utf-8")).hexdigest()
    model: dict[int, tuple[dict[str, float], float]] = {}
    for width in (3, 4):
        counts: Counter[str] = Counter()
        for word in words:
            letters = "".join(character for character in word.upper() if "A" <= character <= "Z")
            counts.update(letters[index : index + width] for index in range(len(letters) - width + 1))
        total = sum(counts.values())
        logs = {gram: math.log(count / total) for gram, count in counts.items()}
        model[width] = logs, math.log(0.01 / total)
    return model, corpus_hash


def _score(text: str, model: dict[int, tuple[dict[str, float], float]]) -> float:
    score = 0.0
    for width, (logs, floor) in model.items():
        score += sum(logs.get(text[index : index + width], floor) for index in range(len(text) - width + 1))
    return score


def _decode(raw: bytes, mapping: dict[int, int]) -> str:
    key = [ord(character) - ord("a") for character in BEAUFORT_KEY]
    return "".join(
        chr(ord("A") + (key[index % len(key)] - mapping[symbol]) % 26)
        for index, symbol in enumerate(raw)
    )


def _published_mapping(raw: bytes) -> dict[int, int]:
    readme = README.read_text(encoding="utf-8-sig")
    match = re.search(
        r"- phase 3\.2\.1\s+The first blob.*?converted to letters:\s*\n\s*([a-z]+)",
        readme,
        re.DOTALL,
    )
    if match is None or len(match.group(1)) != len(raw):
        raise ValueError("published Phase 3.2 ciphertext is unavailable or has changed length")
    mapping: dict[int, int] = {}
    reverse: dict[int, int] = {}
    for symbol, character in zip(raw, match.group(1)):
        value = ord(character) - ord("a")
        if symbol in mapping and mapping[symbol] != value:
            raise ValueError("published symbol mapping is not functional")
        if value in reverse and reverse[value] != symbol:
            raise ValueError("published symbol mapping is not injective")
        mapping[symbol] = value
        reverse[value] = symbol
    return mapping


def run() -> dict[str, object]:
    raw = _raw_symbol_record()
    symbols = sorted(set(raw))
    if len(symbols) != 26:
        raise ValueError("Phase 3.2 record does not contain exactly 26 symbols")
    key = [ord(character) - ord("a") for character in BEAUFORT_KEY]

    partial: dict[int, int] = {}
    for index, plaintext_character in enumerate(ARCHITECT_CRIB):
        cipher_value = (key[index % len(key)] - (ord(plaintext_character) - ord("A"))) % 26
        symbol = raw[index]
        if symbol in partial and partial[symbol] != cipher_value:
            raise ValueError("Architect crib is inconsistent with a symbol substitution")
        partial[symbol] = cipher_value
    if len(partial) != 23:
        raise ValueError("Architect crib no longer fixes the expected 23 symbols")

    missing_symbols = sorted(set(symbols) - set(partial))
    missing_values = sorted(set(range(26)) - set(partial.values()))
    if len(missing_symbols) != 3 or len(missing_values) != 3:
        raise ValueError("unexpected residual symbol-permutation size")

    model, corpus_hash = _build_model()
    candidates: list[dict[str, object]] = []
    complete_mappings: list[dict[int, int]] = []
    for permutation in itertools.permutations(missing_values):
        mapping = dict(partial)
        mapping.update(zip(missing_symbols, permutation))
        plaintext = _decode(raw, mapping)
        complete_mappings.append(mapping)
        candidates.append(
            {
                "residual_mapping": {
                    f"{symbol:02x}": chr(ord("a") + value)
                    for symbol, value in zip(missing_symbols, permutation)
                },
                "score": _score(plaintext, model),
                "plaintext_sha256": hashlib.sha256(plaintext.encode("ascii")).hexdigest(),
                "prefix": plaintext[:180],
            }
        )
    order = sorted(range(len(candidates)), key=lambda index: float(candidates[index]["score"]), reverse=True)
    best_index, runner_index = order[:2]
    best = candidates[best_index]
    runner = candidates[runner_index]
    score_margin = float(best["score"]) - float(runner["score"])
    if score_margin <= 100:
        raise ValueError("independent language model does not select the residual mapping decisively")
    recovered = complete_mappings[best_index]
    plaintext = _decode(raw, recovered)
    if not plaintext.startswith(ARCHITECT_CRIB):
        raise ValueError("recovered plaintext lost the independent crib")

    # Only after recovery, compare against the community-published mapping.
    published = _published_mapping(raw)
    mapping_agreement = sum(recovered[symbol] == published[symbol] for symbol in symbols)

    result: dict[str, object] = {
        "status": "RECOVERED",
        "method": "76-letter external Architect crib fixes 23 symbols; generic English model ranks 3! residual assignments",
        "raw_record_length": len(raw),
        "raw_record_sha256": hashlib.sha256(raw).hexdigest(),
        "beaufort_key": BEAUFORT_KEY.upper(),
        "crib": ARCHITECT_CRIB,
        "crib_length": len(ARCHITECT_CRIB),
        "crib_fixed_symbol_count": len(partial),
        "residual_symbol_count": len(missing_symbols),
        "residual_candidate_count": len(candidates),
        "model": {
            "package": "wordfreq",
            "version": importlib.metadata.version("wordfreq"),
            "language": "en",
            "top_word_count": WORD_COUNT,
            "word_list_sha256": corpus_hash,
            "ngrams": [3, 4],
        },
        "candidates_ranked": [candidates[index] for index in order],
        "best_score_margin": score_margin,
        "recovered_mapping": {
            f"{symbol:02x}": chr(ord("a") + recovered[symbol]) for symbol in symbols
        },
        "published_mapping_agreement": mapping_agreement,
        "published_mapping_size": len(published),
        "plaintext": plaintext,
        "plaintext_sha256": hashlib.sha256(plaintext.encode("ascii")).hexdigest(),
        "contains_take_private_key_phrase": "TAKETHEPRIVATEKEY" in plaintext,
        "contains_prime_basics_phrase": "REINSERTINGTHEPRIMEBASICS" in plaintext,
        "contains_seven_passwords_phrase": "SEVENINTERTWINEDPASSWORDS" in plaintext,
        "ends_ciao_bella_o": plaintext.endswith("CIAOBELLAO"),
        "scope_note": (
            "The README ciphertext/mapping is not consulted until after the six residual candidates are ranked. "
            "The opening crib is a Matrix Architect quotation independently motivated by the authenticated preamble."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
