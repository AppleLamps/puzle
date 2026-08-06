"""Audit the direct 479 yin-yang route and its Architect continuation.

This keeps the new observation separate from the unauthenticated Cosmic branch:

* assign the 24 original spiral marker colours to consecutive primes 2..89;
* verify blue=484 and yellow=479, then zero blue prime 5 to balance 479=479;
* use 479 as a zero-based index into the authenticated Architect plaintext;
* enumerate only literal text/heart/140/source-code/prime/23-16-7 derivations;
* exact-gate every resulting scalar against Half and Better Half.

The audit emits hashes and near-match diagnostics, but emits private material only
if it exactly matches a prize target.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import hmac
import json
import re
from pathlib import Path

from coincurve import PrivateKey

from .extract import ROOT
from .secp256k1_verify import BASE58, N, hash160, wif
from .targets import (
    BETTER_ADDRESS,
    BETTER_H160,
    HALF_ADDRESS,
    HALF_H160,
    HALF_PUBLIC_UNCOMPRESSED,
)


RESULT_PATH = ROOT / "yinyang_479_continuation_audit.json"
PHASE32_PATH = ROOT / "phase32_symbol_recovery.json"

MARKERS = "BBBBYBBBYYBBBBYBBYYBYYBY"
WISE_QUOTE = (
    "The future is fluid. Each act, each decision, and each development creates "
    "new possibilities and eliminates others. The future is ours to direct."
)
LAST_WORDS_BEFORE_ARCHITECT = "One for one, four for one."
PHASE32_AES_KEY = bytes.fromhex(
    "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
)

HALF_PUBLIC = HALF_PUBLIC_UNCOMPRESSED
def primes_through(limit: int) -> list[int]:
    return [
        value
        for value in range(2, limit + 1)
        if all(value % divisor for divisor in range(2, int(value**0.5) + 1))
    ]


def words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z]+", text)


def normalizations(text: str) -> dict[str, bytes]:
    logical = " ".join(text.split())
    letters = "".join(words(logical))
    no_punctuation = " ".join(words(logical))
    return {
        "literal": logical.encode("ascii"),
        "lower": logical.lower().encode("ascii"),
        "upper": logical.upper().encode("ascii"),
        "words-spaced": no_punctuation.encode("ascii"),
        "words-spaced-lower": no_punctuation.lower().encode("ascii"),
        "letters": letters.encode("ascii"),
        "letters-lower": letters.lower().encode("ascii"),
        "letters-upper": letters.upper().encode("ascii"),
    }


def intertwine(parts: list[str]) -> str:
    """Read ragged words by columns, preserving source order."""
    return "".join(
        part[column]
        for column in range(max(map(len, parts), default=0))
        for part in parts
        if column < len(part)
    )


def classical_shift(text: str, key: str, mode: str) -> str:
    clean_text = "".join(char for char in text.upper() if char.isalpha())
    clean_key = "".join(char for char in key.upper() if char.isalpha())
    if not clean_text or not clean_key:
        return ""
    output = []
    for index, char in enumerate(clean_text):
        value = ord(char) - ord("A")
        key_value = ord(clean_key[index % len(clean_key)]) - ord("A")
        if mode == "vigenere-encrypt":
            result = value + key_value
        elif mode == "vigenere-decrypt":
            result = value - key_value
        elif mode == "beaufort":
            result = key_value - value
        else:
            raise ValueError(f"unsupported classical mode {mode}")
        output.append(chr(ord("A") + result % 26))
    return "".join(output)


def lcp(left: bytes, right: bytes) -> int:
    count = 0
    for a, b in zip(left.hex(), right.hex()):
        if a != b:
            break
        count += 1
    return count


def b58decode_check(value: str) -> bytes | None:
    if not value or any(char not in BASE58 for char in value):
        return None
    number = 0
    for char in value:
        number = number * 58 + BASE58.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    body = b"\0" * (len(value) - len(value.lstrip("1"))) + body
    if len(body) < 5:
        return None
    payload, checksum = body[:-4], body[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return payload if checksum == expected else None


class Audit:
    def __init__(self) -> None:
        self.materials: dict[str, bytes] = {}
        self.material_families: Counter[str] = Counter()
        self.scalar_labels: dict[bytes, list[str]] = defaultdict(list)
        self.scalar_families: Counter[str] = Counter()
        self.matches: list[dict[str, object]] = []
        self.near: list[dict[str, object]] = []
        self.wif_inputs: list[dict[str, object]] = []

    def add(self, family: str, label: str, value: bytes | str) -> None:
        data = value.encode("ascii") if isinstance(value, str) else value
        if not data:
            return
        full_label = f"{family}/{label}"
        if full_label not in self.materials:
            self.materials[full_label] = data
            self.material_families[family] += 1

    def expand_scalars(self) -> None:
        numeric_tweaks = (5, 23, 32, 140, 479, 484)
        for label, material in sorted(self.materials.items()):
            family = label.split("/", 1)[0]
            candidates: dict[str, bytes] = {
                "sha256": hashlib.sha256(material).digest(),
                "double-sha256": hashlib.sha256(hashlib.sha256(material).digest()).digest(),
            }
            if len(material) == 32:
                candidates["raw-32"] = material
            if len(material) >= 32:
                candidates["first-32"] = material[:32]
                candidates["last-32"] = material[-32:]
                offset = (len(material) - 32) // 2
                candidates[f"heart-32@{offset}"] = material[offset : offset + 32]
                if (len(material) - 32) % 2:
                    candidates[f"heart-32@{offset + 1}"] = material[offset + 1 : offset + 33]
            try:
                rendered = material.decode("ascii")
            except UnicodeDecodeError:
                rendered = ""
            if re.fullmatch(r"[0-9a-fA-F]{64}", rendered):
                candidates["hex-32"] = bytes.fromhex(rendered)
            if rendered.isdecimal():
                value = int(rendered)
                if value:
                    candidates["decimal-mod-n"] = (value % N).to_bytes(32, "big")
            payload = b58decode_check(rendered)
            if payload is not None and payload[:1] == b"\x80" and len(payload) in (33, 34):
                compressed = len(payload) == 34 and payload[-1:] == b"\x01"
                key = payload[1:-1] if compressed else payload[1:]
                if len(key) == 32:
                    candidates[f"parsed-wif-{'compressed' if compressed else 'uncompressed'}"] = key
                    self.wif_inputs.append({"label": label, "wif": rendered, "compressed": compressed})

            digest_int = int.from_bytes(hashlib.sha256(material).digest(), "big")
            for tweak in numeric_tweaks:
                for operation, scalar in (
                    ("add", (digest_int + tweak) % N),
                    ("sub", (digest_int - tweak) % N),
                    ("xor", digest_int ^ tweak),
                ):
                    if 1 <= scalar < N:
                        candidates[f"sha256-{operation}-{tweak}"] = scalar.to_bytes(32, "big")

            # "code you carry": the exact SHA-256 password that decrypted phase 3.2.
            digest = hashlib.sha256(material).digest()
            candidates["sha256-xor-carried-code"] = bytes(a ^ b for a, b in zip(digest, PHASE32_AES_KEY))
            candidates["hmac-carried-code"] = hmac.new(PHASE32_AES_KEY, material, hashlib.sha256).digest()
            candidates["hmac-material-key"] = hmac.new(material, PHASE32_AES_KEY, hashlib.sha256).digest()

            for derivation, scalar in candidates.items():
                value = int.from_bytes(scalar, "big")
                if not 1 <= value < N:
                    continue
                scalar_label = f"{label}/{derivation}"
                if scalar_label not in self.scalar_labels[scalar]:
                    self.scalar_labels[scalar].append(scalar_label)
                    self.scalar_families[family] += 1

    def gate(self) -> None:
        for scalar, labels in self.scalar_labels.items():
            point = PrivateKey(scalar).public_key
            pub_u = point.format(compressed=False)
            pub_c = point.format(compressed=True)
            hu = hash160(pub_u)
            hc = hash160(pub_c)
            prize = None
            serialization = None
            if pub_u == HALF_PUBLIC or hu == HALF_H160:
                prize, serialization = "Half", "uncompressed"
            elif hc == HALF_H160:
                prize, serialization = "Half", "compressed"
            elif hu == BETTER_H160:
                prize, serialization = "Better_Half", "uncompressed"
            elif hc == BETTER_H160:
                prize, serialization = "Better_Half", "compressed"
            if prize is not None:
                self.matches.append(
                    {
                        "prize": prize,
                        "serialization": serialization,
                        "labels": labels,
                        "private_key_hex": scalar.hex(),
                        "wif": wif(scalar, compressed=serialization == "compressed"),
                    }
                )

            best = max(
                (
                    (lcp(pub_u, HALF_PUBLIC), "Half-public-uncompressed"),
                    (lcp(hu, HALF_H160), "Half-hash160-uncompressed"),
                    (lcp(hc, HALF_H160), "Half-hash160-compressed"),
                    (lcp(hu, BETTER_H160), "Better-hash160-uncompressed"),
                    (lcp(hc, BETTER_H160), "Better-hash160-compressed"),
                )
            )
            self.near.append(
                {
                    "prefix_nibbles": best[0],
                    "target": best[1],
                    "candidate_sha256": hashlib.sha256(scalar).hexdigest(),
                    "label": labels[0],
                }
            )
        self.near.sort(key=lambda record: (record["prefix_nibbles"], record["label"]), reverse=True)


def add_anchor_text_materials(audit: Audit, plaintext: str, anchors: dict[str, int]) -> None:
    domains = {
        "plaintext": plaintext,
        "continuation-479": plaintext[479:],
        "private-key-tail": plaintext[anchors["PRIVATEKEY"] + len("PRIVATEKEY") :],
    }
    relative_offsets = sorted({0, 5, 7, 16, 23, 32, 64, 140, 479, 484})
    for domain_name, text in domains.items():
        encoded = text.encode("ascii")
        audit.add("indexed-text", f"{domain_name}/full", encoded)
        for offset in relative_offsets:
            if offset < len(encoded):
                audit.add("indexed-text", f"{domain_name}/offset-{offset}", encoded[offset:])
                audit.add("indexed-text", f"{domain_name}/raw32-{offset}", encoded[offset : offset + 32])
                audit.add("indexed-text", f"{domain_name}/window140-{offset}", encoded[offset : offset + 140])
        for length in (140, 479, 484):
            if len(encoded) >= length:
                block = encoded[:length]
                audit.add("heart-center", f"{domain_name}/first-{length}", block)
                offset = (length - 32) // 2
                audit.add("heart-center", f"{domain_name}/first-{length}/heart32", block[offset : offset + 32])

    for name, offset in anchors.items():
        audit.add("indexed-text", f"absolute-{name}-at-{offset}/tail", plaintext[offset:])
        audit.add("indexed-text", f"absolute-{name}-at-{offset}/raw32", plaintext[offset : offset + 32])
        audit.add("indexed-text", f"absolute-{name}-at-{offset}/window140", plaintext[offset : offset + 140])

    for left_name, left in anchors.items():
        for right_name, right in anchors.items():
            if left < right:
                audit.add("indexed-text", f"span-{left_name}-to-{right_name}", plaintext[left:right])


def add_quote_materials(audit: Audit) -> dict[str, object]:
    quote_words = words(WISE_QUOTE)
    quote_forms = normalizations(WISE_QUOTE)
    for label, value in quote_forms.items():
        audit.add("wise-quote", label, value)
        try:
            audit.add("source-codes", f"{label}/ascii-hex", value.hex())
            audit.add("source-codes", f"{label}/ascii-decimal", "".join(f"{byte:03d}" for byte in value))
            audit.add("source-codes", f"{label}/ascii-binary", "".join(f"{byte:08b}" for byte in value))
            audit.add("source-codes", f"{label}/ebcdic-cp273", value.decode("ascii").encode("cp273"))
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass

    audit.add("last-words", "literal", LAST_WORDS_BEFORE_ARCHITECT)
    for label, value in normalizations(LAST_WORDS_BEFORE_ARCHITECT).items():
        audit.add("last-words", label, value)
        for quote_label, quote in quote_forms.items():
            audit.add("last-words", f"{label}-then-quote-{quote_label}", value + quote)
            audit.add("last-words", f"quote-{quote_label}-then-{label}", quote + value)

    # The no-punctuation quote is exactly 140 characters and 23 words.
    quote_140 = " ".join(quote_words)
    quote_140_bytes = quote_140.encode("ascii")
    audit.add("heart-center", "quote140/full", quote_140_bytes)
    audit.add("heart-center", "quote140/central-character-pair", quote_140_bytes[69:71])
    audit.add("heart-center", "quote140/heart32-left", quote_140_bytes[54:86])
    audit.add("heart-center", "quote140/heart32-right", quote_140_bytes[55:87])
    audit.add("heart-center", "quote23/central-word", quote_words[11])

    primes140 = primes_through(140)
    for form_label, value in quote_forms.items():
        for basis in (0, 1):
            selected = bytes(value[index - basis] for index in primes140 if 0 <= index - basis < len(value))
            audit.add("prime-reinsertion", f"quote-{form_label}/all-primes-2-139/{basis}-based", selected)
            first24 = primes_through(89)
            selected24 = bytes(value[index - basis] for index in first24 if 0 <= index - basis < len(value))
            audit.add("prime-reinsertion", f"quote-{form_label}/primes-2-89/{basis}-based", selected24)
            without5 = [index for index in first24 if index != 5]
            selected23 = bytes(value[index - basis] for index in without5 if 0 <= index - basis < len(value))
            audit.add("prime-reinsertion", f"quote-{form_label}/primes-2-89-zero5/{basis}-based", selected23)

    # Literal 23/16/7 readings. The XOR/date mask is retained only as a
    # previously reported comparison; it is not needed for the 479 discovery.
    masks = {
        "direct-first23": MARKERS[:23],
        "direct-last23": MARKERS[1:],
        "direct-zero-blue-prime5": "".join(
            color for prime, color in zip(primes_through(89), MARKERS) if prime != 5
        ),
        "reported-date-xor-5e7db3": "".join("B" if bit == "1" else "Y" for bit in f"{0x5E7DB3:023b}"),
    }
    mask_meta: dict[str, object] = {}
    for mask_name, mask in masks.items():
        mask_meta[mask_name] = {"mask": mask, "B": mask.count("B"), "Y": mask.count("Y")}
        selections: dict[str, list[str]] = {}
        for symbol in ("B", "Y"):
            chosen = [word for word, bit in zip(quote_words, mask) if bit == symbol]
            selections[symbol] = chosen
            audit.add("quote-23-16-7", f"{mask_name}/{symbol}/spaced", " ".join(chosen))
            audit.add("quote-23-16-7", f"{mask_name}/{symbol}/concat", "".join(chosen))
            audit.add("quote-23-16-7", f"{mask_name}/{symbol}/initials", "".join(word[0] for word in chosen))
            audit.add("quote-23-16-7", f"{mask_name}/{symbol}/finals", "".join(word[-1] for word in chosen))
            audit.add("quote-23-16-7", f"{mask_name}/{symbol}/intertwined", intertwine(chosen))
            audit.add("quote-23-16-7", f"{mask_name}/{symbol}/intertwined-reversed", intertwine(chosen[::-1]))

        blue_text = "".join(selections["B"]).lower()
        yellow_text = "".join(selections["Y"]).lower()
        blue_digest = hashlib.sha256(blue_text.encode("ascii")).digest()
        yellow_digest = hashlib.sha256(yellow_text.encode("ascii")).digest()
        blue_int = int.from_bytes(blue_digest, "big")
        yellow_int = int.from_bytes(yellow_digest, "big")
        audit.add("quote-partition-pairs", f"{mask_name}/blue-then-yellow", blue_text + yellow_text)
        audit.add("quote-partition-pairs", f"{mask_name}/yellow-then-blue", yellow_text + blue_text)
        audit.add(
            "quote-partition-pairs",
            f"{mask_name}/interleave-blue-yellow",
            "".join(
                char
                for pair in zip(blue_text, yellow_text)
                for char in pair
            )
            + blue_text[len(yellow_text) :]
            + yellow_text[len(blue_text) :],
        )
        audit.add(
            "quote-partition-pairs",
            f"{mask_name}/digest-xor",
            bytes(a ^ b for a, b in zip(blue_digest, yellow_digest)),
        )
        for operation, scalar in (
            ("blue-plus-yellow", (blue_int + yellow_int) % N),
            ("blue-minus-yellow", (blue_int - yellow_int) % N),
            ("yellow-minus-blue", (yellow_int - blue_int) % N),
        ):
            if scalar:
                audit.add("quote-partition-pairs", f"{mask_name}/{operation}", scalar.to_bytes(32, "big"))

        if sorted((len(selections["B"]), len(selections["Y"]))) == [7, 16]:
            encryption_words = selections["B"] if len(selections["B"]) == 16 else selections["Y"]
            password_words = selections["Y"] if len(selections["Y"]) == 7 else selections["B"]
            message = "".join(encryption_words)
            for key_name, key in (
                ("passwords-concat", "".join(password_words)),
                ("passwords-intertwined", intertwine(password_words)),
                ("passwords-intertwined-reversed", intertwine(password_words[::-1])),
            ):
                for mode in ("vigenere-encrypt", "vigenere-decrypt", "beaufort"):
                    audit.add(
                        "quote-partition-pairs",
                        f"{mask_name}/16-encryptions-7-{key_name}/{mode}",
                        classical_shift(message, key, mode),
                    )

    return {
        "literal_length": len(WISE_QUOTE),
        "no_punctuation_length": len(quote_140),
        "letters_only_length": len("".join(quote_words)),
        "word_count": len(quote_words),
        "words": quote_words,
        "masks": mask_meta,
    }


def run() -> dict[str, object]:
    recovery = json.loads(PHASE32_PATH.read_text(encoding="utf-8"))
    plaintext = recovery["plaintext"]
    if hashlib.sha256(plaintext.encode("ascii")).hexdigest() != recovery["plaintext_sha256"]:
        raise ValueError("authenticated Architect plaintext hash changed")

    primes = primes_through(89)
    if len(primes) != 24 or len(MARKERS) != 24:
        raise ValueError("expected exactly 24 colours and primes")
    blue = [prime for prime, color in zip(primes, MARKERS) if color == "B"]
    yellow = [prime for prime, color in zip(primes, MARKERS) if color == "Y"]
    blue_sum, yellow_sum = sum(blue), sum(yellow)
    difference = blue_sum - yellow_sum
    if (blue_sum, yellow_sum, difference) != (484, 479, 5):
        raise ValueError("direct marker prime sums changed")
    if difference not in blue:
        raise ValueError("difference is no longer a blue-assigned prime")
    if blue_sum - difference != yellow_sum:
        raise ValueError("zeroing the blue difference no longer balances")

    phrases = (
        "PRIVATEKEY",
        "TAKETHISTOHEART",
        "WISEMANABOVE",
        "HUNDREDFOURTY",
        "INVESTMENT",
        "SOURCECODES",
        "PRIMEBASICS",
        "TWENTYTHREECIPHERS",
        "SIXTEENENCRYPTIONS",
        "SEVENINTERTWINEDPASSWORDS",
        "ACTUALPRIVATEKEY",
    )
    anchors = {phrase: plaintext.index(phrase) for phrase in phrases}
    if anchors["PRIVATEKEY"] != yellow_sum:
        raise ValueError("balanced sum no longer indexes PRIVATEKEY")

    audit = Audit()
    add_anchor_text_materials(audit, plaintext, anchors)
    quote_meta = add_quote_materials(audit)

    basic_tokens = {
        "marker-colors": MARKERS,
        "blue-primes-decimal": "".join(map(str, blue)),
        "yellow-primes-decimal": "".join(map(str, yellow)),
        "all-primes-decimal": "".join(map(str, primes)),
        "balanced-sums": "479479",
        "raw-sums": "484479",
        "clue-numbers": "479484514023167",
        "continuation-instruction": plaintext[479:1248],
        "source-prime-instruction": plaintext[1021:1248],
    }
    for label, value in basic_tokens.items():
        audit.add("clue-tokens", label, value)
        audit.add("clue-tokens", f"{label}/lower", value.lower())
        audit.add("clue-tokens", f"{label}/upper", value.upper())

    # Literal combinations of the quote, carried code, and newly derived anchor.
    quote140 = " ".join(words(WISE_QUOTE)).encode("ascii")
    anchor_bytes = b"479"
    for label, left, right in (
        ("quote140-then-479", quote140, anchor_bytes),
        ("479-then-quote140", anchor_bytes, quote140),
        ("quote140-then-carried-code", quote140, PHASE32_AES_KEY),
        ("carried-code-then-quote140", PHASE32_AES_KEY, quote140),
    ):
        audit.add("combined-kdf-inputs", label, left + right)
    audit.add("combined-kdf-inputs", "carried-phase32-aes-key", PHASE32_AES_KEY)
    audit.add(
        "combined-kdf-inputs",
        "quote140-sha256-xor-carried-code",
        bytes(a ^ b for a, b in zip(hashlib.sha256(quote140).digest(), PHASE32_AES_KEY)),
    )

    audit.expand_scalars()
    audit.gate()

    result = {
        "schema": "yinyang-479-architect-continuation-audit-v1",
        "status": "EXACT_MATCH" if audit.matches else "NO_EXACT_MATCH_IN_ENUMERATED_FAMILY",
        "cosmic_used": False,
        "authenticated_plaintext": {
            "length": len(plaintext),
            "sha256": recovery["plaintext_sha256"],
            "anchors_zero_based": anchors,
            "continuation_479_prefix": plaintext[479:639],
            "slice_479_484": plaintext[479:484],
        },
        "prime_balance": {
            "markers": MARKERS,
            "consecutive_primes": primes,
            "blue_primes": blue,
            "yellow_primes": yellow,
            "blue_sum": blue_sum,
            "yellow_sum": yellow_sum,
            "difference": difference,
            "difference_is_blue_prime": difference in blue,
            "blue_after_zeroing_difference": blue_sum - difference,
            "balanced": blue_sum - difference == yellow_sum,
        },
        "wise_quote": quote_meta,
        "last_words_before_architect": {
            "literal": LAST_WORDS_BEFORE_ARCHITECT,
            "normalized": "".join(words(LAST_WORDS_BEFORE_ARCHITECT)).lower(),
            "ibm_code_page_hint": 1141,
        },
        "carried_code": {
            "interpretation": "the exact SHA-256 password that decrypted phase 3.2",
            "hex": PHASE32_AES_KEY.hex(),
        },
        "targets": {
            "Half": {
                "address": HALF_ADDRESS,
                "public_key": HALF_PUBLIC.hex(),
                "hash160": HALF_H160.hex(),
            },
            "Better_Half": {
                "address": BETTER_ADDRESS,
                "hash160": BETTER_H160.hex(),
                "public_key_known": False,
            },
        },
        "counts": {
            "materials": len(audit.materials),
            "materials_by_family": dict(sorted(audit.material_families.items())),
            "unique_scalars": len(audit.scalar_labels),
            "scalar_derivations": sum(map(len, audit.scalar_labels.values())),
            "scalar_derivations_by_family": dict(sorted(audit.scalar_families.items())),
            "valid_wif_inputs": len(audit.wif_inputs),
        },
        "matches": audit.matches,
        "valid_wif_inputs": audit.wif_inputs,
        "strongest_near_misses": audit.near[:20],
        "scope": [
            "Direct 24 marker colours are used without the 23-bit Better-Half mutation.",
            "The 479 balance is accepted because it exactly indexes PRIVATEKEY in authenticated plaintext.",
            "The 140-character source is the punctuation-stripped Jacque Fresco quote printed above the Architect record.",
            "23/16/7 quote partitions include direct colour masks and the previously reported date-XOR mask; the latter is comparison evidence, not required by the 479 route.",
            "Scalar forms are raw/hex/decimal/WIF where applicable, SHA-256/double-SHA-256, centered 32-byte slices, clue-number tweaks, and carried-code XOR/HMAC.",
            "No Cosmic bytes, labels, passwords, plaintext, or Chain 4 outputs enter any candidate.",
        ],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(
        json.dumps(
            {
                "status": output["status"],
                "prime_balance": output["prime_balance"],
                "authenticated_plaintext": output["authenticated_plaintext"],
                "wise_quote": output["wise_quote"],
                "counts": output["counts"],
                "matches": output["matches"],
                "strongest_near_misses": output["strongest_near_misses"][:5],
            },
            indent=2,
        )
    )
