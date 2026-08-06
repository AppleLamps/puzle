"""Exact-key audit for the creator-grounded Heart of Sufism page-140 lead.

This is deliberately a small, source-defined test rather than a wordlist.  The
Architect plaintext points to Witteveen's *The Heart of Sufism*, page 140, and
rewrites language found on that page.  We hash only the visible page units and
the phrases directly selected by that rewrite, then require the complete prize
public key to match.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from solver.secp256k1_verify import N, p2pkh_address, public_key, wif
from solver.targets import HALF_ADDRESS, HALF_PUBLIC_UNCOMPRESSED


TARGET_PUBLIC_KEY = HALF_PUBLIC_UNCOMPRESSED
TARGET_ADDRESS = HALF_ADDRESS


PAGE_140_P1 = """feeling that passes through our mind or heart? There is not one moment of our life wasted, if we only know how to utilize our activity here, how to direct our thought, how to express it in words, how to further it with our movement, how to feel it, so that it may make its own atmosphere. What responsibility! The responsibility that every man has is greater than a king's responsibility. It seems as if every man has a kingdom of his own for which he is responsible—a kingdom which is in no way smaller than any kingdom known to us, but incomparably larger than the kingdoms of the earth. This teaches us to be thoughtful and conscientious and to feel our responsibility with every move we make. When a man does not feel this, he is unaware of himself, he is unaware of the secret of life. He goes on as a drunken man walking in a city. He does not know what he is doing, either for himself, or against himself."""

PAGE_140_P2 = """Now one might ask: “How can a thought live? In what way does it live? Has it a body to live in, has it a mind, has it a breath?” Yes. The first thing we should know is that a breath which comes directly from the source seeks a body, an accommodation in which to function. A thought is as a body. The breath which runs from the source—as a ray of the spirit which may be likened to the sun—makes the thought an entity; it lives as an entity."""

PAGE_140_P3_VISIBLE = """It is these entities that are called in Sufi terms muwakkals, which means elementals. They live, they have a certain purpose to accomplish. They are given birth by man, and behind them there is a purpose to direct their life. Imagine how terrible it is if in a moment's absorption a person expresses his wrath, his passion, his hatred! A word expressed at such a moment must live and carry out its purpose. It is like creating an army of enemies around oneself. Perhaps one thought has a longer life than another; it depends on what body has been given to it. If the body is"""


def alnum_lower(text: str) -> str:
    return "".join(re.findall(r"[a-z0-9]+", text.lower()))


def candidate_texts() -> dict[str, str]:
    page = "\n\n".join((PAGE_140_P1, PAGE_140_P2, PAGE_140_P3_VISIBLE))
    return {
        "page140-visible-prose": page,
        "page140-visible-prose-with-running-title-and-number": f"THE WORLD OF THE MIND\n{page}\n140",
        "page140-paragraph-1": PAGE_140_P1,
        "page140-paragraph-2-source-function": PAGE_140_P2,
        "page140-paragraph-3-word-carries-purpose": PAGE_140_P3_VISIBLE,
        "page140-paragraphs-2-and-3": f"{PAGE_140_P2}\n\n{PAGE_140_P3_VISIBLE}",
        "the-life-of-thought": "The Life of Thought",
        "the-world-of-the-mind": "The World of the Mind",
        "muwakkals": "muwakkals",
        "elementals": "elementals",
        "directly-from-the-source": "directly from the source",
        "in-which-to-function": "in which to function",
        "live-and-carry-out-its-purpose": "live and carry out its purpose",
        "source-function-purpose": "directly from the source in which to function live and carry out its purpose",
        "wise-man-quote": "The future is ours to direct",
    }


def encodings(text: str) -> dict[str, bytes]:
    logical = " ".join(text.split())
    return {
        "utf8-logical": logical.encode(),
        "utf8-lower": logical.lower().encode(),
        "ascii-alnum-lower": alnum_lower(logical).encode(),
        "ascii-alnum-upper": alnum_lower(logical).upper().encode(),
    }


def main() -> None:
    records: list[dict[str, object]] = []
    matches: list[dict[str, object]] = []
    for source, text in candidate_texts().items():
        for normalization, preimage in encodings(text).items():
            key = hashlib.sha256(preimage).digest()
            if not 1 <= int.from_bytes(key, "big") < N:
                continue
            pub = public_key(key, compressed=False)
            record = {
                "source": source,
                "normalization": normalization,
                "preimage_length": len(preimage),
                "preimage_sha256": key.hex(),
                "public_key_match": pub == TARGET_PUBLIC_KEY,
                "address": p2pkh_address(key, compressed=False),
            }
            records.append(record)
            if record["public_key_match"] or record["address"] == TARGET_ADDRESS:
                record["private_key_hex"] = key.hex()
                record["wif_uncompressed"] = wif(key, compressed=False)
                matches.append(record)

    result = {
        "status": "MATCH" if matches else "NO_MATCH_IN_SOURCE_DEFINED_FAMILY",
        "target_public_key": TARGET_PUBLIC_KEY.hex(),
        "target_address": TARGET_ADDRESS,
        "candidate_text_units": len(candidate_texts()),
        "hash_records": len(records),
        "matches": matches,
        "records": records,
    }
    output = Path("tmp/heart_page140_key_audit.json")
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "records"}, indent=2))
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
