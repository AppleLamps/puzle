"""Blind evaluation for the sealed v23 prime104/marker construction."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import string

from .salphaseion_blind_eval import _formats, evaluate as evaluate_aes
from .salphaseion_preregister_v23 import MANIFEST_PATH, RESULT_PATH, SEAL_PATH


def _direct_readable(value: bytes) -> bool:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return False
    printable = sum(character in string.printable or character.isspace() for character in text) / len(text)
    return printable >= 0.95 and bool(re.search(r"[A-Za-z]{4,}", text))


def evaluate() -> dict[str, object]:
    aes = evaluate_aes(MANIFEST_PATH, SEAL_PATH, RESULT_PATH)
    encoded = MANIFEST_PATH.read_bytes()
    manifest = json.loads(encoded)
    unique: dict[str, list[str]] = {}
    for candidate in manifest["candidates"]:
        unique.setdefault(candidate["preimage_hex"], candidate["provenance"])
    accepted_direct: list[dict[str, object]] = []
    for value_hex, provenance in unique.items():
        value = bytes.fromhex(value_hex)
        readable = _direct_readable(value)
        formats = _formats(value)
        if readable or formats:
            accepted_direct.append({
                "preimage_sha256": hashlib.sha256(value).hexdigest(),
                "preimage_base64": base64.b64encode(value).decode("ascii"),
                "provenance": provenance,
                "readable": readable,
                "formats": formats,
            })
    aes["unique_preimage_count"] = len(unique)
    aes["accepted_direct_count"] = len(accepted_direct)
    aes["accepted_direct"] = accepted_direct
    aes["status"] = "ACCEPTED" if accepted_direct or aes["accepted"] or aes["cross_blob"] else "NO_ACCEPTED_RESULT"
    RESULT_PATH.write_text(json.dumps(aes, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return aes


def main() -> None:
    result = evaluate()
    print(json.dumps({key: result[key] for key in (
        "manifest_sha256", "unique_preimage_count", "attempts",
        "strict_padding_hit_count", "accepted_direct_count",
        "accepted_single_blob_count", "accepted_cross_blob_rule_count", "status",
    )}, indent=2))


if __name__ == "__main__":
    main()
