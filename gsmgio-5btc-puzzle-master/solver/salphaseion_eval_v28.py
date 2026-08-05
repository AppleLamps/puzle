"""Evaluate the sealed original-grid right-path construction."""

from __future__ import annotations

import base64
import hashlib
import json
import re

from .salphaseion_blind_eval import _formats, _readable, evaluate
from .salphaseion_preregister_v28 import MANIFEST_PATH, RESULT_PATH, SEAL_PATH, _bytes, _image_grid, _routes


def main():
    aes = evaluate(MANIFEST_PATH, SEAL_PATH, RESULT_PATH)
    _, bit_grid = _image_grid()
    direct = []
    for name, bits in _routes(bit_grid).items():
        value = _bytes(bits)
        readable, metrics = _readable(value)
        formats = _formats(value)
        try: text = value.decode("utf-8")
        except UnicodeDecodeError: text = ""
        url_path = bool(re.fullmatch(r"[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+", text))
        if readable or formats or url_path:
            direct.append({"route": name, "sha256": hashlib.sha256(value).hexdigest(), "base64": base64.b64encode(value).decode("ascii"), "url_path": url_path, "readable": readable, "metrics": metrics, "formats": formats})
    aes["accepted_direct_routes"] = direct
    aes["status"] = "ACCEPTED" if direct or aes["accepted"] or aes["cross_blob"] else "NO_ACCEPTED_RESULT"
    RESULT_PATH.write_text(json.dumps(aes, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"manifest_sha256": aes["manifest_sha256"], "attempts": aes["attempts"], "strict_padding_hit_count": aes["strict_padding_hit_count"], "accepted_single_blob_count": aes["accepted_single_blob_count"], "accepted_direct_route_count": len(direct), "status": aes["status"]}, indent=2))


if __name__ == "__main__": main()
