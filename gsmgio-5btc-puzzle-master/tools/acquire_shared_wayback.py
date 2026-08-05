from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CDX = ROOT / "artifacts" / "wayback_cache" / "cdx_1e45059a34e3965aecffb2f2dc8035198587d0e74faebda836bea54a8ca7a09c.json"
OUT = ROOT / "artifacts" / "shared_wayback"


def sha1_base32(data: bytes) -> str:
    return base64.b32encode(hashlib.sha1(data).digest()).decode("ascii")


def fetch(url: str) -> tuple[bytes, str, int]:
    headers = {"User-Agent": "GSMG-public-archive-audit/1.0 (research; one request at a time)"}
    last_error = ""
    for attempt in range(1, 7):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.read(), response.geturl(), attempt
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = repr(exc)
            time.sleep(min(2 ** attempt, 30))
    raise RuntimeError(f"failed after retries: {url}: {last_error}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = json.loads(CDX.read_text(encoding="utf-8"))
    header = rows[0]
    records = [dict(zip(header, row)) for row in rows[1:]]
    selected = [
        row
        for row in records
        if row["timestamp"] < "20230101000000"
        and row["mimetype"] == "image/png"
        and "/shared/" in row["original"]
    ]
    by_digest: dict[str, list[dict[str, str]]] = {}
    for row in selected:
        by_digest.setdefault(row["digest"], []).append(row)

    assets = []
    for index, (digest, captures) in enumerate(sorted(by_digest.items()), 1):
        capture = sorted(captures, key=lambda row: row["timestamp"])[0]
        url = f"https://web.archive.org/web/{capture['timestamp']}id_/{capture['original']}"
        data, final_url, attempts = fetch(url)
        actual_sha1 = sha1_base32(data)
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha1 != digest:
            raise RuntimeError(
                f"CDX digest mismatch for {capture['original']}: expected {digest}, got {actual_sha1}"
            )
        stem = capture["original"].rsplit("/", 1)[-1].removesuffix(".png")
        path = OUT / f"{capture['timestamp']}_{stem}_{actual_sha256[:12]}.png"
        path.write_bytes(data)
        assets.append(
            {
                "index": index,
                "timestamp": capture["timestamp"],
                "original": capture["original"],
                "capture_url": url,
                "final_url": final_url,
                "cdx_digest_sha1_base32": digest,
                "sha1_verified": True,
                "sha256": actual_sha256,
                "bytes": len(data),
                "attempts": attempts,
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "capture_count_for_digest": len(captures),
            }
        )
        print(f"[{index:02d}/{len(by_digest):02d}] {path.name} SHA1 verified", flush=True)
        time.sleep(0.25)

    report = {
        "scope": "All unique image/png CDX digests below /shared/ with timestamp before 2023-01-01",
        "cdx_path": str(CDX.relative_to(ROOT)).replace("\\", "/"),
        "cdx_sha256": hashlib.sha256(CDX.read_bytes()).hexdigest(),
        "capture_rows": len(selected),
        "unique_digests": len(by_digest),
        "all_sha1_verified": all(asset["sha1_verified"] for asset in assets),
        "assets": assets,
    }
    (OUT / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
