"""Acquire and scan every early puzzle-adjacent gsmg.io Wayback capture."""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.parse

from .extract import ROOT
from .wayback_source_audit import (
    BODIES,
    CACHE,
    SEARCH_TERMS,
    _fetch_with_retries,
    _replay_url,
    _scan_body,
    _sha1_base32,
    _target_match,
)
from .prime_reinsertion_audit import TARGET_ADDRESS
from .secp256k1_verify import N, base58check, hash160
from coincurve import PrivateKey


RESULT_PATH = ROOT / "wayback_early_asset_audit.json"
SOURCE_RESULT_PATH = ROOT / "wayback_source_audit.json"
EXPECTED_HEADER = ["timestamp", "original", "mimetype", "statuscode", "digest", "length"]


def _is_selected(row: list[str]) -> bool:
    timestamp, original, _mimetype, _statuscode, _digest, _length = row
    path = urllib.parse.urlparse(original).path.lower()
    if timestamp[:4] > "2021":
        return False
    if "/shared/" in path or path.startswith("/register") or path == "/referral":
        return False
    if path.startswith("/api/v1/subscriptions"):
        return False
    return True


def _record(row: list[str]) -> dict[str, str]:
    return dict(zip(EXPECTED_HEADER, row, strict=True)) | {"cdx_digest": row[4], "cdx_length": row[5]}


def _references(body: bytes) -> list[str]:
    """Extract explicit asset/page references, without treating strings as clues."""
    found: set[str] = set()
    patterns = (
        rb"(?:src|href)\s*=\s*['\"]([^'\"#]+)",
        rb"url\(\s*['\"]?([^)'\"#]+)",
        rb"sourceMappingURL=([^\s*]+)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, body, re.IGNORECASE):
            value = match.group(1).decode("utf-8", errors="replace").strip()
            if value and not value.startswith(("data:", "javascript:", "mailto:")):
                found.add(value)
    return sorted(found)


def _load_cdx() -> tuple[Path, bytes, list[list[str]]]:
    source = json.loads(SOURCE_RESULT_PATH.read_text(encoding="utf-8"))
    path = ROOT / source["cdx"]["snapshot_path"]
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != source["cdx"]["snapshot_sha256"]:
        raise ValueError("cached CDX snapshot differs from the verified source audit")
    header, *rows = json.loads(body)
    if header != EXPECTED_HEADER:
        raise ValueError(f"unexpected CDX columns: {header}")
    return path, body, rows


def _previous_cache() -> dict[str, dict[str, object]]:
    cached: dict[str, dict[str, object]] = {}
    for path in (SOURCE_RESULT_PATH, RESULT_PATH):
        if not path.exists():
            continue
        result = json.loads(path.read_text(encoding="utf-8"))
        for item in [*result.get("targets", []), *result.get("assets", [])]:
            digest = item.get("cdx_digest")
            cache_path = item.get("cache_path")
            if digest and cache_path and item.get("retrieval_status") == "SUCCESS":
                cached[str(digest)] = item
    return cached


def run(*, fetch_missing: bool = True) -> dict[str, object]:
    CACHE.mkdir(parents=True, exist_ok=True)
    BODIES.mkdir(parents=True, exist_ok=True)
    cdx_path, cdx_bytes, rows = _load_cdx()
    selected = [row for row in rows if _is_selected(row)]
    if len(selected) != 80 or len({row[4] for row in selected}) != 73:
        raise ValueError(
            "the frozen early-capture selection changed: "
            f"rows={len(selected)}, digests={len({row[4] for row in selected})}"
        )

    captures_by_digest: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in selected:
        captures_by_digest[row[4]].append(_record(row))

    prior = _previous_cache()
    assets: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    all_term_hits: list[dict[str, object]] = []
    all_literals: list[dict[str, object]] = []
    scalar_candidates: dict[bytes, set[str]] = {}
    all_references: set[str] = set()

    for index, (digest, captures) in enumerate(captures_by_digest.items(), start=1):
        representative = captures[0]
        body: bytes | None = None
        retrieval: dict[str, object] = {}
        cached = prior.get(digest)
        if cached:
            cached_path = ROOT / str(cached["cache_path"])
            if cached_path.exists():
                candidate = cached_path.read_bytes()
                if _sha1_base32(candidate) == digest:
                    body = candidate
                    retrieval = {
                        "retrieval_status": "SUCCESS",
                        "http_status": cached.get("http_status", 200),
                        "final_url": cached.get("final_url", _replay_url(representative)),
                        "content_type": cached.get("content_type"),
                        "attempts": 0,
                        "cache_reused": True,
                    }
        if body is None and fetch_missing:
            try:
                body, headers, final_url, status, attempts = _fetch_with_retries(_replay_url(representative))
                retrieval = {
                    "retrieval_status": "SUCCESS",
                    "http_status": status,
                    "final_url": final_url,
                    "content_type": headers.get("Content-Type"),
                    "archive_original_content_type": headers.get("X-Archive-Orig-Content-Type"),
                    "attempts": attempts,
                    "cache_reused": False,
                }
                time.sleep(0.15)
            except Exception as error:
                retrieval = {
                    "retrieval_status": "FAILED",
                    "error_type": type(error).__name__,
                    "error": str(error),
                }
        elif body is None:
            retrieval = {"retrieval_status": "FAILED", "error_type": "CacheMiss", "error": "body is not cached"}

        asset: dict[str, object] = {
            "cdx_digest": digest,
            "captures": captures,
            "capture_count": len(captures),
            **retrieval,
        }
        if body is None:
            failures.append({
                "cdx_digest": digest,
                "original": representative["original"],
                "error": str(retrieval["error"]),
            })
        else:
            sha256 = hashlib.sha256(body).hexdigest()
            cache_path = BODIES / f"{sha256}.bin"
            if not cache_path.exists():
                cache_path.write_bytes(body)
            scan = _scan_body(body, f"{representative['timestamp']}/{representative['original']}")
            references = _references(body)
            all_references.update(references)
            asset.update({
                "length": len(body),
                "sha256": sha256,
                "sha1_base32": _sha1_base32(body),
                "cdx_digest_verified": _sha1_base32(body) == digest,
                "cache_path": str(cache_path.relative_to(ROOT)).replace("\\", "/"),
                "term_hits": scan["term_hits"],
                "source_map_references": scan["source_map_references"],
                "explicit_references": references,
                "literal_count": len(scan["literals"]),
                "decoded_inline_source_maps": scan["decoded_inline_source_maps"],
                "decoded_inline_source_map_bytes": scan["decoded_inline_source_map_bytes"],
                "inline_source_map_decode_failures": scan["inline_source_map_decode_failures"],
            })
            for hit in scan["term_hits"]:
                all_term_hits.append({"cdx_digest": digest, **hit})
            for literal in scan["literals"]:
                all_literals.append({"cdx_digest": digest, **literal})
            for candidate, provenances in scan["scalar_candidates"].items():
                scalar_candidates.setdefault(candidate, set()).update(provenances)
        assets.append(asset)
        if fetch_missing and (index % 10 == 0 or index == len(captures_by_digest)):
            print(f"early Wayback progress {index}/{len(captures_by_digest)}; failures={len(failures)}", flush=True)

    matches: list[dict[str, object]] = []
    for candidate, provenances in scalar_candidates.items():
        if _target_match(candidate):
            scalar = int.from_bytes(candidate, "big") % N
            uncompressed = PrivateKey(scalar.to_bytes(32, "big")).public_key.format(compressed=False)
            address = base58check(b"\0" + hash160(uncompressed))
            matches.append({
                "private_hex": f"{scalar:064x}",
                "address": address,
                "address_verified": address == TARGET_ADDRESS,
                "provenances": sorted(provenances),
            })

    succeeded = [asset for asset in assets if asset["retrieval_status"] == "SUCCESS"]
    verified = [asset for asset in succeeded if asset.get("cdx_digest_verified")]
    puzzle_assets = [
        {
            "timestamp": capture["timestamp"],
            "original": capture["original"],
            "sha256": asset["sha256"],
            "length": asset["length"],
            "cache_path": asset["cache_path"],
        }
        for asset in succeeded
        for capture in asset["captures"]
        if urllib.parse.urlparse(capture["original"]).path.lower() == "/puzzle"
    ]
    local_puzzle = ROOT / "puzzle.png"
    local_puzzle_sha256 = hashlib.sha256(local_puzzle.read_bytes()).hexdigest()
    for item in puzzle_assets:
        item["matches_local_puzzle_png"] = item["sha256"] == local_puzzle_sha256

    result: dict[str, object] = {
        "status": "COMPLETE_NO_MATCH" if not failures and not matches else "MATCH" if matches else "PARTIAL_RETRIEVAL",
        "audit_date": "2026-08-03",
        "cdx": {
            "snapshot_path": str(cdx_path.relative_to(ROOT)).replace("\\", "/"),
            "snapshot_sha256": hashlib.sha256(cdx_bytes).hexdigest(),
            "all_capture_rows": len(rows),
            "selection_rule": "captures through 2021, excluding /shared/, /register*, exact /referral, and /api/v1/subscriptions*",
            "selected_capture_rows": len(selected),
            "selected_unique_digests": len(captures_by_digest),
            "selected_unique_original_urls": len({row[1] for row in selected}),
            "year_counts": dict(sorted(Counter(row[0][:4] for row in selected).items())),
            "mimetype_counts": dict(sorted(Counter(row[2] for row in selected).items())),
        },
        "retrieval": {
            "capture_rows_covered": sum(int(asset["capture_count"]) for asset in succeeded),
            "unique_digest_target_count": len(assets),
            "success_count": len(succeeded),
            "failure_count": len(failures),
            "cdx_digest_verified_count": len(verified),
            "failures": failures,
        },
        "scan": {
            "search_terms": list(SEARCH_TERMS),
            "term_hits": all_term_hits,
            "explicit_reference_count": len(all_references),
            "explicit_references": sorted(all_references),
            "source_map_reference_count": sum(len(asset.get("source_map_references", [])) for asset in succeeded),
            "decoded_inline_source_maps": sum(int(asset.get("decoded_inline_source_maps", 0)) for asset in succeeded),
            "inline_source_map_decode_failures": sum(int(asset.get("inline_source_map_decode_failures", 0)) for asset in succeeded),
            "literal_records": len(all_literals),
            "unique_29_byte_literals": len({item.get("hex", item.get("value")) for item in all_literals if item["kind"] in ("hex-29", "whole-body-29")}),
            "unique_30_byte_literals": len({item.get("hex", item.get("value")) for item in all_literals if item["kind"] in ("hex-30", "whole-body-30")}),
            "unique_32_byte_scalar_candidates": len(scalar_candidates),
            "body_sha256_cd3fea3d_prefix_matches": [
                {"cdx_digest": asset["cdx_digest"], "sha256": asset["sha256"]}
                for asset in succeeded if str(asset["sha256"]).startswith("cd3fea3d")
            ],
            "target_matches": matches,
        },
        "puzzle_capture_comparison": {
            "local_puzzle_png_sha256": local_puzzle_sha256,
            "archive_captures": puzzle_assets,
        },
        "assets": assets,
        "scope_note": "Every exact selected CDX row is represented; byte-identical rows share one content-verified retrieval. Exclusions are account/shared/subscription surfaces rather than puzzle-facing pages or assets.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
