"""Cached, content-verified Wayback audit for unresolved GSMG public artifacts."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from coincurve import PrivateKey, PublicKey

from .extract import ROOT
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "wayback_source_audit.json"
CACHE = ROOT / "artifacts" / "wayback_cache"
BODIES = CACHE / "bodies"
CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
SALPHASEION_PATH = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")
USER_AGENT = "GSMG-public-evidence-audit/1.0"
SEARCH_TERMS = {
    "cosmic_A": rb"cosmic_A",
    "cd3fea3d": rb"cd3fea3d",
    "ca[280:312]": rb"ca\s*\[\s*280\s*:\s*312\s*\]",
    "cc[833:865]": rb"cc\s*\[\s*833\s*:\s*865\s*\]",
    "row1-4": rb"row1\s*[-_]\s*4|rows?\s*1\s*[-_]\s*4",
    "K_I1": rb"K_I1",
    "K_I2": rb"K_I2",
    "trail1": rb"trail1",
    "XOR triangle": rb"XOR\s+triangle",
    "chain4 mask": rb"b657264f2f6e6921",
    "chain4 password": rb"38d4f4c90cb45fdfc8cff50d0ed1c5740a25de4b8e946d0a5ae2667a23a259cc",
}


def _cdx_url() -> str:
    query = urllib.parse.urlencode([
        ("url", "gsmg.io/*"),
        ("output", "json"),
        ("filter", "statuscode:200"),
        ("collapse", "digest"),
        ("fl", "timestamp,original,mimetype,statuscode,digest,length"),
    ])
    return f"{CDX_ENDPOINT}?{query}"


def _request(url: str, timeout: int = 45) -> tuple[bytes, dict[str, str], str, int]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(), dict(response.headers.items()), response.geturl(), response.status


def _fetch_with_retries(url: str, attempts: int = 3) -> tuple[bytes, dict[str, str], str, int, int]:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            body, headers, final_url, status = _request(url)
            return body, headers, final_url, status, attempt
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as error:
            last_error = error
            if attempt < attempts:
                time.sleep(2 ** (attempt - 1))
    assert last_error is not None
    raise last_error


def _sha1_base32(data: bytes) -> str:
    return base64.b32encode(hashlib.sha1(data).digest()).decode("ascii").rstrip("=")


def _select_targets(rows: list[list[str]]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    primary: dict[str, dict[str, str]] = {}
    supplementary: dict[str, dict[str, str]] = {}
    for timestamp, original, mimetype, statuscode, digest, length in rows:
        record = {
            "timestamp": timestamp,
            "original": original,
            "mimetype": mimetype,
            "statuscode": statuscode,
            "cdx_digest": digest,
            "cdx_length": length,
        }
        is_primary = (
            re.search(rf"{SALPHASEION_PATH}$", original) is not None
            or re.search(r"/js/app\.js(?:\?|$)", original) is not None
            or mimetype == "application/json"
        )
        if is_primary:
            primary.setdefault(digest, record)
        if mimetype == "application/octet-stream":
            supplementary.setdefault(digest, record)
    return list(primary.values()), list(supplementary.values())


def _replay_url(record: dict[str, str]) -> str:
    return f"https://web.archive.org/web/{record['timestamp']}id_/{record['original']}"


def _scan_body(body: bytes, provenance: str) -> dict[str, object]:
    payloads = [("raw", body)]
    if body.startswith(b"\x1f\x8b"):
        try:
            payloads.append(("gzip-decoded", gzip.decompress(body)))
        except (gzip.BadGzipFile, EOFError):
            pass

    inline_maps: dict[bytes, str] = {}
    inline_map_decode_failures = 0
    inline_pattern = re.compile(
        rb"sourceMappingURL=data:application/json(?:;charset=[A-Za-z0-9_-]+)?;base64,([A-Za-z0-9+/=]+)"
    )
    for parent_name, parent in list(payloads):
        for match in inline_pattern.finditer(parent):
            token = match.group(1)
            try:
                decoded = base64.b64decode(token, validate=True)
            except (ValueError, base64.binascii.Error):
                inline_map_decode_failures += 1
                continue
            # A finite safety bound prevents a malformed page from expanding
            # without limit while remaining far above every retrieved asset.
            if len(decoded) > 25_000_000:
                inline_map_decode_failures += 1
                continue
            inline_maps.setdefault(decoded, f"inline-source-map-{len(inline_maps) + 1}-from-{parent_name}")
    payloads.extend((name, decoded) for decoded, name in inline_maps.items())

    term_hits: list[dict[str, object]] = []
    source_maps: set[str] = set()
    literals: list[dict[str, object]] = []
    scalar_candidates: dict[bytes, set[str]] = {}
    for payload_name, payload in payloads:
        for label, pattern in SEARCH_TERMS.items():
            matches = list(re.finditer(pattern, payload, re.IGNORECASE))
            if matches:
                term_hits.append({
                    "term": label,
                    "payload": payload_name,
                    "count": len(matches),
                    "offsets": [match.start() for match in matches[:20]],
                })
        for match in re.finditer(rb"sourceMappingURL=([^\s*]+)", payload):
            source_maps.add(match.group(1).decode("latin1", errors="replace"))

        for match in re.finditer(rb"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{60}|[0-9A-Fa-f]{58})(?![0-9A-Fa-f])", payload):
            literal = match.group(1)
            decoded = bytes.fromhex(literal.decode("ascii"))
            literals.append({"kind": f"hex-{len(decoded)}", "offset": match.start(1), "hex": literal.decode("ascii").lower()})
            if len(decoded) == 32:
                scalar_candidates.setdefault(decoded, set()).add(f"{provenance}/{payload_name}/hex@{match.start(1)}")

        # Limit Base64 candidates to quoted, standalone strings of the exact
        # lengths capable of encoding 32 bytes; this avoids arbitrary windows
        # through minified JavaScript.
        for match in re.finditer(rb"(['\"])([A-Za-z0-9+/]{43}=?|[A-Za-z0-9+/]{44})\1", payload):
            token = match.group(2)
            try:
                decoded = base64.b64decode(token + b"=" * ((-len(token)) % 4), validate=True)
            except (ValueError, base64.binascii.Error):
                continue
            if len(decoded) != 32:
                continue
            literals.append({"kind": "base64-32", "offset": match.start(2), "value": token.decode("ascii")})
            scalar_candidates.setdefault(decoded, set()).add(f"{provenance}/{payload_name}/base64@{match.start(2)}")

        if len(payload) in (29, 30, 32):
            literals.append({"kind": f"whole-body-{len(payload)}", "offset": 0, "hex": payload.hex()})
            if len(payload) == 32:
                scalar_candidates.setdefault(payload, set()).add(f"{provenance}/{payload_name}/whole-body")

    return {
        "term_hits": term_hits,
        "source_map_references": sorted(source_maps),
        "literals": literals,
        "scalar_candidates": scalar_candidates,
        "decoded_inline_source_maps": len(inline_maps),
        "decoded_inline_source_map_bytes": sum(len(value) for value in inline_maps),
        "inline_source_map_decode_failures": inline_map_decode_failures,
    }


def _target_match(candidate: bytes) -> bool:
    scalar = int.from_bytes(candidate, "big") % N
    if not scalar:
        return False
    return PrivateKey(scalar.to_bytes(32, "big")).public_key.format(compressed=True) == TARGET_COMPRESSED


def run(*, refresh_cdx: bool = True, fetch_missing: bool = True) -> dict[str, object]:
    CACHE.mkdir(parents=True, exist_ok=True)
    BODIES.mkdir(parents=True, exist_ok=True)
    previous = json.loads(RESULT_PATH.read_text(encoding="utf-8")) if RESULT_PATH.exists() else {}
    previous_by_digest = {
        record["cdx_digest"]: record
        for record in previous.get("targets", [])
        if record.get("retrieval_status") == "SUCCESS"
    }

    if refresh_cdx:
        cdx_bytes, _, _, status, _ = _fetch_with_retries(_cdx_url())
        if status != 200:
            raise ValueError(f"CDX query returned HTTP {status}")
        cdx_sha256 = hashlib.sha256(cdx_bytes).hexdigest()
        cdx_path = CACHE / f"cdx_{cdx_sha256}.json"
        cdx_path.write_bytes(cdx_bytes)
    else:
        cdx_relative = previous.get("cdx", {}).get("snapshot_path")
        if not cdx_relative:
            raise ValueError("no cached CDX snapshot is recorded")
        cdx_path = ROOT / cdx_relative
        cdx_bytes = cdx_path.read_bytes()
        cdx_sha256 = hashlib.sha256(cdx_bytes).hexdigest()

    cdx_data = json.loads(cdx_bytes)
    header, *rows = cdx_data
    expected_header = ["timestamp", "original", "mimetype", "statuscode", "digest", "length"]
    if header != expected_header:
        raise ValueError(f"unexpected CDX columns: {header}")
    primary, supplementary = _select_targets(rows)
    if len(primary) != 64:
        raise ValueError(f"the provenance-recorded primary selection no longer yields 64 targets: {len(primary)}")
    if len(supplementary) != 5:
        raise ValueError(f"expected five octet-stream controls, found {len(supplementary)}")

    targets: list[dict[str, object]] = []
    all_term_hits: list[dict[str, object]] = []
    all_literals: list[dict[str, object]] = []
    scalar_candidates: dict[bytes, set[str]] = {}
    failures: list[dict[str, str]] = []
    for index, (group, selected) in enumerate((("primary64", primary), ("octet_stream_controls", supplementary))):
        for record in selected:
            digest = record["cdx_digest"]
            cached = previous_by_digest.get(digest)
            body: bytes | None = None
            retrieval: dict[str, object]
            if cached:
                cached_path = ROOT / str(cached["cache_path"])
                if cached_path.exists():
                    candidate = cached_path.read_bytes()
                    if _sha1_base32(candidate) == digest and hashlib.sha256(candidate).hexdigest() == cached["sha256"]:
                        body = candidate
                        retrieval = {
                            "retrieval_status": "SUCCESS",
                            "http_status": cached["http_status"],
                            "final_url": cached["final_url"],
                            "content_type": cached.get("content_type"),
                            "attempts": 0,
                            "cache_reused": True,
                        }
            if body is None and fetch_missing:
                try:
                    body, headers, final_url, http_status, attempts = _fetch_with_retries(_replay_url(record))
                    retrieval = {
                        "retrieval_status": "SUCCESS",
                        "http_status": http_status,
                        "final_url": final_url,
                        "content_type": headers.get("Content-Type"),
                        "archive_original_content_type": headers.get("X-Archive-Orig-Content-Type"),
                        "attempts": attempts,
                        "cache_reused": False,
                    }
                    time.sleep(0.15)
                except Exception as error:  # recorded, not silently converted to a negative scan
                    retrieval = {
                        "retrieval_status": "FAILED",
                        "error_type": type(error).__name__,
                        "error": str(error),
                    }
            elif body is None:
                retrieval = {"retrieval_status": "FAILED", "error_type": "CacheMiss", "error": "body is not cached"}

            target: dict[str, object] = {"group": group, **record, **retrieval}
            if body is None:
                failures.append({"cdx_digest": digest, "original": record["original"], "error": str(retrieval["error"])})
            else:
                sha256 = hashlib.sha256(body).hexdigest()
                cache_path = BODIES / f"{sha256}.bin"
                if not cache_path.exists():
                    cache_path.write_bytes(body)
                digest_verified = _sha1_base32(body) == digest
                scan = _scan_body(body, f"{record['timestamp']}/{record['original']}")
                target.update({
                    "length": len(body),
                    "sha256": sha256,
                    "sha1_base32": _sha1_base32(body),
                    "cdx_digest_verified": digest_verified,
                    "cache_path": str(cache_path.relative_to(ROOT)).replace("\\", "/"),
                    "term_hits": scan["term_hits"],
                    "source_map_references": scan["source_map_references"],
                    "literal_count": len(scan["literals"]),
                    "decoded_inline_source_maps": scan["decoded_inline_source_maps"],
                    "decoded_inline_source_map_bytes": scan["decoded_inline_source_map_bytes"],
                    "inline_source_map_decode_failures": scan["inline_source_map_decode_failures"],
                })
                for hit in scan["term_hits"]:
                    all_term_hits.append({"timestamp": record["timestamp"], "original": record["original"], **hit})
                for literal in scan["literals"]:
                    all_literals.append({"timestamp": record["timestamp"], "original": record["original"], **literal})
                for candidate, provenances in scan["scalar_candidates"].items():
                    scalar_candidates.setdefault(candidate, set()).update(provenances)
            targets.append(target)
            completed = len(targets)
            if fetch_missing and (completed % 10 == 0 or completed == 69):
                print(f"wayback progress {completed}/69; failures={len(failures)}", flush=True)

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

    succeeded = [target for target in targets if target["retrieval_status"] == "SUCCESS"]
    verified = [target for target in succeeded if target.get("cdx_digest_verified")]
    unique_body_hashes = {target["sha256"] for target in succeeded}
    prefix_body_matches = [
        {"timestamp": target["timestamp"], "original": target["original"], "sha256": target["sha256"]}
        for target in succeeded
        if str(target["sha256"]).startswith("cd3fea3d")
    ]
    result: dict[str, object] = {
        "status": "COMPLETE_NO_MATCH" if not failures and not matches else "MATCH" if matches else "PARTIAL_RETRIEVAL",
        "audit_date": "2026-08-03",
        "cdx": {
            "query_url": _cdx_url(),
            "snapshot_path": str(cdx_path.relative_to(ROOT)).replace("\\", "/"),
            "snapshot_sha256": cdx_sha256,
            "collapsed_capture_rows": len(rows),
            "unique_original_urls": len({row[1] for row in rows}),
            "global_unique_digest_values": len({row[4] for row in rows}),
            "selection_rule": f"deduplicate by CDX digest after selecting exact /{SALPHASEION_PATH}, /js/app.js(?:?|$), or MIME application/json",
            "primary_target_count": len(primary),
            "supplementary_octet_stream_count": len(supplementary),
        },
        "retrieval": {
            "target_count": len(targets),
            "success_count": len(succeeded),
            "failure_count": len(failures),
            "cdx_digest_verified_count": len(verified),
            "unique_body_sha256_count": len(unique_body_hashes),
            "failures": failures,
        },
        "scan": {
            "search_terms": list(SEARCH_TERMS),
            "term_hits": all_term_hits,
            "source_map_reference_count": sum(len(target.get("source_map_references", [])) for target in succeeded),
            "decoded_inline_source_maps": sum(int(target.get("decoded_inline_source_maps", 0)) for target in succeeded),
            "decoded_inline_source_map_bytes": sum(int(target.get("decoded_inline_source_map_bytes", 0)) for target in succeeded),
            "inline_source_map_decode_failures": sum(int(target.get("inline_source_map_decode_failures", 0)) for target in succeeded),
            "literal_records": len(all_literals),
            "unique_29_byte_literals": len({item.get("hex", item.get("value")) for item in all_literals if item["kind"] in ("hex-29", "whole-body-29")}),
            "unique_30_byte_literals": len({item.get("hex", item.get("value")) for item in all_literals if item["kind"] in ("hex-30", "whole-body-30")}),
            "unique_32_byte_scalar_candidates": len(scalar_candidates),
            "body_sha256_cd3fea3d_prefix_matches": prefix_body_matches,
            "target_matches": matches,
        },
        "targets": targets,
        "scope_note": "A failed retrieval is never counted as a negative scan. Hex/Base64 scalar extraction is limited to standalone literals or whole 32-byte bodies; arbitrary JavaScript byte windows are intentionally excluded.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
