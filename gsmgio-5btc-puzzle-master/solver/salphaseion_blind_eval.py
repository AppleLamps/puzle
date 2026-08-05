"""Evaluate the sealed SalPhaseIon manifest without target-derived checks."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import json
import re
import string
import zlib
import zipfile

from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc, validate_envelope
from .salphaseion_preregister import MANIFEST_PATH, SEAL_PATH


RESULT_PATH = ROOT / "salphaseion_blind_results.json"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58check(value: bytes) -> bool:
    try:
        number = 0
        for byte in value:
            number = number * 58 + BASE58.index(chr(byte))
    except ValueError:
        return False
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    decoded = b"\0" * (len(value) - len(value.lstrip(b"1"))) + decoded
    return len(decoded) >= 5 and hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4] == decoded[-4:]


def _readable(value: bytes) -> tuple[bool, dict[str, object]]:
    if len(value) < 16:
        return False, {"length": len(value)}
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return False, {"length": len(value), "utf8": False}
    printable = sum(character in string.printable or character.isspace() for character in text) / len(text)
    words = re.findall(r"[A-Za-z]{3,}", text)
    accepted = printable >= 0.95 and len(words) >= 3
    return accepted, {
        "length": len(value),
        "utf8": True,
        "printable_or_whitespace_ratio": round(printable, 6),
        "alphabetic_words_length_at_least_3": len(words),
    }


def _png(value: bytes) -> bool:
    if not value.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    cursor = 8
    try:
        while cursor + 12 <= len(value):
            length = int.from_bytes(value[cursor:cursor + 4], "big")
            kind = value[cursor + 4:cursor + 8]
            end = cursor + 12 + length
            if end > len(value):
                return False
            body = value[cursor + 4:cursor + 8 + length]
            if zlib.crc32(body).to_bytes(4, "big") != value[cursor + 8 + length:end]:
                return False
            cursor = end
            if kind == b"IEND":
                return cursor == len(value)
    except (OverflowError, ValueError):
        return False
    return False


def _formats(value: bytes, *, nested: bool = False) -> list[str]:
    formats: list[str] = []
    try:
        json.loads(value.decode("utf-8"))
        formats.append("JSON")
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    try:
        if value[:2] == b"\x1f\x8b" and gzip.decompress(value) is not None:
            formats.append("gzip")
    except (OSError, EOFError):
        pass
    try:
        if len(value) >= 2 and zlib.decompress(value) is not None:
            formats.append("zlib")
    except zlib.error:
        pass
    try:
        with zipfile.ZipFile(io.BytesIO(value)) as archive:
            bad = archive.testzip()
            if bad is None and archive.infolist():
                formats.append("ZIP")
    except (zipfile.BadZipFile, OSError):
        pass
    if _png(value):
        formats.append("PNG")
    if value.startswith(b"-----BEGIN ") and b"-----END " in value:
        formats.append("PEM")
    try:
        validate_envelope(value)
        formats.append("nested-OpenSSL-envelope")
    except ValueError:
        pass
    if 26 <= len(value) <= 60 and _base58check(value):
        formats.append("Base58Check")

    # One recursion layer for canonical text encodings only.
    if not nested:
        compact = b"".join(value.split())
        if len(compact) >= 24 and len(compact) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f]+", compact):
            decoded = bytes.fromhex(compact.decode("ascii"))
            readable, _ = _readable(decoded)
            inner = _formats(decoded, nested=True)
            if readable or inner:
                formats.append("hex->" + (",".join(inner) if inner else "readable-text"))
        if len(compact) >= 24 and len(compact) % 4 == 0 and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", compact):
            try:
                decoded = base64.b64decode(compact, validate=True)
                readable, _ = _readable(decoded)
                inner = _formats(decoded, nested=True)
                if readable or inner:
                    formats.append("Base64->" + (",".join(inner) if inner else "readable-text"))
            except (ValueError, binascii.Error):
                pass
    return formats


def evaluate(manifest_path=MANIFEST_PATH, seal_path=SEAL_PATH, result_path=RESULT_PATH) -> dict[str, object]:
    encoded = manifest_path.read_bytes()
    expected_seal = seal_path.read_text(encoding="ascii").strip()
    actual_seal = hashlib.sha256(encoded).hexdigest()
    if actual_seal != expected_seal:
        raise ValueError("candidate manifest does not match its pre-decryption seal")
    manifest = json.loads(encoded)
    if manifest.get("status") != "SEALED_BEFORE_DECRYPTION":
        raise ValueError("manifest is not marked sealed")

    extracted = extract_all()
    blobs = {
        "salphaseion-short": extracted.chain1_envelope,
        "phase32-small": extracted.chain2_envelope,
        "cosmic-duality": extracted.cosmic_envelope,
    }
    for name, envelope in blobs.items():
        if hashlib.sha256(envelope).hexdigest() != manifest["blobs"][name]["sha256"]:
            raise ValueError(f"{name} differs from sealed manifest")

    padding_hits: list[dict[str, object]] = []
    accepted: list[dict[str, object]] = []
    per_rule: dict[tuple[str, str], list[dict[str, object]]] = {}
    attempts = 0
    for candidate in manifest["candidates"]:
        password = bytes.fromhex(candidate["password_hex"])
        for digest in manifest["declared_crypto"]["kdf_digests"]:
            rule_hits: list[dict[str, object]] = []
            for blob_name, envelope in blobs.items():
                attempts += 1
                try:
                    result = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
                except ValueError:
                    continue
                readable, text_metrics = _readable(result.plaintext)
                formats = _formats(result.plaintext)
                record = {
                    "candidate_id": candidate["candidate_id"],
                    "password_expansion": candidate["password_expansion"],
                    "password_sha256": candidate["password_sha256"],
                    "provenance": candidate["provenance"],
                    "kdf_digest": digest,
                    "blob": blob_name,
                    "plaintext_length": len(result.plaintext),
                    "plaintext_sha256": hashlib.sha256(result.plaintext).hexdigest(),
                    "padding_length": result.padding_length,
                    "readable_text": readable,
                    "text_metrics": text_metrics,
                    "formats": formats,
                }
                padding_hits.append(record)
                if readable or formats:
                    accepted_record = dict(record)
                    accepted_record["plaintext_base64"] = base64.b64encode(result.plaintext).decode("ascii")
                    accepted.append(accepted_record)
                    rule_hits.append(accepted_record)
            if rule_hits:
                per_rule[(candidate["candidate_id"], digest)] = rule_hits

    cross_blob = [
        {
            "candidate_id": candidate_id,
            "kdf_digest": digest,
            "blobs": sorted(record["blob"] for record in records),
        }
        for (candidate_id, digest), records in per_rule.items()
        if len({record["blob"] for record in records}) >= 2
    ]
    result = {
        "schema": "salphaseion-source-only-blind-results-v1",
        "manifest_sha256": actual_seal,
        "attempts": attempts,
        "strict_padding_hit_count": len(padding_hits),
        "accepted_single_blob_count": len(accepted),
        "accepted_cross_blob_rule_count": len(cross_blob),
        "status": "ACCEPTED" if accepted or cross_blob else "NO_ACCEPTED_RESULT",
        "accepted": accepted,
        "cross_blob": cross_blob,
        "padding_hits_without_plaintext": padding_hits,
        "important": "Strict padding hits are recorded by hash and metrics only and are not accepted without a preregistered validator.",
    }
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    result = evaluate()
    print(json.dumps({key: result[key] for key in (
        "manifest_sha256", "attempts", "strict_padding_hit_count",
        "accepted_single_blob_count", "accepted_cross_blob_rule_count", "status"
    )}, indent=2))


if __name__ == "__main__":
    main()
