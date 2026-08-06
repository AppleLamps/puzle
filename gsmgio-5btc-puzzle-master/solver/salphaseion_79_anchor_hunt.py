"""Hunt for the unreproduced Issue #82 79-byte SalPhaseIon SHA256 anchor."""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze, base_digits_to_bytes
from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc, validate_envelope
from .phase32_classical import PHASE32_PASSWORD
from .salphaseion import derive_tokens
from .salphaseion_raw import extract_raw
from .secp256k1_verify import N, p2pkh_address
from .targets import BETTER_ADDRESS, HALF_ADDRESS


WORKSPACE = ROOT.parent
RESULT_PATH = ROOT / "salphaseion_79_anchor_hunt.json"
TARGET_SHA256 = "e2590f1581c75812c6848776f2979d3bf272a75cb95063f1b177a2bbf4992cbd"
PRIZE_ADDRESSES = {
    "Half": HALF_ADDRESS,
    "Better_Half": BETTER_ADDRESS,
}
DIGESTS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")


@dataclass(frozen=True)
class CandidateHit:
    family: str
    label: str
    length: int
    sha256: str
    hex: str


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_sample(data: bytes, limit: int = 96) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in data[:limit])


def record_79(
    family: str,
    label: str,
    data: bytes,
    counts: Counter[str],
    hits: list[CandidateHit],
    samples: list[dict[str, object]] | None = None,
    sample_limit: int = 25,
) -> None:
    if len(data) != 79:
        return
    counts[family] += 1
    digest = sha256_hex(data)
    if samples is not None and len(samples) < sample_limit:
        samples.append(
            {
                "family": family,
                "label": label,
                "sha256": digest,
                "hex_prefix": data[:16].hex(),
                "printable_sample": printable_sample(data),
            }
        )
    if digest == TARGET_SHA256:
        hits.append(CandidateHit(family, label, len(data), digest, data.hex()))


def gate_79_blob(data: bytes) -> dict[str, object]:
    if len(data) != 79:
        raise ValueError("address gate requires a 79-byte 32+32+15 blob")
    first = data[:32]
    second = data[32:64]
    extension = data[64:]
    parts: list[dict[str, object]] = []
    for name, chunk in (("first32", first), ("second32", second)):
        scalar = int.from_bytes(chunk, "big")
        record: dict[str, object] = {
            "part": name,
            "scalar_hex": chunk.hex(),
            "scalar_in_secp256k1_range": 1 <= scalar < N,
            "addresses": None,
            "matches": [],
        }
        if 1 <= scalar < N:
            addresses = {
                "uncompressed": p2pkh_address(chunk, compressed=False),
                "compressed": p2pkh_address(chunk, compressed=True),
            }
            record["addresses"] = addresses
            record["matches"] = [
                {
                    "prize": prize_name,
                    "serialization": serialization,
                    "address": address,
                }
                for serialization, address in addresses.items()
                for prize_name, target in PRIZE_ADDRESSES.items()
                if address == target
            ]
        parts.append(record)
    return {
        "split": "32+32+15",
        "extension_hex": extension.hex(),
        "parts": parts,
        "any_prize_match": any(part["matches"] for part in parts),
    }


def issue82_context() -> dict[str, object]:
    try:
        proc = subprocess.run(
            [
                "gh",
                "issue",
                "view",
                "82",
                "--repo",
                "puzzlehunt/gsmgio-5btc-puzzle",
                "--json",
                "title,body,comments",
            ],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
            timeout=30,
        )
    except Exception as exc:  # gh/network availability is environmental.
        return {"available": False, "error": repr(exc)}

    payload = json.loads(proc.stdout)
    body = payload.get("body") or ""
    comments = payload.get("comments") or []
    target_mentions = []
    for index, comment in enumerate(comments):
        text = comment.get("body") or ""
        if TARGET_SHA256 in text or "SalPhaseIon output" in text or "cosmic_A" in text:
            target_mentions.append(
                {
                    "index": index,
                    "author": (comment.get("author") or {}).get("login"),
                    "createdAt": comment.get("createdAt"),
                    "body_excerpt": text[:1200],
                }
            )
    return {
        "available": True,
        "title": payload.get("title"),
        "body_contains_target": TARGET_SHA256 in body,
        "body_excerpt": body[:1600],
        "comment_count": len(comments),
        "target_related_comments": target_mentions,
        "summary": (
            "Issue #82 body states the 79-byte SHA256 anchor but gives no concrete "
            "bytes, password, digest, or transform. Comments visible to gh add no "
            "reproducible derivation for this anchor."
        ),
    }


def iter_workspace_files() -> Iterable[Path]:
    skip_dirs = {".git", "__pycache__", "node_modules", ".mypy_cache", ".pytest_cache"}
    self_path = Path(__file__).resolve()
    for dirpath, dirnames, filenames in os.walk(WORKSPACE):
        dirnames[:] = [name for name in dirnames if name not in skip_dirs]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path in {RESULT_PATH, self_path}:
                continue
            yield path


def local_hash_search() -> dict[str, object]:
    target = TARGET_SHA256.encode("ascii")
    text_hits: list[dict[str, object]] = []
    exact_79_file_hits: list[dict[str, object]] = []
    exact_79_file_nonmatch_samples: list[dict[str, object]] = []
    scanned_files = 0
    scanned_bytes = 0
    unreadable: list[str] = []
    for path in iter_workspace_files():
        try:
            data = path.read_bytes()
        except OSError:
            unreadable.append(str(path))
            continue
        scanned_files += 1
        scanned_bytes += len(data)
        if target in data:
            text_hits.append(
                {
                    "path": str(path),
                    "byte_offsets": [match.start() for match in re.finditer(re.escape(target), data)][:20],
                }
            )
        if len(data) == 79:
            digest = sha256_hex(data)
            record = {"path": str(path), "sha256": digest}
            if digest == TARGET_SHA256:
                exact_79_file_hits.append(record)
            elif len(exact_79_file_nonmatch_samples) < 25:
                exact_79_file_nonmatch_samples.append(record)
    return {
        "scanned_root": str(WORKSPACE),
        "scanned_files": scanned_files,
        "scanned_bytes": scanned_bytes,
        "target_hash_text_occurrences": text_hits,
        "files_whose_entire_79_bytes_match_target": exact_79_file_hits,
        "sample_79_byte_file_nonmatches": exact_79_file_nonmatch_samples,
        "unreadable_count": len(unreadable),
        "unreadable_samples": unreadable[:20],
    }


def salphaseion_base64_variants() -> dict[str, bytes]:
    raw = extract_raw()
    tokens = raw.textarea1.decode("ascii").split()
    ending = list("shabefanstoo")
    payload_end = len(tokens) - len(ending)
    base64_start = tokens.index("U")
    enter_tokens = list(raw.enter_bits)
    enter_start = next(
        index
        for index in range(base64_start, payload_end - len(enter_tokens) + 1)
        if tokens[index : index + len(enter_tokens)] == enter_tokens
    )
    before = "".join(tokens[base64_start:enter_start])
    enter_ab = "".join(tokens[enter_start : enter_start + len(enter_tokens)])
    after = "".join(tokens[enter_start + len(enter_tokens) : payload_end])
    before_no_z = before[:-1] if before.endswith("z") else before
    variants = {
        "canonical/remove-enter-ab": before + after,
        "issue72-described/blob1-plus-literal-z-plus-blob2": before_no_z + "z" + after,
        "drop-final-z-as-separator": before_no_z + after,
        "include-enter-ab-as-base64": before + enter_ab + after,
        "include-enter-word-as-base64": before + "enter" + after,
        "include-enter-base64": before + base64.b64encode(b"enter").decode("ascii").rstrip("=") + after,
        "uppercase-z-separator": before_no_z + "Z" + after,
        "double-z-between-parts": before + "z" + after,
        "part1-only": before,
        "part2-only": after,
    }
    valid: dict[str, bytes] = {}
    for label, text in variants.items():
        padded = text + "=" * (-len(text) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
            validate_envelope(decoded)
        except Exception:
            continue
        valid[label] = decoded
    return valid


def password_byte_variants(label: str, value: bytes | str) -> Iterable[tuple[str, bytes]]:
    base = value.encode("utf-8") if isinstance(value, str) else value
    forms = [(label, base)]
    try:
        text = base.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text:
        compact = re.sub(r"[^A-Za-z0-9]", "", text)
        forms.extend(
            [
                (f"{label}/lower", text.lower().encode("utf-8")),
                (f"{label}/upper", text.upper().encode("utf-8")),
                (f"{label}/title", text.title().encode("utf-8")),
            ]
        )
        if compact and compact != text:
            forms.append((f"{label}/alnum", compact.encode("utf-8")))
    seen: set[bytes] = set()
    for variant_label, variant in forms:
        if variant and variant not in seen:
            seen.add(variant)
            yield variant_label, variant


def build_passwords() -> dict[str, bytes]:
    inputs = extract_all()
    sal = derive_tokens()
    chains = reconstruct(inputs, sal)
    chain4 = reconstruct_chain4(chains)
    raw = extract_raw()
    texts = {
        "literal/ZION": "ZION",
        "literal/zion": "zion",
        "literal/ION": "ION",
        "literal/SalPhaseIon": "SalPhaseIon",
        "literal/SALTPhaseZION": "SALTPhaseZION",
        "literal/HASHTHETEXT": "HASHTHETEXT",
        "literal/rEdEmPtIoN": "rEdEmPtIoN",
        "literal/AWAKENZION": "AWAKENZION",
        "marker/matrix": raw.matrix_marker,
        "marker/lastwords": raw.lastwords_marker,
        "marker/thispassword": raw.password_marker,
        "marker/enter": raw.enter_marker,
        "marker/first-hint": raw.sha_first_hint,
        "marker/answer-too": raw.sha_answer_too,
        "known/phase32-password-hex": PHASE32_PASSWORD.decode("ascii"),
        "known/chain1-wif": chains.chain1_wif,
    }
    for index, token in enumerate(sal.tokens, start=1):
        texts[f"token/{index}/{token}"] = token
    token_lists = {
        "direct4": sal.directly_decoded,
        "all7": sal.tokens,
        "first5-canonical": sal.tokens[:5],
        "last3-semantic": sal.tokens[4:],
    }
    passwords: dict[str, bytes] = {}

    def add(label: str, value: bytes | str) -> None:
        for variant_label, variant in password_byte_variants(label, value):
            passwords.setdefault(variant_label, variant)

    for label, text in texts.items():
        add(label, text)
    for label, values in token_lists.items():
        for sep_label, sep in (("concat", ""), ("space", " "), ("dash", "-"), ("underscore", "_"), ("colon", ":"), ("z", "z")):
            add(f"tokens/{label}/{sep_label}", sep.join(values))
    tokens = tuple(sal.tokens)
    for length in range(1, len(tokens) + 1):
        for start in range(0, len(tokens) - length + 1):
            add(f"tokens/contiguous-{start + 1}-{start + length}", "".join(tokens[start : start + length]))
    for perm in itertools.permutations(tokens, len(tokens)):
        add("tokens/all7-permutation/" + "-".join(str(tokens.index(item) + 1) for item in perm), "".join(perm))
    for size in range(1, len(tokens) + 1):
        for indexes in itertools.combinations(range(len(tokens)), size):
            digest_xor = bytearray(32)
            for index in indexes:
                digest = hashlib.sha256(tokens[index].encode("utf-8")).digest()
                for pos, value in enumerate(digest):
                    digest_xor[pos] ^= value
            label = "digest-xor/tokens-" + "-".join(str(index + 1) for index in indexes)
            add(label, bytes(digest_xor))
            add(label + "-hex", bytes(digest_xor).hex())
    for label, value in {
        "bytes/cosmic-xor-password": sal.xor_password,
        "bytes/chain1-key1": chains.chain1.key1,
        "bytes/chain1-key2": chains.chain1.key2,
        "bytes/chain1-extension": chains.chain1.extension,
        "bytes/chain2-key1": chains.chain2.key1,
        "bytes/chain2-key2": chains.chain2.key2,
        "bytes/chain2-extension": chains.chain2.extension,
        "bytes/cosmic-b-extension": chains.cosmic_b.extension,
        "bytes/chain4-password": chain4.password,
    }.items():
        add(label, value)
        add(label + "-hex", value.hex())
    return passwords


def openssl_sweep(counts: Counter[str], hits: list[CandidateHit]) -> dict[str, object]:
    inputs = extract_all()
    sal = derive_tokens()
    chains = reconstruct(inputs, sal)
    chain4 = reconstruct_chain4(chains)
    envelopes = {
        "chain1-short": inputs.chain1_envelope,
        "chain2-small": inputs.chain2_envelope,
        "phase32": inputs.phase32_envelope,
        "cosmic-duality": inputs.cosmic_envelope,
        "chain4-embedded": chain4.embedded_envelope,
    }
    for label, envelope in salphaseion_base64_variants().items():
        envelopes[f"salphaseion-parse/{label}"] = envelope
    passwords = build_passwords()
    attempts = 0
    padding_hits = 0
    len79_hits = 0
    len79_samples: list[dict[str, object]] = []
    seen_attempts: set[tuple[str, str, bytes]] = set()
    for envelope_label, envelope in envelopes.items():
        for password_label, password in passwords.items():
            for digest in DIGESTS:
                key = (envelope_label, digest, password)
                if key in seen_attempts:
                    continue
                seen_attempts.add(key)
                attempts += 1
                try:
                    dec = decrypt_salted_aes256_cbc(envelope, password, digest=digest)
                except Exception:
                    continue
                padding_hits += 1
                if len(dec.plaintext) == 79:
                    len79_hits += 1
                    record_79(
                        "openssl",
                        f"{envelope_label}|{password_label}|{digest}",
                        dec.plaintext,
                        counts,
                        hits,
                        len79_samples,
                    )
    zion_plain = decrypt_salted_aes256_cbc(inputs.chain1_envelope, b"ZION", digest="sha256").plaintext
    return {
        "envelopes": {label: {"length": len(value), "sha256": sha256_hex(value)} for label, value in envelopes.items()},
        "digest_names": list(DIGESTS),
        "unique_password_candidates": len(passwords),
        "attempts": attempts,
        "pkcs7_padding_hits": padding_hits,
        "plaintext_len_79_hits": len79_hits,
        "len79_sample_limit": len(len79_samples),
        "len79_samples": len79_samples,
        "issue72_zion_claim": {
            "reproduced_len": len(zion_plain),
            "sha256": sha256_hex(zion_plain),
            "matches_target": sha256_hex(zion_plain) == TARGET_SHA256,
            "hex": zion_plain.hex(),
        },
    }


def window_candidates(label: str, data: bytes, family: str, counts: Counter[str], hits: list[CandidateHit]) -> int:
    tested = 0
    for offset in range(0, max(0, len(data) - 79 + 1)):
        record_79(family, f"{label}[{offset}:{offset + 79}]", data[offset : offset + 79], counts, hits)
        tested += 1
    return tested


def known_material_windows(counts: Counter[str], hits: list[CandidateHit]) -> dict[str, object]:
    inputs = extract_all()
    sal = derive_tokens()
    chains = reconstruct(inputs, sal)
    chain4 = reconstruct_chain4(chains)
    phase32 = decrypt_salted_aes256_cbc(inputs.phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    materials = {
        "chain1_plaintext": chains.chain1_decryption.plaintext,
        "chain2_plaintext": chains.chain2_decryption.plaintext,
        "cosmic_plaintext": chains.cosmic_decryption.plaintext,
        "chain4_plaintext": chain4.decryption.plaintext,
        "phase32_plaintext": phase32.plaintext,
        "chain1_envelope": inputs.chain1_envelope,
        "chain2_envelope": inputs.chain2_envelope,
        "phase32_envelope": inputs.phase32_envelope,
        "cosmic_envelope": inputs.cosmic_envelope,
        "chain4_embedded_envelope": chain4.embedded_envelope,
    }
    windows_tested = {}
    for label, data in materials.items():
        windows_tested[label] = window_candidates(label, data, "material-window", counts, hits)
    known_nonmatches = {
        "chain1_plaintext": {"length": len(chains.chain1_decryption.plaintext), "sha256": sha256_hex(chains.chain1_decryption.plaintext)},
        "chain2_plaintext": {"length": len(chains.chain2_decryption.plaintext), "sha256": sha256_hex(chains.chain2_decryption.plaintext)},
        "cosmic[0:79]": {"length": 79, "sha256": sha256_hex(chains.cosmic_decryption.plaintext[:79])},
        "cosmic[79:158]": {"length": 79, "sha256": sha256_hex(chains.cosmic_decryption.plaintext[79:158])},
    }
    return {
        "material_lengths": {label: len(data) for label, data in materials.items()},
        "windows_79_tested": windows_tested,
        "known_nonmatches": known_nonmatches,
    }


def pack_int(value: int, width: int, endian: str) -> bytes:
    return value.to_bytes(width, endian, signed=False)


def matrix_cosmic_transforms(counts: Counter[str], hits: list[CandidateHit]) -> dict[str, object]:
    inputs = extract_all()
    sal = derive_tokens()
    chains = reconstruct(inputs, sal)
    matrix = analyze(chains.cosmic_decryption.plaintext)
    candidate_count_before = counts["matrix-cosmic"]
    samples: list[dict[str, object]] = []
    rows = bytes(matrix.row_sums)
    cols = bytes(matrix.column_sums)
    window_candidates("row_sums", rows, "matrix-cosmic", counts, hits)
    window_candidates("column_sums", cols, "matrix-cosmic", counts, hits)
    window_candidates("row_sums||column_sums", rows + cols, "matrix-cosmic", counts, hits)
    window_candidates("column_sums||row_sums", cols + rows, "matrix-cosmic", counts, hits)
    for shift in range(103):
        secondary = bytes(matrix.row_sums[i] + matrix.column_sums[(i + shift) % 103] for i in range(103))
        window_candidates(f"secondary-shift-{shift}", secondary, "matrix-cosmic", counts, hits)
        digits80 = tuple(value - 80 for value in secondary if 80 <= value <= 117)
        if len(digits80) == len(secondary):
            try:
                decoded = base_digits_to_bytes(digits80, 38)
            except ValueError:
                decoded = b""
            if decoded:
                window_candidates(f"base38-secondary-shift-{shift}", decoded, "matrix-cosmic", counts, hits)
    stats = {
        "S": matrix.total_ones,
        "Wr": matrix.weighted_rows,
        "Wc": matrix.weighted_columns,
        "selected_shift": matrix.selected.shift,
        "p_big": 58,
        "p_little": 46,
    }
    stat_specs = (
        ("S", stats["S"], 2),
        ("Wr", stats["Wr"], 4),
        ("Wc", stats["Wc"], 4),
        ("selected_shift", stats["selected_shift"], 1),
        ("p_big", stats["p_big"], 1),
        ("p_little", stats["p_little"], 1),
    )
    # 68-byte base38 output plus 11-byte invariant encodings is a natural
    # exact 79-byte family suggested by the Issue #82 invariant list.
    invariant_blocks: list[tuple[str, bytes]] = []
    for endian in ("big", "little"):
        for names in itertools.permutations(("S", "Wr", "Wc", "p_big"), 4):
            chunks = []
            for name in names:
                spec = next(item for item in stat_specs if item[0] == name)
                chunks.append(pack_int(spec[1], spec[2], endian))
            invariant_blocks.append((f"{endian}/" + "-".join(names), b"".join(chunks)))
        for names in itertools.permutations(("S", "Wr", "Wc", "p_little"), 4):
            chunks = []
            for name in names:
                spec = next(item for item in stat_specs if item[0] == name)
                chunks.append(pack_int(spec[1], spec[2], endian))
            invariant_blocks.append((f"{endian}/" + "-".join(names), b"".join(chunks)))
    for label, block in invariant_blocks:
        for composed_label, data in (
            (f"base38||invariants/{label}", matrix.base38_bytes + block),
            (f"invariants||base38/{label}", block + matrix.base38_bytes),
            (f"half||better||invariants/{label}", matrix.half + matrix.better_half + block),
        ):
            record_79("matrix-cosmic", composed_label, data, counts, hits, samples)
    # Also test 64-byte Half/Better with common 15-byte tails from matrix stats.
    tails: list[tuple[str, bytes]] = [
        ("trail1-repeat", (matrix.trail1 * 4)[:15]),
        ("selected-secondary-first15", matrix.selected.secondary[:15]),
        ("selected-secondary-last15", matrix.selected.secondary[-15:]),
        ("rows-first15", rows[:15]),
        ("cols-first15", cols[:15]),
    ]
    for endian in ("big", "little"):
        stats13 = b"".join(pack_int(value, width, endian) for _, value, width in stat_specs)
        tails.append((f"all-stats-{endian}-plus-00", stats13 + b"\0\0"))
        tails.append((f"all-stats-{endian}-plus-trail", (stats13 + matrix.trail1)[:15]))
    for label, tail in tails:
        record_79("matrix-cosmic", f"half||better||tail/{label}", matrix.half + matrix.better_half + tail, counts, hits, samples)
        record_79("matrix-cosmic", f"better||half||tail/{label}", matrix.better_half + matrix.half + tail, counts, hits, samples)
    return {
        "cosmic_sha256": sha256_hex(chains.cosmic_decryption.plaintext),
        "matrix_invariants": stats,
        "selected_secondary_sha256": sha256_hex(matrix.selected.secondary),
        "base38_output_length": len(matrix.base38_bytes),
        "base38_output_sha256": sha256_hex(matrix.base38_bytes),
        "candidate_79_count": counts["matrix-cosmic"] - candidate_count_before,
        "composition_samples": samples[:10],
    }


def run() -> dict[str, object]:
    counts: Counter[str] = Counter()
    hits: list[CandidateHit] = []
    report = {
        "schema": "salphaseion-79-anchor-hunt-v1",
        "target_sha256": TARGET_SHA256,
        "prize_addresses": PRIZE_ADDRESSES,
        "issue82_context": issue82_context(),
        "local_hash_search": local_hash_search(),
        "known_material_windows": known_material_windows(counts, hits),
        "openssl_sweep": openssl_sweep(counts, hits),
        "matrix_cosmic_transforms": matrix_cosmic_transforms(counts, hits),
    }
    exact_matches = [hit.__dict__ for hit in hits]
    gates = [
        {
            "family": hit.family,
            "label": hit.label,
            "sha256": hit.sha256,
            "gate": gate_79_blob(bytes.fromhex(hit.hex)),
        }
        for hit in hits
    ]
    report["candidate_79_counts_by_family"] = dict(counts)
    report["exact_target_matches"] = exact_matches
    report["reproduced"] = bool(exact_matches)
    report["address_gate"] = {
        "performed": bool(exact_matches),
        "reason": "exact target 79-byte blob found" if exact_matches else "no exact target 79-byte blob was reproduced",
        "results": gates,
    }
    report["conclusion"] = (
        "Target 79-byte SalPhaseIon anchor reproduced."
        if exact_matches
        else "Target 79-byte SalPhaseIon anchor not reproduced from local files, Issue #82 context, "
        "alternate SalPhaseIon base64 parses, OpenSSL password/digest sweeps, known-material "
        "79-byte windows, or bounded Cosmic/matrix 79-byte transforms."
    )
    return report


def main() -> None:
    report = run()
    RESULT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"result_path": str(RESULT_PATH), "reproduced": report["reproduced"]}, indent=2))


if __name__ == "__main__":
    main()
