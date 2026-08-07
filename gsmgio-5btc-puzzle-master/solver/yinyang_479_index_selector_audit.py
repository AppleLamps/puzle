"""Evaluate sealed v71: 479/484/rot180 index selection into Architect or S570."""

from __future__ import annotations

import hashlib
import json
import math
import re

from Crypto.Cipher import AES

from . import targets
from .extract import README, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc, evp_bytes_to_key, strict_pkcs7_unpad
from .phase32_classical import BEAUFORT_KEY, PHASE32_PASSWORD, _beaufort
from .salphaseion_raw import extract_raw
from .salphaseion_split_envelope_preregister import split_envelope
from .yinyang_479_index_selector_preregister import (
    AES_TARGETS,
    BLUE_OFFSET,
    CORPORA,
    INDEX_BASES,
    INDEX_STREAMS,
    KDF_DIGESTS,
    MANIFEST_PATH,
    PASSWORD_FORMS,
    RESULT_PATH,
    SEAL_PATH,
    SELECTION_RULES,
    YINYANG_OFFSET,
    build_manifest,
    expected_aes_trials,
    expected_families,
    expected_scalar_gates,
)
from .yinyang_prime_dual_preregister import prime_lists
from .yinyang_rot180_partition_preregister import partition
from .youwon_middle_block_preregister import difference_state


ENGLISH_RUN = re.compile(rb"[A-Za-z]{6,}")


def _architect_plaintext() -> str:
    readme = README.read_text(encoding="utf-8-sig")
    match = re.search(
        r"- phase 3\.2\.1\s+The first blob.*?converted to letters:\s*\n\s*([a-z]+)",
        readme,
        re.DOTALL,
    )
    if match is None:
        raise ValueError("published Phase 3.2.1 ciphertext not found")
    return _beaufort(match.group(1), BEAUFORT_KEY)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in b"\t\n\r" or 32 <= b <= 126 for b in data) / len(data)


def _legible(data: bytes) -> bool:
    if _printable_ratio(data) < 0.85:
        return False
    return _entropy(data) <= 5.9 or bool(ENGLISH_RUN.search(data))


def _password_bytes(preimage: bytes, form: str) -> bytes:
    if form == "literal":
        return preimage
    digest = hashlib.sha256(preimage).digest()
    if form == "sha256_hex_lower":
        return digest.hex().encode("ascii")
    if form == "sha256_raw32":
        return digest
    raise ValueError(form)


def _index_stream(name: str) -> list[int]:
    lists = prime_lists()
    if name == "yellow9_primes":
        return list(lists["yellow9"])
    if name == "blue15_zero5":
        return list(lists["blue15_zero5"])
    if name == "all24_primes":
        return list(lists["all24"])
    if name == "anchor479484_alternate":
        return [YINYANG_OFFSET if index % 2 == 0 else BLUE_OFFSET for index in range(98)]
    raise ValueError(name)


def _corpora() -> dict[str, str]:
    raw = extract_raw()
    return {
        "architect_az": _architect_plaintext(),
        "s570_faed_ascii": raw.s570,
        "s91_ascii": raw.s91,
        "difference_d_ascii": difference_state()["difference_full"],
    }


def _resolve_index(value: int, base: str, length: int, *, cumulative: list[int]) -> int:
    if base == "absolute_0based":
        return value % length
    if base == "from_479_0based":
        return (YINYANG_OFFSET + value) % length
    if base == "from_479_1based":
        return (YINYANG_OFFSET + value - 1) % length
    if base == "cumulative_from_479_0based":
        cumulative[0] = (cumulative[0] + value) % length
        return cumulative[0]
    raise ValueError(base)


def _select_linear(corpus: str, indices: list[int], base: str) -> str:
    cumulative = [YINYANG_OFFSET]
    chars: list[str] = []
    for value in indices:
        pos = _resolve_index(value, base, len(corpus), cumulative=cumulative)
        chars.append(corpus[pos])
    return "".join(chars)


def _select_mask_gated(corpus: str, indices: list[int], base: str, mask: str) -> str:
    cumulative = [YINYANG_OFFSET]
    chars: list[str] = []
    stream_index = 0
    for bit in mask:
        if bit != "1" or stream_index >= len(indices):
            continue
        pos = _resolve_index(indices[stream_index], base, len(corpus), cumulative=cumulative)
        chars.append(corpus[pos])
        stream_index += 1
    return "".join(chars)


def _select_mask_dual(
    architect: str,
    s570: str,
    mask: str,
    *,
    arch_anchor: int,
    s570_anchor: int,
) -> str:
    chars: list[str] = []
    for step, bit in enumerate(mask):
        if bit == "1":
            corpus, anchor = architect, arch_anchor
        else:
            corpus, anchor = s570, s570_anchor
        pos = (anchor + step) % len(corpus)
        chars.append(corpus[pos])
    return "".join(chars)


def _select(
    rule: str,
    stream: str,
    base: str,
    corpus_name: str,
    corpora: dict[str, str],
    mask: str,
    indices: list[int],
) -> str:
    corpus = corpora[corpus_name]
    if rule == "linear_index":
        return _select_linear(corpus, indices, base)
    if rule == "mask_gated_linear":
        return _select_mask_gated(corpus, indices, base, mask)
    if rule == "mask_dual_corpus_arch479_s570484":
        return _select_mask_dual(
            corpora["architect_az"],
            corpora["s570_faed_ascii"],
            mask,
            arch_anchor=YINYANG_OFFSET,
            s570_anchor=BLUE_OFFSET,
        )
    if rule == "mask_dual_corpus_arch484_s570479":
        return _select_mask_dual(
            corpora["architect_az"],
            corpora["s570_faed_ascii"],
            mask,
            arch_anchor=BLUE_OFFSET,
            s570_anchor=YINYANG_OFFSET,
        )
    raise ValueError(rule)


def _decrypt_target(
    target: str,
    chain1: bytes,
    env48: bytes,
    raw48: bytes,
    password: bytes,
    digest: str,
) -> bytes | None:
    if target == "chain1":
        try:
            return decrypt_salted_aes256_cbc(chain1, password, digest=digest).plaintext
        except ValueError:
            return None
    if target == "env48":
        try:
            return decrypt_salted_aes256_cbc(env48, password, digest=digest).plaintext
        except ValueError:
            return None
    salt = env48[8:16]
    key, evp_iv = evp_bytes_to_key(password, salt, digest=digest)
    iv = evp_iv if target == "raw48_evp_iv" else env48[32:48]
    try:
        padded = AES.new(key, AES.MODE_CBC, iv).decrypt(raw48)
        plaintext, _ = strict_pkcs7_unpad(padded)
        return plaintext
    except ValueError:
        return None


def run() -> dict[str, object]:
    encoded = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SEAL_PATH.read_text(encoding="ascii").strip():
        raise ValueError("preregistration seal mismatch")
    manifest = json.loads(encoded)
    if json.loads(json.dumps(build_manifest())) != manifest:
        raise ValueError("manifest drift")

    targets.self_check()
    part = partition()
    mask = str(part["streams"]["rot180_inversion_mask98"])
    corpora = _corpora()
    chain1 = extract_all().chain1_envelope
    env48, raw48 = split_envelope()

    family_records: list[dict[str, object]] = []
    aes_results: list[dict[str, object]] = []
    scalar_results: list[dict[str, object]] = []
    padding_hits = 0
    legible_outputs = 0
    prize_matches: list[dict[str, object]] = []

    for rule in SELECTION_RULES:
        for stream in INDEX_STREAMS:
            indices = _index_stream(stream)
            for base in INDEX_BASES:
                corpus_names = (
                    ("architect_az",)
                    if rule.startswith("mask_dual")
                    else CORPORA
                )
                for corpus_name in corpus_names:
                    selected = _select(rule, stream, base, corpus_name, corpora, mask, indices)
                    material = selected.encode("ascii")
                    family_id = f"{rule}/{stream}/{base}/{corpus_name}"
                    family_records.append(
                        {
                            "family_id": family_id,
                            "selected_length": len(selected),
                            "selected_sha256": hashlib.sha256(material).hexdigest(),
                        }
                    )
                    for derivation in ("sha256", "double_sha256"):
                        digest = hashlib.sha256(material).digest()
                        if derivation == "double_sha256":
                            digest = hashlib.sha256(digest).digest()
                        hit = targets.gate_scalar_bytes(digest)
                        scalar_results.append(
                            {
                                "family_id": family_id,
                                "derivation": derivation,
                                "prize_match": hit,
                            }
                        )
                        if hit is not None:
                            prize_matches.append({"kind": "scalar", "family_id": family_id, **hit})

                    for form in PASSWORD_FORMS:
                        password = _password_bytes(material, form)
                        for kdf in KDF_DIGESTS:
                            for target in AES_TARGETS:
                                plaintext = _decrypt_target(target, chain1, env48, raw48, password, kdf)
                                record: dict[str, object] = {
                                    "family_id": family_id,
                                    "form": form,
                                    "kdf": kdf,
                                    "target": target,
                                    "padding_valid": plaintext is not None,
                                }
                                if plaintext is None:
                                    aes_results.append(record)
                                    continue
                                padding_hits += 1
                                leg = _legible(plaintext)
                                record["legible"] = leg
                                if leg:
                                    legible_outputs += 1
                                aes_results.append(record)

    if len(family_records) != expected_families():
        raise ValueError("family count drift")
    if len(aes_results) != expected_aes_trials():
        raise ValueError("aes trial count drift")
    if len(scalar_results) != expected_scalar_gates():
        raise ValueError("scalar gate count drift")

    phase32 = decrypt_salted_aes256_cbc(extract_all().phase32_envelope, PHASE32_PASSWORD, digest="sha256")
    status = "COMPLETE_NO_MATCH" if not prize_matches and legible_outputs == 0 else "ACCEPTED"
    result = {
        "schema": manifest["schema"],
        "status": status,
        "scope_note": manifest["scope_note"],
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        "controls": {"phase32_legible_control": phase32.plaintext.startswith(b"I've been waiting for you.")},
        "counts": {
            "families": len(family_records),
            "aes_trials": len(aes_results),
            "scalar_gates": len(scalar_results),
            "padding_hits": padding_hits,
            "legible_outputs": legible_outputs,
            "prize_matches": len(prize_matches),
        },
        "prize_matches": prize_matches,
        "legible_records": [r for r in aes_results if r.get("legible")],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import json as _json

    print(_json.dumps(run()["counts"], indent=2))
