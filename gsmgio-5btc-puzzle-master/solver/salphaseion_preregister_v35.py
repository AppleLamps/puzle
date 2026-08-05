"""Seal the corrected instruction/data grammar for the S fields.

``enter`` occupies the exact Base64 line boundary and is therefore formatting
metadata, not password material.  By the same source syntax, the raw bits that
decode to ``matrixsumlist`` delimit S91 and S570 rather than completing S91.
This round keeps S91 at its natural 7x13 size and applies the exact two-door
answer as a classical modular key to the S fields.  It then uses only the
numeric conversions already demonstrated on the same page.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json

from .extract import ROOT, extract_all
from .salphaseion_preregister_v34 import SEAL_PATH as V34_SEAL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v35.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v35.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v35.json"

KEYS = {
    "neo-core": "theproblemischoice",
    "neo-full": "choicetheproblemischoice",
    "architect-reference": "asyouadequatelyputtheproblemischoice",
}


def _integer_bytes(number: int) -> bytes:
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def _base9(values: list[int]) -> bytes:
    number = 0
    for value in values:
        number = number * 9 + value
    return _integer_bytes(number)


def _decimal_to_hex(values: list[int]) -> bytes:
    hexadecimal = format(int("".join(map(str, values))), "x")
    if len(hexadecimal) % 2:
        hexadecimal = "0" + hexadecimal
    return bytes.fromhex(hexadecimal)


def _apply(field: list[int], key: list[int], operation: str) -> list[int]:
    repeated = [key[index % len(key)] for index in range(len(field))]
    if operation == "field-minus-key":
        return [(left - right) % 9 for left, right in zip(field, repeated)]
    if operation == "key-minus-field":
        return [(right - left) % 9 for left, right in zip(field, repeated)]
    if operation == "field-plus-key":
        return [(left + right) % 9 for left, right in zip(field, repeated)]
    raise ValueError(operation)


def build_manifest():
    raw = extract_raw(); extracted = extract_all(); preimages = defaultdict(set)
    if len(raw.s91) != 91 or len(raw.matrix_marker_bits) != 104 or len(raw.s570) != 570:
        raise ValueError("raw field boundaries changed")

    def add(label, value):
        if value: preimages[value].add(f"corrected-sfield-grammar/{label}")

    records = []
    for field_name, text in (("S91", raw.s91), ("S570", raw.s570)):
        for field_origin in (0, 1):
            field = [(ord(symbol) - 97 + field_origin) % 9 for symbol in text]
            for key_name, key_text in KEYS.items():
                for key_origin in (0, 1):
                    key = [(ord(symbol) - 97 + key_origin) % 9 for symbol in key_text]
                    for operation in ("field-minus-key", "key-minus-field", "field-plus-key"):
                        transformed = _apply(field, key, operation)
                        for direction, values in (("forward", transformed), ("reverse", transformed[::-1])):
                            base = f"{field_name}/field-origin-{field_origin}/{key_name}/key-origin-{key_origin}/{operation}/{direction}"
                            add(f"{base}/digits", "".join(map(str, values)).encode("ascii"))
                            add(f"{base}/symbols-a0", bytes(97 + value for value in values))
                            add(f"{base}/raw-residue-bytes", bytes(values))
                            add(f"{base}/base9", _base9(values))
                            add(f"{base}/decimal-to-hex", _decimal_to_hex(values))
                            records.append({"label": base, "base9_sha256": sha256_hex(_base9(values)), "decimal_to_hex_sha256": sha256_hex(_decimal_to_hex(values))})

    candidates=[]
    for preimage in sorted(preimages):
        for expansion,password in (("raw",preimage),("sha256-lowerhex",hashlib.sha256(preimage).hexdigest().encode("ascii")),("sha256-raw-digest",hashlib.sha256(preimage).digest())):
            candidates.append({"candidate_id":f"v35c{len(candidates):04d}","preimage_hex":preimage.hex(),"password_expansion":expansion,"password_hex":password.hex(),"password_sha256":sha256_hex(password),"provenance":sorted(preimages[preimage])})
    blobs={"salphaseion-short":extracted.chain1_envelope,"phase32-small":extracted.chain2_envelope,"cosmic-duality":extracted.cosmic_envelope}
    return {"schema":"salphaseion-source-only-preregistration-v35-corrected-sfield-grammar","status":"SEALED_BEFORE_DECRYPTION","extends_v34_manifest_sha256":V34_SEAL.read_text(encoding="ascii").strip(),"source":{"capture_stability":capture_stability(),"textarea1_sha256":sha256_hex(raw.textarea1),"grammar":["S91","matrixsumlist instruction delimiter","S570","lastwordsbeforearchichoice","thispassword","sha256 instruction","Base64 line 1","enter line-break instruction","Base64 line 2","sha256 answer too"],"key_answers":KEYS,"operations":["field-minus-key","key-minus-field","field-plus-key"],"numeric_conversions":["base9 integer to bytes","decimal digit integer to hexadecimal bytes"]},"blobs":{name:{"length":len(value),"sha256":sha256_hex(value),"salt_hex":value[8:16].hex(),"ciphertext_length":len(value)-16} for name,value in blobs.items()},"declared_crypto":{"cipher":"AES-256-CBC","password_to_key":"OpenSSL EVP_BytesToKey","kdf_digests":["md5","sha256"],"padding":"strict PKCS#7","password_expansions":["raw","sha256-lowerhex","sha256-raw-digest"]},"declared_acceptance":{"direct":"existing readable/exact-format rule","aes":"existing v1 readable/exact-format rule","padding_alone":False,"forbidden_evidence":["expected padding length","completed 15-row matrix","Half/Better Half","target point","community plaintext hashes"]},"candidate_count":len(candidates),"candidates":candidates,"records_without_plaintext":records}


def main():
    manifest=build_manifest(); encoded=(json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded); SEAL_PATH.write_text(sha256_hex(encoded)+"\n",encoding="ascii")
    print(json.dumps({"manifest":str(MANIFEST_PATH),"candidate_count":manifest["candidate_count"],"seal_sha256":sha256_hex(encoded)},indent=2))


if __name__ == "__main__": main()
