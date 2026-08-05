"""Seal Neo's last words before the Architect's two-door choice explanation."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import re

from .extract import ROOT, extract_all
from .salphaseion_preregister_v33 import SEAL_PATH as V33_SEAL, TRANSCRIPT_URL
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex


MANIFEST_PATH = ROOT / "salphaseion_preregistered_candidates_v34.json"
SEAL_PATH = ROOT / "salphaseion_preregistered_candidates_v34.sha256"
RESULT_PATH = ROOT / "salphaseion_blind_results_v34.json"

LINES = {
    "neo-last-words": "Choice. The problem is choice.",
    "architect-reference": "As you adequately put, the problem is choice.",
}


def build_manifest():
    raw = extract_raw(); extracted = extract_all(); preimages = defaultdict(set)
    if raw.lastwords_marker != "lastwordsbeforearchichoice": raise ValueError("instruction changed")

    def add(label, text):
        if text: preimages[text.encode("utf-8")].add(f"last-words-before-architect-choice/{label}")

    for line_name, line in LINES.items():
        words = re.findall(r"[A-Za-z]+", line)
        for start in range(len(words)):
            suffix = words[start:]
            for spacing, text in (("compact", "".join(suffix)), ("spaces", " ".join(suffix))):
                add(f"{line_name}/suffix-{start}/{spacing}/lower", text.lower())
                add(f"{line_name}/suffix-{start}/{spacing}/upper", text.upper())
                add(f"{line_name}/suffix-{start}/{spacing}/title", text.title())
        add(f"{line_name}/punctuated/source", line)
        add(f"{line_name}/punctuated/lower", line.lower())
        add(f"{line_name}/punctuated/upper", line.upper())

    candidates=[]
    for preimage in sorted(preimages):
        for expansion,password in (("raw",preimage),("sha256-lowerhex",hashlib.sha256(preimage).hexdigest().encode("ascii")),("sha256-raw-digest",hashlib.sha256(preimage).digest())):
            candidates.append({"candidate_id":f"v34c{len(candidates):03d}","preimage_hex":preimage.hex(),"preimage_utf8":preimage.decode("utf-8"),"password_expansion":expansion,"password_hex":password.hex(),"password_sha256":sha256_hex(password),"provenance":sorted(preimages[preimage])})
    blobs={"salphaseion-short":extracted.chain1_envelope,"phase32-small":extracted.chain2_envelope,"cosmic-duality":extracted.cosmic_envelope}
    return {"schema":"salphaseion-source-only-preregistration-v34-neo-last-words","status":"SEALED_BEFORE_DECRYPTION","extends_v33_manifest_sha256":V33_SEAL.read_text(encoding="ascii").strip(),"source":{"capture_stability":capture_stability(),"textarea1_sha256":sha256_hex(raw.textarea1),"transcript_url":TRANSCRIPT_URL,"exact_lines":LINES,"candidate_rule":"every whole-word suffix including the final word choice, compact/spaced and lower/upper/title case, plus exact punctuation"},"blobs":{name:{"length":len(value),"sha256":sha256_hex(value),"salt_hex":value[8:16].hex(),"ciphertext_length":len(value)-16} for name,value in blobs.items()},"declared_crypto":{"cipher":"AES-256-CBC","password_to_key":"OpenSSL EVP_BytesToKey","kdf_digests":["md5","sha256"],"padding":"strict PKCS#7","password_expansions":["raw","sha256-lowerhex","sha256-raw-digest"]},"declared_acceptance":{"aes":"existing v1 readable/exact-format rule","padding_alone":False,"forbidden_evidence":["expected padding length","Half/Better Half","target point","community plaintext hashes"]},"candidate_count":len(candidates),"candidates":candidates}


def main():
    manifest=build_manifest(); encoded=(json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded); SEAL_PATH.write_text(sha256_hex(encoded)+"\n",encoding="ascii")
    print(json.dumps({"manifest":str(MANIFEST_PATH),"candidate_count":manifest["candidate_count"],"seal_sha256":sha256_hex(encoded)},indent=2))


if __name__ == "__main__": main()
