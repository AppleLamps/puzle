"""Seal S91 matrix-sum-list keying of S570 before the Architect password.

S91 naturally forms 7x13 under the adjacent 13-character instruction.  This
round derives its row and column sum lists in Z/9Z, repeats each list over S570,
then applies the exact two-door answer as a second modular key.  Both operation
orders are fixed, and only the page-established numeric decodings are emitted.
"""

from __future__ import annotations
from collections import defaultdict
import hashlib
import json
from .extract import ROOT, extract_all
from .salphaseion_preregister_v35 import KEYS, SEAL_PATH as V35_SEAL, _base9, _decimal_to_hex
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex

MANIFEST_PATH=ROOT/"salphaseion_preregistered_candidates_v36.json"
SEAL_PATH=ROOT/"salphaseion_preregistered_candidates_v36.sha256"
RESULT_PATH=ROOT/"salphaseion_blind_results_v36.json"

def _op(left,key,name):
    repeated=[key[i%len(key)] for i in range(len(left))]
    if name=="left-minus-key": return [(a-b)%9 for a,b in zip(left,repeated)]
    if name=="key-minus-left": return [(b-a)%9 for a,b in zip(left,repeated)]
    if name=="left-plus-key": return [(a+b)%9 for a,b in zip(left,repeated)]
    raise ValueError(name)

def build_manifest():
    raw=extract_raw(); extracted=extract_all(); preimages=defaultdict(set)
    if len(raw.s91)!=91 or raw.matrix_marker!="matrixsumlist": raise ValueError("S91 boundary changed")
    records=[]
    for origin in (0,1):
        values=[(ord(c)-97+origin)%9 for c in raw.s91]
        matrix=[values[i:i+13] for i in range(0,91,13)]
        sum_lists={
            "row-sums-mod9":[sum(row)%9 for row in matrix],
            "column-sums-mod9":[sum(row[col] for row in matrix)%9 for col in range(13)],
            "rows-then-columns-mod9":[sum(row)%9 for row in matrix]+[sum(row[col] for row in matrix)%9 for col in range(13)],
            "columns-then-rows-mod9":[sum(row[col] for row in matrix)%9 for col in range(13)]+[sum(row)%9 for row in matrix],
        }
        field=[(ord(c)-97+origin)%9 for c in raw.s570]
        for sums_name,sums in sum_lists.items():
            for matrix_op in ("left-minus-key","key-minus-left","left-plus-key"):
                stage1=_op(field,sums,matrix_op)
                for key_name,key_text in KEYS.items():
                    for key_origin in (0,1):
                        architect=[(ord(c)-97+key_origin)%9 for c in key_text]
                        for architect_op in ("left-minus-key","key-minus-left","left-plus-key"):
                            for order,output in (
                                ("matrix-then-architect",_op(stage1,architect,architect_op)),
                                ("architect-then-matrix",_op(_op(field,architect,architect_op),sums,matrix_op)),
                            ):
                                for direction,routed in (("forward",output),("reverse",output[::-1])):
                                    label=f"origin-{origin}/{sums_name}/{matrix_op}/{key_name}/key-origin-{key_origin}/{architect_op}/{order}/{direction}"
                                    for encoding,value in (
                                        ("digits","".join(map(str,routed)).encode("ascii")),
                                        ("symbols-a0",bytes(97+x for x in routed)),
                                        ("raw-residue-bytes",bytes(routed)),
                                        ("base9",_base9(routed)),
                                        ("decimal-to-hex",_decimal_to_hex(routed)),
                                    ): preimages[value].add(f"s91-sumlist-keyed-s570/{label}/{encoding}")
                                    records.append({"label":label,"base9_sha256":sha256_hex(_base9(routed)),"decimal_to_hex_sha256":sha256_hex(_decimal_to_hex(routed))})
    candidates=[]
    for preimage in sorted(preimages):
        for expansion,password in (("raw",preimage),("sha256-lowerhex",hashlib.sha256(preimage).hexdigest().encode("ascii")),("sha256-raw-digest",hashlib.sha256(preimage).digest())):
            candidates.append({"candidate_id":f"v36c{len(candidates):05d}","preimage_hex":preimage.hex(),"password_expansion":expansion,"password_hex":password.hex(),"password_sha256":sha256_hex(password),"provenance":sorted(preimages[preimage])})
    blobs={"salphaseion-short":extracted.chain1_envelope,"phase32-small":extracted.chain2_envelope,"cosmic-duality":extracted.cosmic_envelope}
    return {"schema":"salphaseion-source-only-preregistration-v36-s91-sumlist-keyed-s570","status":"SEALED_BEFORE_DECRYPTION","extends_v35_manifest_sha256":V35_SEAL.read_text(encoding="ascii").strip(),"source":{"capture_stability":capture_stability(),"textarea1_sha256":sha256_hex(raw.textarea1),"layout":"S91=7x13 only; marker bits excluded as instruction metadata","sum_lists":["rows","columns","rows then columns","columns then rows"],"operations":["difference in both directions","sum"],"architect_keys":KEYS,"stage_orders":["matrix then Architect","Architect then matrix"],"records_without_plaintext":records},"blobs":{name:{"length":len(value),"sha256":sha256_hex(value),"salt_hex":value[8:16].hex(),"ciphertext_length":len(value)-16} for name,value in blobs.items()},"declared_crypto":{"cipher":"AES-256-CBC","password_to_key":"OpenSSL EVP_BytesToKey","kdf_digests":["md5","sha256"],"padding":"strict PKCS#7","password_expansions":["raw","sha256-lowerhex","sha256-raw-digest"]},"declared_acceptance":{"aes":"existing v1 readable/exact-format rule","padding_alone":False,"direct_digit_or_symbol_strings":False,"forbidden_evidence":["expected padding length","completed 15-row matrix","Half/Better Half","target point","community plaintext hashes"]},"candidate_count":len(candidates),"candidates":candidates}

def main():
    manifest=build_manifest(); encoded=(json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded); SEAL_PATH.write_text(sha256_hex(encoded)+"\n",encoding="ascii")
    print(json.dumps({"manifest":str(MANIFEST_PATH),"candidate_count":manifest["candidate_count"],"seal_sha256":sha256_hex(encoded)},indent=2))

if __name__=="__main__": main()
