"""Seal exhaustive monoalphabetic substitution of the S-field base-nine digits.

All 9! bijections from source symbols a..i to digits 0..8 are tested.  One
mapping must apply to both S91 and S570.  Each stream is interpreted only as a
whole base-nine integer, using forward/reversed digit order, minimal/fixed byte
width, and big/little byte order.  Output is validated as text, a known file,
or a losslessly decompressible stream; AES is not involved.
"""

from __future__ import annotations
import json,math
from .extract import ROOT
from .salphaseion_raw import capture_stability,extract_raw,sha256_hex

MANIFEST_PATH=ROOT/"sfield_base9_substitution_preregistered.json"
SEAL_PATH=ROOT/"sfield_base9_substitution_preregistered.sha256"
RESULT_PATH=ROOT/"sfield_base9_substitution_results.json"

def build_manifest():
    raw=extract_raw()
    return {"schema":"sfield-exhaustive-base9-substitution-v1","status":"SEALED_BEFORE_OUTPUT_SCORING","source":{"capture_stability":capture_stability(),"textarea1_sha256":sha256_hex(raw.textarea1),"fields":{"S91":{"length":91,"sha256":sha256_hex(raw.s91.encode("ascii")),"fixed_width_bytes":math.ceil(91*math.log2(9)/8)},"S570":{"length":570,"sha256":sha256_hex(raw.s570.encode("ascii")),"fixed_width_bytes":math.ceil(570*math.log2(9)/8)}}},"mapping_family":{"alphabet":"abcdefghi","digit_permutations":"all lexicographic permutations of 012345678","mapping_count":math.factorial(9),"shared_mapping_across_fields":True},"representations":{"digit_directions":["forward","reverse"],"byte_widths":["minimal","fixed information-theoretic ceiling"],"byte_orders":["big","little"],"text_codecs":["utf-8","utf-16le","utf-16be","cp037","cp500","cp1140","latin1"],"file_validators":["PNG","JPEG","PDF","ZIP","GZIP","BZIP2","XZ","ELF","PE","OpenSSL Salted__"],"decompressors":["zlib","gzip","bz2","lzma"]},"declared_acceptance":{"AES_or_padding_used":False,"target_key_or_address_used":False,"text":"same fixed English gate as direct cipher audit","binary":"exact magic or successful lossless decompression only","shared_mapping":"accepted mapping must be reported for both fields even if only one validates"}}

def main():
    manifest=build_manifest(); encoded=(json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded); SEAL_PATH.write_text(sha256_hex(encoded)+"\n",encoding="ascii")
    print(json.dumps({"manifest":str(MANIFEST_PATH),"mapping_count":manifest["mapping_family"]["mapping_count"],"seal_sha256":sha256_hex(encoded)},indent=2))
if __name__=="__main__": main()
