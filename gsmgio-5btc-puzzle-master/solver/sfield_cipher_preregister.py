"""Seal direct cipher-identification families for S91 and S570.

The primary family maps the nine source symbols to the coordinates of a 3x3
square.  Each symbol then contributes two trits.  In particular S570 gives
1140 trits, exactly 380 base-27 symbols.  The finite family below fixes all row
and column label permutations, coordinate swaps, direct and fractionated
coordinate streams, directions, offsets, and source-grounded 27-character
alphabets before any plaintext is ranked.

A disjoint control treats adjacent source symbols as base-nine digit pairs and
tests only affine digit relabelings and fixed ASCII offsets.
"""

from __future__ import annotations
import hashlib
import itertools
import json
from .extract import ROOT
from .salphaseion_raw import capture_stability, extract_raw, sha256_hex

MANIFEST_PATH=ROOT/"sfield_cipher_preregistered.json"
SEAL_PATH=ROOT/"sfield_cipher_preregistered.sha256"
RESULT_PATH=ROOT/"sfield_cipher_results.json"

PERIODS=(3,7,13,15,19,23,26,30,38,91)

def _keyed_alphabet(key):
    output=[]
    for symbol in key+"abcdefghijklmnopqrstuvwxyz":
        if symbol not in output: output.append(symbol)
    return "".join(output)+" "

def build_manifest():
    raw=extract_raw()
    alphabets={
        "az-space":"abcdefghijklmnopqrstuvwxyz ",
        "space-az":" abcdefghijklmnopqrstuvwxyz",
        "keyed-lastwords-space":_keyed_alphabet(raw.lastwords_marker),
        "keyed-architect-answer-space":_keyed_alphabet("theproblemischoice"),
    }
    coordinate_specs=[]
    for row_perm in itertools.permutations(range(3)):
        for column_perm in itertools.permutations(range(3)):
            for swap in (False,True):
                for route in ("interleaved","global-deinterleaved")+tuple(f"period-{period}-deinterleaved" for period in PERIODS):
                    for direction in ("forward","reverse"):
                        for offset in (0,1,2):
                            for alphabet_name in alphabets:
                                for alphabet_reverse in (False,True):
                                    coordinate_specs.append({"row_perm":row_perm,"column_perm":column_perm,"swap_coordinates":swap,"route":route,"direction":direction,"trit_offset":offset,"alphabet":alphabet_name,"alphabet_reverse":alphabet_reverse})
    pair_specs=[]
    for multiplier in (1,2,4,5,7,8):
        for addend in range(9):
            for direction in ("forward","reverse"):
                for digit_offset in (0,1):
                    for pair_endian in ("big","little"):
                        for ascii_offset in (0,32,46,48):
                            pair_specs.append({"multiplier":multiplier,"addend":addend,"direction":direction,"digit_offset":digit_offset,"pair_endian":pair_endian,"ascii_offset":ascii_offset})
    return {"schema":"sfield-direct-cipher-identification-v1","status":"SEALED_BEFORE_OUTPUT_SCORING","source":{"capture_stability":capture_stability(),"textarea1_sha256":sha256_hex(raw.textarea1),"fields":{"S91":{"length":len(raw.s91),"sha256":sha256_hex(raw.s91.encode("ascii"))},"S570":{"length":len(raw.s570),"sha256":sha256_hex(raw.s570.encode("ascii"))}},"structural_fact":"S570 length 570 x two ternary coordinates = 1140 trits = 380 base-27 symbols exactly","alphabets":alphabets},"coordinate_family":{"spec_count":len(coordinate_specs),"specs":coordinate_specs},"base9_pair_control":{"spec_count":len(pair_specs),"specs":pair_specs},"declared_acceptance":{"padding_or_AES_used":False,"target_key_or_address_used":False,"accepted_plaintext":"at least 98 percent printable, 95 percent letters/spaces, at least five dictionary-recognized words, recognized-letter coverage at least 0.55, and length-weighted English Zipf score at least 3.5","ranking_only":"all other scores are leads, not accepted decryptions"}}

def main():
    manifest=build_manifest(); encoded=(json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded); SEAL_PATH.write_text(sha256_hex(encoded)+"\n",encoding="ascii")
    print(json.dumps({"manifest":str(MANIFEST_PATH),"coordinate_spec_count":manifest["coordinate_family"]["spec_count"],"pair_spec_count":manifest["base9_pair_control"]["spec_count"],"seal_sha256":sha256_hex(encoded)},indent=2))

if __name__=="__main__": main()
