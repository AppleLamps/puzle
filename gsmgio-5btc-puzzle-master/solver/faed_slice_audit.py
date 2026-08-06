"""Audit for the 107-character faed[94:201] slice of S570."""

import hashlib
import json
import os
from pathlib import Path

from solver.targets import gate_scalar_bytes

def get_S570():
    # Depending on where this is run from, adjust the path to derived
    path = Path("../derived/salphaseion_parts.json")
    if not path.exists():
        path = Path("derived/salphaseion_parts.json")
    with open(path) as f:
        return json.load(f)["S570"]

def get_slice():
    return get_S570()[94:201]

def run_audit():
    text = get_slice()
    candidates = set()
    
    # 1. Hashes of the raw ASCII
    candidates.add(hashlib.sha256(text.encode()).digest())
    candidates.add(hashlib.sha256(hashlib.sha256(text.encode()).digest()).digest())
    
    # Base-9 conversions
    # Map a->0, b->1, ..., i->8
    def to_base9(s):
        val = 0
        for char in s:
            val = val * 9 + (ord(char) - ord('a'))
        return val

    def get_windows(byte_val):
        wins = []
        if len(byte_val) >= 32:
            for i in range(len(byte_val) - 32 + 1):
                wins.append(byte_val[i:i+32])
        return wins

    # 43 bytes total length
    for val in [to_base9(text), to_base9(text[::-1])]:
        num_bytes = (val.bit_length() + 7) // 8
        for byteorder in ["big", "little"]:
            b_val = val.to_bytes(num_bytes, byteorder)
            for w in get_windows(b_val):
                candidates.add(w)

    # Gate them
    results = []
    for c in candidates:
        hit = gate_scalar_bytes(c)
        if hit:
            results.append({"candidate": c.hex(), "hit": hit})
            
    summary = {
        "scope_note": "v40 faed[94:201] S570 107-char slice format sweep",
        "candidates_tested": len(candidates),
        "matches": results,
    }
    
    # Save results
    out_path = Path("results/salphaseion_faed_slice_audit.json")
    out_path.parent.mkdir(exist_ok=True, parents=True)
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)

if __name__ == "__main__":
    run_audit()
