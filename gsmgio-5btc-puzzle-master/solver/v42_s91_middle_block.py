import json
import hashlib
from pathlib import Path
from solver.targets import gate_scalar_bytes

def evaluate_int(s: str, alphabet: str, is_le: bool) -> bytes:
    val = 0
    base = len(alphabet)
    for ch in s:
        val = val * base + alphabet.index(ch)
    
    # Need to pad to 32 bytes
    b = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
    if len(b) > 32:
        # If somehow > 32 bytes, just take lowest 32 or whatever, but 49 chars in base-10 is < 32 bytes
        b = b[-32:]
    
    # Pad to 32 bytes big-endian
    padded = b.rjust(32, b'\0')
    if is_le:
        padded = padded[::-1]
    return padded

def main():
    root = Path(__file__).parent.parent
    
    parts_path = root.parent / "derived" / "salphaseion_parts.json"
    with open(parts_path) as f:
        parts = json.load(f)
        
    s91 = parts["S91"]
    assert len(s91) == 91
    
    block = s91[21:70]
    assert len(block) == 49
    
    candidates = []
    
    # 1. SHA-256
    candidates.append(hashlib.sha256(block.encode('ascii')).digest())
    # 2. Double SHA-256
    candidates.append(hashlib.sha256(hashlib.sha256(block.encode('ascii')).digest()).digest())
    
    for s in [block, block[::-1]]:
        # 3, 4: Base-9 (a-i -> 0-8)
        # We need alphabet to be 'abcdefghi' corresponding to 0..8
        candidates.append(evaluate_int(s, "abcdefghi", False))
        candidates.append(evaluate_int(s, "abcdefghi", True))
        
        # 5, 6: Base-10 (a-i -> 1-9) -> We can treat 'a' as 1, 'b' as 2, ..., 'i' as 9. 
        # So we can use a dummy 0 at index 0: '-abcdefghi'
        candidates.append(evaluate_int(s, "-abcdefghi", False))
        candidates.append(evaluate_int(s, "-abcdefghi", True))
        
    matches = []
    for c in candidates:
        assert len(c) == 32
        result = gate_scalar_bytes(c)
        if result:
            matches.append(result)
            
    out = {
        "scope_note": "v42 S91 49-Char Middle Block Format Sweep",
        "candidates_tested": len(candidates),
        "matches": matches
    }
    
    out_path = root / "results" / "v42_s91_middle_block.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

if __name__ == "__main__":
    main()
