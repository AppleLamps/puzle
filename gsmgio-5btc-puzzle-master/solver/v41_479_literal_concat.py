import json
import hashlib
from pathlib import Path
from solver.targets import gate_scalar_bytes

def main():
    root = Path(__file__).parent.parent
    phase32_path = root / "phase32_symbol_recovery.json"
    
    with open(phase32_path) as f:
        data = json.load(f)
        
    plaintext = data["plaintext"]
    assert len(plaintext) == 1539
    
    text = plaintext[479:1539]
    assert len(text) == 1060
    assert text.startswith("PRIVATEKEYYOUVEEARNEDITBUTPLEASE")
    
    l1 = "matrixsumlist"
    l2 = "lastwordsbeforearchichoice"
    l3 = "yinyang"
    
    cand1 = text + l1 + l2 + l3
    cand2 = l1 + l2 + l3 + text
    
    cands = [cand1, cand2]
    matches = []
    
    for c in cands:
        scalar = hashlib.sha256(c.encode('ascii')).digest()
        result = gate_scalar_bytes(scalar)
        if result:
            matches.append(result)
            
    out = {
        "scope_note": "v41 479-Continuation Literal 7-Phrase Concatenation",
        "candidates_tested": len(cands),
        "matches": matches
    }
    
    out_path = root / "results" / "v41_479_literal_concat.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

if __name__ == "__main__":
    main()
