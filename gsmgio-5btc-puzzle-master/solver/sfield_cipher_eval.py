"""Evaluate sealed S-field cipher-identification families without AES."""

from __future__ import annotations
import hashlib
import json
import math
import re
from wordfreq import zipf_frequency
from .salphaseion_raw import extract_raw,sha256_hex
from .sfield_cipher_preregister import MANIFEST_PATH,RESULT_PATH,SEAL_PATH

def _coordinate_stream(text,spec):
    pairs=[]
    rp=spec["row_perm"]; cp=spec["column_perm"]
    for symbol in text:
        index=ord(symbol)-97; pair=(rp[index//3],cp[index%3])
        pairs.append(pair[::-1] if spec["swap_coordinates"] else pair)
    route=spec["route"]
    if route=="interleaved": trits=[v for pair in pairs for v in pair]
    elif route=="global-deinterleaved": trits=[p[0] for p in pairs]+[p[1] for p in pairs]
    else:
        period=int(route.split("-")[1]); trits=[]
        for start in range(0,len(pairs),period):
            block=pairs[start:start+period]; trits.extend(p[0] for p in block); trits.extend(p[1] for p in block)
    if spec["direction"]=="reverse": trits=trits[::-1]
    trits=trits[spec["trit_offset"]:]
    trits=trits[:len(trits)//3*3]
    return [trits[i]*9+trits[i+1]*3+trits[i+2] for i in range(0,len(trits),3)]

def _decode_coordinate(text,spec,alphabets):
    alphabet=alphabets[spec["alphabet"]]
    if spec["alphabet_reverse"]: alphabet=alphabet[::-1]
    return "".join(alphabet[value] for value in _coordinate_stream(text,spec))

def _decode_pairs(text,spec):
    digits=[((ord(c)-97)*spec["multiplier"]+spec["addend"])%9 for c in text]
    if spec["direction"]=="reverse": digits=digits[::-1]
    digits=digits[spec["digit_offset"]:]; digits=digits[:len(digits)//2*2]
    values=[]
    for i in range(0,len(digits),2):
        a,b=digits[i:i+2]; value=a*9+b if spec["pair_endian"]=="big" else b*9+a
        values.append((value+spec["ascii_offset"])%256)
    return bytes(values).decode("latin1")

def _score(text):
    if not text: return {"score":-999.0,"accepted":False}
    printable=sum(c in "\n\r\t" or 32<=ord(c)<127 for c in text)/len(text)
    letterspace=sum(c.isalpha() or c.isspace() for c in text)/len(text)
    words=re.findall(r"[A-Za-z]{2,}",text.lower())
    recognized=[word for word in words if zipf_frequency(word,"en")>=3.0]
    recognized_chars=sum(len(word) for word in recognized)
    alpha_chars=max(1,sum(c.isalpha() for c in text))
    coverage=recognized_chars/alpha_chars
    weighted=sum(len(word)*zipf_frequency(word,"en") for word in recognized)/max(1,recognized_chars)
    common=sum(text.upper().count(chunk) for chunk in ("THE","AND","ING","ION","THIS","THAT","YOU","PASSWORD","MATRIX","CHOICE"))/max(1,len(text))
    score=4*printable+4*letterspace+5*coverage+weighted+12*common
    accepted=printable>=.98 and letterspace>=.95 and len(recognized)>=5 and coverage>=.55 and weighted>=3.5
    return {"score":score,"accepted":accepted,"printable_ratio":printable,"letter_space_ratio":letterspace,"recognized_words":recognized,"recognized_word_count":len(recognized),"recognized_letter_coverage":coverage,"weighted_zipf":weighted,"common_chunk_rate":common}

def _record(family,field,spec,text):
    metrics=_score(text)
    return {"family":family,"field":field,"spec":spec,"output_length":len(text),"output_sha256":sha256_hex(text.encode("latin1")),"preview":text[:500],"metrics":metrics}

def main():
    encoded=MANIFEST_PATH.read_bytes(); expected=SEAL_PATH.read_text(encoding="ascii").strip()
    if sha256_hex(encoded)!=expected: raise ValueError("manifest seal mismatch")
    manifest=json.loads(encoded); raw=extract_raw(); fields={"S91":raw.s91,"S570":raw.s570}
    top=[]; accepted=[]; counts={"coordinate":0,"base9-pairs":0}
    def retain(record):
        nonlocal top
        if record["metrics"]["accepted"]: accepted.append(record)
        top.append(record); top=sorted(top,key=lambda item:item["metrics"]["score"],reverse=True)[:100]
    for spec in manifest["coordinate_family"]["specs"]:
        for field,text in fields.items():
            retain(_record("3x3-to-base27",field,spec,_decode_coordinate(text,spec,manifest["source"]["alphabets"])))
            counts["coordinate"]+=1
    for spec in manifest["base9_pair_control"]["specs"]:
        for field,text in fields.items():
            retain(_record("base9-pairs",field,spec,_decode_pairs(text,spec)))
            counts["base9-pairs"]+=1
    result={"schema":"sfield-direct-cipher-identification-results-v1","manifest_sha256":expected,"evaluated":counts,"accepted_count":len(accepted),"accepted":accepted,"top_ranked":top,"status":"ACCEPTED_READABLE_OUTPUT" if accepted else "NO_ACCEPTED_PLAINTEXT"}
    RESULT_PATH.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"manifest_sha256":expected,"evaluated":counts,"accepted_count":len(accepted),"best_score":top[0]["metrics"]["score"],"best_family":top[0]["family"],"best_field":top[0]["field"],"best_preview":top[0]["preview"][:200],"status":result["status"]},indent=2))

if __name__=="__main__": main()
