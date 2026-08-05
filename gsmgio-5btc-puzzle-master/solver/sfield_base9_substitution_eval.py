"""Evaluate every shared base-nine digit substitution for S91 and S570."""

from __future__ import annotations
import base64,bz2,gzip,heapq,hashlib,io,itertools,json,lzma,math,zlib,zipfile
from .salphaseion_raw import extract_raw,sha256_hex
from .sfield_base9_substitution_preregister import MANIFEST_PATH,RESULT_PATH,SEAL_PATH
from .sfield_cipher_eval import _score

CODECS=("utf-8","utf-16le","utf-16be","cp037","cp500","cp1140","latin1")

def _representations(text,perm,fixed_width):
    table=str.maketrans("abcdefghi","".join(map(str,perm)))
    for direction,source in (("forward",text),("reverse",text[::-1])):
        digits=source.translate(table); number=int(digits,9)
        minimal=max(1,(number.bit_length()+7)//8)
        for width_name,width in (("minimal",minimal),("fixed",fixed_width)):
            if width<minimal: continue
            big=number.to_bytes(width,"big")
            yield direction,width_name,"big",big
            yield direction,width_name,"little",big[::-1]

def _validate_binary(data):
    exact=[]
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data)>=24 and data[12:16]==b"IHDR": exact.append("PNG")
    if data.startswith(b"\xff\xd8\xff") and data.endswith(b"\xff\xd9"): exact.append("JPEG")
    if data.startswith(b"%PDF-") and b"%%EOF" in data[-64:]: exact.append("PDF")
    if data.startswith(b"PK\x03\x04"):
        try:
            if zipfile.is_zipfile(io.BytesIO(data)): exact.append("ZIP")
        except Exception: pass
    if data.startswith(b"\x7fELF") and len(data)>=20 and data[4] in (1,2) and data[5] in (1,2) and data[6]==1: exact.append("ELF")
    if data.startswith(b"MZ") and len(data)>=64:
        pe_offset=int.from_bytes(data[60:64],"little")
        if pe_offset+4<=len(data) and data[pe_offset:pe_offset+4]==b"PE\x00\x00": exact.append("PE")
    if data.startswith(b"Salted__") and len(data)>=32 and (len(data)-16)%16==0: exact.append("OpenSSL-Salted")
    decompressed=[]
    decompressors=[]
    if len(data)>=2 and data[0]==0x78 and (data[0]*256+data[1])%31==0: decompressors.append(("zlib",zlib.decompress))
    if data.startswith(b"\x1f\x8b"): decompressors.append(("gzip",gzip.decompress))
    if data.startswith(b"BZh"): decompressors.append(("bz2",bz2.decompress))
    if data.startswith(b"\xfd7zXZ\x00"): decompressors.append(("lzma",lzma.decompress))
    for name,fn in decompressors:
        try:
            output=fn(data)
            decompressed.append({"codec":name,"length":len(output),"sha256":sha256_hex(output),"preview_hex":output[:100].hex()})
        except Exception: pass
    return exact,decompressed

def _cheap_text_records(data):
    records=[]
    for codec in CODECS:
        try: text=data.decode(codec)
        except (UnicodeDecodeError,LookupError): continue
        printable=sum(c in "\n\r\t" or 32<=ord(c)<127 for c in text)/max(1,len(text))
        letterspace=sum(c.isalpha() or c.isspace() for c in text)/max(1,len(text))
        records.append((4*printable+4*letterspace,codec,printable,letterspace,text))
    return records

def main():
    encoded=MANIFEST_PATH.read_bytes(); seal=SEAL_PATH.read_text(encoding="ascii").strip()
    if sha256_hex(encoded)!=seal: raise ValueError("manifest seal mismatch")
    manifest=json.loads(encoded); raw=extract_raw(); fields={"S91":raw.s91,"S570":raw.s570}
    widths={name:manifest["source"]["fields"][name]["fixed_width_bytes"] for name in fields}
    accepted=[]; cheap_top=[]; evaluated=0; sequence=0
    for perm in itertools.permutations(range(9)):
        mapping="".join(map(str,perm)); per_mapping={}
        for field,text in fields.items():
            records=[]
            for direction,width_name,byte_order,data in _representations(text,perm,widths[field]):
                evaluated+=1; magics,decompressed=_validate_binary(data)
                record={"field":field,"direction":direction,"width":width_name,"byte_order":byte_order,"length":len(data),"sha256":sha256_hex(data),"magic":magics,"decompressed":decompressed}
                records.append(record)
                if magics or decompressed: accepted.append({"mapping":mapping,**record,"acceptance":"exact-binary"})
                for cheap,codec,printable,letterspace,text in _cheap_text_records(data):
                    sequence+=1
                    item=(cheap,sequence,{"mapping":mapping,**record,"codec":codec,"printable_ratio":printable,"letter_space_ratio":letterspace,"text_base64":base64.b64encode(text.encode("utf-8")).decode("ascii")})
                    if len(cheap_top)<1000: heapq.heappush(cheap_top,item)
                    elif item[:2]>cheap_top[0][:2]: heapq.heapreplace(cheap_top,item)
            per_mapping[field]=records
    top=[]
    for _,_,record in sorted(cheap_top,reverse=True):
        text=base64.b64decode(record.pop("text_base64")).decode("utf-8")
        metrics=_score(text); ranked={**record,"metrics":metrics,"preview":text[:300]}
        top.append(ranked)
        if metrics["accepted"]: accepted.append({**ranked,"acceptance":"readable-text"})
    top=sorted(top,key=lambda item:item["metrics"]["score"],reverse=True)[:50]
    result={"schema":"sfield-exhaustive-base9-substitution-results-v1","manifest_sha256":seal,"mappings":math.factorial(9),"representations_evaluated":evaluated,"accepted_count":len(accepted),"accepted":accepted,"top_ranked_text":top,"status":"ACCEPTED_EXACT_OR_READABLE_OUTPUT" if accepted else "NO_ACCEPTED_OUTPUT"}
    RESULT_PATH.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"manifest_sha256":seal,"mappings":math.factorial(9),"representations_evaluated":evaluated,"accepted_count":len(accepted),"best_score":top[0]["metrics"]["score"],"best_field":top[0]["field"],"best_mapping":top[0]["mapping"],"best_codec":top[0]["codec"],"best_preview":top[0]["preview"][:200],"status":result["status"]},indent=2))
if __name__=="__main__": main()
