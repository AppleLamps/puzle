"""Evaluate the corrected S-field instruction grammar."""

from __future__ import annotations
import base64
import hashlib
import json
from .salphaseion_blind_eval import _formats, _readable, evaluate
from .salphaseion_preregister_v35 import MANIFEST_PATH, RESULT_PATH, SEAL_PATH

def main():
    result=evaluate(MANIFEST_PATH,SEAL_PATH,RESULT_PATH)
    manifest=json.loads(MANIFEST_PATH.read_bytes()); unique={}
    for candidate in manifest["candidates"]: unique.setdefault(candidate["preimage_hex"],candidate["provenance"])
    direct=[]
    for value_hex,provenance in unique.items():
        value=bytes.fromhex(value_hex); readable,metrics=_readable(value); formats=_formats(value)
        if readable or formats:
            direct.append({"sha256":hashlib.sha256(value).hexdigest(),"base64":base64.b64encode(value).decode("ascii"),"provenance":provenance,"readable":readable,"metrics":metrics,"formats":formats})
    result["accepted_direct_count"]=len(direct); result["accepted_direct"]=direct
    result["status"]="ACCEPTED" if direct or result["accepted"] or result["cross_blob"] else "NO_ACCEPTED_RESULT"
    RESULT_PATH.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"manifest_sha256":result["manifest_sha256"],"attempts":result["attempts"],"strict_padding_hit_count":result["strict_padding_hit_count"],"accepted_direct_count":len(direct),"accepted_single_blob_count":result["accepted_single_blob_count"],"accepted_cross_blob_rule_count":result["accepted_cross_blob_rule_count"],"status":result["status"]},indent=2))

if __name__ == "__main__": main()
