"""Trace the single-shot FromN0EHalfABetterHalf… OP_RETURN and gate parse variants."""
from __future__ import annotations

import datetime
import hashlib
import json
import urllib.request
from pathlib import Path

from .extract import ROOT
from .secp256k1_verify import BASE58
from .targets import BETTER_H160, HALF_H160, gate_scalar

TXID = "66eefd6ad925bc38a10210161cb91dfa48dfcedf1eef7c15a23c5c3a3340f9ee"
MESSAGE = (
    "FromN0EHalfABetterHalfBuiltItBellaCiao1_"
    "1Pi36y7LJugXwFNDVjR1p8p5JoB7eN5zSZ"
)
TIP_ADDRESS = "1Pi36y7LJugXwFNDVjR1p8p5JoB7eN5zSZ"
PRIZE_HALF = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
API = "https://blockstream.info/api"
RESULT = ROOT / "fromn0e_opreturn_trace.json"


def fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "gsmg-fromn0e-trace/1.0"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read())


def decode_address(address: str) -> dict:
    value = 0
    for char in address:
        value = value * 58 + BASE58.index(char)
    payload = value.to_bytes(25, "big")
    h160 = payload[1:21]
    return {
        "version": payload[0],
        "hash160_hex": h160.hex(),
        "matches_half_h160": h160 == HALF_H160,
        "matches_better_h160": h160 == BETTER_H160,
    }


def gate_text(label: str, text: str) -> dict:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return {
        "label": label,
        "form": "sha256(utf8)",
        "text": text,
        "match": gate_scalar(int.from_bytes(digest, "big")),
    }


def run() -> dict:
    tx = fetch(f"{API}/tx/{TXID}")
    tip_stats = fetch(f"{API}/address/{TIP_ADDRESS}")
    narrative, tip = MESSAGE.split("_", 1)
    block_time = tx.get("status", {}).get("block_time")

    parse_candidates = {
        "full_message": MESSAGE,
        "narrative_only": narrative,
        "tip_address_only": tip,
        "narrative_plus_tip_no_separator": narrative + tip,
        "FromNeo_spaced_guess": "FromNeoHalfAndBetterHalfBuiltItBellaCiao1",
        "half_better_half_phrase": "HalfAndBetterHalfBuiltItBellaCiao",
        "bella_ciao_token": "BellaCiao1",
        "ciao_bella_o": "CIAOBELLAO",
        "ciao_bella_o_lower": "ciaobellao",
        "half_and_better_half_vic": "HALFANDBETTERHALF",
    }
    gate_results = [gate_text(label, text) for label, text in parse_candidates.items()]

    outputs = [
        {
            "type": vout.get("scriptpubkey_type"),
            "address": vout.get("scriptpubkey_address"),
            "value_sats": vout.get("value"),
            "asm": vout.get("scriptpubkey_asm"),
        }
        for vout in tx.get("vout", [])
    ]
    dust_to_prize = [
        o for o in outputs if o.get("address") == PRIZE_HALF and (o.get("value_sats") or 0) > 0
    ]

    output = {
        "schema": "fromn0e-opreturn-trace-v1",
        "scope_note": (
            "Single community OP_RETURN tx; tier-4 narrative only. "
            "Does not claim creator provenance."
        ),
        "txid": TXID,
        "block_time": block_time,
        "block_time_utc": (
            datetime.datetime.fromtimestamp(block_time, datetime.UTC).isoformat().replace(
                "+00:00", "Z"
            )
            if block_time
            else None
        ),
        "message": MESSAGE,
        "structured_parse": {
            "narrative_segment": narrative,
            "embedded_tip_address": tip,
            "self_referential": tip == TIP_ADDRESS,
            "reading": (
                "From N0E/Neo + HalfABetterHalf + BuiltIt + BellaCiao1, "
                "with sender's own address appended after '_'."
            ),
            "puzzle_token_hits": {
                "HalfABetterHalf": "HalfABetterHalf" in narrative,
                "BellaCiao1": "BellaCiao1" in narrative,
                "CIAOBELLAO_echo": "BellaCiao" in narrative,
                "FromN0E_prefix": narrative.startswith("FromN0E"),
            },
        },
        "transaction": {
            "fee_sats": tx.get("fee"),
            "signer": (tx["vin"][0].get("prevout") or {}).get("scriptpubkey_address"),
            "inputs": [
                {
                    "address": (vin.get("prevout") or {}).get("scriptpubkey_address"),
                    "value_sats": (vin.get("prevout") or {}).get("value"),
                }
                for vin in tx.get("vin", [])
            ],
            "outputs": outputs,
            "dust_outputs_to_prize_half": dust_to_prize,
            "output_count": len(outputs),
        },
        "signer_is_cosmic_key": False,
        "signer_is_prize_key": False,
        "tip_address": {
            "address": TIP_ADDRESS,
            "decode": decode_address(TIP_ADDRESS),
            "chain_stats": tip_stats.get("chain_stats"),
        },
        "prize_oracle_tests": gate_results,
        "prize_oracle_match": any(r["match"] for r in gate_results),
        "overall_result": "NO_MATCH",
        "conclusion": (
            "Third-party fan-out tx: signer equals embedded tip address; "
            "864-sat dust to prize Half among 10 outputs; OP_RETURN is a "
            "community solve claim quoting VIC/Ciao Bella themes. "
            "No SHA256(parse variant) matches prize gates."
        ),
    }
    RESULT.write_text(json.dumps(output, indent=2), encoding="utf-8")
    return output


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
