#!/usr/bin/env python3
"""Verify the prize addresses and the creator's halving pattern on-chain.

Phase 3.2.2 is reported to say the private keys belong to "HALF AND BETTER HALF"
and "need funds to live". That is checkable: the prize address and the address it
funded are both public, and the transfers between them line up with Bitcoin's
halvings.
"""

import datetime
import json
import urllib.request

HALF = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER_HALF = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
API = "https://blockstream.info/api"

# block heights of the Bitcoin halvings, for comparison with the transfer blocks
HALVINGS = {210000: "2012", 420000: "2016", 630000: "2020", 840000: "2024", 1050000: "2028"}


def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return json.load(urllib.request.urlopen(request, timeout=60))


def balance(address):
    stats = get(f"{API}/address/{address}")["chain_stats"]
    return (
        stats["tx_count"],
        stats["funded_txo_sum"] / 1e8,
        stats["spent_txo_sum"] / 1e8,
        (stats["funded_txo_sum"] - stats["spent_txo_sum"]) / 1e8,
    )


def history(address):
    out, last = [], None
    while True:
        url = f"{API}/address/{address}/txs/chain" + (f"/{last}" if last else "")
        batch = get(url)
        if not batch:
            break
        out += batch
        last = batch[-1]["txid"]
        if len(batch) < 25:
            break
    return out


def when(tx):
    ts = tx["status"].get("block_time")
    return datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%d") if ts else "?"


def main():
    for label, address in (("Half", HALF), ("Better Half", BETTER_HALF)):
        count, funded, spent, held = balance(address)
        print(f"{label:12} {address}")
        print(f"  {count:4} txs   received {funded:.8f}   spent {spent:.8f}   balance {held:.8f} BTC")

    print("\ntransfers from the prize address to the second address")
    total = 0.0
    for tx in sorted(history(BETTER_HALF), key=lambda t: t["status"].get("block_time") or 0):
        senders = {v.get("prevout", {}).get("scriptpubkey_address") for v in tx["vin"]}
        if HALF not in senders:
            continue
        amount = sum(
            v["value"] for v in tx["vout"] if v.get("scriptpubkey_address") == BETTER_HALF
        ) / 1e8
        height = tx["status"]["block_height"]
        prior = max((h for h in HALVINGS if h <= height), default=None)
        gap = height - prior if prior else None
        print(
            f"  {when(tx)}  {amount:>10.8f} BTC  block {height}"
            f"  ({HALVINGS[prior]} halving at {prior}, +{gap} blocks)"
        )
        total += amount
    print(f"  total moved: {total:.8f} BTC")

    print("\nOP_RETURN messages carried on these addresses")
    seen = {}
    for address in (HALF, BETTER_HALF):
        for tx in history(address):
            for out in tx["vout"]:
                if out.get("scriptpubkey_type") != "op_return":
                    continue
                payload = out["scriptpubkey_asm"].split(" ")[-1]
                try:
                    message = bytes.fromhex(payload).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    continue
                if message.strip():
                    seen.setdefault(message.strip(), when(tx))
    for message, date in sorted(seen.items(), key=lambda kv: kv[1]):
        print(f"  {date}  {message[:90]!r}")


if __name__ == "__main__":
    main()
