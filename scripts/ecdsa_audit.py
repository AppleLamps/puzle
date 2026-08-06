#!/usr/bin/env python3
"""Audit the prize addresses' ECDSA signatures for recoverable nonces.

If a signer ever reuses a nonce k, two signatures share the same r and the
private key falls straight out:

    k = (z1 - z2) / (s1 - s2)      d = (s1*k - z1) / r

This is worth settling because it does not depend on solving any part of the
puzzle. It also establishes what is even possible: an address that has never
spent has never published a signature or a public key, so no such analysis
exists for it.
"""

import json
import urllib.request
from collections import defaultdict

HALF = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
BETTER_HALF = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
API = "https://blockstream.info/api"

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return json.load(urllib.request.urlopen(request, timeout=60))


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


def der_rs(sig_hex):
    """Pull (r, s) out of a DER signature, ignoring the trailing sighash byte."""
    raw = bytes.fromhex(sig_hex)
    if len(raw) < 8 or raw[0] != 0x30:
        return None
    body = raw[2 : 2 + raw[1]]
    if not body or body[0] != 0x02:
        return None
    rlen = body[1]
    r = int.from_bytes(body[2 : 2 + rlen], "big")
    rest = body[2 + rlen :]
    if not rest or rest[0] != 0x02:
        return None
    slen = rest[1]
    s = int.from_bytes(rest[2 : 2 + slen], "big")
    return r, s


def signatures(address):
    """Every (r, s, pubkey, txid) this address has published."""
    found = []
    for tx in history(address):
        for index, vin in enumerate(tx["vin"]):
            prev = vin.get("prevout") or {}
            if prev.get("scriptpubkey_address") != address:
                continue
            items = list(vin.get("witness") or [])
            asm = vin.get("scriptsig_asm") or ""
            items += [tok for tok in asm.split() if not tok.startswith("OP_")]
            for token in items:
                try:
                    parsed = der_rs(token)
                except ValueError:
                    continue
                if parsed:
                    found.append((parsed[0], parsed[1], tx["txid"], index))
    return found


def main():
    for label, address in (("Half", HALF), ("Better Half", BETTER_HALF)):
        stats = get(f"{API}/address/{address}")["chain_stats"]
        spent = stats["spent_txo_sum"]
        print(f"{label:12} {address}")
        if spent == 0:
            print("  has never spent an output: no signature and no public key on chain")
            print("  -> no nonce analysis is possible, and the key is not even pubkey-exposed")
            continue
        sigs = signatures(address)
        print(f"  {len(sigs)} ECDSA signatures published")
        by_r = defaultdict(list)
        for r, s, txid, index in sigs:
            by_r[r].append((s, txid, index))
        repeats = {r: v for r, v in by_r.items() if len(v) > 1}
        print(f"  distinct r values: {len(by_r)}")
        print(f"  reused r values:   {len(repeats)}")
        for r, entries in repeats.items():
            distinct_s = {s for s, _, _ in entries}
            print(f"    r={r:#x} appears {len(entries)} times, {len(distinct_s)} distinct s")
            if len(distinct_s) > 1:
                print("    *** NONCE REUSE WITH DIFFERENT s: private key is recoverable ***")
            else:
                print("    (same r and same s: this is the same signature seen twice, not reuse)")
        smalls = [r for r in by_r if r.bit_length() < 250]
        print(f"  r values with fewer than 250 bits (a crude bias probe): {len(smalls)}")


if __name__ == "__main__":
    main()
