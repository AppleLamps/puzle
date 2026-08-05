"""Audit the literal on-chain ``Half`` / ``Better Half`` relationship.

This is an algebraic and transaction-structure audit.  It does not score or
search plaintexts.  It verifies the two prize spends from raw transactions,
checks whether Better Half is a simple serialization/scalar transform of the
known prize point, and tests exact affine half/double relations between the
ECDSA nonces used in the 2020 and 2024 prize spends.
"""

from __future__ import annotations

import json

from coincurve import PrivateKey, PublicKey

from .blockchain_nonce_audit import _p2pkh_script, parse_transaction
from .extract import ROOT
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "halving_relation_audit.json"
SIGNATURE_MANIFEST = ROOT / "blockchain_nonce_audit.json"
RAW_TXS = ROOT / "artifacts" / "blockchain_cache" / "raw_txs"
BETTER_HALF_ADDRESS = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
TX_2020 = "2aa9a4a90be819d5122d70c993280785a0508f163521e7b38cebb4db0b071b13"
TX_2024 = "88cdb3cdca12b471551b1b26188508a14ca5fd8a415223ffb7c190381c9b9df3"
TARGET_UNCOMPRESSED = (
    b"\x04" + TARGET_X.to_bytes(32, "big") + TARGET_Y.to_bytes(32, "big")
)
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")


def _address(public: PublicKey, compressed: bool) -> str:
    return base58check(b"\0" + hash160(public.format(compressed=compressed)))


def _raw(txid: str) -> bytes:
    return (RAW_TXS / f"{txid}.bin").read_bytes()


def _op_return(script: bytes) -> str | None:
    if not script or script[0] != 0x6A:
        return None
    if len(script) < 2:
        return ""
    opcode = script[1]
    if opcode <= 75:
        payload = script[2 : 2 + opcode]
    elif opcode == 0x4C and len(script) >= 3:
        payload = script[3 : 3 + script[2]]
    else:
        return f"hex:{script[1:].hex()}"
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return f"hex:{payload.hex()}"


def _transaction_record(txid: str) -> dict[str, object]:
    tx = parse_transaction(_raw(txid))
    better_script = _p2pkh_script(BETTER_HALF_ADDRESS)
    return {
        "txid": txid,
        "input_count": len(tx.inputs),
        "outputs": [
            {
                "vout": index,
                "satoshis": output.value,
                "script_pubkey_hex": output.script_pubkey.hex(),
                "is_better_half": output.script_pubkey == better_script,
                "op_return": _op_return(output.script_pubkey),
            }
            for index, output in enumerate(tx.outputs)
        ],
        "better_half_satoshis": sum(
            output.value for output in tx.outputs if output.script_pubkey == better_script
        ),
    }


def _simple_point_relations() -> list[dict[str, object]]:
    point = PublicKey(TARGET_UNCOMPRESSED)
    inverse_two = pow(2, -1, N)
    multipliers = {
        "same": 1,
        "half": inverse_two,
        "double": 2,
        "negative": N - 1,
        "negative_half": (-inverse_two) % N,
        "negative_double": N - 2,
    }
    records = []
    for label, multiplier in multipliers.items():
        transformed = point.multiply(multiplier.to_bytes(32, "big"))
        addresses = {
            "compressed": _address(transformed, True),
            "uncompressed": _address(transformed, False),
        }
        records.append({
            "relation": label,
            "multiplier_hex": f"{multiplier:064x}",
            "addresses": addresses,
            "better_half_match": BETTER_HALF_ADDRESS in addresses.values(),
        })
    return records


def _nonce_relation_tests(signatures: list[dict[str, object]]) -> dict[str, object]:
    left = [item for item in signatures if item["txid"] == TX_2020]
    right = [item for item in signatures if item["txid"] == TX_2024]
    inverse_two = pow(2, -1, N)
    multipliers = {
        "same": 1,
        "half": inverse_two,
        "double": 2,
        "negative": N - 1,
        "negative_half": (-inverse_two) % N,
        "negative_double": N - 2,
    }
    matches: list[dict[str, object]] = []
    tests = 0
    for a in left:
        for b in right:
            r_a, z_a = int(a["r"]), int(a["z"])
            r_b, z_b = int(b["r"]), int(b["z"])
            for relation, multiplier in multipliers.items():
                for sign_a in (1, -1):
                    for sign_b in (1, -1):
                        tests += 1
                        s_a = sign_a * int(a["s"]) % N
                        s_b = sign_b * int(b["s"]) % N
                        # k_b = multiplier * k_a.  Eliminate the shared d:
                        # (s_b*m*r_a - r_b*s_a) k_a = z_b*r_a-r_b*z_a.
                        denominator = (s_b * multiplier * r_a - r_b * s_a) % N
                        if not denominator:
                            continue
                        k_a = (z_b * r_a - r_b * z_a) * pow(denominator, -1, N) % N
                        if not k_a:
                            continue
                        k_b = multiplier * k_a % N
                        private = (s_a * k_a - z_a) * pow(r_a, -1, N) % N
                        if not private:
                            continue
                        # Exact equation checks precede the expensive point gate.
                        equations_hold = (
                            s_a * k_a - z_a - r_a * private
                        ) % N == 0 and (
                            s_b * k_b - z_b - r_b * private
                        ) % N == 0
                        public = PrivateKey.from_int(private).public_key
                        target_match = public.format(compressed=True) == TARGET_COMPRESSED
                        if equations_hold and target_match:
                            matches.append({
                                "relation": relation,
                                "vin_2020": a["vin"],
                                "vin_2024": b["vin"],
                                "signature_sign_2020": sign_a,
                                "signature_sign_2024": sign_b,
                                "nonce_2020_hex": f"{k_a:064x}",
                                "nonce_2024_hex": f"{k_b:064x}",
                                "private_hex": f"{private:064x}",
                                "target_point_match": True,
                            })
    return {"tests": tests, "matches": matches}


def run() -> dict[str, object]:
    manifest = json.loads(SIGNATURE_MANIFEST.read_text(encoding="utf-8"))
    signatures = [
        item for item in manifest["corpus"]["signatures"]
        if item["address"] == TARGET_ADDRESS and item["txid"] in (TX_2020, TX_2024)
    ]
    if len(signatures) != 6 or not all(item["signature_verified"] for item in signatures):
        raise AssertionError("expected six independently verified prize signatures")
    transactions = [_transaction_record(TX_2020), _transaction_record(TX_2024)]
    points = _simple_point_relations()
    nonce_relations = _nonce_relation_tests(signatures)
    result: dict[str, object] = {
        "schema": "gsmg-halving-relation-audit-v1",
        "status": "PRIVATE_KEY_MATCH" if nonce_relations["matches"] else "NO_PRIVATE_KEY_MATCH",
        "addresses": {"Half": TARGET_ADDRESS, "Better_Half": BETTER_HALF_ADDRESS},
        "transactions": transactions,
        "total_to_better_half_satoshis": sum(
            int(record["better_half_satoshis"]) for record in transactions
        ),
        "known_point_serializations": {
            "uncompressed_address": base58check(b"\0" + hash160(TARGET_UNCOMPRESSED)),
            "compressed_address": base58check(b"\0" + hash160(TARGET_COMPRESSED)),
        },
        "simple_point_relations": points,
        "simple_point_match": any(item["better_half_match"] for item in points),
        "nonce_relations": nonce_relations,
        "scope": (
            "Exact raw-transaction, EC point, and ECDSA equation checks only. "
            "Nonce affine offsets and general scalar searches are not included."
        ),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
