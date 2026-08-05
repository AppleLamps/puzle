"""Point-gate the authenticated seven-diagonal set against Chain 4.

The structural S91/S570 route produces seven diagonals before their sums spell
``WITVEEN``.  Chain 4 independently contains C(7, 3) = 35 aligned 32-byte
blocks.  This audit tests the literal natural-order correspondence without
using padding, printability, language scoring, or an expected plaintext.

Acceptance is deliberately severe: a decrypted 32-byte block must derive one
of the two funded puzzle addresses (the original Half address or the Better
Half address), under either public-key serialization.
"""

from __future__ import annotations

import hashlib
import itertools
import json

from Crypto.Cipher import AES
from coincurve import PrivateKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .salphaseion import derive_tokens
from .secp256k1_verify import N, base58check, hash160


RESULT_PATH = ROOT / "witteveen_chain4_two_oracle_audit.json"
PRIZE_ADDRESSES = {
    "Half": "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "Better_Half": "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa",
}


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _xor(values: tuple[bytes, ...]) -> bytes:
    output = bytearray(32)
    for value in values:
        for index, byte in enumerate(value):
            output[index] ^= byte
    return bytes(output)


def _sum(values: tuple[bytes, ...]) -> bytes:
    integer = sum(int.from_bytes(value, "big") for value in values) % (1 << 256)
    return integer.to_bytes(32, "big")


def _addresses(candidate: bytes) -> dict[str, str]:
    scalar = int.from_bytes(candidate, "big") % N
    if not scalar:
        return {}
    public = PrivateKey(scalar.to_bytes(32, "big")).public_key
    return {
        name: base58check(b"\0" + hash160(public.format(compressed=compressed)))
        for name, compressed in (("uncompressed", False), ("compressed", True))
    }


def run() -> dict[str, object]:
    chains = reconstruct(extract_all(), derive_tokens())
    chain4 = reconstruct_chain4(chains)
    triples = list(itertools.combinations(range(7), 3))
    if len(chain4.blocks) != len(triples) != 35:
        raise AssertionError("expected C(7,3) and 35 Chain-4 blocks")

    # The first representation preserves the displayed structural blank.  The
    # second treats that genuine zero as an omitted character.  The remaining
    # two are the exact summed letters and exact decimal sums from the audit.
    sources = {
        "diagonal-strings-with-blank": (b"W", b"VN", b"_KJ", b"CHCK", b"WJZ", b"JV", b"N"),
        "diagonal-strings-zero-omitted": (b"W", b"VN", b"KJ", b"CHCK", b"WJZ", b"JV", b"N"),
        "diagonal-sum-letters": tuple(bytes([byte]) for byte in b"WITVEEN"),
        "diagonal-sum-decimals": tuple(str(value).encode("ascii") for value in (22, 34, 19, 21, 56, 30, 13)),
    }
    ivs = {
        "ecb": None,
        "cbc-zero": bytes(16),
        "cbc-operand-head": chain4.opcode_operand[:16],
        "cbc-operand-tail": chain4.opcode_operand[-16:],
    }

    tested = 0
    matches: list[dict[str, object]] = []
    model_digests: list[dict[str, object]] = []
    for source_name, elements in sources.items():
        for case_name, routed in (
            ("source-case", elements),
            ("lowercase", tuple(value.lower() for value in elements)),
        ):
            for direction_name, order in (("forward", (0, 1, 2)), ("reverse", (2, 1, 0))):
                for separator_name, separator in (("empty", b""), ("nul", b"\0")):
                    key_sets: dict[str, list[bytes]] = {
                        "sha256-joined": [],
                        "xor-member-sha256": [],
                        "sum-member-sha256": [],
                    }
                    for triple in triples:
                        members = tuple(routed[triple[index]] for index in order)
                        digests = tuple(_sha256(member) for member in members)
                        key_sets["sha256-joined"].append(_sha256(separator.join(members)))
                        key_sets["xor-member-sha256"].append(_xor(digests))
                        key_sets["sum-member-sha256"].append(_sum(digests))

                    for key_model, keys in key_sets.items():
                        model_hash = hashlib.sha256(b"".join(keys)).hexdigest()
                        model_digests.append({
                            "source": source_name,
                            "case": case_name,
                            "direction": direction_name,
                            "separator": separator_name,
                            "key_model": key_model,
                            "key_stream_sha256": model_hash,
                        })
                        for mode_name, iv in ivs.items():
                            for block_index, (key, block) in enumerate(zip(keys, chain4.blocks)):
                                if iv is None:
                                    plaintext = AES.new(key, AES.MODE_ECB).decrypt(block)
                                else:
                                    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(block)
                                tested += 1
                                addresses = _addresses(plaintext)
                                for serialization, address in addresses.items():
                                    if address not in PRIZE_ADDRESSES.values():
                                        continue
                                    matches.append({
                                        "source": source_name,
                                        "case": case_name,
                                        "direction": direction_name,
                                        "separator": separator_name,
                                        "key_model": key_model,
                                        "mode": mode_name,
                                        "triple": list(triples[block_index]),
                                        "block_index": block_index,
                                        "private_hex": plaintext.hex(),
                                        "serialization": serialization,
                                        "address": address,
                                        "prize_role": next(role for role, target in PRIZE_ADDRESSES.items() if target == address),
                                    })

    result: dict[str, object] = {
        "schema": "witteveen-chain4-two-prize-oracle-audit-v1",
        "status": "MATCH" if matches else "NO_MATCH",
        "source": {
            "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
            "block_count": len(chain4.blocks),
            "combination": "natural lexicographic C(7,3)",
            "seven_diagonal_strings": ["W", "VN", "_KJ", "CHCK", "WJZ", "JV", "N"],
            "seven_diagonal_sum_letters": "WITVEEN",
        },
        "prize_addresses": PRIZE_ADDRESSES,
        "model_count": len(model_digests),
        "decryptions_point_gated": tested,
        "matches": matches,
        "model_digests": model_digests,
        "scope": "No plaintext/padding acceptance; only exact P2PKH ownership of either funded prize address.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"],
        "model_count": output["model_count"],
        "decryptions_point_gated": output["decryptions_point_gated"],
        "matches": output["matches"],
    }, indent=2))
