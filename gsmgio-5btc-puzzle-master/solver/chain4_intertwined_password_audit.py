"""Audit Chain 4 as 35 ciphertexts under C(7,3) intertwined passwords.

The authenticated Architect plaintext mentions seven intertwined passwords,
and Chain 4 contains exactly 35 aligned 32-byte blocks.  Since C(7,3)=35, this
tests a missing possibility from the prior combinatorial audit: the blocks may
be encrypted *by* triple-derived keys rather than equal to triple-derived
hashes or arithmetic folds.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json

from Crypto.Cipher import AES
from coincurve import PrivateKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .salphaseion_blind_eval import _formats, _readable
from .secp256k1_verify import N, base58check, hash160


MANIFEST_PATH = ROOT / "chain4_intertwined_preregistered.json"
SEAL_PATH = ROOT / "chain4_intertwined_preregistered.sha256"
RESULT_PATH = ROOT / "chain4_intertwined_results.json"
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")
SEPARATORS = {"empty": b"", "nul": b"\0", "colon": b":", "newline": b"\n"}


def _sha(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _strict_unpad(value: bytes) -> bytes | None:
    if not value:
        return None
    count = value[-1]
    if not 1 <= count <= 16 or value[-count:] != bytes([count]) * count:
        return None
    return value[:-count]


def _models() -> list[dict[str, object]]:
    sal = derive_tokens()
    triples = list(itertools.combinations(range(7), 3))
    models: list[dict[str, object]] = []

    sources = {
        "raw-tokens": [token.encode("utf-8") for token in sal.tokens],
        "digest-bytes": list(sal.digests),
        "digest-lowerhex": [digest.hex().encode("ascii") for digest in sal.digests],
    }
    for source_name, elements in sources.items():
        for order in itertools.permutations(range(3)):
            for separator_name, separator in SEPARATORS.items():
                keys = [
                    _sha(separator.join(elements[triple[index]] for index in order))
                    for triple in triples
                ]
                models.append({
                    "name": f"sha256/{source_name}/order-{''.join(map(str, order))}/{separator_name}",
                    "keys": [key.hex() for key in keys],
                })

    digest_ints = [int.from_bytes(digest, "big") for digest in sal.digests]
    xor_keys = []
    sum_keys = []
    for triple in triples:
        xor_value = 0
        for index in triple:
            xor_value ^= digest_ints[index]
        xor_keys.append(xor_value.to_bytes(32, "big"))
        sum_keys.append((sum(digest_ints[index] for index in triple) % (1 << 256)).to_bytes(32, "big"))
    models.extend([
        {"name": "triple-digest-xor", "keys": [key.hex() for key in xor_keys]},
        {"name": "triple-digest-sum-mod-2^256", "keys": [key.hex() for key in sum_keys]},
    ])
    return models


def build_manifest() -> dict[str, object]:
    chain4 = reconstruct_chain4(reconstruct(extract_all(), derive_tokens()))
    models = _models()
    ivs = {
        "ecb": b"",
        "cbc-zero": bytes(16),
        "cbc-operand-head": chain4.opcode_operand[:16],
        "cbc-operand-tail": chain4.opcode_operand[-16:],
    }
    return {
        "schema": "chain4-c7-3-intertwined-password-cipher-audit-v1",
        "status": "SEALED_BEFORE_DECRYPTION",
        "source": {
            "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
            "block_count": len(chain4.blocks),
            "block_sha256": [hashlib.sha256(block).hexdigest() for block in chain4.blocks],
            "combination_rule": "lexicographic C(7,3)",
            "architect_phrase": "SEVEN INTERTWINED PASSWORDS",
        },
        "cipher_modes": {name: value.hex() for name, value in ivs.items()},
        "acceptance": {
            "structural": "strict PKCS7 plus readable text or exact parser/format",
            "assignment_independent": "maximum bipartite matching on strict-padding edges",
            "cryptographic": "complete secp256k1 prize point plus P2PKH address",
            "padding_alone": False,
        },
        "models": models,
    }


def prepare() -> None:
    manifest = build_manifest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(encoded)
    SEAL_PATH.write_text(hashlib.sha256(encoded).hexdigest() + "\n", encoding="ascii")
    print(json.dumps({
        "model_count": len(manifest["models"]),
        "keys_per_model": 35,
        "cipher_mode_count": len(manifest["cipher_modes"]),
        "seal_sha256": hashlib.sha256(encoded).hexdigest(),
    }, indent=2))


def _maximum_matching(graph: list[set[int]], right_size: int) -> int:
    assigned: list[int | None] = [None] * right_size

    def augment(left: int, visited: set[int]) -> bool:
        for right in graph[left]:
            if right in visited:
                continue
            visited.add(right)
            if assigned[right] is None or augment(assigned[right], visited):
                assigned[right] = left
                return True
        return False

    return sum(augment(left, set()) for left in range(len(graph)))


def _target_gate(value: bytes) -> dict[str, object] | None:
    scalar = int.from_bytes(value, "big") % N
    if not scalar:
        return None
    public = PrivateKey(scalar.to_bytes(32, "big")).public_key
    if public.format(compressed=True) != TARGET_COMPRESSED:
        return None
    address = base58check(b"\0" + hash160(public.format(compressed=False)))
    return {
        "private_hex": f"{scalar:064x}",
        "address": address,
        "address_match": address == TARGET_ADDRESS,
    }


def run() -> None:
    encoded = MANIFEST_PATH.read_bytes()
    seal = SEAL_PATH.read_text(encoding="ascii").strip()
    if hashlib.sha256(encoded).hexdigest() != seal:
        raise ValueError("manifest seal mismatch")
    manifest = json.loads(encoded)
    chain4 = reconstruct_chain4(reconstruct(extract_all(), derive_tokens()))
    if hashlib.sha256(chain4.decryption.plaintext).hexdigest() != manifest["source"]["chain4_sha256"]:
        raise ValueError("Chain 4 source changed after sealing")

    mode_ivs = {name: bytes.fromhex(value) for name, value in manifest["cipher_modes"].items()}
    model_records: list[dict[str, object]] = []
    accepted: list[dict[str, object]] = []
    target_matches: list[dict[str, object]] = []
    decryptions = 0
    for model in manifest["models"]:
        keys = [bytes.fromhex(value) for value in model["keys"]]
        for mode_name, iv in mode_ivs.items():
            padding_graph: list[set[int]] = [set() for _ in keys]
            semantic_edges: list[dict[str, object]] = []
            natural_padding = 0
            natural_semantic = 0
            printable_total = 0
            for key_index, key in enumerate(keys):
                for block_index, block in enumerate(chain4.blocks):
                    if mode_name == "ecb":
                        plaintext = AES.new(key, AES.MODE_ECB).decrypt(block)
                    else:
                        plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(block)
                    decryptions += 1
                    gate = _target_gate(plaintext)
                    if gate:
                        target_matches.append({
                            "model": model["name"], "mode": mode_name,
                            "key_index": key_index, "block_index": block_index, **gate,
                        })
                    unpadded = _strict_unpad(plaintext)
                    if unpadded is None:
                        if key_index == block_index:
                            printable_total += sum(32 <= byte < 127 for byte in plaintext)
                        continue
                    padding_graph[key_index].add(block_index)
                    if key_index == block_index:
                        natural_padding += 1
                        printable_total += sum(32 <= byte < 127 for byte in unpadded)
                    readable, metrics = _readable(unpadded)
                    formats = _formats(unpadded)
                    if readable or formats:
                        edge = {
                            "key_index": key_index, "block_index": block_index,
                            "plaintext_sha256": hashlib.sha256(unpadded).hexdigest(),
                            "length": len(unpadded), "readable": readable,
                            "metrics": metrics, "formats": formats,
                        }
                        semantic_edges.append(edge)
                        if key_index == block_index:
                            natural_semantic += 1
                            accepted.append({"model": model["name"], "mode": mode_name, **edge})
            model_records.append({
                "model": model["name"],
                "mode": mode_name,
                "padding_edge_count": sum(len(edges) for edges in padding_graph),
                "maximum_padding_matching": _maximum_matching(padding_graph, len(chain4.blocks)),
                "natural_order_padding_count": natural_padding,
                "natural_order_semantic_count": natural_semantic,
                "natural_order_printable_byte_count": printable_total,
                "semantic_edges": semantic_edges,
            })

    best_matching = max(record["maximum_padding_matching"] for record in model_records)
    best_natural = max(record["natural_order_padding_count"] for record in model_records)
    result = {
        "schema": "chain4-c7-3-intertwined-password-cipher-results-v1",
        "manifest_sha256": seal,
        "decryptions": decryptions,
        "model_mode_records": model_records,
        "best_maximum_padding_matching": best_matching,
        "best_natural_order_padding_count": best_natural,
        "accepted_natural_order_semantic_results": accepted,
        "target_matches": target_matches,
        "status": "MATCH" if target_matches else "NO_ACCEPTED_RESULT",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "manifest_sha256": seal,
        "decryptions": decryptions,
        "best_maximum_padding_matching": best_matching,
        "best_natural_order_padding_count": best_natural,
        "accepted_natural_order_semantic_results": len(accepted),
        "target_matches": len(target_matches),
        "status": result["status"],
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "run"))
    arguments = parser.parse_args()
    if arguments.mode == "prepare":
        prepare()
    else:
        run()


if __name__ == "__main__":
    main()
