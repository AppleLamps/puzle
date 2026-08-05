"""Test Chain 4 as seven intertwined five-block encrypted streams."""

from __future__ import annotations

import hashlib
import json

from Crypto.Cipher import AES

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .extract import ROOT, extract_all
from .salphaseion import derive_tokens
from .salphaseion_blind_eval import _formats, _readable


RESULT_PATH = ROOT / "chain4_seven_stream_audit.json"


def _strict_unpad(value: bytes) -> bytes | None:
    count = value[-1]
    if not 1 <= count <= 16 or value[-count:] != bytes([count]) * count:
        return None
    return value[:-count]


def _maximum_matching(graph: list[set[int]]) -> int:
    assigned: list[int | None] = [None] * 7

    def augment(left: int, seen: set[int]) -> bool:
        for right in graph[left]:
            if right in seen:
                continue
            seen.add(right)
            if assigned[right] is None or augment(assigned[right], seen):
                assigned[right] = left
                return True
        return False

    return sum(augment(left, set()) for left in range(7))


def run() -> dict[str, object]:
    sal = derive_tokens()
    chain4 = reconstruct_chain4(reconstruct(extract_all(), sal))
    blocks = list(chain4.blocks)
    layouts = {
        "contiguous-seven-by-five": [b"".join(blocks[index * 5:(index + 1) * 5]) for index in range(7)],
        "round-robin-seven-streams": [b"".join(blocks[index::7]) for index in range(7)],
    }
    ivs = {
        "zero": bytes(16),
        "operand-head": chain4.opcode_operand[:16],
        "operand-tail": chain4.opcode_operand[-16:],
    }
    keys = list(sal.digests)
    records: list[dict[str, object]] = []
    accepted: list[dict[str, object]] = []
    for layout_name, streams in layouts.items():
        for mode in ("ecb", "cbc"):
            mode_ivs = {"none": b""} if mode == "ecb" else ivs
            for iv_name, iv in mode_ivs.items():
                graph: list[set[int]] = [set() for _ in range(7)]
                semantic_edges: list[dict[str, object]] = []
                natural_padding = 0
                natural_semantic = 0
                for key_index, key in enumerate(keys):
                    for stream_index, stream in enumerate(streams):
                        if mode == "ecb":
                            plaintext = AES.new(key, AES.MODE_ECB).decrypt(stream)
                        else:
                            plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(stream)
                        unpadded = _strict_unpad(plaintext)
                        if unpadded is None:
                            continue
                        graph[key_index].add(stream_index)
                        if key_index == stream_index:
                            natural_padding += 1
                        readable, metrics = _readable(unpadded)
                        formats = _formats(unpadded)
                        if readable or formats:
                            edge = {
                                "key_index": key_index,
                                "stream_index": stream_index,
                                "plaintext_length": len(unpadded),
                                "plaintext_sha256": hashlib.sha256(unpadded).hexdigest(),
                                "readable": readable,
                                "metrics": metrics,
                                "formats": formats,
                            }
                            semantic_edges.append(edge)
                            if key_index == stream_index:
                                natural_semantic += 1
                                accepted.append({
                                    "layout": layout_name, "mode": mode, "iv": iv_name, **edge,
                                })
                records.append({
                    "layout": layout_name,
                    "mode": mode,
                    "iv": iv_name,
                    "padding_edge_count": sum(len(edges) for edges in graph),
                    "maximum_padding_matching": _maximum_matching(graph),
                    "natural_padding_count": natural_padding,
                    "natural_semantic_count": natural_semantic,
                    "semantic_edges": semantic_edges,
                })

    result = {
        "schema": "chain4-seven-intertwined-five-block-streams-v1",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "layouts": list(layouts),
        "key_rule": "seven source-order SHA256 token digests, retaining repeated matrixsumlist",
        "records": records,
        "accepted": accepted,
        "status": "ACCEPTED" if accepted else "NO_ACCEPTED_RESULT",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"],
        "best_padding_matching": max(record["maximum_padding_matching"] for record in output["records"]),
        "best_natural_padding": max(record["natural_padding_count"] for record in output["records"]),
        "accepted": len(output["accepted"]),
    }, indent=2))
