"""Reconstruct and verify the GSMG target/component ECDSA signature corpus."""

from __future__ import annotations

import concurrent.futures
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import itertools
import json
from pathlib import Path
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

from coincurve import PrivateKey, PublicKey

from .chain4 import reconstruct_chain4
from .chains import reconstruct
from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .prime_reinsertion_audit import TARGET_ADDRESS, TARGET_X, TARGET_Y
from .salphaseion import derive_tokens
from .secp256k1_verify import BASE58, N, base58check, hash160


RESULT_PATH = ROOT / "blockchain_nonce_audit.json"
CACHE = ROOT / "artifacts" / "blockchain_cache"
PAGES = CACHE / "address_pages"
RAW_TXS = CACHE / "raw_txs"
PREIMAGES = CACHE / "sighash_preimages"
API = "https://blockstream.info/api"
USER_AGENT = "GSMG-transaction-signature-audit/1.0"
ADDRESSES = (
    TARGET_ADDRESS,
    "1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu",
    "145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ",
)
TARGET_COMPRESSED = bytes([2 + (TARGET_Y & 1)]) + TARGET_X.to_bytes(32, "big")
HISTORICAL_CORE_INVENTORY_SHA256 = "691b6f15b6eb87d488d066ca8631dd99a58080db810601ea4c69f116d23f41a1"


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _varint(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated varint")
    prefix = data[offset]
    if prefix < 0xFD:
        return prefix, offset + 1
    widths = {0xFD: 2, 0xFE: 4, 0xFF: 8}
    width = widths[prefix]
    end = offset + 1 + width
    if end > len(data):
        raise ValueError("truncated varint payload")
    return int.from_bytes(data[offset + 1 : end], "little"), end


@dataclass(frozen=True)
class TxInput:
    prev_txid: str
    prev_vout: int
    script_sig: bytes
    sequence: int
    witness: tuple[bytes, ...]


@dataclass(frozen=True)
class TxOutput:
    value: int
    script_pubkey: bytes


@dataclass(frozen=True)
class Transaction:
    version: int
    inputs: tuple[TxInput, ...]
    outputs: tuple[TxOutput, ...]
    locktime: int
    has_witness: bool


def parse_transaction(raw: bytes) -> Transaction:
    if len(raw) < 10:
        raise ValueError("transaction is too short")
    offset = 0
    version = int.from_bytes(raw[offset : offset + 4], "little", signed=True)
    offset += 4
    has_witness = raw[offset : offset + 2] == b"\0\x01"
    if has_witness:
        offset += 2
    input_count, offset = _read_varint(raw, offset)
    provisional: list[tuple[str, int, bytes, int]] = []
    for _ in range(input_count):
        if offset + 36 > len(raw):
            raise ValueError("truncated transaction input")
        prev_txid = raw[offset : offset + 32][::-1].hex()
        prev_vout = int.from_bytes(raw[offset + 32 : offset + 36], "little")
        offset += 36
        script_length, offset = _read_varint(raw, offset)
        script_sig = raw[offset : offset + script_length]
        offset += script_length
        if offset + 4 > len(raw):
            raise ValueError("truncated input sequence")
        sequence = int.from_bytes(raw[offset : offset + 4], "little")
        offset += 4
        provisional.append((prev_txid, prev_vout, script_sig, sequence))
    output_count, offset = _read_varint(raw, offset)
    outputs: list[TxOutput] = []
    for _ in range(output_count):
        if offset + 8 > len(raw):
            raise ValueError("truncated transaction output")
        value = int.from_bytes(raw[offset : offset + 8], "little")
        offset += 8
        script_length, offset = _read_varint(raw, offset)
        script = raw[offset : offset + script_length]
        offset += script_length
        outputs.append(TxOutput(value, script))
    witnesses: list[tuple[bytes, ...]] = [tuple() for _ in provisional]
    if has_witness:
        witnesses = []
        for _ in provisional:
            item_count, offset = _read_varint(raw, offset)
            stack: list[bytes] = []
            for _ in range(item_count):
                item_length, offset = _read_varint(raw, offset)
                stack.append(raw[offset : offset + item_length])
                offset += item_length
            witnesses.append(tuple(stack))
    if offset + 4 != len(raw):
        raise ValueError(f"transaction parse ended at {offset + 4}, expected {len(raw)}")
    locktime = int.from_bytes(raw[offset : offset + 4], "little")
    inputs = tuple(
        TxInput(prev_txid, prev_vout, script_sig, sequence, witnesses[index])
        for index, (prev_txid, prev_vout, script_sig, sequence) in enumerate(provisional)
    )
    return Transaction(version, inputs, tuple(outputs), locktime, has_witness)


def _serialize_transaction(tx: Transaction, *, include_witness: bool) -> bytes:
    output = bytearray(struct.pack("<i", tx.version))
    if include_witness and tx.has_witness:
        output += b"\0\x01"
    output += _varint(len(tx.inputs))
    for txin in tx.inputs:
        output += bytes.fromhex(txin.prev_txid)[::-1]
        output += struct.pack("<I", txin.prev_vout)
        output += _varint(len(txin.script_sig)) + txin.script_sig
        output += struct.pack("<I", txin.sequence)
    output += _varint(len(tx.outputs))
    for txout in tx.outputs:
        output += struct.pack("<Q", txout.value)
        output += _varint(len(txout.script_pubkey)) + txout.script_pubkey
    if include_witness and tx.has_witness:
        for txin in tx.inputs:
            output += _varint(len(txin.witness))
            for item in txin.witness:
                output += _varint(len(item)) + item
    output += struct.pack("<I", tx.locktime)
    return bytes(output)


def transaction_id(tx: Transaction) -> str:
    return _sha256d(_serialize_transaction(tx, include_witness=False))[::-1].hex()


def legacy_sighash_preimage(
    tx: Transaction,
    input_index: int,
    script_code: bytes,
    sighash_type: int,
) -> tuple[bytes | None, bytes]:
    if not 0 <= input_index < len(tx.inputs):
        raise ValueError("sighash input index is out of range")
    base_type = sighash_type & 0x1F
    anyone_can_pay = bool(sighash_type & 0x80)
    if base_type not in (1, 2, 3):
        raise ValueError(f"unsupported legacy sighash base type {base_type}")
    if base_type == 3 and input_index >= len(tx.outputs):
        # Historical SIGHASH_SINGLE bug: uint256::ONE is returned directly.
        return None, b"\x01" + b"\0" * 31

    source_indices = [input_index] if anyone_can_pay else list(range(len(tx.inputs)))
    output = bytearray(struct.pack("<i", tx.version))
    output += _varint(len(source_indices))
    for original_index in source_indices:
        txin = tx.inputs[original_index]
        output += bytes.fromhex(txin.prev_txid)[::-1]
        output += struct.pack("<I", txin.prev_vout)
        script = script_code if original_index == input_index else b""
        output += _varint(len(script)) + script
        sequence = txin.sequence
        if original_index != input_index and base_type in (2, 3):
            sequence = 0
        output += struct.pack("<I", sequence)

    if base_type == 1:
        selected_outputs = list(tx.outputs)
    elif base_type == 2:
        selected_outputs = []
    else:
        selected_outputs = [TxOutput(0xFFFFFFFFFFFFFFFF, b"") for _ in range(input_index)]
        selected_outputs.append(tx.outputs[input_index])
    output += _varint(len(selected_outputs))
    for txout in selected_outputs:
        output += struct.pack("<Q", txout.value)
        output += _varint(len(txout.script_pubkey)) + txout.script_pubkey
    output += struct.pack("<I", tx.locktime)
    output += struct.pack("<I", sighash_type)
    preimage = bytes(output)
    return preimage, _sha256d(preimage)


def _script_pushes(script: bytes) -> list[bytes]:
    pushes: list[bytes] = []
    offset = 0
    while offset < len(script):
        opcode = script[offset]
        offset += 1
        if opcode <= 75:
            length = opcode
        elif opcode == 0x4C:
            if offset >= len(script):
                raise ValueError("truncated OP_PUSHDATA1")
            length = script[offset]
            offset += 1
        elif opcode == 0x4D:
            if offset + 2 > len(script):
                raise ValueError("truncated OP_PUSHDATA2")
            length = int.from_bytes(script[offset : offset + 2], "little")
            offset += 2
        elif opcode == 0x4E:
            if offset + 4 > len(script):
                raise ValueError("truncated OP_PUSHDATA4")
            length = int.from_bytes(script[offset : offset + 4], "little")
            offset += 4
        else:
            raise ValueError(f"non-push opcode {opcode:#x} in P2PKH scriptSig")
        if offset + length > len(script):
            raise ValueError("truncated pushed value")
        pushes.append(script[offset : offset + length])
        offset += length
    return pushes


def _parse_der_signature(der: bytes) -> tuple[int, int]:
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2 or der[2] != 0x02:
        raise ValueError("invalid DER ECDSA sequence")
    r_length = der[3]
    r_start, r_end = 4, 4 + r_length
    if r_end + 2 > len(der) or der[r_end] != 0x02:
        raise ValueError("invalid DER ECDSA r integer")
    s_length = der[r_end + 1]
    s_start, s_end = r_end + 2, r_end + 2 + s_length
    if s_end != len(der):
        raise ValueError("invalid DER ECDSA s integer")
    r_bytes, s_bytes = der[r_start:r_end], der[s_start:s_end]
    if not r_bytes or not s_bytes or r_bytes[0] & 0x80 or s_bytes[0] & 0x80:
        raise ValueError("negative or empty DER integer")
    if len(r_bytes) > 1 and r_bytes[0] == 0 and not r_bytes[1] & 0x80:
        raise ValueError("non-minimal DER r integer")
    if len(s_bytes) > 1 and s_bytes[0] == 0 and not s_bytes[1] & 0x80:
        raise ValueError("non-minimal DER s integer")
    r, s = int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")
    if not 1 <= r < N or not 1 <= s < N:
        raise ValueError("ECDSA scalar outside curve order")
    return r, s


def _decode_base58check(value: str) -> bytes:
    number = 0
    for character in value:
        number = number * 58 + BASE58.index(character)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    raw = b"\0" * (len(value) - len(value.lstrip("1"))) + raw
    if len(raw) < 5 or _sha256d(raw[:-4])[:4] != raw[-4:]:
        raise ValueError("invalid Base58Check address")
    return raw[:-4]


def _p2pkh_script(address: str) -> bytes:
    payload = _decode_base58check(address)
    if len(payload) != 21 or payload[0] != 0:
        raise ValueError("expected mainnet P2PKH address")
    return b"\x76\xa9\x14" + payload[1:] + b"\x88\xac"


def _api_request(path_or_url: str, attempts: int = 4) -> bytes:
    url = path_or_url if path_or_url.startswith("http") else API + path_or_url
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as error:
            last_error = error
            if attempt + 1 < attempts:
                time.sleep(2**attempt)
    assert last_error is not None
    raise last_error


def _cache_json_bytes(data: bytes, directory: Path) -> tuple[Path, object]:
    parsed = json.loads(data)
    sha256 = hashlib.sha256(data).hexdigest()
    path = directory / f"{sha256}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(data)
    return path, parsed


def _fetch_address_history(address: str) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    summary_bytes = _api_request(f"/address/{address}")
    summary_path, summary = _cache_json_bytes(summary_bytes, PAGES)
    page_records: list[dict[str, object]] = []
    transactions: dict[str, dict[str, object]] = {}
    page_url = f"/address/{address}/txs"
    seen_page_urls: set[str] = set()
    while page_url not in seen_page_urls:
        seen_page_urls.add(page_url)
        page_bytes = _api_request(page_url)
        page_path, page = _cache_json_bytes(page_bytes, PAGES)
        if not isinstance(page, list):
            raise ValueError("address transaction page is not a JSON list")
        page_records.append({
            "request": page_url,
            "path": str(page_path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": hashlib.sha256(page_bytes).hexdigest(),
            "record_count": len(page),
        })
        for transaction in page:
            if transaction["status"].get("confirmed"):
                transactions[transaction["txid"]] = transaction
        confirmed = [transaction for transaction in page if transaction["status"].get("confirmed")]
        if not confirmed:
            break
        page_url = f"/address/{address}/txs/chain/{confirmed[-1]['txid']}"
        if len(page) < 25:
            # Confirm with one terminal empty page so the manifest proves the
            # pagination boundary rather than inferring it from page length.
            terminal_bytes = _api_request(page_url)
            terminal_path, terminal = _cache_json_bytes(terminal_bytes, PAGES)
            page_records.append({
                "request": page_url,
                "path": str(terminal_path.relative_to(ROOT)).replace("\\", "/"),
                "sha256": hashlib.sha256(terminal_bytes).hexdigest(),
                "record_count": len(terminal),
            })
            if terminal:
                raise ValueError("Esplora returned a nonempty terminal page after a short page")
            break
    summary_record = {
        "request": f"/address/{address}",
        "path": str(summary_path.relative_to(ROOT)).replace("\\", "/"),
        "sha256": hashlib.sha256(summary_bytes).hexdigest(),
        "data": summary,
    }
    return summary_record, page_records, list(transactions.values())


def _load_cached_address_history(address: str, previous: dict[str, object]) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    address_record = previous["address_histories"][address]
    summary_record = address_record["summary"]
    summary_bytes = (ROOT / summary_record["path"]).read_bytes()
    if hashlib.sha256(summary_bytes).hexdigest() != summary_record["sha256"]:
        raise ValueError("cached address summary hash mismatch")
    page_records = address_record["pages"]
    transactions: dict[str, dict[str, object]] = {}
    for record in page_records:
        page_bytes = (ROOT / record["path"]).read_bytes()
        if hashlib.sha256(page_bytes).hexdigest() != record["sha256"]:
            raise ValueError("cached address page hash mismatch")
        page = json.loads(page_bytes)
        if len(page) != record["record_count"]:
            raise ValueError("cached address page record count mismatch")
        for transaction in page:
            if transaction["status"].get("confirmed"):
                transactions[transaction["txid"]] = transaction
    return summary_record, page_records, list(transactions.values())


def _raw_path(txid: str) -> Path:
    return RAW_TXS / f"{txid}.bin"


def _obtain_raw_transactions(txids: set[str], fetch_missing: bool) -> dict[str, bytes]:
    RAW_TXS.mkdir(parents=True, exist_ok=True)
    result: dict[str, bytes] = {}
    missing: list[str] = []
    for txid in sorted(txids):
        path = _raw_path(txid)
        if path.exists():
            raw = path.read_bytes()
            if transaction_id(parse_transaction(raw)) != txid:
                raise ValueError(f"cached raw transaction {txid} fails its txid")
            result[txid] = raw
        else:
            missing.append(txid)
    if missing and not fetch_missing:
        raise ValueError(f"{len(missing)} raw transactions are missing from the offline cache")

    def fetch(txid: str) -> tuple[str, bytes]:
        raw = _api_request(f"/tx/{txid}/raw")
        if transaction_id(parse_transaction(raw)) != txid:
            raise ValueError(f"Blockstream raw response fails txid {txid}")
        _raw_path(txid).write_bytes(raw)
        return txid, raw

    if missing:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            for completed, (txid, raw) in enumerate(executor.map(fetch, missing), 1):
                result[txid] = raw
                if completed % 25 == 0 or completed == len(missing):
                    print(f"raw transaction cache {completed}/{len(missing)}", flush=True)
    return result


def _core_inventory_sha256(signatures: list[dict[str, object]]) -> str:
    core = [
        {"address": item["address"], "txid": item["txid"], "vin": item["vin"], "r": item["r"], "s": item["s"]}
        for item in signatures
    ]
    core.sort(key=lambda item: (item["address"], item["txid"], item["vin"], item["r"], item["s"]))
    encoded = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def run(*, refresh_histories: bool = True, fetch_missing: bool = True) -> dict[str, object]:
    CACHE.mkdir(parents=True, exist_ok=True)
    PREIMAGES.mkdir(parents=True, exist_ok=True)
    previous = json.loads(RESULT_PATH.read_text(encoding="utf-8")) if RESULT_PATH.exists() else {}
    histories: dict[str, dict[str, object]] = {}
    all_transactions: dict[str, dict[str, object]] = {}
    spend_records: list[dict[str, object]] = []
    for address in ADDRESSES:
        if refresh_histories:
            summary, pages, transactions = _fetch_address_history(address)
        else:
            if not previous:
                raise ValueError("no prior blockchain manifest exists for offline reconstruction")
            summary, pages, transactions = _load_cached_address_history(address, previous)
        summary_data = summary["data"]
        expected_tx_count = summary_data["chain_stats"]["tx_count"]
        if len(transactions) != expected_tx_count:
            raise ValueError(f"address history for {address} has {len(transactions)} confirmed txs, expected {expected_tx_count}")
        histories[address] = {"summary": summary, "pages": pages, "confirmed_transaction_count": len(transactions)}
        for transaction in transactions:
            all_transactions[transaction["txid"]] = transaction
            for vin, txin in enumerate(transaction["vin"]):
                prevout = txin.get("prevout")
                if prevout and prevout.get("scriptpubkey_address") == address:
                    spend_records.append({
                        "address": address,
                        "txid": transaction["txid"],
                        "vin": vin,
                        "block_height": transaction["status"].get("block_height"),
                        "block_time": transaction["status"].get("block_time"),
                        "prev_txid": txin["txid"],
                        "prev_vout": txin["vout"],
                        "api_prevout_script": prevout["scriptpubkey"],
                        "api_prevout_value": prevout["value"],
                    })
        expected_spends = summary_data["chain_stats"]["spent_txo_count"]
        actual_spends = sum(record["address"] == address for record in spend_records)
        if actual_spends != expected_spends:
            raise ValueError(f"address {address} exposes {actual_spends} spending inputs, expected {expected_spends}")

    required_txids = {record["txid"] for record in spend_records} | {record["prev_txid"] for record in spend_records}
    raw_transactions = _obtain_raw_transactions(required_txids, fetch_missing)
    expected_pubkeys: dict[str, bytes] = {TARGET_ADDRESS: TARGET_COMPRESSED}
    sal = derive_tokens()
    chains = reconstruct(extract_all(), sal)
    chain4 = reconstruct_chain4(chains)
    matrix = analyze(chains.cosmic_decryption.plaintext)
    expected_pubkeys[ADDRESSES[1]] = PrivateKey(matrix.half).public_key.format(compressed=True)
    expected_pubkeys[ADDRESSES[2]] = PrivateKey(matrix.better_half).public_key.format(compressed=True)

    signatures: list[dict[str, object]] = []
    for record in sorted(spend_records, key=lambda item: (item["address"], item["block_height"], item["txid"], item["vin"])):
        tx_raw = raw_transactions[record["txid"]]
        tx = parse_transaction(tx_raw)
        vin = int(record["vin"])
        txin = tx.inputs[vin]
        if txin.prev_txid != record["prev_txid"] or txin.prev_vout != record["prev_vout"]:
            raise ValueError("raw transaction input differs from address-history prevout")
        prev_raw = raw_transactions[record["prev_txid"]]
        prev_tx = parse_transaction(prev_raw)
        prev_output = prev_tx.outputs[int(record["prev_vout"])]
        expected_script = _p2pkh_script(str(record["address"]))
        if prev_output.script_pubkey != expected_script or prev_output.script_pubkey.hex() != record["api_prevout_script"]:
            raise ValueError("raw previous output does not match the P2PKH address/API script")
        if prev_output.value != record["api_prevout_value"]:
            raise ValueError("raw previous output value differs from API provenance")
        pushes = _script_pushes(txin.script_sig)
        if len(pushes) != 2 or len(pushes[1]) not in (33, 65):
            raise ValueError("spending input is not canonical two-push P2PKH")
        signature_with_type, public_key_bytes = pushes
        der, sighash_type = signature_with_type[:-1], signature_with_type[-1]
        r, s = _parse_der_signature(der)
        public = PublicKey(public_key_bytes)
        derived_address = base58check(b"\0" + hash160(public_key_bytes))
        if derived_address != record["address"]:
            raise ValueError("scriptSig public key does not derive the audited address")
        if public.format(compressed=True) != expected_pubkeys[str(record["address"])]:
            raise ValueError("scriptSig public key differs from the independently verified component point")
        preimage, z_bytes = legacy_sighash_preimage(tx, vin, prev_output.script_pubkey, sighash_type)
        if preimage is None:
            preimage_path = None
            preimage_sha256 = None
            preimage_length = None
        else:
            preimage_sha256 = hashlib.sha256(preimage).hexdigest()
            path = PREIMAGES / f"{preimage_sha256}.bin"
            if not path.exists():
                path.write_bytes(preimage)
            preimage_path = str(path.relative_to(ROOT)).replace("\\", "/")
            preimage_length = len(preimage)
        signature_verified = public.verify(der, z_bytes, hasher=None)
        if not signature_verified:
            raise ValueError("ECDSA signature does not verify against reconstructed sighash")
        signatures.append({
            **record,
            "r": r,
            "s": s,
            "z": int.from_bytes(z_bytes, "big"),
            "z_hex": z_bytes.hex(),
            "sighash_type": sighash_type,
            "der_hex": der.hex(),
            "public_key_hex": public_key_bytes.hex(),
            "public_key_compressed_hex": public.format(compressed=True).hex(),
            "signature_verified": True,
            "current_raw_tx_sha256": hashlib.sha256(tx_raw).hexdigest(),
            "previous_raw_tx_sha256": hashlib.sha256(prev_raw).hexdigest(),
            "script_code_hex": prev_output.script_pubkey.hex(),
            "preimage_path": preimage_path,
            "preimage_sha256": preimage_sha256,
            "preimage_length": preimage_length,
        })

    if len(signatures) != 187:
        raise ValueError(f"signature corpus cardinality changed: {len(signatures)}")
    counts_by_address = Counter(str(item["address"]) for item in signatures)
    expected_counts = {TARGET_ADDRESS: 6, ADDRESSES[1]: 91, ADDRESSES[2]: 90}
    if dict(counts_by_address) != expected_counts:
        raise ValueError(f"signature counts differ from historical corpus: {dict(counts_by_address)}")
    core_sha256 = _core_inventory_sha256(signatures)
    if core_sha256 != HISTORICAL_CORE_INVENTORY_SHA256:
        raise ValueError("independently reconstructed r/s inventory differs from the historical ledger")

    r_groups: dict[int, list[dict[str, object]]] = defaultdict(list)
    for signature in signatures:
        r_groups[int(signature["r"])].append(signature)
    repeated_r = {str(r): group for r, group in r_groups.items() if len(group) > 1}
    repeated_nonce_recoveries: list[dict[str, object]] = []
    for r_text, group in repeated_r.items():
        r = int(r_text)
        for left, right in itertools.combinations(group, 2):
            if left["public_key_compressed_hex"] != right["public_key_compressed_hex"]:
                continue
            for left_sign in (1, -1):
                for right_sign in (1, -1):
                    denominator = (left_sign * int(left["s"]) - right_sign * int(right["s"])) % N
                    if not denominator:
                        continue
                    nonce = (int(left["z"]) - int(right["z"])) * pow(denominator, -1, N) % N
                    private = (left_sign * int(left["s"]) * nonce - int(left["z"])) * pow(r, -1, N) % N
                    if private and PrivateKey.from_int(private).public_key.format(compressed=True).hex() == left["public_key_compressed_hex"]:
                        recovered_public = PrivateKey.from_int(private).public_key
                        recovered_address = base58check(b"\0" + hash160(recovered_public.format(compressed=False)))
                        repeated_nonce_recoveries.append({
                            "left": [left["txid"], left["vin"]],
                            "right": [right["txid"], right["vin"]],
                            "nonce_hex": f"{nonce:064x}",
                            "private_hex": f"{private:064x}",
                            "prize_point_match": recovered_public.format(compressed=True) == TARGET_COMPRESSED,
                            "address": recovered_address,
                            "prize_address_match": recovered_address == TARGET_ADDRESS,
                            "accepted": recovered_public.format(compressed=True) == TARGET_COMPRESSED and recovered_address == TARGET_ADDRESS,
                        })

    recovered_k_bytes = [
        chains.chain1.key1, chains.chain1.key2,
        chains.chain2.key1, chains.chain2.key2,
        chains.cosmic_b.key1, chains.cosmic_b.key2,
        chains.cosmic_h.key1, chains.cosmic_h.key2,
    ]
    candidate_values: dict[str, int] = {
        **{f"block_{index:02d}": int.from_bytes(block, "big") for index, block in enumerate(chain4.blocks)},
        "operand30": int.from_bytes(chain4.opcode_operand, "big"),
        "magnitude29": int.from_bytes(chain4.operand, "big"),
        "prefix31": int.from_bytes(chain4.structured_prefix, "big"),
        **{name: int.from_bytes(value, "big") for name, value in zip(
            ("K_C1", "K_C2", "K_S1", "K_S2", "K_B1", "K_B2", "K_H1", "K_H2"), recovered_k_bytes
        )},
        "Half": int.from_bytes(matrix.half, "big"),
        "Better_Half": int.from_bytes(matrix.better_half, "big"),
    }
    nonce_candidates: dict[int, list[str]] = defaultdict(list)
    for label, value in candidate_values.items():
        for sign, signed in (("positive", value), ("negative", -value)):
            scalar = signed % N
            if scalar:
                nonce_candidates[scalar].append(f"{label}/{sign}")
    r_to_nonce_candidates: dict[int, list[tuple[int, str]]] = defaultdict(list)
    for scalar, labels in nonce_candidates.items():
        point = PrivateKey.from_int(scalar).public_key.format(compressed=False)
        r_value = int.from_bytes(point[1:33], "big") % N
        for label in labels:
            r_to_nonce_candidates[r_value].append((scalar, label))

    known_nonce_matches: list[dict[str, object]] = []
    for signature in signatures:
        for nonce, label in r_to_nonce_candidates.get(int(signature["r"]), []):
            private = (
                (int(signature["s"]) * nonce - int(signature["z"]))
                * pow(int(signature["r"]), -1, N)
            ) % N
            if not private:
                continue
            public = PrivateKey.from_int(private).public_key
            signer_match = public.format(compressed=True).hex() == signature["public_key_compressed_hex"]
            prize_point_match = public.format(compressed=True) == TARGET_COMPRESSED
            address = base58check(b"\0" + hash160(public.format(compressed=False)))
            known_nonce_matches.append({
                "txid": signature["txid"], "vin": signature["vin"], "candidate": label,
                "nonce_hex": f"{nonce:064x}", "private_hex": f"{private:064x}",
                "signer_match": signer_match, "prize_point_match": prize_point_match,
                "address": address, "prize_address_match": address == TARGET_ADDRESS,
                "accepted": signer_match and prize_point_match and address == TARGET_ADDRESS,
            })

    direct_prize_candidates = []
    for scalar, labels in nonce_candidates.items():
        public = PrivateKey.from_int(scalar).public_key
        if public.format(compressed=True) == TARGET_COMPRESSED:
            address = base58check(b"\0" + hash160(public.format(compressed=False)))
            direct_prize_candidates.append({"candidates": labels, "private_hex": f"{scalar:064x}", "address": address})

    raw_manifest = [
        {
            "txid": txid,
            "path": str(_raw_path(txid).relative_to(ROOT)).replace("\\", "/"),
            "length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "txid_verified": transaction_id(parse_transaction(raw)) == txid,
        }
        for txid, raw in sorted(raw_transactions.items())
    ]
    tip_height = int(_api_request("/blocks/tip/height").decode("ascii")) if refresh_histories else previous["chain_snapshot"]["tip_height"]
    tip_hash = _api_request("/blocks/tip/hash").decode("ascii") if refresh_histories else previous["chain_snapshot"]["tip_hash"]

    result: dict[str, object] = {
        "status": "MATCH" if (
            any(item["accepted"] for item in known_nonce_matches)
            or any(item["accepted"] for item in repeated_nonce_recoveries)
            or bool(direct_prize_candidates)
        ) else "COMPLETE_NO_MATCH",
        "audit_date": "2026-08-03",
        "chain4_sha256": hashlib.sha256(chain4.decryption.plaintext).hexdigest(),
        "source": {
            "api": API,
            "api_documentation": "https://github.com/Blockstream/esplora/blob/master/API.md",
            "historical_core_inventory_sha256": HISTORICAL_CORE_INVENTORY_SHA256,
            "reconstructed_core_inventory_sha256": core_sha256,
            "historical_inventory_reproduced": core_sha256 == HISTORICAL_CORE_INVENTORY_SHA256,
        },
        "chain_snapshot": {"tip_height": tip_height, "tip_hash": tip_hash},
        "address_histories": histories,
        "corpus": {
            "signature_count": len(signatures),
            "counts_by_address": dict(counts_by_address),
            "unique_spending_transactions": len({item["txid"] for item in signatures}),
            "raw_transaction_count": len(raw_manifest),
            "raw_transactions": raw_manifest,
            "all_txids_verified": all(item["txid_verified"] for item in raw_manifest),
            "all_signatures_verified": all(item["signature_verified"] for item in signatures),
            "sighash_types": dict(Counter(str(item["sighash_type"]) for item in signatures)),
            "unique_r_count": len(r_groups),
            "repeated_r_groups": repeated_r,
            "signatures": signatures,
        },
        "nonce_audit": {
            "repeated_nonce_recoveries": repeated_nonce_recoveries,
            "candidate_base_values": len(candidate_values),
            "candidate_signed_nonces": len(nonce_candidates),
            "known_nonce_equation_tests": len(signatures) * len(nonce_candidates),
            "legacy_target_block_nonce_tests": counts_by_address[TARGET_ADDRESS] * len(chain4.blocks),
            "known_nonce_r_matches": known_nonce_matches,
            "accepted_known_nonce_matches": [item for item in known_nonce_matches if item["accepted"]],
            "direct_prize_candidate_matches": direct_prize_candidates,
        },
        "scope_note": "The corpus is complete for confirmed spends visible in the three recorded P2PKH address histories at the recorded chain tip. It does not make claims about signatures under unrelated keys or off-chain signatures.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "status": output["status"],
        "chain_snapshot": output["chain_snapshot"],
        "signature_count": output["corpus"]["signature_count"],
        "counts_by_address": output["corpus"]["counts_by_address"],
        "raw_transaction_count": output["corpus"]["raw_transaction_count"],
        "unique_r_count": output["corpus"]["unique_r_count"],
        "nonce_audit": output["nonce_audit"],
    }, indent=2))
