"""Authenticate and reproduce the original Decentraland GSMG audio clue."""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import urllib.request

from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion import derive_tokens


RESULT_PATH = ROOT / "decentraland_audio_audit.json"
CACHE = ROOT / "artifacts" / "audio_audit"
CONTENT_BASE = "https://peer.decentraland.org/content"
POINTER = "-41,-17"
ENTITY_CID = "QmRK2YoLei9wrxLvHUKisywobxEvczTicXepPxKLKzN51v"
AUDIO_CID = "QmeRy5MjmEZ2W6J3DwhQfht5HKBKXBFpoGzSkzmjeGKiDK"
GAME_CID = "QmcoAs6kCXynZksyNDB7RTgVYfTkxyrLb8nEU2RJepbhoE"
SCENE_CID = "QmdESuCguQMVXRKYwcXRJLdNcEcfi3ZXxTGPLEE3NC8czC"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
USER_AGENT = "GSMG-public-evidence-audit/1.0"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cid_digest(cid: str) -> str:
    value = 0
    for char in cid:
        value = value * 58 + BASE58.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(cid) - len(cid.lstrip("1"))) + raw
    if len(raw) != 34 or raw[:2] != b"\x12\x20":
        raise ValueError(f"{cid} is not a CIDv0 SHA-256 multihash")
    return raw[2:].hex()


def _request(url: str, data: bytes | None = None) -> bytes:
    request = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read()


def _cached(name: str, url: str, *, fetch_missing: bool, data: bytes | None = None) -> bytes:
    path = CACHE / name
    if path.exists():
        return path.read_bytes()
    if not fetch_missing:
        raise ValueError(f"missing cached Decentraland artifact: {path}")
    body = _request(url, data)
    path.write_bytes(body)
    return body


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run(*, fetch_missing: bool = True, regenerate_media: bool = False) -> dict[str, object]:
    CACHE.mkdir(parents=True, exist_ok=True)
    content = f"{CONTENT_BASE}/contents"
    entity_bytes = _cached("entity.json", f"{content}/{ENTITY_CID}", fetch_missing=fetch_missing)
    scene_bytes = _cached("scene.json", f"{content}/{SCENE_CID}", fetch_missing=fetch_missing)
    game_bytes = _cached("game.js", f"{content}/{GAME_CID}", fetch_missing=fetch_missing)
    audio_bytes = _cached("puzzlepiece.mp3", f"{content}/{AUDIO_CID}", fetch_missing=fetch_missing)
    active_bytes = _cached(
        "active_pointer.json",
        f"{CONTENT_BASE}/entities/active",
        fetch_missing=fetch_missing,
        data=json.dumps({"pointers": [POINTER]}).encode("utf-8"),
    )
    associated_bytes = _cached(
        "audio_active_entities.json",
        f"{content}/{AUDIO_CID}/active-entities",
        fetch_missing=fetch_missing,
    )

    immutable = {
        "entity": (ENTITY_CID, entity_bytes),
        "scene": (SCENE_CID, scene_bytes),
        "game": (GAME_CID, game_bytes),
        "audio": (AUDIO_CID, audio_bytes),
    }
    for label, (cid, body) in immutable.items():
        if _sha256(body) != _cid_digest(cid):
            raise ValueError(f"{label} bytes do not match their Decentraland CID")

    entity = json.loads(entity_bytes)
    scene = json.loads(scene_bytes)
    active = json.loads(active_bytes)
    associated = json.loads(associated_bytes)
    content_map = {item["file"]: item["hash"] for item in entity["content"]}
    if content_map != {
        "bin/game.js": GAME_CID,
        "scene.json": SCENE_CID,
        "sounds/puzzlepiece.mp3": AUDIO_CID,
    }:
        raise ValueError("scene content manifest changed")
    if ENTITY_CID not in associated or not any(item.get("id") == ENTITY_CID for item in active):
        raise ValueError("audio/parcel active-entity association did not verify")
    if POINTER not in entity["pointers"] or POINTER not in scene["scene"]["parcels"]:
        raise ValueError("expected parcel pointer is absent")

    ffprobe = shutil.which("ffprobe")
    ffmpeg = shutil.which("ffmpeg")
    if not ffprobe or not ffmpeg:
        raise ValueError("ffprobe and ffmpeg are required for the audio reproduction")
    audio_path = CACHE / "puzzlepiece.mp3"
    probe = json.loads(subprocess.run(
        [ffprobe, "-v", "error", "-show_format", "-show_streams", "-of", "json", str(audio_path)],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout)
    stream = probe["streams"][0]
    if stream["codec_name"] != "mp3" or stream["channels"] != 2 or stream["sample_rate"] != "44100":
        raise ValueError("unexpected source audio format")

    difference_path = CACHE / "channel_difference.wav"
    spectrogram_path = CACHE / "channel_difference_spectrogram.png"
    text_spectrogram_path = CACHE / "channel_difference_text.png"
    if regenerate_media or not difference_path.exists():
        _run([ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-i", str(audio_path), "-af", "pan=mono|c0=c0-c1", str(difference_path)])
    if regenerate_media or not spectrogram_path.exists():
        _run([ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-i", str(difference_path), "-lavfi", "showspectrumpic=s=1800x1000:legend=1:scale=log:fscale=lin:color=rainbow", "-frames:v", "1", str(spectrogram_path)])
    if regenerate_media or not text_spectrogram_path.exists():
        _run([ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-i", str(difference_path), "-lavfi", "showspectrumpic=s=3000x1200:legend=0:scale=log:fscale=lin:color=fiery:start=1000:stop=9000:drange=80", "-frames:v", "1", str(text_spectrogram_path)])

    # The authentic command motivates a direct audit of the ambiguous
    # SalPhaseIon phrase "our first hint is your last command".  Test the
    # command itself and other source-grounded strings at the two semantic
    # token slots; strict padding plus the 1327-byte structure is the gate.
    sal = derive_tokens()
    p6_candidates = [
        "yourlastcommand", "HASHTHETEXT", "hashthetext", "enter", "matrixsumlist",
        "lastwordsbeforearchichoice", "thispassword",
        "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    ]
    p7_candidates = [
        "secondanswer", "HASHTHETEXT", "hashthetext", "enter", "matrixsumlist",
        "lastwordsbeforearchichoice", "thispassword",
        "theflowerblossomsthroughwhatseemstobeaconcretesurface", "causality",
        "jacquefresco", "giveitjustonesecond", "heisenbergsuncertaintyprinciple",
    ]
    cosmic_envelope = extract_all().cosmic_envelope
    substitution_hits: list[dict[str, object]] = []
    for token6, token7 in itertools.product(p6_candidates, p7_candidates):
        tokens = [*sal.tokens[:5], token6, token7]
        digests = [hashlib.sha256(token.encode("utf-8")).digest() for token in tokens]
        password = bytes(a ^ b ^ c ^ d ^ e ^ f ^ g for a, b, c, d, e, f, g in zip(*digests))
        try:
            decryption = decrypt_salted_aes256_cbc(cosmic_envelope, password)
        except ValueError:
            continue
        substitution_hits.append({
            "token6": token6,
            "token7": token7,
            "plaintext_length": len(decryption.plaintext),
            "plaintext_sha256": _sha256(decryption.plaintext),
            "has_expected_1327_byte_structure": len(decryption.plaintext) == 1327,
        })

    result: dict[str, object] = {
        "status": "VERIFIED",
        "audit_date": "2026-08-03",
        "official_content_server": CONTENT_BASE,
        "entity": {
            "cid": ENTITY_CID,
            "sha256": _sha256(entity_bytes),
            "type": entity["type"],
            "pointers": entity["pointers"],
            "timestamp_ms": entity["timestamp"],
            "title": entity["metadata"]["display"]["title"],
            "owner": entity["metadata"]["owner"],
            "content": entity["content"],
            "active_entity_association_verified": True,
        },
        "audio": {
            "cid": AUDIO_CID,
            "sha256": _sha256(audio_bytes),
            "length": len(audio_bytes),
            "manifest_path": "sounds/puzzlepiece.mp3",
            "codec": stream["codec_name"],
            "sample_rate": int(stream["sample_rate"]),
            "channels": stream["channels"],
            "duration_seconds": float(stream["duration"]),
            "bit_rate": int(stream["bit_rate"]),
            "encoder": probe["format"].get("tags", {}).get("TSS"),
        },
        "scene": {
            "cid": SCENE_CID,
            "sha256": _sha256(scene_bytes),
            "base": scene["scene"]["base"],
            "parcels": scene["scene"]["parcels"],
        },
        "game": {
            "cid": GAME_CID,
            "sha256": _sha256(game_bytes),
            "references_audio": b"sounds/puzzlepiece.mp3" in game_bytes,
            "display_text_present": b"GSMG.IO" in game_bytes and b"5 BTC PUZZLE CHALLENGE" in game_bytes,
        },
        "reproduction": {
            "operation": "decode stereo MP3; mono = left - right; render spectrogram",
            "message": "HASHTHETEXT",
            "message_evidence": "visual reading of the generated spectrogram; not automated OCR",
            "channel_difference_wav": str(difference_path.relative_to(ROOT)).replace("\\", "/"),
            "channel_difference_sha256": _sha256(difference_path.read_bytes()),
            "spectrogram": str(spectrogram_path.relative_to(ROOT)).replace("\\", "/"),
            "spectrogram_sha256": _sha256(spectrogram_path.read_bytes()),
            "text_spectrogram": str(text_spectrogram_path.relative_to(ROOT)).replace("\\", "/"),
            "text_spectrogram_sha256": _sha256(text_spectrogram_path.read_bytes()),
        },
        "salphaseion_substitution_audit": {
            "motivation": "test whether the authenticated HASHTHETEXT command replaces the literal yourlastcommand semantic token",
            "token6_candidates": p6_candidates,
            "token7_candidates": p7_candidates,
            "tested_pairs": len(p6_candidates) * len(p7_candidates),
            "strict_padding_hits": substitution_hits,
            "hashthetext_token_hits": [
                hit for hit in substitution_hits
                if hit["token6"].lower() == "hashthetext" or hit["token7"].lower() == "hashthetext"
            ],
        },
        "impact": "Authenticates the original HASHTHETEXT clue and its Decentraland ownership/path. It adds no new post-Chain-4 operand and does not define cosmic_A/ca, row1-4, or K_I1.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
