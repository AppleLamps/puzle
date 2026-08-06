"""Creator-frontier giveaway audit: Cosmic pubkey-delta, HASHTHETEXT S-fields,
Witteveen selectors, and creator-pipeline yin-yang variants.

Gates every scalar against BOTH prize P2PKH addresses (Half + Better Half).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from coincurve import PrivateKey

from .cosmic_matrix import analyze
from .extract import ROOT, extract_all
from .openssl_compat import decrypt_salted_aes256_cbc
from .salphaseion import derive_tokens
from .secp256k1_verify import N, P, base58check, hash160
from .chains import reconstruct
from .chain4 import reconstruct_chain4
from .targets import (
    BETTER_ADDRESS,
    BETTER_H160,
    HALF_ADDRESS,
    HALF_H160,
    HALF_PUBLIC_UNCOMPRESSED,
)


RESULT_PATH = ROOT / "creator_frontier_giveaway_audit.json"

HALF_ADDR = HALF_ADDRESS
BETTER_ADDR = BETTER_ADDRESS
PRIZE = {"Half": HALF_ADDR, "Better_Half": BETTER_ADDR}
HALF_PUB = HALF_PUBLIC_UNCOMPRESSED
HX = int.from_bytes(HALF_PUB[1:33], "big")
HY = int.from_bytes(HALF_PUB[33:65], "big")

CREATOR_PIPELINE = (
    "yellowblueprimes",
    "matrixsumlist",
    "lastwordsbeforearchichoice",
    "yinyang",
    "wewontgiveawaythepassword",
    "itsinfrontofyoureyesbutyourenotseeingit",
    "verylaststepisatruegiveawaypromised",
)

DIAG_SUMS = (22, 34, 19, 21, 56, 30, 13)


def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _xor_many(vals: list[bytes]) -> bytes:
    out = bytearray(32)
    for v in vals:
        vv = v if len(v) == 32 else _sha(v)
        for i, x in enumerate(vv[:32]):
            out[i] ^= x
    return bytes(out)


def _addresses(candidate: bytes) -> dict[str, str]:
    scalar = int.from_bytes(candidate, "big") % N
    if not scalar:
        return {}
    pub = PrivateKey(scalar.to_bytes(32, "big")).public_key
    return {
        "uncompressed": base58check(b"\0" + hash160(pub.format(compressed=False))),
        "compressed": base58check(b"\0" + hash160(pub.format(compressed=True))),
    }


def _gate(candidates: list[tuple[str, bytes]], matches: list[dict], tested: list[int]) -> None:
    seen: set[bytes] = set()
    for label, raw in candidates:
        if len(raw) < 32:
            # promote short material via sha256
            variants = [(label + "/sha256", _sha(raw))]
        elif len(raw) == 32:
            variants = [(label, raw)]
        else:
            variants = []
            for i in range(0, len(raw) - 31):
                variants.append((f"{label}/win[{i}:{i+32}]", raw[i : i + 32]))
            variants.append((label + "/sha256", _sha(raw)))
            if len(raw) >= 64:
                variants.append((label + "/sha256-first32", _sha(raw[:32])))
                variants.append((label + "/sha256-last32", _sha(raw[-32:])))
        for vlabel, cand in variants:
            # also try reversed
            for final_label, final in (
                (vlabel, cand),
                (vlabel + "/rev", cand[::-1]),
                (vlabel + "/dsha", _sha(_sha(cand))),
            ):
                if final in seen:
                    continue
                seen.add(final)
                tested[0] += 1
                addrs = _addresses(final)
                for ser, addr in addrs.items():
                    for role, target in PRIZE.items():
                        if addr == target:
                            matches.append(
                                {
                                    "label": final_label,
                                    "private_hex": final.hex(),
                                    "serialization": ser,
                                    "address": addr,
                                    "prize_role": role,
                                }
                            )


def _map_letters(s: str) -> str:
    return "".join(str(ord(c) - ord("a") + 1) for c in s)


def _hex_digit_pair_decode(digit_stream: str) -> list[tuple[str, bytes]]:
    """Decode digit stream as hex digit pairs (Decentraland HASHTHETEXT style)."""
    out: list[tuple[str, bytes]] = []
    for offset in (0, 1):
        buf = bytearray()
        ok = True
        chunk = digit_stream[offset:]
        if len(chunk) % 2:
            chunk = chunk[:-1]
        for i in range(0, len(chunk), 2):
            pair = chunk[i : i + 2]
            try:
                # interpret decimal digit pair as hex nibble pair
                # HASHTHETEXT used decimal-looking pairs that ARE hex digits 0-9 only
                val = int(pair, 16)
            except ValueError:
                ok = False
                break
            if val > 255:
                ok = False
                break
            buf.append(val)
        if ok and buf:
            out.append((f"hexpairs@off{offset}", bytes(buf)))
            # also try interpreting as decimal byte values (0-99)
            buf2 = bytearray()
            ok2 = True
            for i in range(0, len(chunk), 2):
                pair = chunk[i : i + 2]
                try:
                    val = int(pair, 10)
                except ValueError:
                    ok2 = False
                    break
                if not 0 <= val <= 255:
                    ok2 = False
                    break
                buf2.append(val)
            if ok2 and buf2:
                out.append((f"decpairs@off{offset}", bytes(buf2)))
    return out


def _sfield_variants(s: str) -> list[tuple[str, str]]:
    digits = _map_letters(s)
    n = len(digits)
    primes = {p for p in range(2, n + 1) if all(p % d for d in range(2, int(p**0.5) + 1))}
    # 1-indexed positions
    yin = "".join(str(10 - int(d)) if d != "0" else "0" for d in digits)
    zero_primes = "".join("0" if (i + 1) in primes else digits[i] for i in range(n))
    zero_nonprimes = "".join("0" if (i + 1) not in primes else digits[i] for i in range(n))
    omit_primes = "".join(digits[i] for i in range(n) if (i + 1) not in primes)
    omit_nonprimes = "".join(digits[i] for i in range(n) if (i + 1) in primes)
    return [
        ("raw", digits),
        ("yin", yin),
        ("zero_primes", zero_primes),
        ("zero_nonprimes", zero_nonprimes),
        ("omit_primes", omit_primes),
        ("omit_nonprimes", omit_nonprimes),
    ]


def experiment_hashtext_sfields(parts: dict) -> tuple[list[tuple[str, bytes]], dict]:
    candidates: list[tuple[str, bytes]] = []
    meta = {"streams": 0, "decoded": 0, "asciiish": []}
    fields = {
        "S91": parts["S91"],
        "S570": parts["S570"],
        "S91||S570": parts["S91"] + parts["S570"],
        "S570||S91": parts["S570"] + parts["S91"],
    }
    for fname, text in fields.items():
        for vname, stream in _sfield_variants(text):
            meta["streams"] += 1
            for dname, decoded in _hex_digit_pair_decode(stream):
                meta["decoded"] += 1
                label = f"sfield/{fname}/{vname}/{dname}"
                candidates.append((label, decoded))
                # flag readable
                printable = sum(32 <= b < 127 for b in decoded)
                if decoded and printable / len(decoded) > 0.85 and len(decoded) >= 8:
                    try:
                        ascii_txt = decoded.decode("ascii")
                    except UnicodeDecodeError:
                        ascii_txt = None
                    if ascii_txt and re.search(r"[A-Za-z]{4,}", ascii_txt):
                        meta["asciiish"].append({"label": label, "text": ascii_txt[:200]})
                # salted envelope?
                if decoded.startswith(b"Salted__") or (
                    len(decoded) >= 16 and decoded[:8] == b"Salted__"
                ):
                    meta.setdefault("salted", []).append(label)
    return candidates, meta


def experiment_cosmic_pubkey_delta(cosmic_pt: bytes, chain4_blocks: list[bytes]) -> tuple[list[tuple[str, bytes]], dict]:
    matrix = analyze(cosmic_pt)
    C = matrix.base38_bytes
    assert C[0] == 0x04
    Cx = C[1:33]
    Cy = C[33:65]
    trail = C[64:68]
    Hx = HALF_PUB[1:33]
    Hy = HALF_PUB[33:65]
    Dx = _xor_bytes(Cx, Hx)
    Dy = _xor_bytes(Cy, Hy)
    D64 = Dx + Dy
    Mx = ((HX - int.from_bytes(Cx, "big")) % P).to_bytes(32, "big")
    My = ((HY - int.from_bytes(Cy, "big")) % P).to_bytes(32, "big")
    candidates: list[tuple[str, bytes]] = [
        ("cosmic/Dx", Dx),
        ("cosmic/Dy", Dy),
        ("cosmic/D64", D64),
        ("cosmic/Mx", Mx),
        ("cosmic/My", My),
        ("cosmic/Mx||My", Mx + My),
        ("cosmic/Dx||Dy", D64),
        ("cosmic/trail", trail),
        ("cosmic/Dx^Dy", _xor_bytes(Dx, Dy)),
        ("cosmic/sha(D64)", _sha(D64)),
        ("cosmic/sha(Dx||Dy||trail)", _sha(D64 + trail)),
        ("cosmic/half_raw", matrix.half),
        ("cosmic/better_raw", matrix.better_half),
    ]
    # XOR D64 over chain4 block pairs
    for i in range(len(chain4_blocks) - 1):
        pair = chain4_blocks[i] + chain4_blocks[i + 1]
        candidates.append((f"c4pair[{i},{i+1}]^D64", _xor_bytes(pair, D64)))
        candidates.append((f"c4pair[{i},{i+1}]^MxMy", _xor_bytes(pair, Mx + My)))
    # also XOR each block with Dx/Dy
    for i, blk in enumerate(chain4_blocks):
        candidates.append((f"c4[{i}]^Dx", _xor_bytes(blk, Dx)))
        candidates.append((f"c4[{i}]^Dy", _xor_bytes(blk, Dy)))
        candidates.append((f"c4[{i}]^Mx", _xor_bytes(blk, Mx)))
        candidates.append((f"c4[{i}]^My", _xor_bytes(blk, My)))

    meta = {
        "base38_hex": C.hex(),
        "Dx_hex": Dx.hex(),
        "Dy_hex": Dy.hex(),
        "Mx_hex": Mx.hex(),
        "My_hex": My.hex(),
        "Dx_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in Dx),
        "Dy_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in Dy),
        "Dx_has_trail": trail in Dx or trail in Dy or trail in D64,
        "zero_prefix_Dx": Dx[:4].hex(),
        "zero_prefix_Dy": Dy[:4].hex(),
    }
    return candidates, meta


def experiment_witteveen_selectors(chain4_blocks: list[bytes]) -> tuple[list[tuple[str, bytes]], dict]:
    candidates: list[tuple[str, bytes]] = []
    # numeric selectors mod 35 -> 0-based indices
    idxs = [((v - 1) % 35) for v in DIAG_SUMS]
    idxs_raw = [(v % 35) for v in DIAG_SUMS]
    words = {
        "WITVEEN": "WITVEEN",
        "WITTEVEEN": "WITTEVEEN",
        "HJWITTEVEEN": "HJWITTEVEEN",
        "unaware": "unaware",
        "source": "source",
        "function": "function",
        "purpose": "purpose",
        "yinyang": "yinyang",
        "HASHTHETEXT": "HASHTHETEXT",
    }
    word_idxs = {}
    for name, w in words.items():
        vals = [((ord(c.upper()) - 64) % 35) for c in w if c.isalpha()]
        word_idxs[name] = vals

    def fold(blocks: list[bytes], tag: str) -> None:
        if not blocks:
            return
        x = bytearray(32)
        s = 0
        for b in blocks:
            s = (s + int.from_bytes(b, "big")) % N
            for i, bb in enumerate(b):
                x[i] ^= bb
        candidates.append((f"wit/{tag}/xor", bytes(x)))
        candidates.append((f"wit/{tag}/sum", s.to_bytes(32, "big")))
        candidates.append((f"wit/{tag}/sha-concat", _sha(b"".join(blocks))))
        if len(blocks) >= 2:
            candidates.append((f"wit/{tag}/first", blocks[0]))
            candidates.append((f"wit/{tag}/last", blocks[-1]))

    fold([chain4_blocks[i] for i in idxs], "diagsums-1based")
    fold([chain4_blocks[i] for i in idxs_raw], "diagsums-0based")
    # pairwise products of indices
    for a, b in zip(idxs, idxs[1:]):
        fold([chain4_blocks[a], chain4_blocks[b]], f"pair-{a}-{b}")

    for name, vals in word_idxs.items():
        sel = [chain4_blocks[v % 35] for v in vals]
        fold(sel, f"word-{name}")
        # yin/yang split: vowels vs consonants
        vowels = []
        cons = []
        for c, blk in zip(words[name], sel):
            if c.lower() in "aeiou":
                vowels.append(blk)
            else:
                cons.append(blk)
        fold(vowels, f"word-{name}-vowels")
        fold(cons, f"word-{name}-cons")
        if vowels and cons:
            # xor of vowel-fold and cons-fold
            vx = bytearray(32)
            cx = bytearray(32)
            for b in vowels:
                for i, bb in enumerate(b):
                    vx[i] ^= bb
            for b in cons:
                for i, bb in enumerate(b):
                    cx[i] ^= bb
            candidates.append((f"wit/word-{name}-yin^yang", _xor_bytes(bytes(vx), bytes(cx))))

    # page140 unaware as mask on Cosmic halves handled elsewhere; here as selector seed
    unaware_sha = _sha(b"unaware")
    for i, blk in enumerate(chain4_blocks):
        candidates.append((f"wit/unaware^c4[{i}]", _xor_bytes(unaware_sha, blk)))

    meta = {"diag_indices_1based": idxs, "diag_indices_0based": idxs_raw, "word_count": len(words)}
    return candidates, meta


def experiment_creator_pipeline_yinyang(cosmic_env: bytes) -> tuple[list[tuple[str, bytes]], dict]:
    candidates: list[tuple[str, bytes]] = []
    meta: dict = {"aes_hits": [], "aes_attempts": 0}

    # Creator-pipeline digest XOR prefixes
    digests = [_sha(t.encode()) for t in CREATOR_PIPELINE]
    for end in range(1, len(digests) + 1):
        key = _xor_many(digests[:end])
        label = "pipe/xor-to-" + CREATOR_PIPELINE[end - 1]
        candidates.append((label, key))
        for digest_name in ("md5", "sha256"):
            meta["aes_attempts"] += 1
            try:
                dec = decrypt_salted_aes256_cbc(cosmic_env, key, digest=digest_name)
                meta["aes_hits"].append(
                    {
                        "label": label,
                        "digest": digest_name,
                        "len": len(dec.plaintext),
                        "sha": _sha(dec.plaintext).hex(),
                        "head": dec.plaintext[:32].hex(),
                    }
                )
                candidates.append((label + f"/aes-{digest_name}-pt", dec.plaintext))
            except Exception:
                pass

    # Instruction-replacement model on public 7-token XOR
    public_tokens = [
        "matrixsumlist",
        "enter",
        "lastwordsbeforearchichoice",
        "thispassword",
        "matrixsumlist",
        "yourlastcommand",
        "secondanswer",
    ]
    replacements = {
        "yourlastcommand": [
            "yellowblueprimes",
            "yinyang",
            "unaware",
            "WITTEVEEN",
            "HASHTHETEXT",
            "verylaststepisatruegiveawaypromised",
            "itsinfrontofyoureyesbutyourenotseeingit",
        ],
        "secondanswer": [
            "yellowblueprimes",
            "yinyang",
            "unaware",
            "WITTEVEEN",
            "HASHTHETEXT",
            "verylaststepisatruegiveawaypromised",
            "wewontgiveawaythepassword",
        ],
        "enter": ["yellowblueprimes", "yinyang", "<3"],
        "thispassword": ["yinyang", "wewontgiveawaythepassword", "itsinfrontofyoureyesbutyourenotseeingit"],
    }
    # single substitutions
    for slot, alts in replacements.items():
        idx = public_tokens.index(slot)
        for alt in alts:
            toks = list(public_tokens)
            toks[idx] = alt
            key = _xor_many([_sha(t.encode()) for t in toks])
            label = f"subst/{slot}->{alt}"
            candidates.append((label, key))
            for digest_name in ("md5",):
                meta["aes_attempts"] += 1
                try:
                    dec = decrypt_salted_aes256_cbc(cosmic_env, key, digest=digest_name)
                    meta["aes_hits"].append(
                        {
                            "label": label,
                            "digest": digest_name,
                            "len": len(dec.plaintext),
                            "sha": _sha(dec.plaintext).hex(),
                        }
                    )
                    candidates.append((label + "/aes-pt", dec.plaintext))
                except Exception:
                    pass

    # dual subst yourlastcommand + secondanswer
    for a in replacements["yourlastcommand"]:
        for b in replacements["secondanswer"]:
            toks = list(public_tokens)
            toks[5] = a
            toks[6] = b
            key = _xor_many([_sha(t.encode()) for t in toks])
            label = f"dual/{a}+{b}"
            candidates.append((label, key))
            meta["aes_attempts"] += 1
            try:
                dec = decrypt_salted_aes256_cbc(cosmic_env, key, digest="md5")
                meta["aes_hits"].append(
                    {"label": label, "digest": "md5", "len": len(dec.plaintext), "sha": _sha(dec.plaintext).hex()}
                )
                candidates.append((label + "/aes-pt", dec.plaintext))
            except Exception:
                pass

    # literal concatenations as passwords / scalars
    for phrase in (
        "".join(CREATOR_PIPELINE),
        "".join(CREATOR_PIPELINE[:4]),
        "yinyang",
        "yingyang",
        "verylaststepisatruegiveawaypromised",
        "itsinfrontofyoureyesbutyourenotseeingit",
        "wewontgiveawaythepassword",
        "HASHTHETEXT",
        "yellowblueprimes",
    ):
        candidates.append((f"lit/{phrase[:40]}", phrase.encode()))
        candidates.append((f"litsha/{phrase[:40]}", _sha(phrase.encode())))

    return candidates, meta


def experiment_halving_arithmetic(matrix_half: bytes, matrix_better: bytes) -> list[tuple[str, bytes]]:
    """Creator halves prize at halvings — try arithmetic halvings on Cosmic scalars."""
    h = int.from_bytes(matrix_half, "big")
    b = int.from_bytes(matrix_better, "big")
    out: list[tuple[str, bytes]] = []
    for name, val in (
        ("half/2", h // 2),
        ("better/2", b // 2),
        ("(h+b)/2", (h + b) // 2),
        ("(h-b)/2 % N", ((h - b) // 2) % N),
        ("(b-h)/2 % N", ((b - h) // 2) % N),
        ("h^b", h ^ b),
        ("(h^b)/2", (h ^ b) // 2),
        ("h*2 % N", (h * 2) % N),
        ("b*2 % N", (b * 2) % N),
        ("h+b % N", (h + b) % N),
        ("h-b % N", (h - b) % N),
        ("b-h % N", (b - h) % N),
        ("h*inv(b) % N", (h * pow(b % N, -1, N)) % N if b % N else 0),
        ("b*inv(h) % N", (b * pow(h % N, -1, N)) % N if h % N else 0),
        # halvings as right-shift
        ("h>>1", h >> 1),
        ("b>>1", b >> 1),
        ("h>>2", h >> 2),
        ("b>>2", b >> 2),
    ):
        if val:
            out.append((f"halve/{name}", (val % N).to_bytes(32, "big")))
    # known Half pubkey as Q = d*G; if Cosmic half is related by factor
    # try d_guess = discrete? can't. Try: if Cosmic half * G somehow...
    # Check whether Cosmic half/better as scalars produce related points to Half pubkey
    return out


def run() -> dict:
    parts = json.loads((ROOT.parent / "derived" / "salphaseion_parts.json").read_text())
    extracted = extract_all()
    tokens = derive_tokens()
    chains = reconstruct(extracted, tokens)
    chain4 = reconstruct_chain4(chains)
    cosmic_pt = chains.cosmic_decryption.plaintext
    cosmic_env = extracted.cosmic_envelope

    matches: list[dict] = []
    tested = [0]
    meta: dict = {}

    # 1) HASHTHETEXT S-fields
    c1, m1 = experiment_hashtext_sfields(parts)
    meta["hashtext_sfields"] = m1
    _gate(c1, matches, tested)

    # 2) Cosmic pubkey delta
    c2, m2 = experiment_cosmic_pubkey_delta(cosmic_pt, list(chain4.blocks))
    meta["cosmic_delta"] = m2
    _gate(c2, matches, tested)

    # 3) Witteveen selectors
    c3, m3 = experiment_witteveen_selectors(list(chain4.blocks))
    meta["witteveen"] = m3
    _gate(c3, matches, tested)

    # 4) Creator pipeline / yinyang
    c4, m4 = experiment_creator_pipeline_yinyang(cosmic_env)
    meta["creator_pipeline"] = {
        "aes_attempts": m4["aes_attempts"],
        "aes_hits": m4["aes_hits"],
        "candidate_preimages": len(c4),
    }
    _gate(c4, matches, tested)

    # 5) Halving arithmetic on Cosmic halves
    matrix = analyze(cosmic_pt)
    c5 = experiment_halving_arithmetic(matrix.half, matrix.better_half)
    meta["halving_arith"] = {"candidates": len(c5)}
    _gate(c5, matches, tested)

    # 6) Re-gate known Cosmic/Chain4 windows + trail combinations (Better-aware)
    regen: list[tuple[str, bytes]] = []
    regen.append(("cosmic/half", matrix.half))
    regen.append(("cosmic/better", matrix.better_half))
    regen.append(("cosmic/trail1", matrix.trail1))
    regen.append(("cosmic/half^better", _xor_bytes(matrix.half, matrix.better_half)))
    regen.append(("cosmic/half||better", matrix.half + matrix.better_half))
    # trail splice into halves
    t = matrix.trail1
    for name, half in (("H", matrix.half), ("B", matrix.better_half)):
        for pos in range(0, 33, 4):
            spliced = half[:pos] + t[: min(4, 32 - pos)] + half[pos + min(4, 32 - pos) :]
            if len(spliced) == 32:
                regen.append((f"splice/{name}@{pos}", spliced))
    for i, blk in enumerate(chain4.blocks):
        regen.append((f"c4blk[{i}]", blk))
    meta["regen"] = {"candidates": len(regen)}
    _gate(regen, matches, tested)

    result = {
        "schema": "creator-frontier-giveaway-audit-v1",
        "status": "MATCH" if matches else "NO_MATCH",
        "scalar_tests": tested[0],
        "prize_matches": matches,
        "prize_addresses": PRIZE,
        "meta": meta,
        "notes": [
            "HASHTHETEXT digit-pair decode over S91/S570 variants",
            "Cosmic base38 XOR/sub delta vs known Half pubkey",
            "Witteveen/page140 as Chain4 block selectors",
            "Creator-pipeline XOR and instruction-substitution Cosmic passwords",
            "Halving arithmetic on Cosmic halves",
            "All scalars gated to Half AND Better Half hash160/address",
        ],
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    out = run()
    print(
        json.dumps(
            {
                "status": out["status"],
                "scalar_tests": out["scalar_tests"],
                "prize_matches": out["prize_matches"],
                "hashtext_asciiish": out["meta"]["hashtext_sfields"].get("asciiish", []),
                "cosmic_delta_ascii": {
                    "Dx": out["meta"]["cosmic_delta"]["Dx_ascii"],
                    "Dy": out["meta"]["cosmic_delta"]["Dy_ascii"],
                },
                "aes_hits": out["meta"]["creator_pipeline"]["aes_hits"],
                "aes_attempts": out["meta"]["creator_pipeline"]["aes_attempts"],
            },
            indent=2,
        )
    )
