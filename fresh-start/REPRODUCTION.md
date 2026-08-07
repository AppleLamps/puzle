# Reproduction

Python 3 and nothing else. No third-party packages, no network access, no path
outside this folder. Run from the folder root.

```bash
python3 tools/verify_all.py
```

That is the whole thing: it re-derives every stage from the committed PNG and
HTML and checks each against its digest. Everything below is the same work,
step by step, so you can watch each stage instead of taking the summary.

## Stage by stage

```bash
python3 tools/poster_spiral.py          # PNG  → gsmg.io/theseedisplanted, markers → F73D92
python3 tools/extract_ciphertexts.py    # HTML → ciphertexts/*.b64
python3 tools/phase2_phase3.py          # AES chain: phase 2 → phase 3 → phase 3.2
python3 tools/phase32_classical.py      # symbol record → Beaufort → VIC checkerboard
python3 tools/salphaseion_fields.py     # SalPhaseIon stream fields and literals
python3 tools/prize_gate.py             # target constants and gate self-check
python3 tools/fitted_observations.py    # the fitted arithmetic, with its assumptions
```

`phase32_classical.py` needs `phase2_phase3.py` to have run; `fitted_observations.py`
needs `phase32_classical.py`. Everything else is independent. Output lands in
`derived/`, which is disposable — delete it and re-run at any time.

## What each step actually proves

| Step | What fixes the result |
| --- | --- |
| Poster spiral | The bits decode to a readable URL, the residual is `0000`, and the 24 markers land on exactly every 8th bit. An arbitrary read order does none of that. |
| Phase 2 | Decrypts under `sha256("causality")` to coherent English. |
| Phase 3 | Decrypts under the seven-part digest to coherent English. |
| Phase 3.2 | Decrypts to coherent English; plaintext SHA-256 stated below. |
| Symbol record | 1,539 bytes over exactly 26 distinct symbols; SHA-256 stated below. |
| EBCDIC map | Every symbol maps to a lowercase letter and the map is a bijection over 26. A wrong code page does not close. |
| Beaufort | Output is readable English; SHA-256 stated below. |
| VIC checkerboard | Output is a readable sentence; SHA-256 stated below. |
| Prize gate | Half's on-chain public key hashes to the address in its own base58 decode. |

Note what is *not* on that list: nothing is accepted because it unpadded
cleanly, and nothing is accepted because a password "looked right".

## Digests

| Object | SHA-256 |
| --- | --- |
| Phase 3.2 AES plaintext (2,422 bytes) | `b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34` |
| Raw 1,539-byte symbol record | `bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b` |
| Architect plaintext (1,539 letters) | `56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241` |
| VIC checkerboard plaintext | `878b7afacc9e35412e76b8506cc8297fa5aeba5381e108dc421b71a0ab8993d8` |
| Seven-part phase 2 answer (the phase 3 password) | `1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5` |

## Passwords

Each is the **64 ASCII hex characters** of a SHA-256 digest, not the 32 raw
bytes. OpenSSL's `EVP_BytesToKey` derives the key and IV; these envelopes use
the SHA-256 digest variant (OpenSSL 1.1.0+ default), not MD5.

| Payload | Password |
| --- | --- |
| Phase 2 | `sha256("causality")` |
| Phase 3 | `1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5` |
| Phase 3.2 | `sha256("jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple")` = `250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c` |

With the OpenSSL CLI, once `tools/phase2_phase3.py` has written `ciphertexts/phase32.b64`:

```bash
openssl enc -aes-256-cbc -d -a -md sha256 -in ciphertexts/phase32.b64 \
  -pass pass:250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c
```

## Gating a candidate key

`tools/prize_gate.py` is the only acceptance test in this folder.

```python
import sys
sys.path.insert(0, "tools")
from prize_gate import gate_scalar_bytes

gate_scalar_bytes(bytes.fromhex("…64 hex chars…"))   # None, "Half", or "Better Half"
```

It re-derives both hash160s from the addresses themselves, so there is no
constant to mistype. Do not copy the targets into a new module.

## Integrity of the inputs

```bash
sha256sum -c SHA256SUMS
```

If a fingerprint changes, an input changed — every digest above is downstream
of those bytes.

## About the tools

`tools/aes.py` ships a pure-Python AES-256-CBC so nothing needs installing; it
uses `cryptography` or `pycryptodome` instead when either is importable and
working. `tools/png.py` reads the poster without Pillow. Both are decryption and
decoding only, and both self-test: `python3 tools/aes.py` checks the FIPS-197
AES-256 vector.
