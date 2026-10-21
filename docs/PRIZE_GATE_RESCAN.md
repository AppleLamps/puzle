# Prize-gate rescan of stored outputs (2026-10-21)

**Result: 0 prize matches.** Every candidate key that the shared checker can find in this
repository's committed files was gated against both prize targets under both public-key
serializations. This is a bounded negative over the files and encodings below, nothing more.

## The checker

`gsmgio-5btc-puzzle-master/solver/prize_gate.py` (prize_gate 1.0.1, sha256 `9dfa1d2fb4769d57…`) is byte-identical across the
GSMG repositories. It gates:

- **Half** `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`: hash160 under both serializations, plus its on-chain public key;
- **Better Half** `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa`: hash160 under both serializations (it has never spent).

Inside each file it parses raw 32-byte windows (binary files), every 64-character hex window, WIF
(compressed and uncompressed), mini keys, 32-byte base64 tokens, 60 to 78 digit decimals, sha256 of the
whole file, and hex or base64 blobs decoded and parsed once more. `python3 gsmgio-5btc-puzzle-master/solver/prize_gate.py selftest`
plants a key in every one of those encodings, in both target slots and both serializations; all 55
checks passed before this scan ran.

## Gate defects fixed in this repository

- None needed. `solver/targets.py` already gates both targets under both serializations; the shared checker is installed as `solver/prize_gate.py` and takes its constants from `solver.targets`, as `CLAUDE.md` requires. It adds what `targets.py` does not do: parsing hex, WIF, mini, base64 and decimal keys out of plaintexts.
- `tests/test_prize_gate.py` (3 tests) checks that the constants are the canonical objects, that the planted controls fire, and that `NON_TARGETS` never match. Full suite: 66 passed.

## Scope

- Files scanned: 1,599 (520 binary), 209.7 MB
- Unique scalars gated: 15,870,086 (duplicates across files gated once)
- Run time: 940 s with the `coincurve` backend

| Candidate kind | Count |
| --- | ---: |
| `raw32` | 7,021,374 |
| `hex64` | 5,045,375 |
| `b64blob/raw32` | 3,771,824 |
| `b64blob/hex64` | 28,331 |
| `derived_sha256_stripped` | 952 |
| `b64` | 843 |
| `derived_sha256` | 824 |
| `dec` | 375 |
| `mini` | 110 |
| `hexblob/dec` | 54 |
| `wif_uncompressed` | 11 |
| `wif_compressed` | 8 |
| `hexblob/b64` | 4 |
| `hexblob/mini` | 1 |

Files with the most candidates:

- `transcripts/rollout-2026-08-04T21-14-50-019fcf7c-cc26-7b91-b013-c82ce7cfddf0.jsonl`: 3,524,563
- `gsmgio-5btc-puzzle-master/salphaseion_preregistered_candidates_v36.json`: 2,858,326
- `gsmgio-5btc-puzzle-master/artifacts/wayback_cache/bodies/dce49319e0d8e948e0c035306397d0f44a240a644327594484530364bca19dac.bin`: 2,619,082
- `gsmgio-5btc-puzzle-master/salphaseion_preregistered_candidates_v29.json`: 858,195
- `gsmgio-5btc-puzzle-master/artifacts/wayback_cache/bodies/fb22ae661b2afe99d074852b523a85816c71ca41994cb3751b517e86d30c0b07.bin`: 412,415
- `gsmgio-5btc-puzzle-master/artifacts/wayback_cache/bodies/21d9b4485e0fe3baee6cdaf0eeb9c4252ab913b5f98535987ae8c5c8d10ca6b4.bin`: 409,400
- `gsmgio-5btc-puzzle-master/artifacts/wayback_cache/bodies/db57f2ec0483e1b62f3bf87350f20998e565bb1bb547a437e1722420bc73c10d.bin`: 405,512
- `gsmgio-5btc-puzzle-master/artifacts/wayback_cache/bodies/1e3aed358b31910459791f75860606de32b627d092ada19d8c33683228369705.bin`: 391,195
- `gsmgio-5btc-puzzle-master/artifacts/wayback_cache/bodies/004bf81bba2cb80907748458a7b4419411070262ff40a9a74642990d5fcd0cd5.bin`: 390,167
- `gsmgio-5btc-puzzle-master/artifacts/wayback_cache/bodies/ee9e1ae669beabc10a296f9bd03020135825d9b6bab0fc7e01e80dba9a84e7dd.bin`: 388,514

## Not covered

- Media and archives, skipped by extension: 1 `.jpg`, 1 `.mp3`, 2 `.pdf`, 127 `.png`, 1 `.wav`.
- Raw 32-byte windows are taken only over binary files; text files get the text parsers.
- Outputs that were never committed (for example gitignored run directories) cannot be rescanned.

## Reproduce

```
pip install coincurve            # optional, about 18,000 scalars per second
python3 gsmgio-5btc-puzzle-master/solver/prize_gate.py selftest
python3 gsmgio-5btc-puzzle-master/solver/prize_gate.py scan . --json /tmp/rescan.json
```

The compact summary is `gsmgio-5btc-puzzle-master/prize_gate_rescan.json`.
