# Reproduction commands

Run from the repository root unless noted. Requires Python 3 and dependencies
from `../gsmgio-5btc-puzzle-master/` (see that package for install).

## Standalone stage scripts (read `../sources/`, write `../derived/`)

```bash
python3 scripts/solve.py          # poster spiral → URL
python3 scripts/solve_rebus.py    # rebus tiles
python3 scripts/phase23.py        # phases 2 and 3
python3 scripts/inspect_bundle.py # phase1verification 404 check
```

## Package modules (authenticated stage checks)

```bash
cd ../gsmgio-5btc-puzzle-master

python3 -m solver.targets              # re-derive prize target constants
python3 -m solver.phase32_classical      # symbol record, Beaufort, VIC checkerboard
python3 -m solver.phase32_symbol_recovery # Architect plaintext + SHA-256
python3 -m solver.salphaseion            # SalPhaseIon field token decode (stdout)
python3 -m solver.extract                # list embedded envelope sizes
```

## Expected digests (verify your output matches)

| object | SHA-256 |
| --- | --- |
| Raw 1,539-byte symbol record | `bd7a29432546c67c4170e0c523ddbf43ae82d20ee187d1b4dbf7907a0faf4c7b` |
| Architect plaintext (1,539 letters) | `56c43a300e28b86bb43b8dcbae74c43c76bde90b3e1190620fb656f2c94b2241` |
| Phase 3.2 AES plaintext | `b82afeb86f9e50848220f9b64b744b821400308aea273a1c949b9d2d0e408a34` |
| VIC checkerboard plaintext | `878b7afacc9e35412e76b8506cc8297fa5aeba5381e108dc421b71a0ab8993d8` |
| Seven-part phase 2 gate | `1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5` |

## Phase 3.2 decrypt (OpenSSL reference)

Password (64 ASCII characters, not 32 raw bytes):

```text
250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c
```

```bash
# If you have the phase 3.2 Base64 blob in a file phase32.b64:
openssl enc -aes-256-cbc -d -a -in phase32.b64 \
  -pass pass:250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c \
  -md sha256
```

## Beaufort (Architect)

- Key: `THEMATRIXHASYOU`
- Operation: Beaufort / P = K − C (mod 26)
- Input: 1,539-letter lowercase ciphertext from published README transliteration
- Output must match `artifacts/architect_plaintext.txt`

## Prize gate (any candidate scalar)

```python
import sys
sys.path.insert(0, "../gsmgio-5btc-puzzle-master")
from solver.targets import gate_scalar_bytes
gate_scalar_bytes(bytes.fromhex("YOUR32BYTEHEX"))  # None unless prize match
```

## Integrity note

Parent repository tests (`python3 -m pytest -q` in the solver package) verify
reproducibility of many stages. Running them validates the **codebase**, not your
independent hypothesis. Prefer matching the digests above from your own extraction
path first.
