# Tools

Dependency-free Python 3. Nothing here imports a third-party package, opens a
network connection, or resolves a path outside this folder. `_paths.py` is the
only place paths are defined, and every one of them is relative to
`fresh-start/`.

Run everything and check it against its digests:

```bash
python3 tools/verify_all.py
```

## Stage tools

| File | What it does |
| --- | --- |
| `poster_spiral.py` | Reads the poster PNG as a 14×14 grid, walks the spiral, decodes the URL and the 24 markers |
| `extract_ciphertexts.py` | Pulls the AES envelopes out of `archives/*.html` into `ciphertexts/` |
| `phase2_phase3.py` | Decrypts phase 2, phase 3, and the phase 3.2 envelope carried inside phase 3 |
| `phase32_classical.py` | Symbol record → EBCDIC → Beaufort → Architect plaintext; and the VIC checkerboard |
| `salphaseion_fields.py` | Splits the SalPhaseIon stream and decodes the literals that actually decode |
| `prize_gate.py` | The only acceptance test for a candidate private key |
| `fitted_observations.py` | Recomputes the quoted arithmetic and prints what each result assumes |

## Support modules

| File | What it does |
| --- | --- |
| `_paths.py` | Every path, all inside this folder |
| `aes.py` | AES-256-CBC decryption; pure Python, with a faster backend if one is installed |
| `openssl_aes.py` | `EVP_BytesToKey` and the OpenSSL `Salted__` envelope format |
| `png.py` | Minimal PNG reader, so the image stages do not need Pillow |

`aes.py` and `png.py` exist so a bare Python 3 install is enough. Both self-test:
`python3 tools/aes.py` checks the FIPS-197 AES-256 vector against both the
installed backend and the pure-Python path.

## Conventions

- A tool prints what it computed and how it checked it. Where a result has a
  known digest, the tool prints MATCH or the digest it expected instead.
- No tool asserts a result is correct because it decrypted without error.
  `openssl_aes.py` documents why valid padding is not evidence.
- Anything computed goes to `derived/`, which is disposable. Committed inputs
  are never written to.
- `prize_gate.py` holds the only copy of the target constants, and re-derives
  them from the addresses. Do not copy them elsewhere.
