# Fresh start — a self-contained workspace for the GSMG.IO 5 BTC puzzle

This folder is a **clean room**. Everything needed to work on the puzzle is
inside it: the creator-published images and pages, the ciphertexts extracted
from those pages, the tools that re-derive every reproducible stage, and the
on-chain facts about the prize addresses.

Two properties are deliberate, and both are worth keeping:

- **Nothing here reads anything outside this folder.** No path escapes it, no
  tool imports a package from elsewhere, and no document points at a file you
  would have to go and find. Copy the folder anywhere and it still runs.
- **Nothing here is inherited on trust.** Every factual claim below is either
  something you can decrypt, hash, or look up on chain — or it is labelled as
  an assumption. Where an earlier reading could not be reproduced from the
  material committed here, this folder says so rather than repeating it.

## Verify it before you read it

```bash
python3 tools/verify_all.py
```

That starts from the committed PNG and HTML, re-derives every stage, and checks
each against its digest. It needs Python 3 and nothing else — no third-party
packages, no network. Thirty-four checks; if any prints FAIL, believe the line
rather than the prose.

## Layout

| Path | Contents |
| --- | --- |
| `CREATOR_STATEMENTS.md` | Creator chronology and the 2023-02-23 seven-phrase pipeline |
| `PRIZE_TARGETS.md` | Half and Better Half; how a candidate key is accepted |
| `AUTHENTICATED_STAGES.md` | Every reproduced stage, with the digest that fixes it |
| `INVENTORY.md` | What is in this folder, where it came from, what is missing |
| `REPRODUCTION.md` | How to re-derive everything, and what each step proves |
| `CREATOR_WEBSITE_LINKS.md` | Original gsmg.io URLs plus Wayback captures |
| `links.json` | The same links, machine-readable |
| `archives/` | Local HTML copies of creator pages |
| `images/` | Poster PNG and the eight rebus tiles |
| `ciphertexts/` | Base64 AES envelopes pulled out of those pages |
| `artifacts/` | Committed plaintext extracts, to compare your output against |
| `tools/` | Dependency-free Python that re-derives every stage |
| `derived/` | Everything the tools compute. Disposable; not committed |
| `SHA256SUMS` | Fingerprints of every committed input |

## Evidence rules

1. **Creator-published artifacts** — the pages, images and ciphertexts — and
   **messages from the creator's account** are the strongest evidence.
2. **A successful AES decryption to coherent plaintext** authenticates that
   ciphertext and password. Coherent means you can read it, not that it unpadded.
3. **An exact hash** of a named byte string fixes a result once you reproduce it.
4. **On-chain data** — addresses, spends, public keys — is independently checkable.
5. Everything else needs independent proof before you build on it.

When a result depends on a choice nobody has shown the creator made — index
base, prime assignment, matrix orientation, token order — it is **fitted**, not
authenticated. `tools/fitted_observations.py` recomputes the best-known fitted
results and prints the assumption alongside each one, so the number never
travels without its caveat.

## Things that have produced false positives

None of these is evidence, however striking it looks:

- **Valid PKCS#7 padding.** A `Salted__` envelope that unpads cleanly proves
  nothing — over a large candidate space it happens by chance about 1 time in
  256. `tools/openssl_aes.py` says so in the code, and you can watch it happen:
  probing the 96-byte SalPhaseIon envelope finds a password that unpads to 60
  bytes of pure noise.
- **A readable English fragment** inside otherwise random output.
- **A vanity address prefix.**
- **A number that works out.** Arithmetic that lands exactly is a reason to look
  closer, not a result — see `fitted_observations.py`.
- **On-chain activity at an address a solver published.** That is a consequence
  of publication, never creator confirmation. `tools/prize_gate.py` lists the
  four such addresses as `NON_TARGETS`.

## Prize status

The funded private keys have not been publicly recovered. The creator has said
the puzzle remains valid. Check the current balances on chain yourself — the
addresses are in `PRIZE_TARGETS.md`.

## Working here

1. Run `tools/verify_all.py` so you know the baseline holds.
2. Read `AUTHENTICATED_STAGES.md` for what is fixed, and `INVENTORY.md` for what
   is missing.
3. Read `CREATOR_STATEMENTS.md` — the creator's own words outrank any
   conclusion drawn about them, including the ones in this folder.
4. Form hypotheses from creator statements and authenticated text.
5. Gate every candidate scalar through `tools/prize_gate.py`. It is the only
   acceptance test. Do not re-declare the target constants anywhere else.

If you write down a new result, write down what fixes it: a digest, a decrypt,
or an on-chain lookup. If nothing fixes it, label it fitted and say which
convention it rests on. That labelling is the only thing keeping this folder
from turning into the kind of record it was made to avoid.
