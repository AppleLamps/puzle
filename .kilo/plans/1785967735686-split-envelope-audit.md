# Split-envelope (env48 / raw48) sealed audit

## Goal

Close the remaining **OPEN** SalPhaseIon item — "independent role of the 48-byte
envelope" (`docs/ATTEMPT_LOG.md` §5, and §12 frontier item 3) — by testing the
two 48-byte halves of the short blob as *independent decryption targets* under
only authenticated key/IV/password material, plus an envelope-salt control
hunt. Scope confirmed with user: **narrow sealed audit** (no replay of the
~1M historical password manifests; that is the "wider password search" the
docs deprioritize).

## Why this is the frontier

`docs/SOLVED_STAGE_REAUDIT.md` (2026-08-05) names it explicitly: after the
Architect source-prime reinsertion (`COMPLETE_NO_MATCH`) and the S91/S570
base-9 exhaustion (`NO_ACCEPTED_OUTPUT`), the best remaining
creator-authenticated frontier is the 48-byte envelope and the operational
meaning of the decoded field literals, requiring *a new source-authenticated
control*.

## Verified facts (reproduced 2026-08-05)

- The first-textarea base64 splits around the unique `enter` marker into two
  64-char runs:
  - **env48** = run 1 → 48 bytes, `Salted__` + salt `3ab585348552415d` + 2
    ciphertext blocks. sha256 `f35efe2236bf60310e7b645ad297b70c6fd1670e5717d7601f5319e69d489b1b`.
  - **raw48** = run 2 → 48 bytes, no header (3 blocks).
    sha256 `bab0c6d922a323c893f071b3b70885d00ae885914dbd70568dd6a032bc05ed70`.
  - Glued (enter deleted) = the chain-1 envelope (96 bytes); opens with the
    five-token joke password → 79-byte triplet → WIF
    `5K2byJMssxFKuTgnk9YQjpBz5FhkwwF2LaZoAyTus8HjGEpz8AT` → chain-2.
- Every sealed family (v1–v39, cross-stage, instruction audit) targeted only
  the **glued** short blob, `phase32-small`, and `cosmic-duality`. env48-alone
  and raw48-alone were never sealed targets (only ad-hoc probes in
  `CREATOR_SOURCED.md`).
- Envelope salts: env48 `3ab585348552415d`, chain2 `b45a5e3d827593ca`,
  phase32 `eefc4c5befc1656a`, cosmic `2d3f6fe06dc950e6`. Quick check: none
  occurs in chain-1/2 plaintexts or S91/S570 base-9 byte streams; full hunt
  remains open.
- Existing helpers: `solver/salphaseion_raw.py` (frozen token split),
  `solver/chains.py::reconstruct` (chain-1/2 triplets, Cosmic decryption with
  key+IV), `solver/salphaseion.py` (`xor_password` = 7-token digest XOR),
  `solver/openssl_compat.py`, `solver/secp256k1_verify.py` (`N`, `hash160`,
  `wif`), `coincurve` for point gates. Prize gates: Half exact uncompressed
  point (`04f4d1bbd9…` / y `9c73d25f…`), Better hash160
  `4bc468447fe1b048ad030a2f9a125478eabc4ed6`.

## Tasks

### 1. `solver/salphaseion_split_envelope_preregister.py`

Deterministically rebuild env48/raw48 from the earliest Wayback capture
(`salphaseion_raw` token logic; assert the two pinned sha256 values and that
`env48 + raw48 == chain1_envelope`). Freeze a manifest with:

- **targets**: `env48` (OpenSSL envelope), `raw48` (raw 3-block candidate),
  plus `chain1-glued` as positive control only.
- **K1 — direct AES-256-CBC key+IV on raw48 (no KDF)**. Keys (all derived in
  code from `chains.reconstruct`, never hard-coded without provenance):
  Cosmic key (`6ac438fa…`), chain-1 `key1`/`key2`, chain-2 `key1`/`key2`, the
  seven token digests, their XOR (`a795de11…`), `sha256(chain1 pt)`,
  `sha256(chain2 pt)`. IVs (frozen): zero, Cosmic IV (`c6ff2e39…`),
  `chain1.key1[:16]`, `chain1.key2[:16]`, `chain2.key1[:16]`,
  `chain2.key2[:16]`, each 15-byte tail `key3` left-padded with `0x00` to 16.
  Full cross product, dedup.
- **K2 — EVP passwords on env48 standalone** (finite authenticated token set
  only): the five chain-1 tokens in frozen physical source order, the glued
  joke password, the six decoded field literals, `HASHTHETEXT`/`hashthetext`,
  the seven 2023 creator-pipeline words, the seven authenticated stage
  passwords. Two forms each (raw bytes, lowercase sha256 hex) × {md5, sha256}
  `EVP_BytesToKey`, strict PKCS#7.
- **K3 — stage-two `shabefanstoo` rule on the split blobs**: for every
  strict-padding plaintext from K1/K2, test `sha256(whole plaintext)` (raw
  digest, lowercase hex) as (a) EVP password on env48, (b) direct AES-256 key
  on raw48 under the frozen IV set. Whole plaintext only; no splitting or
  inspection (avoids the v23 tautology class).
- **K4 — raw48 byte grammar (non-AES)**: every 32-byte window (offsets 0–16)
  as secp256k1 scalar → Half point + Better hash160 (both serializations);
  base58check on whole/segments; magic/format scan reusing
  `salphaseion_blind_eval._formats`.
- **K5 — salt control hunt**: the four envelope salts, both endiannesses,
  searched in: chain-1/chain-2 plaintexts, Cosmic 1327-pt, Chain 4 1151-pt,
  Architect raw 1539-byte record + transliteration, S91/S570 base-9 bytes
  (both page conventions) and decimal digit strings, poster pixel RGB streams
  (`follow_the_white_rabbit.png`, `puzzle.png`), and `F73D92`/`A94021`/
  `5E7DB3` derivatives. Any hit = designed-link candidate, reported verbatim.

Write `salphaseion_split_envelope_preregistered.json` +
`.sha256` seal, matching repo sealing conventions.

### 2. `solver/salphaseion_split_envelope_eval.py`

Verify seal and target hashes; derive all key material via
`chains.reconstruct` (fails loudly if any upstream artifact changes). Positive
controls that must pass before evaluation: glued envelope + joke password →
79 bytes sha256 `1449a217…`; WIF → chain-2 `b40fce72…`; XOR password → Cosmic
`4f7a1e4e…`. Run K1–K5. Acceptance gates identical to the blind evaluator
(padding alone never suffices; readable-text rule; exact parser/checksum
formats; cross-blob rule) plus prize gates on every 32-byte output slice.
Write `salphaseion_split_envelope_results.json`: per-family counts, dedup
counts, candidate-stream sha256, controls block, status
(`ACCEPTED_*` / `NO_ACCEPTED_OUTPUT`).

### 3. Tests — `tests/test_salphaseion_split_envelope.py`

- Split reconstruction matches both pinned sha256 values and glues to the
  chain-1 envelope.
- Positive controls decrypt to the pinned plaintext hashes.
- Preregistration is deterministic (regenerate → byte-identical manifest and
  seal).
- Planted control: encrypt a known message into a synthetic raw48 with one
  manifest (key, IV) pair; eval recovers it (mirrors the planted-fixture
  style of the MITM/XOR-subset audits).
- Run the full existing suite (`python -m pytest tests/`) — no regressions.

### 4. Documentation updates (after execution)

- `docs/ATTEMPT_LOG.md`: new §5 row with counts/status resolving the OPEN
  48-byte row; update §12 (item 3 resolved; item 4 already closed by the
  base-9 exhaustion).
- `docs/SOLVED_STAGE_REAUDIT.md`: append outcome. If negative, record the CBC
  dual-use infeasibility note: the glued control authenticates env48+raw48 as
  one chained message, and the same ciphertext cannot carry two designed
  plaintexts under two keys, so the split-independent reading is structurally
  untenable — the audit converts that argument into a sealed negative.

## Failure modes / boundaries

- Padding hits at random rate (~0.4% MD5, ~0.26% sha256 per blob) are
  expected; they are recorded by hash only and never accepted.
- No Cosmic/Chain-4 password enumeration, no historical manifest replay, no
  new semantic tokens. If all families are negative, the item closes as a
  sealed negative — do not widen the manifest post hoc.
- K3 stage-two uses whole plaintexts only.

## Validation

1. `python -m solver.salphaseion_split_envelope_preregister` → manifest +
   seal; printed sha256 recorded.
2. `python -m solver.salphaseion_split_envelope_eval` → results JSON; all
   three positive controls true.
3. `python -m pytest tests/` green including the new module.
4. Counts in the result JSON match the attempt-log row.

## Out of scope / open questions

- Replaying the ~1M historical sealed passwords against env48 (rejected with
  user; only a new authenticated clue would justify it).
- 479-continuation remaining choice lattice (XOR/polarity/intertwine/cipher
  variants) — separate future audit if this one closes negative.
- Acquisition of `cosmic_A` / `ca[280:312]` / `row1-4` / `K_I1` (research
  task, not computation).
