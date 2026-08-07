# Running attempt log

Last consolidated: 2026-08-06.

This is the canonical, append-only index of puzzle approaches represented in
the repository, git history, community notes, and prior-agent transcript. It
groups mechanically equivalent variants while preserving distinct hypotheses.
Detailed counts and candidate manifests remain in the linked result files.
Unless a path starts with `../` or names a root document, evidence filenames are
relative to `gsmgio-5btc-puzzle-master/`. Transcript-only attempts are labelled
as such when no reproducible result artifact was checked in.

Legend: **SOLVED**, **NEGATIVE**, **OPEN**, **SUPERSEDED**, **FITTED**,
**CAUTION** (a correction attached to the row above it).

Completeness pass (2026-08-05): compared this log against all 120 experiment
modules (excluding support utilities), all 51 audit-named JSON artifacts, the
full prior-agent rollout, `tmp/kenorb-*`, `tmp/cody-chain.md`, the research
ledger, verification report, solution narrative, and git history. Distinct
hypotheses are separate rows; purely mechanical variants remain grouped with
their tested counts. A sealed-but-unexecuted manifest is **OPEN**, never
reported as a failed test.

## 1. First poster and second door

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | 14×14 down-first counter-clockwise spiral, black/blue=1 and white/yellow=0 → `gsmg.io/theseedisplanted` | `SOLUTION.md`, `../scripts/solve.py` |
| **SUPERSEDED** | 12×12 rabbit maze/yellow breadcrumb route; third right move enters black and the source grid is 14×14 | `SOLUTION.md`, agent rollout |
| **SOLVED** | Spiral-ordered marker bits → `F73D92`; row-major `BE2B9B` is the wrong ordering | `first_grid_secondary_audit.json` |
| **SOLVED** | All 24 colour markers occupy URL byte boundaries and equal the URL-byte LSBs | `RESEARCH_LEDGER.md` |
| **NEGATIVE** | Direct row-major/spiral colour-stream passwords and keys (packed bits, hex, A1Z26 and related forms): 40 unique preimages, 360 AES attempts | `color_stream_password_audit.json` |
| **NEGATIVE** | QR finder “merlon” textures; all three crops are byte-identical | `first_grid_secondary_audit.json` |
| **NEGATIVE** | Pad/scan the rabbit grid as a QR code | `CREATOR_SOURCED.md` |
| **NEGATIVE** | Eight spiral symmetries and fifteen colour maps; only door one is readable | `CREATOR_SOURCED.md` |
| **SOLVED (location) / OPEN (role)** | Unique off-white cell `(7,4)`, zero-based spiral index 163 = byte 20, bit 3, inside the `n` of `planted`; its intended special role remains open | `SOLUTION.md`, `CREATOR_SOURCED.md` |
| **NEGATIVE** | Off-white cell as a "dual-prime index" (spiral 163 and row-major 103 both prime, tying it to the creator's prime hints). The two indices use different bases: zero-based row-major is 7·14+4 = 102 (composite) and one-based spiral is 164 (composite). Under either single convention the pair breaks | community claim, 2026-06-28; verified here |
| **OPEN (observation)** | A 14×14 grid minus its main diagonal splits into two triangles of (196−14)/2 = 91 cells, and 91 = C(14,2) — the exact length of the S91 field, with the `YOUWON` split's 21 = C(7,2). Arithmetic confirmed; no construction attached, and 91 is small enough that the echo may be coincidence | community observation, 2026-08-04; verified here |
| **NEGATIVE** | Treat off-white as one, producing `…theseedispla~ted`, then hash/key-test | `../derived/second_door_yinyang_joint_audit.json` |
| **SOLVED** | Structural counts: 86 black versus 85 white + 1 off-white; L/R and diagonal dualities are real | `../derived/second_door_yinyang_joint_audit.json` |
| **SOLVED** | Resistor-code structural totals Y=4, B=6, W=9, R=2 give total 900 (eye/off-white treated as 9) or 891 (eye treated as 0) | `../derived/second_door_yinyang_joint_audit.json` |
| **NEGATIVE** | 1,794 yin/yang materials covering colour inversion, L/R, top/bottom, diagonal and interleave rules → 2,413 scalars and 8,076 AES attempts, no prize/structured result | `../derived/second_door_yinyang_joint_audit.json` |
| **NEGATIVE** | All-grid resistor streams, prime-zeroing, 14×14 sums/products/determinants, URL-prime/HASHTHETEXT, and rabbit-nest morphology families | `second_door_frontier_derivations.json` |
| **NEGATIVE** | Force yellow marker LSBs to one → `gsmg/io/uieseeeisqmaouee`; red/resistor and prime-zero variants | `../derived/second_door_yellow_red_audit.json` |
| **NEGATIVE** | Yellow/red follow-up prime-zero, character-prime, resistor+yflip and red-XOR families: 292 unique scalars | `../derived/second_door_yellow_red_followup.json` |
| **SOLVED arithmetic / FITTED interpretation** | Direct poster assignment of primes 2..89: Blue=484, Yellow=479; zero blue prime 5 → `479=479`. Consecutive-prime assignment and zeroing semantics are clue-motivated, not cryptographically authenticated | `CREATOR_SOURCED.md` |
| **FITTED structural hit** | Authenticated A–Z plaintext at zero-based offset 479 starts `PRIVATEKEY…`; one-based position 479 does not. This is a strong hit, not a convention-free key derivation | `ARCHITECT_479_CONTINUATION.md` |
| **NEGATIVE** | Broad creator-frontier second-door family: 102,093 unique scalars and 41,660 AES checks | `second_door_frontier_derivations.json` |
| **NEGATIVE** | `yellowblueprimes` bounded derivations independent of Cosmic | `second_door_yellowblueprimes_audit.json` |
| **NEGATIVE** | Earlier reconstructed creator pipeline (`yellowblueprimes`→matrix sums→Architect words→yin/yang): 86 core + 21 on-chain/name candidates, 2,064 decryptions | `SOLUTION.md`, `../scripts/pipeline.py` |
| **NEGATIVE** | Re-grounded pipeline reconstruction from first image through 479/Architect/Cosmic AES: 161 explicit AES candidates (4 forms × 2 KDFs, 7-token XOR, raw key), 2 valid padding hits (7-token XOR and a chance `lastwords` suffix), 0 legible, 0 prize match; underdetermined step identified as the 479 → yin-yang composition rule | `PIPELINE_RECONSTRUCTION_REPORT.md`, `reconstruct_pipeline.py`, `reconstruct_pipeline_results.json` |

## 2. Rebus and phase-one verification

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | Pair eight rebus tiles by mirrored gutters/letter fragments → “cryptologic warning, can you dig it?” | `SOLUTION.md`, `../scripts/solve_rebus.py` |
| **SOLVED (historical evidence)** | Song-lyric continuation supplies the reported form password `theflowerblossomsthroughwhatseemstobeaconcretesurface`; the archived POST cannot be replayed | `SOLUTION.md`, git `c4b6a20e` |
| **SOLVED (partial control)** | PNG fingerprints pin `CAN YOU` and constrain the remaining groups, but do not independently resolve every pair | `SOLUTION.md` |
| **NEGATIVE** | Treat archived `/phase1verification` GET 404 as a clue; it is the SPA catch-all and the real form used POST | `../scripts/inspect_bundle.py`, `SOLUTION.md` |

## 3. Phase two and seven parts

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | AES part-one password `causality` | `SOLUTION.md` |
| **SOLVED** | Decode parts 2–7: Safenet/Luna/HSM, binary, raw source hex, and chess FEN | `SOLUTION.md` |
| **NEGATIVE** | Part 6 as the genesis-block headline from row 16/a wrong `main.cpp` revision; intended source is SourceForge r133 line 1616's raw `0x` literal | `SOLUTION.md` |
| **NEGATIVE** | Part 7 as bishop/monk move `Bxb7#`; the Buddhist/ahimsa reading instead selects the sole non-mating move `Rc6+` | `SOLUTION.md` |
| **NEGATIVE** | Template B as string arithmetic `i7 → 49`; complex arithmetic gives `(5i-i)^2 = -16` | `SOLUTION.md` |
| **NEGATIVE** | Correct values with `SafeNet`/`safenet`/`luna` casing; authenticated concatenation requires `Safenet` and `Luna` | `SOLUTION.md` |
| **SUPERSEDED** | 349M (git `71bde92`) then ~437M (`SOLUTION.md`) assemblies tested against the wrong SalPhaseIon URL-hash oracle | git history, `SOLUTION.md` |
| **NEGATIVE** | Single-word dictionaries on three remaining phase-two blobs | git `d4f7186` |
| **NEGATIVE** | Repeated ECDSA nonce/HNP route; 187 signatures have distinct `r` values | `blockchain_nonce_audit.json` |
| **SOLVED** | Correct seven-part concatenation/hash opens the phase-three ciphertext | `VERIFICATION_REPORT.md` |
| **SOLVED** | SalPhaseIon URL is instead SHA-256 of the first poster's visible text/address | `SOLUTION.md` |

## 4. Phase 3.1 and 3.2

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | Fresco + `giveitjustonesecond` + Heisenberg answer hash decrypts phase 3.2 | `README.md`, `phase32_classical.json` |
| **NEGATIVE** | Phase-3.1 first-riddle answer `choice` rather than `future`/Jacque Fresco | `SOLUTION.md` |
| **SOLVED** | Recover 26-symbol substitution independently from an Architect crib and language scoring | `phase32_symbol_recovery.json` |
| **SOLVED** | Beaufort key `THEMATRIXHASYOU` reproduces the 1539-letter Architect plaintext | `phase32_classical.json` |
| **SOLVED** | VIC straddling checkerboard reproduces the Half/Better-Half funds message | same |
| **CAUTION** | The committed VIC alphabet `FUBCDORA.LETHINGKYMVPS.JQZXW` has 28 characters but only 27 distinct, because `.` is duplicated where the README's own derivation produces `/` (line 332 derives the `/` form; line 336 invokes the `.` form). Decoding this ciphertext under both alphabets gives byte-identical plaintext — the differing cell is never selected — so no result changes, but any future decode reaching that cell would be wrong | `phase32_classical.json`, `README.md` lines 332/336; verified here |
| **SOLVED/FITTED** | Align the puzzle's Architect plaintext against the Matrix Reloaded source: 31 edit blocks and 179/835 matching words; alignment is reproducible, semantic intent of substitutions is interpretive | `architect_substitution_audit.json` |
| **NEGATIVE** | Direct CP1141 decode from “one for one, four for one” | `ARCHITECT_479_CONTINUATION.md` |
| **NEGATIVE** | Architect word anchors 121/142/182/237 as passwords/scalars | `book_anchor_audit.json` |
| **NEGATIVE** | L4 phrases as repeating-XOR, Beaufort, or Vigenère cribs over Chain 4 | `l4_crib_audit.json`, `l4_beaufort_audit.json` |
| **SOLVED counts / FITTED quote selection** | Selected Fresco quote is 23 words and 140 characters after removing five punctuation marks; the exact full quote is community editorial context, while `jacquefresco` is the authenticated riddle answer | `ARCHITECT_479_CONTINUATION.md` |
| **SOLVED arithmetic / FITTED operation** | `F73D92 XOR A94021` → significant-bit mask with 23 bits, 16 ones and 7 zeroes; DDMMYYYY serialization, XOR, leading-zero removal and word alignment are inferred | same |
| **NEGATIVE** | Seven zero-selected Fresco words expanded to 372 candidates across four ciphertexts, three passphrase forms, two KDF digests and the phase-two hash oracle | `SOLUTION.md` |
| **NEGATIVE** | 479/484/472/140 windows, heart-centres, prime streams and zero-character-5 families: 725 records, 587 unique scalars | `architect_479_bounded_search.json` |
| **NEGATIVE** | The same bounded set as 1,174 Half point offsets `P_H±tG` and 1,174 signed ECDSA nonce candidates (7,044 `r` comparisons) | `architect_479_bounded_search.json` |
| **NEGATIVE** | 479 continuation materials: 10,693 unique scalars | `yinyang_479_continuation_audit.json` |
| **NEGATIVE** | Constrained 23-word/16/7/intertwine/Beaufort semantic pipeline; `NO_EXACT_PRIZE_MATCH` | `architect_479_semantic_pipeline.json` |
| **NEGATIVE** | Chaocipher, historical/modern Bellaso, Porta, Vigenère, Beaufort and reversals: 110,712 derivations, 90,840 unique scalars | `ciao_bella_479_audit.json` |
| **NEGATIVE** | “Both beginning and end” 32-character edge keys | `architect_beginning_end_audit.json` |
| **NEGATIVE** | Literal AND/OR/XOR over the 16/7 quote split | `architect_479_and_or_audit.json` |
| **NEGATIVE** | `asbothbeginningandend` and normalization/password variants | `architect_lastwords_yinyang_audit.json` |
| **NEGATIVE** | Exact derived yin-yang phrase against the Cosmic page ciphertext; no candidate passed decryption padding (`results=[]`) | `architect_yinyang_cosmic_exact_test.json` |
| **NEGATIVE** | Preregistered Architect “source codes / prime basics” operations on raw and transliterated 1,539-byte records: 168 records, 132 unique valid scalars, no Half/Better-Half match | `architect_source_prime_reinsertion_audit.json` |
| **OPEN** | Intended operation after the 479 `PRIVATEKEY…` pointer | `ARCHITECT_479_CONTINUATION.md` |

## 5. SalPhaseIon extraction and direct locks

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | Mechanically segment S91, `matrixsumlist`, S570, trailing decimal fields, hint literals, and embedded AES | `SALPHASEION_PREREGISTRATION.md` |
| **SOLVED** | Decimal/base16 fields → `lastwordsbeforearchichoice` and `thispassword` | same |
| **SOLVED** | Binary markers → `matrixsumlist` and `enter` | same |
| **REPRODUCIBLE/FITTED** | Five-token password decrypts a 79-byte record, but token order, inclusion of `enter`, omission of SHA phrases and repeated `matrixsumlist` are not source-instructed | `VERIFICATION_REPORT.md` |
| **NEGATIVE** | Apply the same password to the independent 48-byte envelope alone | `CREATOR_SOURCED.md` |
| **REPRODUCIBLE/FITTED** | Serializing the first 32 bytes as WIF opens the phase-3.2 trailing envelope; this is a one-way link, not a demonstrated mutual unlock | `VERIFICATION_REPORT.md` |
| **FITTED** | Interpret `yourlastcommand` and `secondanswer` as tokens six/seven | `VERIFICATION_REPORT.md` |
| **SOLVED/FITTED** | XOR seven token digests decrypts Cosmic to a reproducible 1327 bytes; token semantics remain fitted | same |
| **NEGATIVE** | Instruction grammar (`matrixsumlist`/`enter`/`lastwords…`/`thispassword` as operations rather than literals): 281,816 decryptions per envelope; only the known five-token control reproduces downstream structure | `salphaseion_instruction_audit.json` |
| **NEGATIVE (historical, partially reproducible)** | Community/Kenorb 500–1,500 password narrative: Matrix quotes, sums, KDFs, PBKDF2, direct key/IV and classical ciphers; several cited helper scripts are absent | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | Exact uppercase Beaufort paragraph hash `216411b7…4597ba` against the adjacent blob | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | Seven-token XOR used on the SalPhaseIon envelope as passphrase/direct AES key; this does not contradict its later Cosmic success | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | `THEMATRIXHASYOU` Beaufort/Vigenère variants and affine `P=2(C-8) mod 9` over the letter grid | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | Claimed Cosmic key/IV applied directly to the SalPhaseIon blob | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | Historical matrix-sum password extractions (inconsistent partial/full totals 422 versus 3239) | `tmp/kenorb-analysis.md` |
| **NEGATIVE (framing) / OPEN (slice)** | Read the 2021-04-01 `{1},{4},{21}` line as row indices into a 21-row decomposition of the SalPhaseIon plaintext: row 1 = `dbbi` (S91), row 21 = `anstoo`, row 4 = `faed[94:201]`. The framing does not survive: asked for the 22 boundary offsets the claimant stated that the split "isn't from an independent rule, it's as-transcribed from the soup layout" and that "the 21 boundaries were NOT fixed independently before applying {1,4,21}". Checked here — the canonical `textarea1` contains no line breaks, so there is no 21-row structure to recover. The ~107-character S570 slice itself remains untested | community claim and retraction, 2026-07-13; `CREATOR_SOURCED.md` |
| **SOLVED arithmetic / OPEN meaning** | S91 minus the Phase 3.2 VIC plaintext, letterwise mod 26, spells `YOUWON` at zero-based index 21, splitting 91 as 21/49/21. All five published checkpoints reproduce from repository artifacts. Two further signals select the same index: the subtraction's borrow rail has its only run of seven there, reading `1111111` = 127 = `DEL`, and the VIC checkerboard's two-digit-codeword rail has its longest run (nine) there | `youwon_index21_audit.json`, `solver/youwon_index21_audit.py` |
| **NEGATIVE** | Bounded 32-byte family derived from that alignment (25 string sources × 3 letter cases × {SHA-256, XOR 0x7f, byte-reversed} plus five integer readings): 143 unique in-range scalars, planted positive control accepted and real targets rejected on the same path | `youwon_index21_audit.json` |
| **NEGATIVE** | Reported continuation of that alignment: S570 self-keyed bifid → `BTCSEED‖P1‖z`, digraph rail reversed → `KMODEST`, the step-2 `DEL` removing `K` whose bifid-square coordinates (2,5) read `BE` under A1Z26 → `YOU WON - BE MODEST`. Both published hashes match their strings (`sha256("kmodest")`, `sha256("YOUWONBEMODEST")`), and the terminal strings are gated in the family above. The steps themselves are not re-derived: step 4 is disclaimed by its own author as "a convention not a forced step" | `youwon_index21_audit.json` |
| **NEGATIVE (community)** | `btcseed` bifid channel → 24-word BIP39 mnemonic. The channel split is real, but the valid checksum is not evidence: 13 of 3,624 mapping×offset windows are checksum-valid by chance against an expected 14, offset 27 and length 132 are free parameters, BIP44/49/84 derivations and the raw entropy miss both addresses, and the prize address is a vanity address that cannot come from a seed phrase | community reproduction, 2026-07-02 |
| **CAUTION** | The borrow rail is *not* independent corroboration: the subtraction underflows exactly when `m + a ≥ 26`, which the high-alphabet letters of `YOUWON` force at all six positions. Only the VIC rail is independent of S91, and under 20,000 random permutations of the VIC plaintext the two rails' longest runs coincide 8.4% of the time | same |
| **NEGATIVE** | Independent role of the 48-byte envelope: sealed split audit of env48/raw48 as independent targets — 112 direct AES-256-CBC key+IV attempts on raw48 (authenticated chain/Cosmic keys, token digests, XOR, chain-plaintext digests × frozen IV set), 84 EVP password attempts on env48 (21 unique authenticated passwords × 2 forms × 2 digests; one random-rate MD5 padding hit, `hashthetext`), 12 stage-two `shabefanstoo` derivations, 17 raw48 window scalar gates plus 18 base58check/format scans, 272 envelope-salt searches across 17 corpora; no prize match, `NO_ACCEPTED_OUTPUT` | `salphaseion_split_envelope_preregistered.json`, `salphaseion_split_envelope_results.json` |

## 6. SalPhaseIon preregistration and S-field families

The exact candidate manifests and counts are in
`SALPHASEION_PREREGISTRATION.md`; equivalent microvariants are grouped here.

| Status | Attempt family | Evidence |
| --- | --- | --- |
| **NEGATIVE** | Blind candidate families v1–v22: 71,184 AES decryptions, random-rate padding only | `salphaseion_blind_results.json` through `salphaseion_blind_results_v22.json` |
| **NEGATIVE** | Cross-stage v1 whole-plaintext SHA-answer-too rules: 71,184 stage-one attempts; no accepted stage two | `salphaseion_cross_stage_results.json` |
| **NEGATIVE** | Cross-stage v2 source-layout rules: 32,706 stage-one + 1,428 stage-two attempts | `salphaseion_cross_stage_results_v2.json` |
| **NEGATIVE** | Cross-stage v3 Lo Shu rules: 13,824 stage-one + 876 stage-two attempts | `salphaseion_cross_stage_results_v3.json` |
| **NEGATIVE** | v23 prime-count/104=π(570) identities | `salphaseion_blind_results_v23.json`, `SALPHASEION_PREREGISTRATION.md` |
| **NEGATIVE** | v24–v25 source-layout/dual-matrix families | `salphaseion_blind_results_v24.json`, `salphaseion_blind_results_v25.json` |
| **NEGATIVE** | v26 split/layout families | `salphaseion_blind_results_v26.json` |
| **NEGATIVE** | v27 Lo Shu families | `salphaseion_blind_results_v27.json` |
| **NEGATIVE (prize) / ACCEPTED (known route)** | v28 eight second-door spiral symmetries; blind schema accepts a rotated recovery of door one, but finds no new route or prize | `salphaseion_blind_results_v28.json` |
| **NEGATIVE** | v29–v32 retired 15-row completion, transposition and spiral grammars (8,640 / 5,808 / 1,008 / 1,200 candidates) | `salphaseion_blind_results_v29.json`, `salphaseion_blind_results_v30.json`, `salphaseion_blind_results_v31.json`, `salphaseion_blind_results_v32.json` |
| **NEGATIVE** | v33–v34 corrected 7×13/S570 grammar families | `salphaseion_blind_results_v33.json`, `salphaseion_blind_results_v34.json` |
| **NEGATIVE (prize) / ACCEPTED (format-only)** | v35 corrected instruction grammar: 9,720 AES attempts, 43 strict-padding hits; accepted JSON-digit outputs are not prize/plaintext authentication | `salphaseion_blind_results_v35.json` |
| **NEGATIVE** | v36 Architect suffix family: 58,860 AES attempts | `salphaseion_blind_results_v36.json` |
| **NEGATIVE** | v37 URL characters/bits at prime slots | `url_prime_reinsertion_results.json` |
| **NEGATIVE** | v38 zero-prime 7×13/VIC family: 2,551,032 AES trials | `RESEARCH_LEDGER.md` |
| **NEGATIVE** | v39 19×30 “last words” transpositions: 1,807,668 AES trials | same |
| **NEGATIVE** | v40 faed[94:201] S570 107-char slice format sweep: 50 unique scalars | `salphaseion_faed_slice_audit.json` |
| **NEGATIVE** | v41 479-Continuation Literal 7-Phrase Concatenation: 2 candidates | `v41_479_literal_concat.json` |
| **NEGATIVE** | v42 S91 49-Char Middle Block Format Sweep: 10 candidates | `v42_s91_middle_block.json` |
| **NEGATIVE** | Bounded `matrixsumlist` grid/list/base-9/scalar family | `matrixsumlist_audit.json` |
| **NEGATIVE** | Prime-reinsertion serializations: 1,376 scalar records, 160 unique nonzero scalars | `prime_reinsertion_audit.json` |
| **NEGATIVE** | S-field T9 substitution/global decode | `sfield_t9_audit.json` |
| **NEGATIVE** | S-field 3×3 window-sum inverse; no readable unique inverse (`sat=false`) | `sfield_matrix_sum_inverse.json` |
| **NEGATIVE** | Direct S-field cipher identification: 82,944 coordinate and 3,456 base9-pair specifications | `sfield_cipher_results.json` |
| **NEGATIVE** | Exhaustive shared base-9 substitution: all 362,880 digit mappings, 5,806,080 representations, fixed text/file/decompression gates; no accepted output | `sfield_base9_substitution_preregistered.json`, `sfield_base9_substitution_results.json` |
| **NEGATIVE** | S570 direct reductions to Chain 4/prize scalars | `sfield_reduction_audit.json` |
| **NEGATIVE** | Reproduce claimed 79-byte anchor `e2590f15…`; `reproduced=false` | `salphaseion_79_anchor_hunt.json` |

## 7. Witteveen/Cody structural branch

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED/FITTED** | T13/S91 arithmetic produces `AFFECTTHISB` under recorded column-sum conventions | `tmp/cody-chain.md` |
| **SOLVED (structural)** | S570 half-fold contains `HILLONE` and `KG` without zeroing or plaintext scoring | `solver/witteveen_identity_audit.py`, `tmp/witteveen_identity_audit.json` |
| **FITTED** | Zero indices 400/474 to alter `OA` into `HS` and obtain `ASKHSKEY` | `tmp/cody-chain.md`, `solver/witteveen_identity_audit.py` |
| **FITTED/OPEN** | Cody inferred multiplier 3 from the appearance of `SPACE` and rotated T5 to `COMPS`; the rollout later proposed a convention-dependent `EVEN → XOR → 3` internal justification, still without a prize result | `tmp/cody-chain.md`, agent rollout |
| **SOLVED/FITTED** | Component/diagonal conventions produce `WITVEEN`; zero `O` from `TOE` and insert `TE` → `WITTEVEEN` | `WITTEVEEN_IDENTITY_AUDIT.md` |
| **SUPERSEDED (interpretive)** | Treat Witteveen as the creator's yin-yang endpoint; direct 479 balance is simpler, but neither branch yields a prize key | `CREATOR_SOURCED.md` |
| **NEGATIVE** | Standard/order-one and small-Hill routes: 57,572 scalar candidates | `tmp/cody-chain.md` |
| **NEGATIVE** | 32-component/JKKG/half/direct/hash family: 5,224 expanded candidates, 31,344 scalar checks and 156,720 AES decryptions | `tmp/cody-chain.md` |
| **NEGATIVE** | AES-128/192/256 CBC/ECB, EVP MD5/SHA1/SHA256/SHA512 and PBKDF2 clue-password family: 298,458 decryptions | `tmp/cody-chain.md` |
| **NEGATIVE** | T5 symmetries, 16 apex paths, line reads and MUF/JBE overlays: 952 decryptions | `tmp/cody-chain.md` |
| **NEGATIVE** | Literal `<3`, best-of-everything, A/B folds and canonical T23 traversals: 15,288 scalars + 61,152 AES tests | `tmp/cody-chain.md` |
| **NEGATIVE** | Canonical 276→256 reductions: 13,104 reductions, 56,128 unique scalars and 209,664 direct/hash/endian checks | `tmp/cody-chain.md` |
| **NEGATIVE** | Hal Finney, H=±42, Conway/Life, common Matrix phrases, Witteveen/name/title/Hill/COMPS scalar and AES forms | `tmp/cody-chain.md`, `creator_frontier_giveaway_audit.json` |
| **NEGATIVE** | *Heart of Sufism* page-140 source units and word `unaware` as keys | `tmp/heart_page140_key_audit.json` |
| **NEGATIVE** | Separate page-140 Google Books/Architect/seed-139 decisive hash test | `solver/page140_key_test.py` |
| **NEGATIVE** | Seven Witteveen diagonals: 96 Chain 4 models and 13,440 decryptions | `witteveen_chain4_two_oracle_audit.json` |
| **NEGATIVE** | T23 16/7 split and beginning/end scalar families | `salphaseion_t23_16_7_audit.json` |
| **NEGATIVE** | Passport-prime 23/16/7 → Hill → Playfair (`KTG`) → Chain 4 AES/scalar family | `passport_prime_playfair_audit.json` |
| **NEGATIVE** | Passport-derived seven components × Chain 4: 1,952 models, 1,093,120 cipher operations and 4,997,120 point-gated candidates | `passport_intertwined_chain4_audit.json` |
| **NEGATIVE** | Passport → Hill → Playfair → `EVEN` even/odd and `+-` reductions: 1,408 candidates | `passport_even_chain4_audit.json` |
| **NEGATIVE** | S570 classical ciphers, one-for-one/four-for-one, Witteveen/page-140 selectors and short-envelope alternatives: 59,644 scalar tests | `salphaseion_selector_frontier_audit.json` |
| **NEGATIVE (orphan result)** | Seven authenticated stage passwords intertwined/hashed/scalar-tested: 282 unique scalars; no generator module was checked in | `seven_stage_passwords_intertwine_audit.json` |

## 8. Cosmic matrix and Half/Better-Half interpretations

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **REPRODUCIBLE/FITTED** | 1327 bytes → 103×103 bits, +7 cyclic column shift, range 80..117, base-38 → 68 bytes and `trail1`; arithmetic reproduces but layout, range/base and split are selected conventions | `VERIFICATION_REPORT.md` |
| **NEGATIVE** | Interpret leading `04||x||y` as an uncompressed secp256k1 point; point is off-curve | `SOLUTION.md` |
| **NEGATIVE** | Treat two 32-byte slices as the prize Half/Better-Half keys | `half_better_combination_audit.json` |
| **NEGATIVE** | Every standard script/address serialization for those slices | `CREATOR_SOURCED.md` |
| **NEGATIVE** | EC add/subtract/multiply, ECDH, hash, HMAC, AES key-on-key | `half_better_combination_audit.json` |
| **NEGATIVE (transcript-only)** | Cosmic as BIP32 32+32+4 parent/chain/index, including endian, hardened and leaked-child parent-recovery variants; no standalone result artifact was checked in | agent rollout |
| **NEGATIVE (transcript-only)** | Cosmic even/odd deinterleave and paired K_B/K_H arithmetic, EC/ECDH, XOR, hash/HMAC and AES key-on-key constructions | agent rollout |
| **NEGATIVE (transcript-only)** | Paired Chain 4 `EVEN` interpretation: 7,200 scalar candidates | agent rollout |
| **NEGATIVE** | Yin/yang row/column matrix duals and alternate base-38 readings | `CREATOR_SOURCED.md` |
| **NEGATIVE (earlier sweep)** | 321 distinct chain values under arithmetic/XOR/hash combinations | `SOLUTION.md` |
| **NEGATIVE** | Formal cross-branch search: 1,120 Chain 4 windows × 12 Half/Better/trail/operand constants, 81,760 candidates and 79,519 unique scalars | `frontier_experiment.json` |
| **SUPERSEDED** | Equate page label “Cosmic Duality” with creator-named yin-yang | `CREATOR_SOURCED.md` |

## 9. Chain 4

| Status | Attempt family | Evidence |
| --- | --- | --- |
| **SOLVED/FITTED** | Reproduce 1151-byte `+-`, 31-byte prefix, 35×32-byte block layout; exposing mask is fitted | `VERIFICATION_REPORT.md` |
| **NEGATIVE** | C(7,3)=35 intertwined-password AES assignments | `chain4_intertwined_results.json` |
| **NEGATIVE** | GF(2) seven-vector model; 35 blocks have rank 35 | `chain4_combinatorial_audit.json` |
| **NEGATIVE** | Additive subset MITM families M1–M5 (~9.5T logical evaluations) | `chain4_mitm_audit.json` |
| **NEGATIVE** | Exhaustive 2^35 signed `+-` patterns per constant across 15 constant families | `chain4_signed_mitm_audit.json` |
| **NEGATIVE** | XOR subsets of sizes 3, 4, and 7 | `chain4_xor_subset_audit.json` |
| **NEGATIVE** | Modular product/division subsets | `chain4_product_subset_audit.json` |
| **NEGATIVE** | Exhaustive 31-byte one-byte completion: 32 positions × 256 bytes × six transforms = 48,966 scalars | `chain4_prefix_completion_audit.json` |
| **NEGATIVE** | Exhaustive 29-byte contiguous three-byte operand completion using BSGS: 120 families, 2,013,265,920 logical candidates | `chain4_operand_completion_audit.json` |
| **NEGATIVE** | `trail1` contiguous splices: 1,410 scalars | `trail1_splice_experiment.json` |
| **NEGATIVE** | `trail1` ordered non-repeating permutations: 10,152 scalars | `trail1_permutation_experiment.json` |
| **NEGATIVE** | Exact serialized T8 adjacent-XOR triangle in 18,432 layouts | `xor_triangle_audit.json`, `chain4_completed_triangle.json` |
| **NEGATIVE** | Clue-bounded XOR-triangle, Cosmic-formula, Pascal/Witteveen and T5/HILLONE trail families: 8,771 unique scalars | `xor_triangle_trail_audit.json` |
| **NEGATIVE (transcript-only)** | Complete the Chain 4 prefix with the actual `0x01` padding byte on either side; both orientations fail all 28 T8 equations | agent rollout |
| **NEGATIVE (transcript-only)** | Playfair/AES/`+-` Chain 4 family: 306,144 unique point-gated scalars | agent rollout |
| **NEGATIVE** | Nested AES/integer probes and token digest keys | `chain4_aes_integer_audit.json` |
| **NEGATIVE** | Four E-fragment scalar families | `efragment_scalar_audit.json` |
| **NEGATIVE** | `+-` grammar/password audit | `chain4_plusminus_grammar_audit.json` |
| **NEGATIVE** | Liftable x-coordinate pair/triple relations | `chain4_xcoordinate_audit.json` |
| **NEGATIVE** | Seven contiguous/round-robin five-block streams | `chain4_seven_stream_audit.json` |
| **NEGATIVE** | Entropy split near byte 246 as a structural discriminator | `chain4_split_audit.json` |
| **NEGATIVE** | Door-2 LCP7 literal formula | `door2_formula_audit.json` |
| **OPEN** | Unpublished/unreproduced operands `cosmic_A`, `ca[280:312]`, `row1-4`, `K_I1` | `VERIFICATION_REPORT.md` |

## 10. Blockchain, final-key, and external-source routes

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | Extract Half's exact uncompressed public key from six prize-address spends and verify it against the P2PKH address | `blockchain_nonce_audit.json` |
| **SOLVED (transactions) / NEGATIVE (key relation)** | Confirm Better Half received 2.5 BTC and later 1.25 BTC at halvings; tested simple private/public-key relations do not match | `halving_relation_audit.json` |
| **NEGATIVE** | Same-key compressed/uncompressed, point half/double/negation, and simple affine relations | same |
| **NEGATIVE** | Repeated/non-small/derived ECDSA nonce candidates | `blockchain_nonce_audit.json` |
| **NEGATIVE (transcript-only)** | Passport/F73D92/XOR values as exact ECDSA nonces, differences and ratios; no target nonce below 2^24 | agent rollout |
| **NEGATIVE (transcript-only)** | Halving-height/amount/fee/dust affine nonce family: 22,032 equations; no result artifact was checked in | agent rollout |
| **NEGATIVE (transcript-only)** | Same-key compressed form, EC half/double/negation and 216 cross-halving nonce equations on the authentic address pair | agent rollout |
| **SUPERSEDED (transcript-only)** | Re-gate 68 immediate scalars, then 38,219 unique values from 82 audit files, against both funded addresses; no artifact was ever checked in, so the claim was unverifiable. Replaced by the committed corpus-wide re-gate below | agent rollout |
| **NEGATIVE** | Corpus-wide re-gate: 163 JSON artifacts, 1,402,149,098 bytes, 793,185 unique 64-hex tokens, 1,586,356 unique in-range scalars, big-endian and byte-reversed, against Half's exact public key, Half's hash160 and Better Half's hash160 under both serializations. Planted control accepted through the production gate as a synthetic Half public key and a synthetic Better Half hash160, and rejected against the real targets | `universal_regate.json`, `solver/universal_regate.py` |
| **INFRASTRUCTURE** | Single source of truth for both funded targets, their available gates, and the two published non-targets; `self_check()` re-derives every constant from the Base58Check address text | `solver/targets.py` |
| **SETTLED** | "Half and Better Half" names the creator and his partner, not two derivable keys. Two idiomatic creator uses of "the better half" (2025-04-28, 2026-03-03), consistently singular prize language, and `17ucy…` receiving exactly 2.5 then 1.25 BTC at the two halvings while never spending. One prize target: `1GSMG…` | `docs/HALF_AND_BETTER_HALF.md` |
| **NEGATIVE** | 41 OP_RETURN messages as password corpus | `SOLUTION.md` |
| **SOLVED** | Decentraland audio difference channel decodes `HASHTHETEXT` | `decentraland_audio_audit.json` |
| **NEGATIVE** | Hash obvious creator texts, page-140 units, clue strings and normalizations into prize scalars | `creator_frontier_giveaway_audit.json` |
| **NEGATIVE** | Wayback CDX URL/body search for missing operands (`cosmic_A`, `ca`, `K_I1`) and second-door pages | `wayback_source_audit.json` |
| **NEGATIVE** | Early gsmg.io asset harvest, literal/term scan, PNG/hash comparison and scalar extraction | `wayback_early_asset_audit.json` |
| **NEGATIVE** | The four archived `gsmg.io/…quintessentialhumandelusion…` paths are not a door. Reading `lastwordsbeforearchichoice` as the Architect's last words before Neo's door choice yields the "Hope" line, and the CDX cache does contain those URLs — but all four were captured within 64 seconds on 2026-03-10 at 12,253–12,306 bytes, matching the modern catch-all app shell, and every live response now follows `length = 1029 + 3 × path_length` from domain-parking infrastructure. Solver probes, not creator pages. Recorded because the paths look compelling and will be rediscovered | `artifacts/wayback_cache/cdx_1e45059a….json`, `artifacts/door_probe/CLASSIFICATION.md` |
| **NEGATIVE** | Creator-posted Telegram media as a hidden channel. All 3 photos and 10 of his 15 other items are now readable (`tools/telegram_media_reattach.py` matches orphaned media to messages by name and byte size); every one is a reaction meme, including both 2023-08-03 clips posted a minute from "the hardest part is done". The 5 unrecovered are self-describing joke filenames posted while deflecting hint requests | `docs/TELEGRAM_2026_REVIEW.md`, `docs/TRANSCRIPTS.md` |
| **OPEN** | X2SH values H/Y and intended use of `# X 2 S H 4 Y 0 Q B 15 #` | `CREATOR_SOURCED.md` |

## 11. Historical or abandoned transcript leads

| Status | Attempt | Why retired |
| --- | --- | --- |
| **SOLVED stream / SUPERSEDED colour claim** | `F73D92` is exactly the URL-byte LSB stream. RGB `(247,61,146)` does not occur in the source image; treating the packed hex as a “rose source colour” was solver-added | `first_grid_secondary_audit.json`, `ARCHITECT_479_CONTINUATION.md` |
| **NEGATIVE** | `0x77` selects seven Chain 4 blocks | Many bytes have the same frequency |
| **NEGATIVE** | Book/death-date key for H.J. Witteveen | Funding chronology and target gates fail |
| **FITTED/OPEN** | Playfair/Four-square produced `EVEN` and `XORU`; the rollout claimed `EVEN → XOR → 3` as an internal control, but downstream Cosmic/Chain4/address tests failed | agent rollout |
| **NEGATIVE** | Cosmic component-address activity as creator confirmation | Transactions were solver-authored |
| **NEGATIVE** | Cosmic output as on-curve point or BIP32 parent | Exact curve/address gates fail |
| **SUPERSEDED** | `unaware` as “in front of your eyes” final answer | Reproducible extraction, but key-negative; 479 is a stronger direct pointer |
| **SUPERSEDED** | `F73D92 // 2 + 3` as the primary 24→23 bridge | Drops/changes authenticated URL bits; passport XOR and direct 479 are better constrained |
| **NEGATIVE (transcript-only)** | `THEPROBLEMISCHOICE` 18-letter overlay, two 15-letter Architect halves and literal 19×30→19×15 fold | No control; fold destroyed existing controls |
| **NEGATIVE (transcript-only)** | All-seven diagonal SHA-256/XOR/sum constructions as brainwallet shares | No funded-address match |
| **NEGATIVE** | Reported `YOUWON+64` S91 extraction under direct 32-byte folds/base encodings | Exact target gates failed; superseded by the reproduced alignment in section 5 |

## 12. Current open frontier

1. Determine the intended operation after Architect offset 479.
2. Explain the 23/16/7 partition without introducing a free cipher/key choice.
3. Recover or reject the unavailable community operands with source provenance.
4. Derive a scalar matching Half's exact public key. Per
   [HALF_AND_BETTER_HALF.md](HALF_AND_BETTER_HALF.md) this is the only prize
   target; the Better Half hash160 gate is retained in `solver/targets.py` as
   cheap insurance, not as a second objective.
5. Explain the `YOUWON` alignment at S91 index 21. The arithmetic reproduces and
   the 21/49/21 split is exact, but no construction built from it has reached a
   prize gate, and only one of its three corroborating signals is independent.
   The 49-letter middle block itself is now gated by v44 (section 14); what
   remains open is why the alignment exists at all.

Resolved on 2026-08-05: the independent 48-byte SalPhaseIon envelope (former
item 3; sealed split-envelope audit, `salphaseion_split_envelope_results.json`,
`NO_ACCEPTED_OUTPUT`) and the intended S91/S570 continuation (former item 4;
sealed exhaustive shared base-9 substitution, `NO_ACCEPTED_OUTPUT`).

Re-derivability note (2026-08-06): the split-envelope closure above could not
be re-executed from committed bytes until this date, because its manifest was
sealed against an uncommitted input file. It now re-derives through
`salphaseion_split_envelope_results_v2.json`, with every result key identical.
See section 14.

No agent or checked-in audit has yet passed either prize oracle.


## 13. F-A-E / 9×63 continuation (2026-08-06)

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **VERIFIED structural observation / HEURISTIC interpretation** | Read S570 as the header `fae` followed by 567 symbols. The remainder is exactly 9×63; S570 has a nine-symbol alphabet and the next raw field has exactly 63 symbols. This supplies a new low-free-parameter `matrixsumlist` candidate. Separately, the F-A-E Sonata was a musical cryptogram made collaboratively for a friend, who was challenged to identify each composer's movements; this may explain Jrk's “close friends” / “NOTES” wording, but Jrk never authenticated that association | `../findings.md` §13; F-A-E Sonata historical sources linked there |
| **NEGATIVE (bounded)** | Source-order one-/zero-based 9×63 column sums and 63×9 row sums: nine fixed serializations, SHA-256/double-SHA scalar gates, and 168 short-envelope AES trials | `fae_9x63_preregistered.json` (seal `887c961a…340308e`), `fae_9x63_audit.json`, `solver/fae_9x63_audit.py`; 104 unique scalars, no prize match; no structured AES plaintext; one random-looking one-byte-padding output rejected |
| **NEGATIVE (bounded)** | v45 paired-list family, executing the second half of the OPEN row below: the four sealed sum lists combined elementwise with the following F63 digits under ten fixed pairings (add, both subtractions, XOR, product, three moduli, both interleaves) and the same nine serializations. 360 records, 660 unique scalars, 1,128 short-envelope AES trials, two chance padding hits against ~4.4 expected, no structured plaintext. Best elementwise agreement with F63 is 7 of 63 | `fae_paired_list_preregistered.json` (seal `7fbff3e8…13f894b`), `fae_paired_list_audit.json`, `solver/fae_paired_list_audit.py`; planted control accepted and real targets rejected on the same path |
| **CLOSED — NEGATIVE (v54, 2026-08-06)** | The sonata comparison is resolved **without** an external score, because S570's own statistics rule out a note stream. Melodic contour: mean melodic step 2.859 vs random-shuffle mean 2.901 (p = 0.30) — a real melody sits far left (mean step ~1); S570 sits at the shuffle center. FAE motto: `fae` occurs 2× vs 0.65 expected by chance, i.e. not the recurring unifying cell it is throughout the real sonata. Interval distribution is near-uniform over a–i, not peaked near zero. Re-tested under the recorded task's own **note/rest** mapping (i=rest, letters=note names, chromatic): small-step share |d|≤2 = 0.46 vs 0.6-0.8 for real melodies, step distribution indistinguishable from shuffle (p=0.19); diatonic mapping p=0.15. So a specific-score comparison is moot — S570 is not melodic under any of three mappings. Second recorded next-action (63 colsums × F63 digits) rechecked: 6/63 mod-9 agreement vs ~7 chance, confirming v45. The `faed` opening is a 4-letter coincidence (~1/2400), not evidence of music | `v54_fae_sonata_preregistered.json` (seal `d4c04220…91df13c7`), `v54_fae_sonata_audit.json` |
| **CAUTION** | The "best: 12/63" agreement reported here and in `../findings.md` §13 is **not** weak support for the 9×63 reading. Measured against 20,000 shuffles of the source field it is p = 0.022 uncorrected and the best of 16 comparisons, so roughly p = 0.36 corrected — indistinguishable from noise | §14c below; `matrixsumlist_instruction_audit.json` |

Provenance correction: `messages58.html` reply links show that Jrk's “many NOTES” replied to Anderson's request for another “NOTE” moment. Anderson's `youmeandself` URLs replied to “Give yourself yourself...”; Jrk's later “Nice” replied to an earlier clonazepam message, not those URLs. Any creator-endorsement reading is retracted.

## 14. Independent re-verification and audit-integrity pass (2026-08-06)

An independent session re-derived the headline claims from committed artifacts
rather than trusting the write-ups, then checked whether the recorded negatives
can still be re-executed at all. Every arithmetic claim held. Four defects in
how results were recorded did not.

### Claims re-derived from committed bytes

| Status | Claim | What was recomputed |
| --- | --- | --- |
| **CONFIRMED** | Poster 24 colours + consecutive primes → Blue 484 / Yellow 479; the imbalance is the blue prime 5; zeroing it gives 479 = 479 | Recomputed from the marker string and the first 24 primes |
| **CONFIRMED** | Architect `plaintext[479:]` begins `PRIVATEKEYYOUVEEARNEDITBUTPLEASE`; one-based 479 lands on the preceding `E` | 1,539-letter plaintext; `PRIVATEKEY` occurs exactly twice, at 479 and 1238, and 479 is preceded by `TAKETHE` |
| **CONFIRMED** | `YOUWON` at zero-based index 21 of `S91 − VIC (mod 26)`, splitting 91 as 21/49/21; all five published checkpoints reproduce | `solver/youwon_index21_audit.py` re-run; the 8.4% rail-coincidence caveat is unchanged and still applies |
| **CONFIRMED** | S570 = `fae` + 567 = 9×63, nine-symbol alphabet, following raw field exactly 63 symbols | Re-derived from `extract_raw()` |
| **CONFIRMED** | Both prize gates and their controls: planted target accepted, real targets rejected, on the production code path | `solver.targets.self_check()` plus `gate_point` positive/negative controls |

### Recording defects found and repaired

| Status | Defect | Evidence |
| --- | --- | --- |
| **DEFECT (repaired)** | `salphaseion_split_envelope_preregistered.json` is correctly sealed but was built against an uncommitted copy of `seven_stage_passwords_intertwine_audit.json` (`e9cc5043…` vs the committed `be85c87d…`), so the evaluator's own drift gate rejected it and open-frontier item 3's closure could not be re-executed by anyone. Exactly one manifest path differs, so the candidate families are unaffected. v1 is left untouched; the re-sealed v2 reproduces `NO_ACCEPTED_OUTPUT` with **every** result key identical | `solver/salphaseion_split_envelope_reseal.py`, `salphaseion_split_envelope_results_v2.json` |
| **DEFECT (repaired)** | `architect_source_prime_reinsertion_audit.json` recorded `manifest_sha256` `3c7073ae…`, which no committed manifest produces and which appears in no commit. Re-running against committed bytes yields the same `COMPLETE_NO_MATCH` and 132 unique valid scalars under manifest `b3dc146d…` | `architect_source_prime_reinsertion_audit.json` |
| **NOT A DEFECT (documented)** | The v38 and v39 manifests are absent from version control, so their result digests resolve to nothing and the two largest negatives (2,551,032 and 1,807,668 AES trials) look unauditable. They are gitignored by size — 770 MB and 550 MB — and both regenerate **bit-exactly** to their sealed digests from committed code | verified this session; `solver/salphaseion_preregister_v38.py`, `…_v39.py` |
| **DEFECT (repaired)** | Two Wayback cache bodies were committed corrupt: their bytes hash to neither their own content-addressed filenames nor their CDX digests. The cache writer skipped any existing path, so they could never be replaced, and the audit rebuilt its cache index from the same result file it overwrites — so one offline run permanently poisoned every later one. Both bodies re-fetched and verified | `solver/wayback_early_asset_audit.py` |
| **INFRASTRUCTURE** | `solver/preregistration_integrity_audit.py` now checks all 60 seals, every recorded manifest digest, and each drift gate, with tests. Status is `CLEAN` as of 2026-08-06 (second pass; see §17) | `preregistration_integrity_audit.json` |

None of these repairs changes any research conclusion: every re-executed
negative reproduced. What changed is that the negatives are now checkable.

### New bounded negative

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **CAUTION** | `v42_s91_middle_block.json` is titled "S91 49-Char Middle Block" and is cited as covering the block that `YOUWON` opens, but it slices the **raw base-9 field** `S91[21:70]` (`ihbeggege…`), not `D[21:70]` (`YOUWONXCPKWGBNAX…`) of the difference string. Different operand; the named block was untested, and v42's ten candidates say nothing about it | verified this session |
| **NEGATIVE (bounded)** | v46: the balanced prime pair used as key material rather than as a text index. Twelve lists the dual reading defines — all 24 primes, the same with the blue 5 zeroed, yellow 9, blue 15, blue-zeroed and blue-dropped, both concatenation orders, the mirror pair, both colour masks, and the `[479, 479]` pair — over nine serializations and six derivations including `yinyang`-prefixed and suffixed hashes, plus 408 short-envelope AES trials. 660 unique scalars, no prize match, one chance padding hit against ~1.6 expected. Distinct from the three prior prime audits, which index text or hash poster streams rather than serializing the value lists | `yinyang_prime_dual_preregistered.json` (seal `5aa3efc2…707d3ad`), `yinyang_prime_dual_audit.json`, `solver/yinyang_prime_dual_audit.py`; planted control accepted and real targets rejected on the same path |
| **NEGATIVE (bounded)** | v44: the difference blocks the 21/49/21 split defines — the full 91 letters, `middle49`, both 21-letter flanks, the middle with `YOUWON` removed, the concatenated flanks, and the two letterwise flank combinations — over two orientations, two letter cases and eight fixed byte derivations, plus 64 short-envelope AES trials. 192 unique scalars, no prize match, no valid padding at all | `youwon_middle_block_preregistered.json` (seal `c0808e1a…172a737`), `youwon_middle_block_audit.json`, `solver/youwon_middle_block_audit.py`; planted control accepted and real targets rejected on the same path |

### 14b. Yin-yang focused pass (2026-08-06)

A yin-yang's defining property as a symbol is **180° rotational symmetry with
colour inversion**. The repository had tested colour inversion, L/R, top/bottom,
diagonal and interleave rules on the poster, and eight spiral symmetries, but
never the partition that rotational inversion itself induces. Measured here
under the authenticated URL bit convention (black/blue = 1, off-white counted
white):

| Status | Structural fact | Note |
| --- | --- | --- |
| **VERIFIED** | The 196 cells form 98 rot180 pairs with no fixed point, and **exactly 49 of the 98 invert** | A perfect half. This is the strongest sense in which the artifact *is* a yin-yang under the symbol's own symmetry — but 49 is exactly the chance expectation, so it is a clean construction, not a surprising coincidence |
| **VERIFIED** | The 49 non-inverting pairs split **26 dark-dark against 23 light-light** | The 49 inverting pairs carry 49 ones and 49 zeros, which is forced, not evidence |
| **VERIFIED** | All three rotations (90°, 180°, 270°) split the 196 comparisons exactly 98 same / 98 different. `flip_h` gives 114/82, `flip_v` 86/110, `transpose` 112/84, `anti_transpose` 106/90 | Only the rotations balance |
| **VERIFIED** | `sources/follow_the_white_rabbit.png` contains exactly **five** distinct colours across all 122,500 pixels, and the off-white `(254,254,254)` region is exactly 625 pixels — one 25×25 cell | So there is exactly **one** anomalous cell. A yin-yang has two eyes; the poster has one. No near-black twin exists, and any "two eyes" reading is closed on this artifact |
| **VERIFIED** | The off-white cell `(7,4)` has spiral index 163; its rot180 partner `(6,9)` is black at spiral index 173. The four innermost spiral cells — the residual beyond the 192 URL bits — are all white, which is the recorded `0000` | The partner being black is unremarkable on its own: 86 of 196 cells are dark |
| **NEGATIVE (bounded)** | v47: eight streams from the rot180 partition — both 98-cell halves in spiral order, the inversion mask and its complement, the pair-first-member stream, the concatenated 196, and the dark-dark and light-light pair streams — over four serializations and seven derivations including `yinyang`-prefixed and suffixed hashes, plus 124 short-envelope AES trials. 201 unique scalars, no prize match, **no valid padding at all** | `yinyang_rot180_partition_preregistered.json` (seal `c69d8798…0fe49c1`), `yinyang_rot180_partition_audit.json`, `solver/yinyang_rot180_partition_audit.py`; planted control accepted and real targets rejected |
| **REJECTED (false positive, recorded so it is not re-found)** | Using the poster's 14 row sums as offsets from 479 into the Architect plaintext yields `EYEKEETAYYKEKY`, and the column sums yield `EYEYEKVEKTYEEE`. Both open with `EYE`, which is tempting next to `itsinfrontofyoureyesbutyourenotseeingit`. It is an artifact: small offsets from 479 land inside `PRIVATEKEY`, whose letters supply E, Y and E at 485/489/487, and everything after the third character is noise | This is exactly the "readable English fragment" trap in `CLAUDE.md`; no candidate was gated on it |

Also computed and unremarkable: the poster bit matrix has 101 ones; row sums
total 101 with top-half 48 versus bottom-half 53; column sums give left 54
versus right 47. None of the sum lists spell anything as direct, offset,
cumulative or `479`-anchored indices into the Architect plaintext.

**Assessment.** Yin-yang remains unreached, consistent with the creator's own
position as of 2026-03-03. The artifact carries genuine, now fully inventoried
duality — 86 = 86, the mirrored L/R counts 44/42 against 42/44, the 49/98
rotational split — but every balance found so far is a *property* rather than an
operation, and no transform turning any of them into a door or a scalar has been
found. The missing piece is still a composition rule, not more candidates.

### 14c. `matrixsumlist` as instruction versus literal (2026-08-06)

`CLAUDE.md` records an unresolved tension: `matrixsumlist` is an authenticated
SalPhaseIon literal *and* phrase 2 of the creator's ordered pipeline, which reads
like an instruction. If it is an instruction, the obvious objects are the two
undecoded base-9 fields beside it. v48 tests that reading three ways.

| Status | Test and result | Evidence |
| --- | --- | --- |
| **VERIFIED (closes the bridge reading by dimension)** | Enumerate every rectangular factorisation of 91, 570 and 567, both axes, both `a..i` mappings — 102 forced sum lists. **Only four have a length matching any other authenticated field**, and all four are the 9×63 and 63×9 readings of S570-after-`fae` pointing at the same 63-symbol `lastwords` field. Nothing addresses the 29-symbol password field or S91. So "build a matrix, sum it, and the list is the next operand" has exactly one dimensional target in the whole SalPhaseIon corpus | `matrixsumlist_instruction_audit.json` |
| **NEGATIVE** | The self-labelling test. `S91 = 7 × 13` and `matrixsumlist` is exactly 13 letters, so a 7×13 matrix has one column per letter of its own name; if the 13 column sums spelled `MATRIXSUMLIST` the instruction reading would be self-authenticating. Best result across two mappings and three mod-26 reductions is **1 of 13** | same |
| **NEGATIVE (statistical)** | The one apparent signal in this area is now quantified. `findings.md` §13 reports the best sums-versus-F63 agreement as 12 of 63. Against 20,000 shuffles of the source field that is p = 0.022 uncorrected — but it is the best of **16** comparisons, so the corrected p is roughly 0.36. **It is noise.** Every other comparison lands between p = 0.22 and p = 0.89 | same |
| **NEGATIVE (bounded)** | The scalar and AES family: all 102 forced sum lists × nine serializations × four derivations, plus 3,292 short-envelope AES trials. 4,012 unique scalars, no prize match, 15 chance padding hits against ~12.9 expected, no structured plaintext | `matrixsumlist_instruction_preregistered.json` (seal `11074fc9…9e24d18`), `solver/matrixsumlist_instruction_audit.py`; planted control accepted and real targets rejected |
| **VERIFIED** | Whole-field totals under `a=1..i=9`: S91 = **422**, S570 = 3,079. The 422 reproduces the historical S91 matrix-sum total recorded in `tmp/kenorb-analysis.md`, which had it as one of two inconsistent figures | same |

**How the tension now stands.** The literal reading is authenticated — the
104-symbol `a`/`b` block decodes to `matrixsumlist` exactly. The instruction
reading, with S91 or S570 as its object, has no dimensional support beyond a
single 9×63 target, fails the self-labelling test it would pass if the fields
were self-describing, and reaches no gate. That does not refute an instruction
reading whose object is some *other* artifact, but it removes the S-fields as its
likely referent. Weight should shift toward `matrixsumlist` being a literal, and
toward the pipeline phrases naming objects rather than operations.

### 14d. The creator's own acceptance criterion, applied (2026-08-06)

Reading only creator statements, one line is an **acceptance criterion** and has
never been used as one:

> 2021-03-14 — "Breaking salphation should be giving the feeling of the phase's
> name."

`SalPhaseIon` points at *salvation*. Taken plainly, a correct break produces
something a human recognises. That is exactly the standard the phase-3.2 break
meets, and it is testable.

| Status | Measurement | Evidence |
| --- | --- | --- |
| **VERIFIED (true positive)** | The phase-3.2 envelope under its authenticated password decrypts to 2,422 bytes at 5.78 bits/byte entropy and 0.598 printable, opening `I've been waiting for you. You have many questions...` — legible on sight | `salvation_coherence_audit.json` |
| **VERIFIED (the chain fails the criterion)** | The three chained unlocks the whole post-3.2 branch rests on are **not legible**. Chain 1 under the five-token password: 79 bytes, 6.13 bits/byte, 0.392 printable. Chain 2 under the derived WIF: 79 bytes, 6.09, 0.456. Cosmic under the seven-token XOR: 1,327 bytes, **7.87 bits/byte with 255 distinct byte values** — indistinguishable from random | same |
| **VERIFIED (the null)** | Valid strict PKCS#7 padding arises by chance on these envelopes at **0.325–0.379%** per random password (20,000 trials each). The repository's own v38 recorded 10,065 padding hits in 2,551,032 trials = 0.394%, i.e. exactly the chance rate | same |
| **VERIFIED (empirical demonstration)** | The v49 sweep produced **12,132 padding hits in 3,094,352 attempts (0.392%) and zero legible outputs.** Twelve thousand clean unpaddings, not one readable. Padding is therefore worthless as evidence, demonstrated rather than asserted | same |
| **NEGATIVE (bounded)** | v49 Part B: the creator's seven published phrases plus the four authenticated SalPhaseIon literals, `yingyang` and `salvation`, swept as ordered combinations up to five tokens — his own ordered prefixes first — over three separators, two letter cases and EVP MD5/SHA-256, against all four authenticated envelopes. 386,794 passwords, 3,094,352 attempts, **no legible break and no prize match** | `solver/salvation_coherence_audit.py` |

**What this changes.** It does not prove the chain is wrong, and it does not
recover a key. It establishes that **nothing after phase 3.2 is authenticated**:
the five-token chain-1 unlock, the WIF-derived chain-2 unlock and the
seven-token XOR Cosmic unlock are each consistent with padding luck, and none is
self-authenticating. `CLAUDE.md` already states that clean padding proves
nothing — that rule was simply never applied to the repository's own load-bearing
chain, and applying it removes the authentication from everything downstream,
including the 1327-byte Cosmic plaintext, the base-38 output and all of Chain 4.

This aligns three creator statements that previously sat awkwardly. He never
named Cosmic, Chain 4 or base-38. He said "the hardest part is done" on
2023-08-03, when the community's last *legible* result was phase 3.2. And he
said breaking SalPhaseIon should feel like its name — which no 79-byte
high-entropy blob does.

**Consequence for the search.** The correct next lock should yield legible
output, and legibility — not padding, not a scored near-match — is the gate to
search under. The 96-byte chain-1 envelope is the first place the chain leaves
legibility behind, which makes it the highest-value target, and its correct
password is unknown rather than known.

### 14e. The "seven intertwined passwords" family under the legibility gate (2026-08-06)

v49 concluded that the 96-byte chain-1 envelope is the first place the chain
leaves legibility behind and that its correct password should be treated as
unknown, searched under a legibility gate rather than padding. v50 acts on that
by chasing the two families v49 left open, both grounded in creator-authenticated
text rather than solver convention:

1. **The authenticated password *format*.** The only password the puzzle ever
   confirms — phase 3.2's `250f3772…` — is the lowercase SHA-256 **hex digest** of
   a phrase, used as ASCII with the `-md sha256` KDF. v49 swept raw phrase text
   only and never applied that format.
2. **"Seven intertwined passwords."** The Architect plaintext — tier 1, it
   decrypts from a creator ciphertext — says the finisher must "SELECT FROM OVER
   TWENTYTHREE CIPHERS SIXTEEN ENCRYPTIONS ANDOR SEVEN INTERTWINED PASSWORDS."
   Every prior intertwine audit braided the seven *stage answers*
   (`seven_stage_passwords_intertwine_audit.json`, `chain4_intertwined_results.json`);
   none braided the seven *phrases* of the 2023-02-23 image, whose order is the
   strongest structural constraint in the puzzle.

| Status | Test and result | Evidence |
| --- | --- | --- |
| **NEGATIVE (bounded)** | Family A — sha256-format passwords. For each named creator text (the seven phrases, the seven SalPhaseIon tokens, the Architect and its `[479:]` / `[:479]` slices, S91, S570, the numeric fields, and the other authenticated strings) the lowercase and uppercase SHA-256 hex, the double-SHA-256 hex, and the raw 32-byte digest, under EVP MD5 and SHA-256, against chain1/chain2/cosmic. 140 passwords, 840 attempts, 5 chance padding hits, no legible break, no prize match | `intertwined_password_coherence_audit.json` |
| **NEGATIVE (bounded)** | Family B — intertwined passwords. Round-robin **braid** (continue past exhausted parts) and **zip** (stop at shortest) of every ordered subset of the seven 2023-02-23 phrases, and of the seven SalPhaseIon tokens with the two placeholder tokens (`yourlastcommand`, `secondanswer`) substituted by their creator-sourced readings — each material tested raw and as its SHA-256 hex, under both KDFs, against all three envelopes. 102,991 distinct materials, 1,235,892 attempts, **4,745 padding hits at 0.384% — the chance rate — no legible break and no prize match** | same |

**Assessment.** Two more large creator-grounded password families for the
post-3.2 envelopes are now closed, and both land at exactly the chance padding
rate v49 measured, reinforcing that clean unpadding on these envelopes is noise.
Combined with v49, the raw-phrase, sha256-format, and phrase/token-intertwine
readings of the "seven intertwined passwords" are all falsified for chain1,
chain2 and cosmic. This does not refute the *reading* — non-round-robin
interleavings, other KDFs, and operands the creator never published all remain —
but it removes the most literal constructions. The result reinforces v49's core
finding rather than overturning it: the door after phase 3.2 has not been opened,
and no phrase-derived AES password opens it.

### Corrections to standing guidance

- `faed[94:201]` is **already gated** as v40 (`salphaseion_faed_slice_audit.json`,
  50 unique scalars). `docs/TELEGRAM_2026_REVIEW.md` §7 item 2, section 5 above,
  and `CLAUDE.md` still describe it as untested. Anyone acting on that wording
  would be re-running a closed family; only a genuinely new family beyond v40's
  format sweep is worth attempting.
- The "seven intertwined passwords" reading of the AES chain is now closed for
  the raw-phrase (v49), sha256-format (v50-A) and round-robin-intertwine (v50-B)
  constructions. A new attempt in this area must use a genuinely different
  interleaving rule, KDF, or operand, not another concatenation or braid of the
  same phrases.

## 15. Creator pipeline poster → Architect and OP_RETURN trace (2026-08-06)

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | Compose the creator 2023-02-23 pipeline on authenticated poster + Architect material: `yellowblueprimes` offset 479; `matrixsumlist` as 14×14 resistor row/column sum lists (eye zeroed variants included); index into Architect A–Z plaintext; optional Hope-quote overlay; yin/yang yellow-vs-blue row/column balance lists | `creator_pipeline_poster_architect_preregistered.json`, `creator_pipeline_poster_architect_audit.json`, `solver/creator_pipeline_poster_architect_audit.py`; **162** unique scalars, no prize match; excludes Cosmic/Chain4/base38 |
| **NEGATIVE (community / tier-4)** | Trace OP_RETURN tx `66eefd6a…` (`FromN0EHalfABetterHalfBuiltItBellaCiao1_1Pi36y7…`): signer is embedded tip address (not prize/Cosmic keys); fan-out includes **864 sats** dust to prize Half; **10** SHA256 parse variants gated | `fromn0e_opreturn_trace.json`, `solver/fromn0e_opreturn_trace.py`, `tx_message_scan.json`; `NO_MATCH` |

## 16. Split-envelope authenticated-format pass + record correction (2026-08-06, Cowork)

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **RECORD CORRECTION** | The 2026-07-12 "few stable qubits" line was quoted without its governing conditional in `TELEGRAM_2026_REVIEW.md`, producing an ECDLP-hardness reading that leaked into planning. Full quote (messages 66587-66590, verified against export bytes): asked "salphaseion is 100% solveable?" the creator answered "Yes", then "And IIFF I'm somehow still wrong, which I'm most likely not as I've verified many times back then after some sad rushed mistakes, it's all still solvable with a few stable qubits." Primary claim is classical solvability; qubits is a conditional fallback. ECDLP reading marked SUPERSEDED in `TELEGRAM_2026_REVIEW.md` §2/§4/§8, `CREATOR_SOURCED.md`, and `README.md` | corrected files delivered 2026-08-06 |
| **NEGATIVE (bounded)** | v51: the two split SalPhaseIon envelopes env48 (`Salted__`, salt `3ab585348552415d`) and raw48 (headerless), plus raw48+env48-salt, glued96 and chain2, under the puzzle's only authenticated password **format** (lowercase/upper sha256-hex, double-sha256-hex, raw-32, and raw), EVP MD5 and SHA-256, over 37 creator-grounded texts. Searched under a **legibility** gate (printable≥0.85 and entropy≤5.9, or a ≥6-letter English run), not padding. 1,850 AES trials, 74 scalar gate tests, **0 legible outputs, 0 prize matches**; 12 padding hits vs ~6.8 expected, all high-entropy. Broad 74-word follow-up on env48/raw48/glued: 864 trials, 4 padding hits at chance, 0 legible | `v51_hashthetext_format_preregistered.json` (seal `b09fe31a…56cfeb5e`), `v51_hashthetext_format_audit.json`; controls: glue MD5 reproduces the 79-byte record, phase 3.2 legible-control passes, prize-gate pos/neg controls pass |
| **VERIFIED (null, closes a route by reason)** | S91 and S570 under the authenticated p1/p2 decode (a=1..i=9,o=0; decimal→hex→ASCII) give garbage (printable 0.42 / 0.33). The route depends on the field being a zero-bearing integer; p1/p2 contain `o`=0 and decode, the S-fields are pure 1–9 and cannot | this session |
| **READ (not mined)** | `Cosmic Duality (Mysteries of the Unknown)` (Time-Life, 152pp) extracted and read: a general survey of dualism; the classic yin-yang "seed of its opposite" description appears verbatim. No embedded cipher/key/puzzle string. Supports yin-yang as the creator's *concept* for balance-carrying-opposite; does not supply an operation | `SOLVE_SESSION_2026-08-06.md` §4 |
| **NEGATIVE (bounded)** | v52: the one self-declared creator hint (2026-07-12 "close friends … NOTE: that is a hint") built as a small preregistered recognition set — 55 publicly creator-associated, puzzle-relevant strings from his own Telegram messages (Jacque Fresco / Venus Project, GSMG = "Globally Supporting My Generation", better half, Matrix callbacks he emphasized, Neo passport date, his stated "ASCII 127 myself", the Hope quote, Dutch/purple asides, Bella Ciao, Witteveen) × 6 password forms × 2 KDFs × 6 envelope modes (env48/raw48/raw48+env48-salt/glued96/chain2/phase32), plus sha256/double-sha256 scalar gates. Searched under legibility, not padding. 3,960 AES trials, 110 scalar tests, **0 legible outputs, 0 prize matches**; 20 padding hits vs ~14.7 expected, all high-entropy. Not open-ended identity research | `v52_close_friends_personal_preregistered.json` (seal `1737a377…f23dd11`), `v52_close_friends_personal_audit.json`; prize-gate pos/neg controls pass |
| **VERIFIED (from raw pixels, this session)** | Returned to the first image and rebuilt it from `follow_the_white_rabbit.png` pixels, not the audits: 5 colours, off-white `(254,254,254)` = exactly one 25×25 cell at (7,4); the whole image lies on an exact 5-pixel (70×70) grid and every 14×14 cell is uniform **except the 7 the bunny crosses** — so the nest holds exactly one sub-grid object, the white-rabbit line drawing, and no additional bitstream. Reproduced the down-first CCW spiral (black+blue=1) → `gsmg.io/theseedisplanted`; the 24 blue/yellow markers = the 24 byte-LSB cells → `F73D92`; blue/yellow on first 24 primes → 484/479, imbalance = blue prime 5 → 479=479 | this session; `rabbit_view.png`, `bunny_zoom.png` |
| **NEGATIVE (bounded)** | v53: red divider used as a genuine operand (the repo's own "barely used" gap). Full poster confirmed 1048×1556, red `#ED1C24` 15px (rows 1047-1061). Resistor grid (K0 W9 B6 Y4, O∈{9,0}) over spiral/row/col orders × zeroing {none, prime-spiral-index, prime-value, eye} × red=2 as prefix/suffix/multiplier/xor/modulus × {digit-int, row/col/rowcol sums, totals}, each gated as sha256/double-sha256/raw. 288 gated derivations, **0 prize matches** | `v53_red_resistor_preregistered.json` (seal `21ad5560…160963cb`), `v53_red_resistor_audit.json`; gate pos/neg controls pass |
| **VERIFIED (on-chain, this session)** | Creator's own oracle checked via blockstream: prize `1GSMG…` = 125,634,510 sats (1.25634510 BTC, 125 tx), unchanged from the repo's recorded figure; `17ucy…` = 375,054,755 sats (3.75054755 BTC, 43 tx, spent 0). Puzzle live, yin-yang unreached | blockstream.info API |

## 17. Second integrity pass — CRLF corruption and v51–v54 seal repair (2026-08-06)

An independent session ran `python -m solver.preregistration_integrity_audit`
and `python -m pytest -q` against the current commit and found both failing,
contradicting the `CLEAN` / 52-passed status recorded in §14 and `CLAUDE.md`.
The defects were not new research findings; they were recording failures
introduced *after* the §14 pass by commit `2795cba` (v51–v54) and by a Windows
`core.autocrlf=true` checkout.

| Status | Defect and repair | Evidence |
| --- | --- | --- |
| **DEFECT (repaired)** | **CRLF corruption of all JSON manifests.** `core.autocrlf=true` on Windows silently converted every `*.json` and `*.sha256` file from LF to CRLF on checkout. Seals were computed against LF bytes, so six seal bindings broke (v44, v45, v46, v47, v48, and the v2 re-seal). The v1 drift gate reported 0 differing paths instead of 1, because the drifted input file's CRLF hash matched the "uncommitted" hash the v1 manifest was sealed against — the "uncommitted copy" was the CRLF version. Repair: `.gitattributes` now enforces `eol=lf` for `*.json` and `*.sha256`; 397 files normalised | `.gitattributes`, `preregistration_integrity_audit.json` |
| **DEFECT (repaired)** | **v51–v54 lacked `.sha256` seal files.** Commit `2795cba` added four preregistered manifests with inline `seal_sha256` fields but no external `.sha256` files, making them invisible to the integrity audit's seal checker. Repair: external `.sha256` seal files written for all four | `v51_hashthetext_format_preregistered.sha256`, `v52_close_friends_personal_preregistered.sha256`, `v53_red_resistor_preregistered.sha256`, `v54_fae_sonata_preregistered.sha256` |
| **DEFECT (repaired)** | **`architect_source_prime_reinsertion_audit.json` digest never corrected on disk.** §14 records this as repaired (`3c7073ae…` → `b3dc146d…`), but the file on disk still held `3c7073ae…`. Repair: `manifest_sha256` field updated to `b3dc146d…`, the actual hash of the committed manifest | `architect_source_prime_reinsertion_audit.json` |
| **INFRASTRUCTURE** | Integrity audit now `CLEAN`: 60 seals checked, 0 mismatches, 0 unresolved digests, 2 absent manifests (v38/v39, gitignored, regenerable), 1 drift gate failing but repaired. Suite: **60 passed, 0 failed** (was 7 failed / 53 passed before this pass) | `preregistration_integrity_audit.json`, `pytest -q` |

**Lesson.** The §14 "CLEAN" status was true at the moment it was written but
became false when the next commit added audits without re-running the integrity
gate. The `core.autocrlf` failure mode is platform-specific and would not have
appeared on Linux. Both are now guarded: `.gitattributes` prevents the CRLF
recurrence, and the integrity audit's test suite will fail if any future commit
breaks a seal. Run the audit before trusting any recorded negative, and run it
again after every commit that touches preregistration files.

## 18. Better Half re-opening — Half-only certificate re-gating (2026-08-06)

The authenticated VIC plaintext reads `THEPRIVATEKEYSBELONGTOHALFANDBETTERHALF`
— "PRIVATE KEYS" (plural), "BELONG TO" (ownership by two named parties). The
repo's conclusion that Better Half is not a derivable target (`HALF_AND_BETTER_HALF.md`)
rested on an inference from creator idiom usage and chain behaviour, not on a
creator statement. An audit of the solver package found five older modules
that define their own `_target_match` against Half's exact public point only
and never test Better Half's `hash160`:

- `solver/prime_reinsertion_audit.py` (160 unique scalars)
- `solver/frontier_experiment.py` (79,519 unique scalars)
- `solver/trail1_splice_experiment.py` (1,410 unique scalars)
- `solver/trail1_permutation_experiment.py` (10,152 unique scalars)
- `solver/page140_key_test.py` (no result JSON on disk; not re-gated)

Their recorded negatives certified only that no candidate matched Half's exact
public key — they said nothing about Better Half. The newer audits (v40–v54)
all route through `solver.targets.gate_scalar`, which tests both targets, so
the gap was confined to these older modules.

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **NEGATIVE (bounded, re-gated)** | Re-ran the four Half-only audit modules with their `_target_match` replaced by `solver.targets.gate_scalar`, which tests both Half (exact pubkey + hash160) and Better Half (hash160 under both serializations) on every candidate. 91,241 total unique scalars re-gated. **0 Half matches, 0 Better Half matches.** Negative control (scalar=1 rejected) and positive control (`targets.self_check()`) both pass | `better_half_regate_audit.json`, `solver/better_half_regate_audit.py`, `tests/test_better_half_regate.py` |

**Assessment.** The four Half-only audit families do not produce a Better Half
key under the full gate. Their original negatives now hold for both targets,
not just Half. This closes the "half a certificate" gap for these specific
families. It does **not** close the broader question of whether Better Half is
a derivable target — only these 91,241 candidates from these four families were
tested. The authenticated plural-keys text and the creator's 2026-07-12 "5 btc
was never the actual prize" statement keep the Better Half hypothesis open as a
research direction, but it is not certified by any existing audit family.

## 19. Cosmic Duality book cover verification + "unity of opposites" audit (2026-08-06)

Telegram-evidence correction first: the 2022-12-10 image that the creator rated
"very specific" / "scary specific" (and named the already-given hint on
2023-01-08) was a photograph of the Time-Life *Cosmic Duality* book cover, not
a generic yin-yang image. Full provenance in `CREATOR_SOURCED.md` (creator
statement table and Damaging fork #2 correction), verified against the
2026-08-05 export (messages 8310/8311/8315/8328; solver identifications
16829/16830/43607). Also added: the creator's only point-up endorsement of a
solver message (2026-03-03, message 60285) — the "turning inward" clause.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | The book's organising phrase (opening essay "The Unity of Opposites", verified in the 152-page scan) and the endorsed turn-inward clause, as a sealed phrase family, tested (a) as sha256/double-sha256 scalar candidates against Half + Better (20 gates, 0 hits); (b) as AES passwords (raw / sha256-hex / sha256-digest × MD5 + SHA-256 EVP) against chain1, chain2, phase32, cosmic under a byte-level legibility gate (240 trials, 0 padding, 0 legible); (c) as the alphabet seed for the authenticated 28-cell VIC straddling checkerboard (row digits 1,4 and 4,1; a=0..i=8 and a=1..i=9) over dbbi (91), faed (570), both reversed ("turning inward"), and both unified directions — 320 checkerboard reads, every decoded answer sha256-gated as a scalar (0 prize matches), every decoded answer AES-tested under both EVP digests (0 legible opens) | `unity_of_opposites_audit.json`, `solver/unity_of_opposites_audit.py`; seal = the module source itself; scope note in the JSON lists the exactly bounded choices |

**Assessment.** The book-cover lead is real (the creator validated the exact
object), but the book's organising phrase does not open any authenticated
envelope, does not gate to either prize target, and does not legibly decode
the two SalPhaseIon streams under the canonical checkerboard. The book
remains an endorsed *object* with no operation attached — consistent with the
existing "READ (not mined)" row in §16, now with the creator's validation
established. The turn-inward endorsement also carries no direct phrase
payload under this family. Next pressure should treat the book cover as an
identity/anchor (like Witteveen) rather than a passphrase source.

## 20. S570 as seven intertwined 9x9 matrices, summed and 180-folded (2026-08-06)

Construction (arithmetic verified): the faed run is 570 symbols = "fae" + 567,
and 567 = 7x9x9, so the remainder is exactly seven 9x9 matrices in the page's
nine-symbol alphabet.  Reading them sequentially OR round-robin ("seven
intertwined"), summing position-wise, and folding the 9x9 sum through its
180-degree rotational opposite leaves **40 pairs + 1 center** - a literal
"The One" (cells (4,4) fixed).  Joins matrixsumlist + seven-intertwined +
turning-inward.  Tested before any looser family.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | Seal: {sequential, intertwined} x {a=1..i=9, a=0..i=8} x fold {sum, |diff|, sum-mod9} x encodings {folded-pairs digits, grid row-major, grid inward-spiral (the poster's own CCW order), grid mod9 a-i, pre-fold spiral} — 244 scalar gates (sha256/double-sha256) vs Half + Better, **0 hits**; 2,928 AES trials (raw / sha256-hex / sha256-digest x MD5 + SHA-256 EVP) vs chain1/chain2/phase32/cosmic, 18 padding hits (0.61%, within sampling noise of the 0.33-0.4% chance rate), **0 legible**; 62 VIC reads with the committed 3.2.2 alphabet, decoded answers sha256-gated + AES-tested, **0 prize matches, 0 opens** | `s570_seven_matrix_fold_audit.json`, `solver/s570_seven_matrix_fold_audit.py`; construction fields and counts recorded in the JSON |

**Assessment.** The 7x9x9 / 40-pairs-plus-center structure is exact and
well-defined (it is a genuine matrix-sum-list reading of S570), but no
encoding of the sum, the fold, the pairs, or the spiral reaches the prize
or opens an envelope.  The construction should not be widened with free
parameters; if it is the intended "matrixsumlist" stage, the missing step
is a selection/reading the creator has not yet named, not more encodings of
this one.

## 21. S570 fold as an Architect[479] selector index source (2026-08-06)

The 40-pair 180-degree fold of the summed S570 seven-9x9 matrices was used as a
**selector index source** into the authenticated Phase 3.2 Architect A-Z
plaintext, exactly as the creator's sealed 2023-02-23 pipeline uses the poster
matrixsumlist: same four index bases (absolute_0based, from_479_0based,
from_479_1based, cumulative_from_479_0based), same five serializations, same
three overlays, same yinyang offset 479, same gate_scalar_bytes acceptance.
The pair reading is the sealed row-major first-40 (flat index < 40) paired with
180-degree opposites, identical to test.py. The cited phrase
REINSERTING THE PRIME BASICS ... SEVEN INTERTWINED PASSWORDS is confirmed
present (space-free) in the authenticated plaintext.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | {sequential, intertwined} x {a=1..i=9, a=0..i=8} x fold {sum, sum-mod9, absdiff, signeddiff} -> 40 pair offsets -> 4 index bases x 3 overlays x 5 serializations — 624 unique scalars vs Half + Better, **0 hits**; 4,608 AES trials (raw / sha256-hex / sha256-digest x MD5 + SHA-256 EVP) vs chain1/chain2/phase32/cosmic, 15 padding hits (0.33%, at the chance rate), **0 legible** | `s570_fold_architect_selector_audit.json` (sha256 `7e247426d561dd31a1b6c771d9b20252b957daf887a2cef17104c8e851c85199`), `solver/s570_fold_architect_selector_audit.py`; 16 families, each with its 40 pair values, index bases, overlays, scalar_tests and result recorded in the JSON |

**Assessment.** The rule for reading the 40 pairs and using them as offsets is
non-arbitrary (creator-sealed), and the construction is well-defined, but no
extraction reaches the prize or opens an envelope. This closes the S570
fold-as-selector line under the creator's own pipeline constants without
adding free parameters.

## 22. Poster resistor sum lists as split-envelope AES passwords

Preregistered test motivated by the underdetermined `matrixsumlist` object in the
creator's 2023-02-23 pipeline: the 14x14 poster resistor row/column sums are a
well-defined `matrixsumlist`, but they had only been used as Architect plaintext
index lists. This test treats them directly as AES passwords against the
SalPhaseIon split halves env48 and raw48.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | Four 14-entry poster resistor sum lists (rows/columns, eye-zeroed and eye-nine) encoded as raw bytes, mod-10 digits/bytes, mod-9 digits/bytes, mod-26 A-Z/a-z with 0-based and 1-based conventions, and two-digit decimal; each password tried in the four standard forms (literal, SHA-256 raw digest, SHA-256 lowercase-hex ASCII, SHA-256 hex decoded) and both EVP_BytesToKey digests (md5, sha256). For env48 the salt in its header is used; for raw48 both the EVP-derived IV and the env48-ciphertext-tail continuation IV are tested. 960 AES attempts against the split halves. 1 valid PKCS#7 padding hit at chance (mod10-digits/SHA-256-hex-ascii/sha256 on env48, plaintext length 31, entropy 4.89, printable 0.32, not readable and no format/prize gate). 0 legible outputs, 0 prize matches. | `poster_resistor_split_envelope_preregistered.json` (seal `ff37c813…0280ffd8`), `poster_resistor_split_envelope_results.json`, `solver/poster_resistor_split_envelope_audit.py`; `python -m solver.preregistration_integrity_audit` reports CLEAN with the new seal binding |

## 23. Freeze creator-named 23/16/7 cipher catalogue (v57, 2026-08-07)

Answers the underdetermined step left after password-composition endgames: which
object the 23/16/7 menu selects as the *cipher catalogue*. Freezes only
creator-named phase-3.2 ciphers — Beaufort, VIC straddling checkerboard
(`.` and `/` alphabets), and the chess-hint alphabet sentence — keyed by the
Fresco 23/16/7 partition plus `THEMATRIXHASYOU`. No free classical-cipher menu.
Outputs gated as scalars and as AES passwords against chain1/cosmic under
legibility (never padding alone).

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | 44 catalogue outputs → 528 AES + 88 raw-key + 440 scalar gates; phase-3.2 AES and VIC positive controls pass; planted scalar control accepted / production rejects; **2 padding hits (0.32%, at chance), 0 legible opens, 0 prize matches** | `cipher_catalogue_23_16_7_preregistered.json` (seal `80c47063…16e5409`), `cipher_catalogue_23_16_7_audit.json` (status `COMPLETE_NO_MATCH`, stream `7a5ac23d…80dfb14`), `solver/cipher_catalogue_23_16_7_preregister.py`, `solver/cipher_catalogue_23_16_7_audit.py`; scope note forbids widening into unnamed classical ciphers. Remaining underdetermined step: whether 23/16/7 names a different operand entirely (not which cipher from an open menu) |
## 24. Reinsert yellowblueprimes lists into Architect source codes (v55, 2026-08-07)

Literal ordered reading of the Architect instruction against the prime basics
already in hand from `yellowblueprimes`: (1) return to the authenticated
1,539-byte Architect source layers (raw / transliteration / A–Z plaintext);
(2) temporarily disseminate the carried code (`THEMATRIXHASYOU` ascii or
digest, or the phase-3.2 OpenSSL passphrase); (3) reinsert the sealed
yellow/blue prime lists at the named anchors `PRIVATEKEY`@479,
`SOURCECODES`@1021, `PRIMEBASICS`@1103 (overwrite / XOR / append). Distinct
from primes-as-indices (`architect_source_prime_reinsertion`), lists-alone
hashing (`yinyang_prime_dual`), and S91 colour insertion (`prime_reinsertion`).

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | 3 layers × 4 disseminations × 8 dual lists × 3 serializations × 6 insert modes × 4 extractors = **6,912** scalars (2,562 unique valid); planted control accepted and real targets rejected on the same path; **0 prize matches** | `prime_basics_source_reinsert_preregistered.json` (seal `15479b5b…473dd0a`), `prime_basics_source_reinsert_audit.json` (status `COMPLETE_NO_MATCH`, stream `dc329ff7…4a6c6ef5`), `solver/prime_basics_source_reinsert_preregister.py`, `solver/prime_basics_source_reinsert_audit.py`; scope note in the JSON excludes Bitcoin Core / HTML source and post-reinsertion 23/16/7 cipher selection |
## 25. Endgame 23/16/7 against SalPhaseIon source + chain1/cosmic (v56, 2026-08-07)

Handoff reading of the Architect instruction with the *object* as SalPhaseIon
source codes (not the Architect speech): prime-select from S91 / S570 / raw
pre-Beaufort / literals / tokens; compose with the Fresco 23-word 140-char quote
under the fitted `F73D92⊕A94021=5E7DB3` 16/7 mask, the seven 2023-02-23 pipeline
phrases, and the authenticated literals/tokens; disseminate the carried
phase-3.2 passphrase; try creator-published `chain1` and `cosmic` envelopes
under literal / normalized / sha256-hex / sha256-raw32 × EVP md5+sha256, plus a
raw-AES-key branch (`IV=sha256(salt)[:16]`); gate every sha256 / double-sha256 /
clue-residual XOR as a scalar. Residual deliberately truncated from ~2^20 to the
clue set {5,7,16,23,140,479,484,1141}.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | 828 preimages → 13,248 AES trials + 1,656 raw-key trials + 8,280 scalar gates; phase-3.2 positive control opens; planted scalar control accepted / production rejects; **43 padding hits (0.29%, at chance), 0 legible opens, 0 prize matches** | `endgame_23_16_7_salphaseion_preregistered.json` (seal `20f2e18a…6f05228`), `endgame_23_16_7_salphaseion_audit.json` (status `COMPLETE_NO_MATCH`, stream `35568e44…5703d953`), `solver/endgame_23_16_7_salphaseion_preregister.py`, `solver/endgame_23_16_7_salphaseion_audit.py`; scope note excludes Cosmic base-38 / Chain 4 and open 2^20 residual. Narrowest remaining underdetermined step recorded in the JSON: which object the 23/16/7 menu selects *as the cipher catalogue* once password composition against the two envelopes is null |

## 26. Pipeline-operand split envelopes + seven-step yin-yang composition (v58–v59, 2026-08-07)

Two sealed falsifiers from the approved post-analysis priorities: (1) legibility-gated
split-envelope passwords from **page-order operands**, not phrase concatenation; (2) a
fixed **composition rule** over seven structural pipeline outputs for unreached yin-yang
step 4.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | v58: pre-enter operands (S91/S570 fields, decoded lastwords/thispassword, four resistor sum lists, three prime serializations) → **env48 only**; post-enter operands (Architect `[479:]` windows, VIC digits/message, rot180 mask/yin streams, `D` difference blocks) → **raw48 only** (both EVP and continuation IV). Three password forms × two KDFs; legibility gate. **192 AES + 48 scalar gates; 1 padding hit (0.52%, at chance), 0 legible, 0 prize** | `pipeline_operand_split_envelope_preregistered.json`, `pipeline_operand_split_envelope_audit.json`, `solver/pipeline_operand_split_envelope_preregister.py`, `solver/pipeline_operand_split_envelope_audit.py`; does not concat seven phrase strings or reopen Cosmic/Chain4 |
| **NEGATIVE (bounded)** | v59: seven structural outputs (one per creator pipeline step) composed by **fold_xor** (cyclic XOR chain) or **fold_sha256_chain** (`h_i = sha256(h_{i-1} \|\| op_i)`); gated as scalars and as env48/raw48 AES passwords under legibility. **36 AES + 4 scalar gates; 0 padding, 0 legible, 0 prize** | `yinyang_seven_operand_composition_preregistered.json`, `yinyang_seven_operand_composition_audit.json`, `solver/yinyang_seven_operand_composition_preregister.py`, `solver/yinyang_seven_operand_composition_audit.py`; does not widen encodings or add classical ciphers |

**Assessment.** The SalPhaseIon enter-marker split does not yield legible plaintext when
each half is keyed by its natural page operands under the authenticated sha256-hex
password format. The two fixed seven-operand compositions also miss. Split-envelope
correct passwords and yin-yang step 4 remain open under rules that forbid phrase
braids and padding-only acceptance.

## 27. Chain-1 structural operands, NOTES hint, and eye-spiral second door (v60–v62, 2026-08-07)

Three sealed falsifiers extending the approved legibility-gated search.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | v60: full v58 structural operand catalogue (24 operands: S91/S570 fields, resistor lists, prime serializations, Architect windows, rot180 streams, `D` blocks) as AES passwords against **chain1** and **chain2** under legibility. **288 AES + 48 scalar gates; 1 padding hit (0.35%, at chance), 0 legible, 0 prize** | `chain1_structural_operand_legibility_preregistered.json`, `chain1_structural_operand_legibility_audit.json`, `solver/chain1_structural_operand_legibility_{preregister,audit}.py`; does not concat phrase text or reopen Cosmic/Chain4 |
| **NEGATIVE (bounded)** | v61: eleven creator-sourced phrases from the 2026-07-12/07-16 NOTE/NOTES/self-giveaway thread (distinct from v52's 55-string recognition set) against env48/raw48/chain1 under legibility. **264 AES + 22 scalar gates; 0 padding, 0 legible, 0 prize** | `notes_hint_legibility_preregistered.json`, `notes_hint_legibility_audit.json`, `solver/notes_hint_legibility_{preregister,audit}.py` |
| **NEGATIVE (bounded)** | v62: six deterministic edits to the 196-bit spiral at off-white eye index 163 (flip, swap with rot180 partner 173, force 0/1, XOR) × two serializations, gated against chain1/env48. **144 AES + 24 scalar gates; 0 padding, 0 legible, 0 prize** | `second_door_eye_spiral_preregistered.json`, `second_door_eye_spiral_audit.json`, `solver/second_door_eye_spiral_{preregister,audit}.py`; baseline URL control passes |

**Assessment.** The 96-byte chain-1 envelope still has no legible break under structural-operand passwords. The July-16 NOTES callback does not open env48/raw48/chain1 as raw phrases. Eye-index spiral bit edits do not reach a prize gate or legible AES plaintext.

## 28. Architect anchor windows, yin-yang 49-interleave, cross-half split pairs (v63–v65, 2026-08-07)

Three sealed falsifiers from the approved next-pass list.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | v63: nine Architect windows bounded only by named anchors (`TAKETHE` 472, `PRIVATEKEY` 479, `RETURN` 1010, `SOURCECODES` 1021, `REINSERTING` 1089) — no free numeric offsets. Legibility-gated AES on chain1/env48/raw48 plus scalar gates. **216 AES + 18 scalar gates; 0 padding, 0 legible, 0 prize** | `architect_anchor_windows_preregistered.json`, `architect_anchor_windows_audit.json`, `solver/architect_anchor_windows_{preregister,audit}.py` |
| **NEGATIVE (bounded)** | v64: four fixed 49-wide interleaves of rot180 mask/yin-first bits with `D[21:70]` middle49 and blue-zero5 primes (`mod26_add_mask49`, `mod26_add_yin_first49`, `ascii_mask_then_middle`, `prime24_interleave_mask`). **48 AES + 8 scalar gates; 0 padding, 0 legible, 0 prize** | `yinyang_interleave_49_preregistered.json`, `yinyang_interleave_49_audit.json`, `solver/yinyang_interleave_49_{preregister,audit}.py` |
| **NEGATIVE (bounded)** | v65: cross-half assignment (env48-class operands on raw48, raw48-class on env48) plus eight frozen pipeline concat pairs on chain1. **336 AES + 80 scalar gates; 2 padding hits at chance, 0 legible, 0 prize** | `split_envelope_cross_pair_preregistered.json`, `split_envelope_cross_pair_audit.json`, `solver/split_envelope_cross_pair_{preregister,audit}.py` |

**Assessment.** Anchor-bounded Architect spans do not gate to Half under fixed serializations or open envelopes legibly. The 49/98 rot180 × middle49 interleave family misses. Cross-half and paired-operand split-envelope readings also miss. Open-frontier item 1 (operation after 479) and yin-yang step 4 remain unresolved beyond these literal readings.

## 29. Chain-1 phrase-digest constructions (v66, 2026-08-07)

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | v66: fifteen frozen password constructions on **chain1** only — seven-phrase XOR digest (parallel to cosmic token-XOR but on tier-1 phrases), hex-braid/zip/concat of phrase SHA-256 hexes, byte-braid of phrase digests, first-four-phrase concat, five-token concat with authenticated `shabefourfirsthintisyourlastcommand` replacing the duplicate `matrixsumlist`, seven-token HASHTHETEXT/`shabefanstoo` variant, and terminal SalPhaseIon field assemblies — each tested as literal / sha256-hex / raw-32 under EVP MD5 and SHA-256, legibility-gated. **90 AES + 30 scalar gates; 0 padding, 0 legible, 0 prize** | `chain1_phrase_digest_legibility_preregistered.json`, `chain1_phrase_digest_legibility_audit.json`, `solver/chain1_phrase_digest_legibility_{preregister,audit}.py`; does not reopen v49 raw phrase combos or v50 hex-format/intertwine families |

**Assessment.** Phrase-digest XOR/braid constructions and authenticated terminal-field assemblies do not open chain1 at all (no PKCS#7 hit), let alone legibly. The only password in this neighbourhood that still unpads is the historical five-token concat (`matrixsumlist` duplicated as token 5); its 79-byte output remains high-entropy and not legible. The correct chain-1 password, if AES at all, is still unknown and must meet the creator's salvation/legibility criterion when found.

## 30. The cipher itself as a free parameter, and non-round-robin weaves (v67–v68, 2026-08-07)

Two assumptions had never been tested, both of them load-bearing for every
post-3.2 negative in this log.

**The cipher was assumed.** Every prior audit decrypted the `Salted__`
envelopes with `aes-256-cbc` and varied only the password. But `openssl enc`
writes the same `Salted__` header for *every* cipher it supports, so the header
does not identify the algorithm — and the Architect plaintext, which is tier 1,
says the finisher must "SELECT FROM OVER TWENTYTHREE CIPHERS SIXTEEN
ENCRYPTIONS". If the five-token password is right but the cipher is wrong, the
observed symptom would be exactly what v49 measured: chance-rate padding and
unreadable high-entropy output.

**"Intertwined" was read as round-robin.** v50 falsified braid and zip over
every ordering, but those are one weave function under permutation.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | v67: the PyCryptodome-implementable subset of the `openssl enc` cipher catalogue — 27 specs covering AES-128/192/256 in CBC/ECB/CFB/OFB/CTR, `des-ede3-cbc`/`-ecb`, `des-ede-cbc`, `des-cbc`/`-ecb`, `bf-cbc`/`-ecb`/`-ofb`, `cast5-cbc`/`-ecb`, `rc2-cbc`/`-ecb`, `rc4`, `rc4-40` — against 20 authenticated passwords on chain1/chain2/cosmic under EVP MD5 and SHA-256, with the KDF generalised to each cipher's key and IV length. Stream modes gated on legibility alone (no padding exists); block modes must also unpad. **3,240 trials; 8 padding hits (0.25%, at or below chance), 0 legible, 0 prize** | `openssl_cipher_catalogue_preregistered.json`, `openssl_cipher_catalogue_audit.json`, `solver/openssl_cipher_catalogue_{preregister,audit}.py`; controls: `aes-256-cbc` + canonical password + MD5 reproduces the pinned 79-byte chain-1 plaintext `1449a217…`, phase 3.2 legible control passes, planted scalar accepted and production gate rejects it |
| **NEGATIVE (bounded)** | v68: fifteen weave functions that are **not** reachable by permuting a round-robin braid — padded column read keeping a fill character, chunk-2/3/4 interleaves, proportional weave, nested pairwise braid, per-part reversal (concat and braid), letterwise mod-26 add and subtract stacks, cycle-XOR, 7-column grid transposition, running Caesar composition, length-sorted concat, head/tail alternation — over the seven 2023-02-23 phrases and the seven SalPhaseIon tokens, each as literal / sha256-hex / raw-32 under both KDFs against chain1 and chain2. **360 AES + 60 scalar gates; 1 padding hit (0.28%, at chance), 0 legible, 0 prize** | `nonroundrobin_weave_preregistered.json`, `nonroundrobin_weave_audit.json`, `solver/nonroundrobin_weave_{preregister,audit}.py` |

**Assessment.** The cipher assumption is now itself a bounded negative: no
alternative `openssl enc` algorithm or mode makes an authenticated password
produce legible output on any post-3.2 envelope. This matters beyond its own
scope, because it removes the most economical explanation for why the chain-1
plaintext is unreadable — "right password, wrong cipher" is closed for this
catalogue. What remains open on the cipher axis is only what PyCryptodome
cannot express: Camellia, SEED, IDEA, GOST, and non-EVP key derivation such as
PBKDF2. On the password axis, "intertwined" is now closed for both round-robin
(v50) and these fifteen non-round-robin weaves.

Neither result recovers a key, and neither promotes the community chain from
tier 2. The joint effect is narrower and more useful: the reason chain1 does
not read is **not** a mis-identified cipher and **not** a mis-read of
"intertwined", so the unexplained parameter is the password material itself —
or chain1 is not the next lock at all.

## 31. Chain-1 PBKDF2 / sequential layers, and extended 479→yinyang compositions (v69–v70, 2026-08-07)

Two sealed falsifiers targeting the two frontiers the record still treats as
genuinely open: a **legible chain-1 unlock** and a **479→yinyang composition
rule** for unreached step 4.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | v69: chain1 under **PBKDF2-HMAC-SHA256** at 1,000 and 10,000 iterations (eighteen authenticated passwords × three forms); **sequential seven-phrase layered decrypt** (full creator-ordered chain per form/KDF); seven **479-anchor** strings (`479`, `484`, `479479`, `484479`, `yellow479blue484`, `TAKETHE`/`PRIVATEKEY` window, Architect `[479:512]`) × three forms × EVP MD5/SHA-256 — all legibility-gated. **156 AES trials; 1 padding hit (0.64%, at chance), 0 legible, 0 prize** | `chain1_pbkdf2_legibility_preregistered.json`, `chain1_pbkdf2_legibility_audit.json`, `solver/chain1_pbkdf2_legibility_{preregister,audit}.py`; closes PBKDF2 and sequential-layer families v67 left open |
| **NEGATIVE (bounded)** | v70: four **new** composition rules over the same seven v59 structural operands — `fold_add_mod256`, `fold_interleave_bytes`, `fold_sha256_concat`, `yinyang_mirror_xor` (XOR steps 1–3 with 5–7, append step-4 rot180 mask) — gated as scalars and as AES passwords on **chain1**, env48, and raw48 (both IV modes). **96 AES + 8 scalar gates; 0 padding, 0 legible, 0 prize** | `yinyang_composition_extended_preregistered.json`, `yinyang_composition_extended_audit.json`, `solver/yinyang_composition_extended_{preregister,audit}.py`; extends v59 without reopening `fold_xor` / `fold_sha256_chain` |

**Assessment.** PBKDF2 at standard iteration counts does not make chain1 legible
under authenticated passwords. Sequential application of all seven creator
phrases as layered decrypts also misses — no intermediate `Salted__` envelope
survives past the first phrase under this rule. The four extended 479→yinyang
compositions do not open chain1 or the split halves, and do not gate to Half.
Both frontiers remain open under rules that forbid padding-only acceptance; the
narrowest remaining hypotheses are (a) chain1 password material not yet in any
frozen family, or chain1 is not the next AES lock; (b) the 479→yinyang step is
not a fixed byte composition over these seven structural operands.

## 32. 479 index selection, chess/poster second door, chain1 raw key material (v71–v73, 2026-08-07)

Three sealed falsifiers from the approved next-pass list, each targeting a
distinct gap left by v59–v70 and the split-envelope work.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | v71: **selection not composition** — four index streams (yellow9, blue-zero5, all24, 479/484 alternate), four index bases (absolute, from-479 0/1-based, cumulative-from-479), four corpora (Architect, S570 faed, S91, difference ``D``), four rules (linear, mask-gated linear, dual-corpus mask with 479/484 anchors). Each selected string gated as scalar and AES password on chain1/env48/raw48. **160 families → 3,840 AES + 320 scalar gates; 3 padding hits (0.08%, below chance), 0 legible, 0 prize** | `yinyang_479_index_selector_preregistered.json`, `yinyang_479_index_selector_audit.json`, `solver/yinyang_479_index_selector_{preregister,audit}.py`; distinct from v59/v70 byte composition, s570_fold matrix indices, v46 prime-as-key-material |
| **NEGATIVE (bounded)** | v72: chess/poster **pre-chain1** bundle — FEN, ahimsa move ``Rc6+``, chess-hint letters, five eye-index URL edits, bunny impure-7 bits, main/anti diagonal lower bit streams — against chain1/env48/raw48 under legibility. **360 AES + 30 scalar gates; 1 padding hit (0.28%, at chance), 0 legible, 0 prize** | `second_door_chess_poster_preregistered.json`, `second_door_chess_poster_audit.json`, `solver/second_door_chess_poster_{preregister,audit}.py`; does not replay second_door_frontier broad families |
| **NEGATIVE (bounded)** | v73: **non-AES** chain1 — glued 96-byte envelope, env48, and raw48 halves as raw key material: sliding 32-byte windows, prefix-32, half XOR/add, env-ciphertext⊕raw48, env-salt⊕raw48 prefix; sha256/double-sha256 derivations; base58check/format scan. **318 scalar gates; 0 prize, 0 base58check** | `chain1_raw_key_material_preregistered.json`, `chain1_raw_key_material_audit.json`, `solver/chain1_raw_key_material_{preregister,audit}.py`; no AES password attempts; extends K4 beyond raw48-only |

**Assessment.** The 479→yinyang step is not recovered by index selection from
479/484/rot180-mask streams into Architect or S570 under the four sealed rules.
Chess FEN/move and poster second-door materials do not legibly open chain1 or
the split halves. The 96-byte chain1 blob does not yield a prize scalar under
direct window/combine parsing. All three frontiers remain open: (a) index rule
may use a corpus or stepping convention outside this family; (b) second door may
require an operation not frozen here; (c) chain1 may still be AES-locked with
unknown password material rather than raw key bytes.

## 33. Chain1 exhaustive non-AES scalar material (v74, 2026-08-07)

Single sealed superset closing the v73 gaps and the cartesian ceiling on
chain1 byte views, plus the decrypted 79-byte triplet path.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | v74: **4,752 scalar gates** in five tiers — (A) v73 combine rules with full sliding (156 gates, 3 derivations); (B/C/D) cartesian over **17 transforms** (3 base scopes, 4 v73 combines, 10 new: strip header, reverses, interleave, env-ciphertext, concat slices, sub mod256, …) × **8 derivations** (raw, sha256, double, sha256^0x7f, reversed digest, reversed-window sha256, mod-n BE/LE) × all 32-byte windows + prefix32 + glued 32+32+32 slices (**4,328 gates**); (E) joke-password **79-byte decrypt** triplet: 48 sliding windows + key1/key2/extension-pad/xor/add direct views (**424 gates**). **0 prize, 0 base58check** | `chain1_raw_key_material_extended_preregistered.json`, `chain1_raw_key_material_extended_audit.json`, `solver/chain1_raw_key_material_extended_{preregister,audit}.py`, `solver/chain1_scalar_material.py`; extends v73; tier E is AES-first-then-scalar, tiers A–D are non-AES |

**Assessment.** Combined with v73 (318 gates) and split-envelope K4 (17 raw48 windows), the chain1 blob and its decrypted triplet exhaust the natural non-AES scalar parse family under eight fixed derivations and seventeen frozen transforms. No prize match. Chain1 as raw key material and as decrypted triplet fields both miss; the live hypothesis remains unknown password material or a pre-chain1 lock.

## 34. Second-door composition and Architect 479 continuation operations (v75–v76, 2026-08-07)

Two sealed falsifiers targeting the highest-value open frontiers after v74.

| Status | Attempt | Evidence and exact scope |
| --- | --- | --- |
| **NEGATIVE (bounded)** | v75: second-door **composition** (not direct password) — six poster operands (eye URL edits, bunny nest, lower/upper 91-cell triangle bit streams, rot180 mask) × four anchor operands (479, 484, yellow9, Architect ``[479:512]``) × four rules (xor, add mod 256, sha256-concat, interleave). Legibility-gated AES on chain1/env48/raw48. **96 compositions → 2,304 AES + 192 scalar gates; 14 padding hits (0.61%, above chance but 0 legible), 0 prize** | `second_door_composition_preregistered.json`, `second_door_composition_audit.json`, `solver/second_door_composition_{preregister,audit}.py`; distinct from v72 direct passwords |
| **NEGATIVE (bounded)** | v76: **named literal operations** after Architect offset 479 — hash-the-text on nine anchor windows, prime reinsert (yellow9/blue-zero5), rot180 mask suffix select, xor/beaufort/mod26/enter-concat/hashthetext-chain on fixed spans. **19 materials → 456 AES + 38 scalar gates; 0 padding, 0 legible, 0 prize** | `architect_479_continuation_ops_preregistered.json`, `architect_479_continuation_ops_audit.json`, `solver/architect_479_continuation_ops_{preregister,audit}.py`; distinct from v63 windows-as-passwords and v71 index selection |

**Assessment.** Poster second-door operands do not unlock chain1 when composed with 479/484 anchors under four fixed rules. Named Architect continuation operations (hash, reinsert, select, Beaufort, mod26, enter-concat, HASHTHETEXT chain) also miss. Open-frontier item 1 remains unresolved; the operation after ``PRIVATEKEY…`` is not any of these nineteen literal transforms. Second door may require a composition rule outside this frozen poster×anchor menu.
