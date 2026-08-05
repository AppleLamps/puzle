# Running attempt log

Last consolidated: 2026-08-05.

This is the canonical, append-only index of puzzle approaches represented in
the repository, git history, community notes, and prior-agent transcript. It
groups mechanically equivalent variants while preserving distinct hypotheses.
Detailed counts and candidate manifests remain in the linked result files.
Unless a path starts with `../` or names a root document, evidence filenames are
relative to `gsmgio-5btc-puzzle-master/`. Transcript-only attempts are labelled
as such when no reproducible result artifact was checked in.

Legend: **SOLVED**, **NEGATIVE**, **OPEN**, **SUPERSEDED**, **FITTED**.

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
| **SOLVED** | 14×14 down-first counter-clockwise spiral, black/blue=1 and white/yellow=0 → `gsmg.io/theseedisplanted` | `SOLUTION.md`, `../solve.py` |
| **SUPERSEDED** | 12×12 rabbit maze/yellow breadcrumb route; third right move enters black and the source grid is 14×14 | `SOLUTION.md`, agent rollout |
| **SOLVED** | Spiral-ordered marker bits → `F73D92`; row-major `BE2B9B` is the wrong ordering | `first_grid_secondary_audit.json` |
| **SOLVED** | All 24 colour markers occupy URL byte boundaries and equal the URL-byte LSBs | `RESEARCH_LEDGER.md` |
| **NEGATIVE** | Direct row-major/spiral colour-stream passwords and keys (packed bits, hex, A1Z26 and related forms): 40 unique preimages, 360 AES attempts | `color_stream_password_audit.json` |
| **NEGATIVE** | QR finder “merlon” textures; all three crops are byte-identical | `first_grid_secondary_audit.json` |
| **NEGATIVE** | Pad/scan the rabbit grid as a QR code | `CREATOR_SOURCED.md` |
| **NEGATIVE** | Eight spiral symmetries and fifteen colour maps; only door one is readable | `CREATOR_SOURCED.md` |
| **OPEN** | Unique off-white cell `(7,4)`, zero-based spiral index 163. Prior notes disagree on byte/bit labelling (`SOLUTION.md` says it is not a payload boundary; `CREATOR_SOURCED.md` maps it inside the `n` byte), so no single “character 21/bit 4” convention is accepted | `SOLUTION.md`, `CREATOR_SOURCED.md` |
| **NEGATIVE** | Treat off-white as one, producing `…theseedispla~ted`, then hash/key-test | `../second_door_yinyang_joint_audit.json` |
| **SOLVED** | Structural counts: 86 black versus 85 white + 1 off-white; L/R and diagonal dualities are real | `../second_door_yinyang_joint_audit.json` |
| **SOLVED** | Resistor-code structural totals Y=4, B=6, W=9, R=2 give total 900 (eye/off-white treated as 9) or 891 (eye treated as 0) | `../second_door_yinyang_joint_audit.json` |
| **NEGATIVE** | 1,794 yin/yang materials covering colour inversion, L/R, top/bottom, diagonal and interleave rules → 2,413 scalars and 8,076 AES attempts, no prize/structured result | `../second_door_yinyang_joint_audit.json` |
| **NEGATIVE** | All-grid resistor streams, prime-zeroing, 14×14 sums/products/determinants, URL-prime/HASHTHETEXT, and rabbit-nest morphology families | `second_door_frontier_derivations.json` |
| **NEGATIVE** | Force yellow marker LSBs to one → `gsmg/io/uieseeeisqmaouee`; red/resistor and prime-zero variants | `../second_door_yellow_red_audit.json` |
| **NEGATIVE** | Yellow/red follow-up prime-zero, character-prime, resistor+yflip and red-XOR families: 292 unique scalars | `../second_door_yellow_red_followup.json` |
| **SOLVED (branch result)** | Direct poster assignment of primes 2..89: Blue=484, Yellow=479; zero blue prime 5 → `479=479`. This is distinct from the fitted S91/Witteveen sums 474/400 | `CREATOR_SOURCED.md` |
| **SOLVED (milestone only)** | Authenticated Architect plaintext offset 479 starts `PRIVATEKEY…`; this confirms an index hit, not a private-key derivation | `ARCHITECT_479_CONTINUATION.md` |
| **NEGATIVE** | Broad creator-frontier second-door family: 102,093 unique scalars and 41,660 AES checks | `second_door_frontier_derivations.json` |
| **NEGATIVE** | `yellowblueprimes` bounded derivations independent of Cosmic | `second_door_yellowblueprimes_audit.json` |
| **NEGATIVE** | Earlier reconstructed creator pipeline (`yellowblueprimes`→matrix sums→Architect words→yin/yang): 86 core + 21 on-chain/name candidates, 2,064 decryptions | `SOLUTION.md`, `../pipeline.py` |

## 2. Rebus and phase-one verification

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | Pair eight rebus tiles by mirrored gutters/letter fragments → `cryptologicwarningcanyoudigit` | `SOLUTION.md`, `../solve_rebus.py` |
| **SOLVED** | PNG encoder fingerprints independently confirm the pairings | `SOLUTION.md` |
| **NEGATIVE** | Treat archived `/phase1verification` GET 404 as a clue; it is the SPA catch-all and the real form used POST | `../inspect_bundle.py`, `SOLUTION.md` |

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
| **SOLVED/FITTED** | Align the puzzle's Architect plaintext against the Matrix Reloaded source: 31 edit blocks and 179/835 matching words; alignment is reproducible, semantic intent of substitutions is interpretive | `architect_substitution_audit.json` |
| **NEGATIVE** | Direct CP1141 decode from “one for one, four for one” | `ARCHITECT_479_CONTINUATION.md` |
| **NEGATIVE** | Architect word anchors 121/142/182/237 as passwords/scalars | `book_anchor_audit.json` |
| **NEGATIVE** | L4 phrases as repeating-XOR, Beaufort, or Vigenère cribs over Chain 4 | `l4_crib_audit.json`, `l4_beaufort_audit.json` |
| **SOLVED** | Fresco quote is exactly 23 words and 140 characters after punctuation removal | `ARCHITECT_479_CONTINUATION.md` |
| **SOLVED** | `F73D92 XOR A94021` (Neo passport expiry) → 23-bit mask with 16 ones/7 zeroes | same |
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
| **OPEN** | Intended operation after the 479 `PRIVATEKEY…` pointer | `ARCHITECT_479_CONTINUATION.md` |

## 5. SalPhaseIon extraction and direct locks

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | Mechanically segment S91, `matrixsumlist`, S570, trailing decimal fields, hint literals, and embedded AES | `SALPHASEION_PREREGISTRATION.md` |
| **SOLVED** | Decimal/base16 fields → `lastwordsbeforearchichoice` and `thispassword` | same |
| **SOLVED** | Binary markers → `matrixsumlist` and `enter` | same |
| **SOLVED** | Five-token self-referential password opens the embedded 79-byte record | `VERIFICATION_REPORT.md` |
| **NEGATIVE** | Apply the same password to the independent 48-byte envelope alone | `CREATOR_SOURCED.md` |
| **SOLVED** | WIF from the first 79-byte record opens the phase-3.2 trailing envelope and establishes a mutual byte link | `VERIFICATION_REPORT.md` |
| **FITTED** | Interpret `yourlastcommand` and `secondanswer` as tokens six/seven | `VERIFICATION_REPORT.md` |
| **SOLVED/FITTED** | XOR seven token digests decrypts Cosmic to a reproducible 1327 bytes; token semantics remain fitted | same |
| **NEGATIVE** | Instruction grammar (`matrixsumlist`/`enter`/`lastwords…`/`thispassword` as operations rather than literals): 281,816 decryptions per envelope; only the known five-token control reproduces downstream structure | `salphaseion_instruction_audit.json` |
| **NEGATIVE (historical, partially reproducible)** | Community/Kenorb 500–1,500 password narrative: Matrix quotes, sums, KDFs, PBKDF2, direct key/IV and classical ciphers; several cited helper scripts are absent | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | Exact uppercase Beaufort paragraph hash `216411b7…4597ba` against the adjacent blob | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | Seven-token XOR used on the SalPhaseIon envelope as passphrase/direct AES key; this does not contradict its later Cosmic success | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | `THEMATRIXHASYOU` Beaufort/Vigenère variants and affine `P=2(C-8) mod 9` over the letter grid | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | Claimed Cosmic key/IV applied directly to the SalPhaseIon blob | `tmp/kenorb-analysis.md` |
| **NEGATIVE** | Historical matrix-sum password extractions (inconsistent partial/full totals 422 versus 3239) | `tmp/kenorb-analysis.md` |
| **OPEN** | Independent role of the 48-byte envelope | `CREATOR_SOURCED.md` |

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
| **NEGATIVE** | Bounded `matrixsumlist` grid/list/base-9/scalar family | `matrixsumlist_audit.json` |
| **NEGATIVE** | Prime-reinsertion serializations: 1,376 scalar records, 160 unique nonzero scalars | `prime_reinsertion_audit.json` |
| **NEGATIVE** | S-field T9 substitution/global decode | `sfield_t9_audit.json` |
| **NEGATIVE** | S-field 3×3 window-sum inverse; no readable unique inverse (`sat=false`) | `sfield_matrix_sum_inverse.json` |
| **NEGATIVE** | Direct S-field cipher identification: 82,944 coordinate and 3,456 base9-pair specifications | `sfield_cipher_results.json` |
| **OPEN / PREREGISTERED, NOT RUN** | Exhaustive shared base-9 substitution: 362,880 digit mappings and fixed representations; sealed manifest exists but no result JSON is checked in | `sfield_base9_substitution_preregistered.json` |
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
| **SOLVED/FITTED** | 1327 bytes → 103×103 bits, +7 digit shift, base-38 → 68 bytes and `trail1` | `VERIFICATION_REPORT.md` |
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
| **NEGATIVE (transcript-only)** | Re-gate 68 immediate scalars, then 38,219 unique values from 82 audit files, against both funded addresses | agent rollout |
| **NEGATIVE** | 41 OP_RETURN messages as password corpus | `SOLUTION.md` |
| **SOLVED** | Decentraland audio difference channel decodes `HASHTHETEXT` | `decentraland_audio_audit.json` |
| **NEGATIVE** | Hash obvious creator texts, page-140 units, clue strings and normalizations into prize scalars | `creator_frontier_giveaway_audit.json` |
| **NEGATIVE** | Wayback CDX URL/body search for missing operands (`cosmic_A`, `ca`, `K_I1`) and second-door pages | `wayback_source_audit.json` |
| **NEGATIVE** | Early gsmg.io asset harvest, literal/term scan, PNG/hash comparison and scalar extraction | `wayback_early_asset_audit.json` |
| **OPEN** | X2SH values H/Y and intended use of `# X 2 S H 4 Y 0 Q B 15 #` | `CREATOR_SOURCED.md` |

## 11. Historical or abandoned transcript leads

| Status | Attempt | Why retired |
| --- | --- | --- |
| **SOLVED/FITTED** | `F73D92` is exactly the URL-byte LSB stream and also literal RGB `(247,61,146)` pink; direct colour/password readings failed and zeroing S570 positions 247/61/146 damaged existing controls | `first_grid_secondary_audit.json`, agent rollout |
| **NEGATIVE** | `0x77` selects seven Chain 4 blocks | Many bytes have the same frequency |
| **NEGATIVE** | Book/death-date key for H.J. Witteveen | Funding chronology and target gates fail |
| **FITTED/OPEN** | Playfair/Four-square produced `EVEN` and `XORU`; the rollout claimed `EVEN → XOR → 3` as an internal control, but downstream Cosmic/Chain4/address tests failed | agent rollout |
| **NEGATIVE** | Cosmic component-address activity as creator confirmation | Transactions were solver-authored |
| **NEGATIVE** | Cosmic output as on-curve point or BIP32 parent | Exact curve/address gates fail |
| **SUPERSEDED** | `unaware` as “in front of your eyes” final answer | Reproducible extraction, but key-negative; 479 is a stronger direct pointer |
| **SUPERSEDED** | `F73D92 // 2 + 3` as the primary 24→23 bridge | Drops/changes authenticated URL bits; passport XOR and direct 479 are better constrained |
| **NEGATIVE (transcript-only)** | `THEPROBLEMISCHOICE` 18-letter overlay, two 15-letter Architect halves and literal 19×30→19×15 fold | No control; fold destroyed existing controls |
| **NEGATIVE (transcript-only)** | All-seven diagonal SHA-256/XOR/sum constructions as brainwallet shares | No funded-address match |
| **NEGATIVE (transcript-only)** | Reported `YOUWON+64` S91 extraction under direct 32-byte folds/base encodings | Exact target gates failed |

## 12. Current open frontier

1. Determine the intended operation after Architect offset 479.
2. Explain the 23/16/7 partition without introducing a free cipher/key choice.
3. Resolve the independent 48-byte SalPhaseIon envelope.
4. Determine whether S91/S570 has an intended continuation beyond its
   reproducible controls.
5. Recover or reject the unavailable community operands with source provenance.
6. Derive a scalar matching:
   - Half exact public key, or
   - Better Half hash160 under a valid public-key serialization.

No agent or checked-in audit has yet passed either prize oracle.
