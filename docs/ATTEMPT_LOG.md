# Running attempt log

Last consolidated: 2026-08-05.

This is the canonical, append-only index of puzzle approaches represented in
the repository, git history, community notes, and prior-agent transcript. It
groups mechanically equivalent variants while preserving distinct hypotheses.
Detailed counts and candidate manifests remain in the linked result files.

Legend: **SOLVED**, **NEGATIVE**, **OPEN**, **SUPERSEDED**, **FITTED**.

## 1. First poster and second door

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | 14×14 down-first counter-clockwise spiral, black/blue=1 and white/yellow=0 → `gsmg.io/theseedisplanted` | `SOLUTION.md`, `solve.py` |
| **SUPERSEDED** | 12×12 rabbit maze/yellow breadcrumb route; third right move enters black and the source grid is 14×14 | `SOLUTION.md`, agent rollout |
| **SOLVED** | Spiral-ordered marker bits → `F73D92`; row-major `BE2B9B` is the wrong ordering | `first_grid_secondary_audit.json` |
| **SOLVED** | All 24 colour markers occupy URL byte boundaries and equal the URL-byte LSBs | `RESEARCH_LEDGER.md` |
| **NEGATIVE** | QR finder “merlon” textures; all three crops are byte-identical | `first_grid_secondary_audit.json` |
| **NEGATIVE** | Pad/scan the rabbit grid as a QR code | `CREATOR_SOURCED.md` |
| **NEGATIVE** | Eight spiral symmetries and fifteen colour maps; only door one is readable | `CREATOR_SOURCED.md` |
| **OPEN** | Unique off-white cell `(7,4)`, character 21/bit 4, prime spiral index 163 | `CREATOR_SOURCED.md` |
| **NEGATIVE** | Treat off-white as one, producing `…theseedispla~ted`, then hash/key-test | `second_door_yinyang_joint_audit.json` |
| **SOLVED** | 86 black and 86 white/off-white cells; L/R and diagonal dualities are real structural facts | `second_door_yinyang_joint_audit.json` |
| **NEGATIVE** | Hash/XOR/coordinate operations over 86/86, L/R, top/bottom, diagonal, and colour inversions | same |
| **NEGATIVE** | Resistor codes Y=4, B=6, W=9, R=2; row/column/eye totals including 900/891 | `second_door_frontier_derivations.json` |
| **NEGATIVE** | Force yellow marker LSBs to one → `gsmg/io/uieseeeisqmaouee`; red/prime follow-ups | `second_door_yellow_red_audit.json` |
| **NEGATIVE** | Prime-index and character-prime zeroing over poster bitstreams | same |
| **SOLVED** | Assign primes 2..89 to marker colours: Blue=484, Yellow=479; zero blue prime 5 → `479=479` | `CREATOR_SOURCED.md` |
| **SOLVED** | Authenticated Architect plaintext offset 479 starts `PRIVATEKEY…` | `ARCHITECT_479_CONTINUATION.md` |
| **NEGATIVE** | Broad creator-frontier second-door scalar/AES families | `second_door_frontier_derivations.json` |
| **NEGATIVE** | `yellowblueprimes` bounded derivations independent of Cosmic | `second_door_yellowblueprimes_audit.json` |

## 2. Rebus and phase-one verification

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | Pair eight rebus tiles by mirrored gutters/letter fragments → `cryptologicwarningcanyoudigit` | `SOLUTION.md`, `solve_rebus.py` |
| **SOLVED** | PNG encoder fingerprints independently confirm the pairings | `SOLUTION.md` |
| **NEGATIVE** | Treat archived `/phase1verification` GET 404 as a clue; it is the SPA catch-all and the real form used POST | `inspect_bundle.py`, `SOLUTION.md` |

## 3. Phase two and seven parts

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | AES part-one password `causality` | `SOLUTION.md` |
| **SOLVED** | Decode parts 2–7: Safenet/Luna/HSM, binary, raw source hex, and chess FEN | `SOLUTION.md` |
| **SUPERSEDED** | 349M then 437M assemblies tested against the wrong SalPhaseIon URL-hash oracle | `SOLUTION.md`, git history |
| **NEGATIVE** | Single-word dictionaries on three remaining phase-two blobs | git `d4f7186` |
| **NEGATIVE** | Repeated ECDSA nonce/HNP route; 187 signatures have distinct `r` values | `blockchain_nonce_audit.json` |
| **SOLVED** | Correct seven-part concatenation/hash opens the phase-three ciphertext | `VERIFICATION_REPORT.md` |
| **SOLVED** | SalPhaseIon URL is instead SHA-256 of the first poster's visible text/address | `SOLUTION.md` |

## 4. Phase 3.1 and 3.2

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | Fresco + `giveitjustonesecond` + Heisenberg answer hash decrypts phase 3.2 | `README.md`, `phase32_classical.json` |
| **SOLVED** | Recover 26-symbol substitution independently from an Architect crib and language scoring | `phase32_symbol_recovery.json` |
| **SOLVED** | Beaufort key `THEMATRIXHASYOU` reproduces the 1539-letter Architect plaintext | `phase32_classical.json` |
| **SOLVED** | VIC straddling checkerboard reproduces the Half/Better-Half funds message | same |
| **NEGATIVE** | Direct CP1141 decode from “one for one, four for one” | `ARCHITECT_479_CONTINUATION.md` |
| **NEGATIVE** | Architect word anchors 121/142/182/237 as passwords/scalars | `book_anchor_audit.json` |
| **NEGATIVE** | L4 phrases as repeating-XOR, Beaufort, or Vigenère cribs over Chain 4 | `l4_crib_audit.json`, `l4_beaufort_audit.json` |
| **SOLVED** | Fresco quote is exactly 23 words and 140 characters after punctuation removal | `ARCHITECT_479_CONTINUATION.md` |
| **SOLVED** | `F73D92 XOR A94021` (Neo passport expiry) → 23-bit mask with 16 ones/7 zeroes | same |
| **NEGATIVE** | 479 windows, heart-centres, prime streams, clue-number tweaks, EC offsets, and ECDSA nonce candidates | `architect_479_bounded_search.json` |
| **NEGATIVE** | 479 continuation materials: 10,693 unique scalars | `yinyang_479_continuation_audit.json` |
| **NEGATIVE** | Constrained 23-word/16/7/intertwine/Beaufort semantic pipeline | `architect_479_semantic_pipeline.json` |
| **NEGATIVE** | Chaocipher, historical/modern Bellaso, Porta, Vigenère, Beaufort and reversals: 90,840 scalars | `ciao_bella_479_audit.json` |
| **NEGATIVE** | “Both beginning and end” 32-character edge keys | `architect_beginning_end_audit.json` |
| **NEGATIVE** | Literal AND/OR/XOR over the 16/7 quote split | `architect_479_and_or_audit.json` |
| **NEGATIVE** | `asbothbeginningandend` and normalization/password variants | `architect_lastwords_yinyang_audit.json` |
| **NEGATIVE** | Exact derived yin-yang phrase against the Cosmic page ciphertext | `architect_yinyang_cosmic_exact_test.json` |
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
| **NEGATIVE** | Community/Kenorb 500–1,500 password narrative: Matrix quotes, sums, KDFs, classical ciphers | `tmp/kenorb-analysis.md` |
| **OPEN** | Independent role of the 48-byte envelope | `CREATOR_SOURCED.md` |

## 6. SalPhaseIon preregistration and S-field families

The exact candidate manifests and counts are in
`SALPHASEION_PREREGISTRATION.md`; equivalent microvariants are grouped here.

| Status | Attempt family | Evidence |
| --- | --- | --- |
| **NEGATIVE** | Blind candidate families v1–v22: 71,184 AES decryptions, random-rate padding only | `salphaseion_blind_results*.json` |
| **NEGATIVE** | Cross-stage SHA-256 answer families v1–v22 | `salphaseion_cross_stage_results*.json` |
| **NEGATIVE** | v23–v27 prime/layout identities, dual matrices, Lo Shu and split controls | preregistration doc |
| **NEGATIVE** | v28 eight second-door spiral symmetries | `salphaseion_blind_results_v28.json` |
| **NEGATIVE** | v29–v32 retired 15-row matrix completion/transposition families | corresponding JSON |
| **NEGATIVE** | v33–v36 corrected 7×13/S570 grammar and Architect suffix families | corresponding JSON |
| **NEGATIVE** | v37 URL characters/bits at prime slots | `url_prime_reinsertion_results.json` |
| **NEGATIVE** | v38 zero-prime 7×13/VIC family: 2,551,032 AES trials | `RESEARCH_LEDGER.md` |
| **NEGATIVE** | v39 19×30 “last words” transpositions: 1,807,668 AES trials | same |
| **NEGATIVE** | Bounded `matrixsumlist` grid/list/base-9/scalar family | `matrixsumlist_audit.json` |
| **NEGATIVE** | Prime-reinsertion scalar serializations | `prime_reinsertion_audit.json` |
| **NEGATIVE** | S-field T9 substitution/global decode | `sfield_t9_audit.json` |
| **NEGATIVE** | S-field 3×3 window-sum inverse; natural systems are UNSAT | `sfield_matrix_sum_inverse.json` |
| **NEGATIVE** | Exhaustive base-9 substitutions and validators | `sfield_cipher_results.json` |
| **NEGATIVE** | S570 direct reductions to Chain 4/prize scalars | `sfield_reduction_audit.json` |
| **NEGATIVE** | Reproduce claimed 79-byte anchor `e2590f15…` | `salphaseion_79_anchor_hunt.json` |

## 7. Witteveen/Cody structural branch

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED** | T13/S91 arithmetic produces `AFFECTTHISB` under recorded conventions | `tmp/cody-chain.md` |
| **SOLVED** | S570 half-fold contains `HILLONE` and `KG` without plaintext scoring | `witteveen_identity_audit.py` |
| **FITTED** | Zero indices 400/474 to alter `OA` into `HS` and obtain `ASKHSKEY` | `ARCHITECT_479_CONTINUATION.md` critique |
| **FITTED** | Multiply by three to manufacture `SPACE`; T5 rotation to `COMPS` | same |
| **SOLVED/FITTED** | Component/diagonal conventions produce `WITVEEN`; zero `O` from `TOE` and insert `TE` → `WITTEVEEN` | `WITTEVEEN_IDENTITY_AUDIT.md` |
| **SUPERSEDED** | Treat Witteveen as the creator's yin-yang endpoint | direct 479 balance is simpler and exact |
| **NEGATIVE** | Witteveen/name/title/Hill/COMPS scalars and AES forms | `creator_frontier_giveaway_audit.json` |
| **NEGATIVE** | *Heart of Sufism* page 140 units and word `unaware` as keys | `heart_page140_key_audit.json` |
| **NEGATIVE** | Seven Witteveen diagonals as Chain 4 passwords | `witteveen_chain4_two_oracle_audit.json` |
| **NEGATIVE** | T23 16/7 split and beginning/end scalar families | `salphaseion_t23_16_7_audit.json` |

## 8. Cosmic matrix and Half/Better-Half interpretations

| Status | Attempt and result | Evidence |
| --- | --- | --- |
| **SOLVED/FITTED** | 1327 bytes → 103×103 bits, +7 digit shift, base-38 → 68 bytes and `trail1` | `VERIFICATION_REPORT.md` |
| **NEGATIVE** | Interpret leading `04||x||y` as an uncompressed secp256k1 point; point is off-curve | `SOLUTION.md` |
| **NEGATIVE** | Treat two 32-byte slices as the prize Half/Better-Half keys | `half_better_combination_audit.json` |
| **NEGATIVE** | Every standard script/address serialization for those slices | `CREATOR_SOURCED.md` |
| **NEGATIVE** | EC add/subtract/multiply, ECDH, hash, HMAC, AES key-on-key | `half_better_combination_audit.json` |
| **NEGATIVE** | Cosmic as BIP32 32+32+4 parent/chain/index | transcript-derived passport/BIP32 audits |
| **NEGATIVE** | Yin/yang row/column matrix duals and alternate base-38 readings | `CREATOR_SOURCED.md` |
| **NEGATIVE** | 321 chain values under arithmetic/XOR/hash combinations | `SOLUTION.md` |
| **NEGATIVE** | Frontier cross-branch Chain4-window/constants search | `frontier_experiment.json` |
| **SUPERSEDED** | Equate page label “Cosmic Duality” with creator-named yin-yang | `CREATOR_SOURCED.md` |

## 9. Chain 4

| Status | Attempt family | Evidence |
| --- | --- | --- |
| **SOLVED/FITTED** | Reproduce 1151-byte `+-`, 31-byte prefix, 35×32-byte block layout; exposing mask is fitted | `VERIFICATION_REPORT.md` |
| **NEGATIVE** | C(7,3)=35 intertwined-password AES assignments | `chain4_intertwined_results.json` |
| **NEGATIVE** | GF(2) seven-vector model; 35 blocks have rank 35 | `chain4_combinatorial_audit.json` |
| **NEGATIVE** | Additive subset MITM families M1–M5 (~9.5T logical evaluations) | `chain4_mitm_audit.json` |
| **NEGATIVE** | Exhaustive 2^35 signed `+-` patterns | `chain4_signed_mitm_audit.json` |
| **NEGATIVE** | XOR subsets of sizes 3, 4, and 7 | `chain4_xor_subset_audit.json` |
| **NEGATIVE** | Modular product/division subsets | `chain4_product_subset_audit.json` |
| **NEGATIVE** | 31-byte one-byte completion and every 29-byte contiguous 24-bit insertion using BSGS | `RESEARCH_LEDGER.md` |
| **NEGATIVE** | `trail1` splice/permutation/completion operations | `trail1_*_experiment.json` |
| **NEGATIVE** | Exact serialized T8 adjacent-XOR triangle in 18,432 layouts | `xor_triangle_audit.json`, `chain4_completed_triangle.json` |
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
| **SOLVED** | Extract and verify Half's exact uncompressed public key from its spend | `VERIFICATION_REPORT.md` |
| **SOLVED** | Confirm Better Half received 2.5 BTC and later 1.25 BTC at Bitcoin halvings | `halving_relation_audit.json` |
| **NEGATIVE** | Same-key compressed/uncompressed, point half/double/negation, and simple affine relations | same |
| **NEGATIVE** | Repeated/non-small/derived ECDSA nonce candidates | `blockchain_nonce_audit.json` |
| **NEGATIVE** | Halving-height/amount/fee affine nonce family | transcript-derived audit |
| **NEGATIVE** | 41 OP_RETURN messages as password corpus | `SOLUTION.md` |
| **SOLVED** | Decentraland audio difference channel decodes `HASHTHETEXT` | `decentraland_audio_audit.json` |
| **NEGATIVE** | Hash obvious creator texts, page-140 units, clue strings and normalizations into prize scalars | `creator_frontier_giveaway_audit.json` |
| **NEGATIVE** | Exhaustive relevant Wayback URL/body/asset search found no archived second-door page or missing operands | `wayback_*_audit.json` |
| **OPEN** | X2SH values H/Y and intended use of `# X 2 S H 4 Y 0 Q B 15 #` | `CREATOR_SOURCED.md` |

## 11. Historical or abandoned transcript leads

| Status | Attempt | Why retired |
| --- | --- | --- |
| **SUPERSEDED** | Pink/RGB interpretation of `F73D92` | It is exactly the URL LSB stream |
| **NEGATIVE** | `0x77` selects seven Chain 4 blocks | Many bytes have the same frequency |
| **NEGATIVE** | Book/death-date key for H.J. Witteveen | Funding chronology and target gates fail |
| **NEGATIVE** | Playfair/Four-square `EVEN`, `XORU`, scalar-three loop | No independent control or prize match |
| **NEGATIVE** | Cosmic component-address activity as creator confirmation | Transactions were solver-authored |
| **NEGATIVE** | Cosmic output as on-curve point or BIP32 parent | Exact curve/address gates fail |
| **SUPERSEDED** | `unaware` as “in front of your eyes” final answer | Reproducible extraction, but key-negative; 479 is a stronger direct pointer |
| **SUPERSEDED** | `F73D92 // 2 + 3` as the primary 24→23 bridge | Drops/changes authenticated URL bits; passport XOR and direct 479 are better constrained |

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
