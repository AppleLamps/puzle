GSMG session — work not currently in the repo
Session 2026-08-07 (cloud). Everything below ran against staged copies and was
never committed to C:\Users\lucas\github-repos\puzle. Session totals: ~9,900
AES decryptions + ~2,000 scalar gates, all gated on a legible open or
solver/targets.py. Zero legible opens, zero prize matches.
A. New methods / results (not in the repo)
	1.	Independent oracle validation, digest split pinned. From sealed bytes:
phase 3.2 reproduces only under EVP_BytesToKey SHA-256 (control opens
“I’ve been waiting for you.”, printable 0.598); the Cosmic envelope reproduces
only under MD5 with the 32-byte seven-digest-XOR password. The two
creator envelopes use different KDF digests — stated explicitly.
	2.	Modality-agnostic “visual” structure gate. New acceptance test beyond
text-legibility: zlib compression ratio + best-reshape bit-adjacency, with
controls (phase 3.2 = 0.71 structured; random/Cosmic = 1.008). Run over 172+
candidate decryptions of both envelopes: all statistically identical to random.
Rules out a hidden image/QR/2-D answer among everything tested.
	3.	Color-layer redundancy proof. Derived from pixels: the 24 markers sit at
spiral indices 7,15,…,191 (every 8th) = the LSB of each of the 24 URL
characters. So blue/yellow is char parity, fully redundant with door 1.
F73D92 = those 24 LSBs; the opposite reading is its complement 08C26D.
Conclusion: the color layer carries no free information, so “color = second
door” is dead on the merits, not by prior claim.
	4.	Isolation of the only non-redundant first-image data. FEFEFE (spiral 163,
byte 20, the n of planted) + the 7 rabbit cells (spiral 172,184,187,
192–195; 192–195 = the 4 residual bits). Rabbit cells all read white (0), so
the rabbit is a picture, not bits. FEFEFE tested as the “character to zero
out” pointer across S91/S570/Architect/479 — null.
	5.	QR decoded independently = https://www.blockchain.com/btc/address/1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe,
nothing hidden. Rabbit glyph faces right/down.
	6.	Sealed systematic matrix-operation sweep (run_sweep.py,
sha256 = dadbd7d0f2da4bd475706d25b00c02bf5b2e205d7ff3b2e50b156db79ff4b167):
6,608 AES + 1,290 scalar gates over both self-labeled grids (S91 7×13, S570
15×38, both orientations) × {row/col/diag/anti/max/min/dr sums, flatten,
snake, spiral} × {digits, letters, a–i, byte, sha, raw} × {raw, prime-zeroed
0/1-based} × both envelopes × md5/sha256, plus S91⊕S570 duals. All null.
B. New negative families added (bounded, gated, not in repo)
	•	Preregistered literal-token AES battery, both envelopes, all six byte reps (286).
	•	matrixsumlist-outputs under the authenticated sha256-hex format (180).
	•	15×38 continuations: yin-yang split (clean 19/19 count split but sums
1657 vs 1422 — a property, not a balance) and positional label pairing incl.
FEFEFE-index rotations (216).
	•	FEFEFE-fixed image → sha256 route, both images, 3 normalizations (60).
	•	Seven pipeline phrases as the “seven intertwined passwords” — XOR / concat /
intertwine / raw-key, both envelopes (210).
	•	Sum-lists as index/selection streams into the choice string, Architect text,
and fields + packed scalars (128).
	•	Prime-zeroing-then-matrix; diagonals / leading-submatrix determinant / transpose
difference / S570−S91 dual; combined 7+38 / 13+15 objects (288).
	•	“white rabbit” as brainwallet + AES: 42 variants incl. Dutch (witte konijn)
and “white rabbi”, 504 trials.
	•	“theory of everything”: 56 phrases (literal ToE, 42/Hitchhiker, Heisenberg/
physics, Fresco/Venus, concat-everything), 1,344 trials.
	•	Creator-message phrases: GSMG expansion, full Fresco quote and its last line
“the future is ours to direct”, Mr Robot, Matrix set, “one for one four for
one”, 608 trials.
	•	sha256("giveaway") and variants (giveit, true giveaway, phrase-7) — gated,
none a prize address.
C. Telegram read — findings not reflected in the repo
	•	Ruled out: the 2024-11-29 “Blueprint is sort of the leading list” line is
supplements banter (NAD/NMN; Bryan Johnson’s Blueprint), immediately
followed by “No hints”. Not a puzzle hint.
	•	The 2026-07-12 “NOTE: that is a hint” attaches to the line “My close friends
have the best chance… but they don’t have the skills some of you do.”
	•	The 2021-04-01 second-door hint {1},{4},{21} carries the creator’s own decode
nudge “R=18 A=1 B=2 … could also be 21 or 1812 bit” (reads toward RABBIT).
	•	Under-explored on record: 2023-01-12 “Focussing on the theory of everything
is also still a valid path to reaching the private key.” Tested here as a
passphrase across every concrete referent — null. In context (“also still a
valid path”) it reads as a second route via understanding his philosophy, not
a string.
D. Interpretive conclusion (new to the record)
All confirmed operations on the confirmed objects are now exhausted across text
and visual modalities. The consistent hypothesis fitting every creator
statement: the final key = sha256(X) where the operation is a public giveaway
and X is a short personal text known to the creator’s close friends — which
is why exhaustive cryptanalysis (repo’s ~1.59M scalars + this session) fails
while he says his unskilled friends are better placed. The missing input is that
text, not a cipher.