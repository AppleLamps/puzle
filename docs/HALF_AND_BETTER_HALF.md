# What "Half and Better Half" means

Settled 2026-08-05 from primary sources. This question decides scope: if the
phrase names **two prize targets**, then every exhaustive certificate in this
repository is only half a certificate, because `17ucy…` has never spent and
admits no point-space gate. If it names **two people**, the search has exactly
one target and the second address is out of scope.

The evidence says it names two people.

## The line itself

The Phase 3.2.2 VIC straddling-checkerboard decode (149 digits, alphabet
`FUBCDORA.LETHINGKYMVPS.JQZXW`, row digits 1 and 4) is exact:

```
INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE
```

Reproduced by `solver/phase32_classical.py`; recorded in `phase32_classical.json`.

Two readings were live:

- **Reading A (two targets).** "Half" and "Better Half" are labels for two
  private keys the solver is meant to derive.
- **Reading B (two people).** "Half" and "Better Half" are the creator and his
  partner. The sentence is a disclaimer — the keys are theirs, and the closing
  clause "and they also need funds to live" explains why the prize shrinks.

## Creator usage settles it

`tmp/creator_jrk.txt` is the creator-only extraction of the community Telegram
export (`tmp/chat_transcript.txt`, 2019-04-20 → 2026-06-12). The creator uses
"better half" twice, in its ordinary English idiom, about a real person:

| Date | Message |
| --- | --- |
| 2025-04-28 | `Ok, the "better half" is hungry. Which means I'm off 🤗` |
| 2026-03-03 | `I'm going to rewatch episode 3.5 with the better half.` |

Both are unprompted, in unrelated conversation, and scare-quoted the first time
in exactly the way someone quotes an idiom they have used publicly before. He
also speaks for two people throughout: "**We** have our reasons halving the price
money at every bitcoin halving event" (2020-11-24), "**We** mentioned this at the
beginning, when the puzzle started" (2021-01-07).

## The prize is singular, and it is the address that shrinks

Every creator statement about what a solver wins is singular, and every one of
them refers to the balance remaining at `1GSMG…`:

| Date | Message |
| --- | --- |
| 2020-10-27 | `https://www.blockchain.com/btc/address/1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe price is indeed still there.` |
| 2020-11-24 | `We have our reasons halving the price money at every bitcoin halving event :-).` |
| 2021-01-07 | `It'll be split on the next halving.` |
| 2023-01-12 | `If you find the answer now, the remaining 2.5 btc is well deserved... Or 5, who knows.` |
| 2023-01-12 | `Every btc halving the price will half too.` |
| 2023-08-06 | `…the person who connects the last pieces for the 'main price' will thus get its hands on the private key…` |
| 2024-04-19 | `There are few prizes to win besides the banter in this chat. A private key, some 'obscure' intel…` |
| 2026-03-03 | `I only need to look at the address. If any of you reaches the next phase, the price is taken in no-time.` |

"**the remaining** 2.5 btc", "**the** private key", "**the** address" — singular
throughout, and never once a second key the solver is expected to produce.

## The chain agrees

`halving_relation_audit.json` records the only two spends of `1GSMG…`. Both were
signed with Half's key, which is how Half's uncompressed public key is on chain
at all:

| txid | to `17ucy…` | to `1GSMG…` (change) |
| --- | ---: | ---: |
| `2aa9a4a9…0b071b13` | 2.50000000 BTC | 2.49815966 BTC |
| `88cdb3cd…1c9b9df3` | 1.25000000 BTC | 1.25324300 BTC |

Exactly 3.75000000 BTC has moved from the prize to `17ucy…`, in two withdrawals
of exactly half the then-current balance, at the 2020 and 2024 Bitcoin halvings.
`17ucy…` is a sink: it has received 44 times and **spent zero times**. It is not
a puzzle output — it is where the creator's half goes. Current state:

| Address | Balance | Role |
| --- | ---: | --- |
| `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` | 1.25634510 BTC | the prize |
| `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` | 3.75055310 BTC | the creator's retained half |

The line "and they also need funds to live" is the caption for that table.

## Conclusion

**SUPERSEDED 2026-08-06.** The conclusion below was that "there is one prize
target" and that the Half-only certificate concern was "no longer a gap". That
resolution rested on an inference from creator idiom usage and chain behaviour,
not on a creator statement. An independent re-audit on 2026-08-06 found two
things that reopen the question:

1. **The authenticated VIC plaintext says plural keys.** The tier-1 decode
   reads `THEPRIVATEKEYSBELONGTOHALFANDBETTERHALF` — "PRIVATE KEYS" (plural),
   "BELONG TO" (ownership by two named parties). The "two people" reading
   resolved this as a disclaimer, but the text itself does not say "the private
   key belongs to me"; it says the keys belong to Half and Better Half. The
   plural is in the authenticated text; the singular is in the inference.
2. **Five existing audits are Half-only certificates.** They define their own
   `_target_match` against `HALF_X`/`HALF_Y` only and never test Better Half's
   `hash160`: `prime_reinsertion_audit.py`, `page140_key_test.py`,
   `frontier_experiment.py`, `trail1_splice_experiment.py`,
   `trail1_permutation_experiment.py`. Their recorded negatives certify only
   that no candidate matched Half's exact public key — they say nothing about
   Better Half. The newer audits (v40–v54) all route through
   `solver.targets.gate_scalar`, which tests both targets, so the gap is
   confined to the older modules.

The original conclusion is retained below for the citation trail.

---

**Original conclusion (2026-08-05, now superseded):**

**There is one prize target: `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe`.** Its
uncompressed public key is on chain, so it supports an exact point gate — the
cheapest and strongest oracle in the puzzle, and the one every audit here
already uses.

`17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` is the creator's own address. No published
material claims a derivation path to it, and none is expected.

## What this does and does not change

- **Chain 4 certificates are not weakened.** The concern that every exhaustive
  audit is a "Half-only certificate" was correct as stated but is no longer a
  gap, because Half is the whole target set.
  **SUPERSEDED:** see above — five older audits are in fact Half-only
  certificates, and the "one target" premise they rest on is an inference, not
  a creator statement.
- **The Better Half gate stays.** `solver/targets.py` still tests
  `hash160(17ucy…)` under both public-key serializations on every candidate. It
  costs one extra hash per candidate and it is the cheap insurance against this
  conclusion being wrong. Do not remove it.
- **Point-space meet-in-the-middle is fully available.** Nothing in the target
  set requires a hash-only gate, so MITM and baby-step/giant-step style
  constructions may be used against the real target without reservation.
- **`matrix_A`/`matrix_B` remain non-targets.** They were named `Half` and
  `Better_Half` in earlier revisions of `VERIFICATION_REPORT.md` purely because
  the shapes matched this line. See `solver/targets.py` `NON_TARGETS` and
  `SOLUTION.md`, "The base-38 addresses are solver noise".

## Residual uncertainty

This is an inference from creator usage and chain behaviour, not a creator
statement of the form "Better Half is not a target". Two things would overturn
it: a creator message asserting a second derivable key, or a derivation that
lands on `4bc468447fe1b048ad030a2f9a125478eabc4ed6`. The gate in
`solver/targets.py` is what would catch the second case.

**Update 2026-08-06:** The residual uncertainty is now treated as a live
hypothesis, not a footnote. The authenticated text says plural keys; five
audits never tested Better Half; and the creator's 2026-07-12 statement that
"the '5' btc was never the actual prize" is consistent with the real payload
being a message rather than (or in addition to) a key. The next action is to
re-gate the Half-only audit families against Better Half's `hash160` under
both serializations, using `solver.targets.gate_scalar` so both targets are
tested on every candidate.
