# Documentation index

## Canonical research documents

| Document | Role | Status |
| --- | --- | --- |
| [`../README.md`](../README.md) | Repository entry point | Maintained |
| [`../CREATOR_SOURCED.md`](../CREATOR_SOURCED.md) | Creator-authenticated chronology and forensic boundary | Maintained |
| [`../SOLUTION.md`](../SOLUTION.md) | Full reconstruction, corrections, and current result | Maintained |
| [`SOLVED_STAGE_REAUDIT.md`](SOLVED_STAGE_REAUDIT.md) | Independent byte/arithmetic re-derivation and evidence boundaries | Maintained |
| [`ATTEMPT_LOG.md`](ATTEMPT_LOG.md) | Unified running list of attempted approaches | **Append here** |
| [`TRANSCRIPTS.md`](TRANSCRIPTS.md) | Agent/community transcript provenance | Maintained |
| [`../gsmgio-5btc-puzzle-master/RESEARCH_LEDGER.md`](../gsmgio-5btc-puzzle-master/RESEARCH_LEDGER.md) | Detailed claim/evidence ledger | Maintained |
| [`../gsmgio-5btc-puzzle-master/VERIFICATION_REPORT.md`](../gsmgio-5btc-puzzle-master/VERIFICATION_REPORT.md) | Generated machine-verification report | Generated |
| [`../gsmgio-5btc-puzzle-master/SALPHASEION_PREREGISTRATION.md`](../gsmgio-5btc-puzzle-master/SALPHASEION_PREREGISTRATION.md) | SalPhaseIon v1–v39 methodology/history | Maintained |
| [`../gsmgio-5btc-puzzle-master/ARCHITECT_479_CONTINUATION.md`](../gsmgio-5btc-puzzle-master/ARCHITECT_479_CONTINUATION.md) | 479 continuation audit | Maintained |
| [`../gsmgio-5btc-puzzle-master/WITTEVEEN_IDENTITY_AUDIT.md`](../gsmgio-5btc-puzzle-master/WITTEVEEN_IDENTITY_AUDIT.md) | Reproducible Witteveen structural chain | Maintained, not a key solve |

## Package navigation

- [Package documentation](../gsmgio-5btc-puzzle-master/docs/INDEX.md)
- [Result JSON catalog](../gsmgio-5btc-puzzle-master/results/README.md)
- [Artifact catalog](../gsmgio-5btc-puzzle-master/artifacts/README.md)
- [Tool catalog](../gsmgio-5btc-puzzle-master/tools/README.md)

## Historical documents

These are retained for provenance, but their open-task lists and conclusions
may be obsolete:

| Document | Current interpretation |
| --- | --- |
| [`../gsmgio-5btc-puzzle-master/tmp/kenorb-analysis.md`](../gsmgio-5btc-puzzle-master/tmp/kenorb-analysis.md) | Historical password campaign; several claims superseded |
| [`../gsmgio-5btc-puzzle-master/tmp/kenorb-gap.md`](../gsmgio-5btc-puzzle-master/tmp/kenorb-gap.md) | Old gap list; many entries now closed |
| [`../gsmgio-5btc-puzzle-master/tmp/cody-chain.md`](../gsmgio-5btc-puzzle-master/tmp/cody-chain.md) | Source report for the Witteveen chain |
| [`../gsmgio-5btc-puzzle-master/README.md`](../gsmgio-5btc-puzzle-master/README.md) | Upstream puzzle corpus and extractor input; do not rewrite as current analysis |

## Update policy

When adding an experiment:

1. Preserve the exact input and provenance.
2. Add or update a reproducible solver module.
3. Record the result JSON and cryptographic acceptance gate.
4. Append one row to `ATTEMPT_LOG.md`.
5. Mark replaced interpretations as **superseded** rather than deleting them.
