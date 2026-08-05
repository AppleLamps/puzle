# Solver package documentation

The package root is intentionally stable: solver modules and tests expect
generated JSON beside `README.md`.

## Reading order

1. [`../../CREATOR_SOURCED.md`](../../CREATOR_SOURCED.md)
2. [`../../SOLUTION.md`](../../SOLUTION.md)
3. [`../../docs/ATTEMPT_LOG.md`](../../docs/ATTEMPT_LOG.md)
4. [`../RESEARCH_LEDGER.md`](../RESEARCH_LEDGER.md)
5. [`../VERIFICATION_REPORT.md`](../VERIFICATION_REPORT.md)

## Specialized documents

| Document | Scope |
| --- | --- |
| [`../SALPHASEION_PREREGISTRATION.md`](../SALPHASEION_PREREGISTRATION.md) | Frozen candidate manifests and blind-test history |
| [`../ARCHITECT_479_CONTINUATION.md`](../ARCHITECT_479_CONTINUATION.md) | 479 pointer and bounded continuation |
| [`../WITTEVEEN_IDENTITY_AUDIT.md`](../WITTEVEEN_IDENTITY_AUDIT.md) | Reproducible Witteveen structural result |
| [`../results/README.md`](../results/README.md) | Result JSON family catalog |
| [`../artifacts/README.md`](../artifacts/README.md) | Source artifact catalog |
| [`../tools/README.md`](../tools/README.md) | Utility scripts |

## Commands

```bash
python3 -m pytest -q
python3 -m solver.report
python3 -m solver.<audit_module>
```

`VERIFICATION_REPORT.md` and `artifacts.json` are generated. Edit their
generators rather than hand-editing generated conclusions.
