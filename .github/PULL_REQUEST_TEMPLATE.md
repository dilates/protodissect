## Summary

<!-- What does this PR change? Link the spec/ADR/issue it implements. -->

## Type

- [ ] feat  [ ] fix  [ ] docs  [ ] test  [ ] perf  [ ] refactor  [ ] chore

## Checklist

- [ ] Spec/docs updated in the same PR if inference behavior changed (CONTRIBUTING rule 1)
- [ ] ADR created/updated for any architectural decision
- [ ] Tests: fast suite green locally (`pytest -m "not eval"`)
- [ ] `mypy --strict` + `ruff` pass
- [ ] facts.json untouched, or change follows the additive-only policy
- [ ] No nondeterminism introduced (no clock/random/string-hash in core paths)

## Determinism statement

<!-- If you touched pcap/flows/cluster/structure: confirm same-input reproducibility. -->