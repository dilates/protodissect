# Contributing to protodissect

Thanks for your interest. We run this like a product: specs first, ADRs for decisions,
capture-driven tests. Reading docs/ARCHITECTURE.md and docs/adr/ before your first PR
is the fastest path to a green review.

## Dev setup

```bash
git clone https://github.com/dilates/protodissect && cd protodissect
uv sync --all-extras
uv run protodissect doctor
uv run pytest -m "not eval"        # fast suite
uv run pytest -m eval              # needs a local Ollama model
```

## Ground rules

1. **No behavior change without a spec.** Inference behavior lives in
   docs/design/pipeline-spec.md; PRs that change it update the spec in the same PR.
2. **Decisions get ADRs.** Architectural changes get docs/adr/ADR-00XX-*.md
   (Status/Context/Decision/Consequences/Alternatives). Renumbering is forbidden.
3. **facts.json schema is frozen** (v1, additive-only); schema changes need an ADR.
4. **Determinism is sacred.** No dict-order reliance, no clock-in-output, no
   `hash()` on strings in the core (PYTHONHASHSEED is not stable). CI enforces
   byte-identical reruns.
5. **Classifiers are pure functions.** No I/O, no randomness, no network.

## Style

- Format/lint: `ruff format && ruff check` (line length 100)
- Types: `mypy --strict` passes on everything under src/
- Conventional Commits (`feat:`, `fix:`, `docs:`, `perf:`, `test:`, `chore:`)
- Public functions get docstrings; internal complexity gets a why comment

## PR process

- One concern per PR; spec/ADR updates ride along
- CI green: lint, types, fast tests, docs checks
- Review gates: 1 approval for docs/tests; 2 approvals for structure inference,
  framing, or facts.json schema changes

## Issues

Labels: `bug` / `P1..P3` / `area:pcap` / `area:inference` / `area:dissector` /
`area:llm` / `good-first-issue` / `help-wanted`. RFC issues for spec discussions;
outcomes land as ADRs.

## Good first issues

`good-first-issue`: corpus cases, Lua generator polish, docs, classifier rules with
existing spec.