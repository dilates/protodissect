# ADR-0008: SQLite + content-addressed blobs, CLI-first

**Status:** Accepted · 2026-09-30

## Context

Sessions hold captures (often large), facts, and reports. Same tradeoffs as fw-diff
(same team, same posture): zero-ops beats server features for this audience.

## Decision

SQLite (WAL) per session for state + content-addressed sha256 blob store under
`~/.cache/protodissect/`. CLI-first; no server, no daemon. Reports are single-file
HTML, no external URLs (a lint rule enforces this).

## Consequences

- `pipx install protodissect` and it works offline; sessions are portable by copying.
- Single-writer per session via flock; workers (if ever needed) are stateless.
- Postgres/DuckDB rejected for the same reasons as fw-diff; re-evaluate only if a
  server product emerges.
