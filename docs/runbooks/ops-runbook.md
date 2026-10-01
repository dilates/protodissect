# Operations Runbook

| | |
|---|---|
| **Audience** | maintainers, CI admins |
| **Last updated** | 2026-09-30 |

## 1. Environment

| Requirement | Minimum | Comfortable |
|---|---|---|
| Python | 3.11 | 3.12 |
| RAM | 2 GB | 8 GB (100 MB captures) |
| LLM (optional) | Ollama, 8B-class model | 70B-class if >= 64 GB |

```bash
git clone https://github.com/dilates/protodissect && cd protodissect
uv sync && uv run protodissect --version
uv run protodissect doctor
```

## 2. Cache and sessions

- Location: `~/.cache/protodissect/` (objects/, sessions/)
- `protodissect sessions list|show <id>|rm <id>`
- Session DBs are single-writer (flock); do not edit them externally mid-run.

## 3. Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `NoFlowsError` on infer | wrong `--port` or the port carries no traffic | `protodissect infer --port <n>`; check flow list in report |
| framing: unknown | unstable framing or too few messages | capture more messages; check notes for mixed framing |
| coverage below gate | encrypted/compressed clusters or wrong split | check per-type breakdown; TLS clusters are flagged |
| naming section absent | provider down or `--llm off` | `ollama list`; or run with `--llm ollama` |
| facts.json differs between runs | nondeterminism: treat as P1 | attach both sessions, file an issue |

## 4. Metrics and logging

Structured JSON logs to stderr; `--log-level debug` includes per-stage timings. Key
counters: parse_errors, flows, clusters, coverage, dropped_names.

## 5. Escalation (maintainers)

1. Nondeterminism: P1, block release.
2. Crash on untrusted capture: P1, check THREAT_MODEL 3.1, coordinate per SECURITY.md.
3. Inference regression on corpus: P2, attach corpus job link.
4. Otherwise: normal triage (CONTRIBUTING labels).