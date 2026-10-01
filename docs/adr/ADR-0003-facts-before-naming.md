# ADR-0003: Deterministic inference first; LLM names fields only

**Status:** Accepted · 2026-09-30 · Load-bearing ADR

## Context

LLMs are excellent at proposing "this looks like a timestamp" and terrible at proving
byte boundaries. A protocol analysis tool whose layout cannot be trusted or reproduced
is worthless to the RE audience.

## Decision

The pipeline splits: a deterministic core (parse, cluster, framing, field inference,
validation) produces facts.json, byte-reproducible. The LLM layer only proposes names
and one-sentence descriptions for fields the core already proved, must cite the field
id, must match a name grammar, and unvalidated names are dropped. No agentic loop, no
tool use, single pass, pinned prompt version.

## Consequences

- `protodissect infer --llm off` (the default) is fully deterministic and offline.
- The LLM can never invent a field, shift a boundary, or change framing.
- CI can gate on facts.json diffs; naming diffs are advisory.
- We forgo "LLM finds the framing": if we ever want that, it must first graduate into a
  deterministic heuristic validated on the corpus.

## Alternatives

- LLM-first protocol inference: stronger on weird cases, but kills reproducibility and
  auditability. Rejected.
- No LLM at all: shipped as the default mode, always available.
