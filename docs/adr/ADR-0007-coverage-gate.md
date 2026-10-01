# ADR-0007: Coverage gate on generated structures

**Status:** Accepted · 2026-09-30

## Context

Inference can be confidently wrong. Analysts need a one-number answer to "how much of
this does the structure actually explain", and CI needs a gate.

## Decision

Every session computes round-trip byte coverage per message type and overall
(message-weighted). `protodissect validate --min-coverage X` (default 0.8) exits 0/1
with a per-type breakdown. Facts record coverage per field and per cluster. Unexplained
bytes surface as variable_tail or gaps, never hidden.

## Consequences

- Inference quality is measurable: corpus targets are framing 100%, field boundary
  F1 >= 0.85, coverage >= 0.90 (PRODUCT_SPEC 5).
- A wrong structure is visible immediately: low coverage with a breakdown pointing at
  the failing cluster.
- We accept that encryption/compression depresses coverage; such clusters are flagged
  (high entropy tail) rather than punished silently.
