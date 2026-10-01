# ADR-0006: Simhash clustering, not embeddings, for message types

**Status:** Accepted · 2026-09-30

## Context

Message type clustering needs to group payloads whose fields align. Options: exact
length buckets, byte-histogram simhash, embedding models.

## Decision

v1: exact length buckets + simhash merge (threshold 0.9) over byte-value histograms.
Embeddings stay a v0.2+ roadmap item behind the same interface.

## Consequences

- Fully deterministic, zero-dependency, fast at 10k-message scale.
- Structurally similar messages with different lengths (optional fields) can split;
  the corpus tracks this, and the merge rule handles the common flags/counter case.
- Embeddings are nondeterministic across model versions and slow at this scale; they
  also cannot beat byte-alignment statistics for grouping identical layouts.

## Alternatives

- Embedding-first clustering: rejected for v1 (see above); revisit for semantic
  clustering of *unaligned* captures in v0.3.
