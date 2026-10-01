# Governance

| | |
|---|---|
| **Status** | Active |

## Roles

- **Contributors** - anyone whose PR lands.
- **Component owners** - named in CODEOWNERS; gate-keep their component.
- **Maintainers** - merge rights, release management, roadmap. Additions by consensus
  after sustained contribution (3+ months, 10+ substantive PRs or equivalent).

## Decision-making

1. Trivial (typos, docs, test cases): PR review.
2. Normal (features within an approved spec): owner approval + CI green.
3. Architectural: an ADR is required (RFC issue, then ADR recorded with rationale).
4. Disagreements: maintainer supermajority; dissent is recorded in the ADR.
   Reversal = superseding ADR, never silent edits.

## What is frozen

- facts.json schema major versions (compatibility policy in the docs).
- The deterministic-core posture: facts-before-naming, local-first LLM
  (ADR-0003, ADR-0004). Changing these requires a major release and explicit consensus.

## Code of conduct

See CODE_OF_CONDUCT.md; maintainers enforce it uniformly.