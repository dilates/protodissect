# Threat Model - protodissect

| | |
|---|---|
| **Status** | Approved |
| **Owner** | Security |

## 1. Assets

A1 Capture files under analysis (sensitive: credentials, tokens, internal hosts)
A2 Derived artifacts (facts, reports, dissectors: inherit A1)
A3 Integrity of the inference verdicts (what CI gates on)
A4 Analyst machine integrity

## 2. Trust boundaries

```
[analyst/CI] --(pcap files)--> [parsers]        untrusted input boundary
[core] --(bounded field context)--> [LLM]       model boundary
[parsers/anything] --(reports)--> [human]       presentation boundary
```

## 3. Threats and mitigations

### 3.1 Malicious capture -> parser (tampering/EoP)

Pathological blocks, huge packets, decompression-style payloads.

| Control | Notes |
|---|---|
| Pure-Python parsers (ADR-0002) | no native code in the parse path |
| Hard caps: packets, total bytes, packet size | truncation with notes, never a crash |
| Per-packet exception isolation | one bad block never kills a session |
| No extraction side effects | readers never write outside the session dir |

Residual risk: accepted; documented.

### 3.2 LLM prompt injection from packet content (tampering of A3)

Strings inside payloads ("ignore previous instructions") reach the model.

| Control | Notes |
|---|---|
| Facts-first architecture (ADR-0003) | the LLM cannot influence framing, boundaries, or types at all |
| Hex framing + instructions | packet bytes are framed as data |
| Output validation | name grammar, per-cluster dedup, evidence citation; failures dropped |
| CI consumes only deterministic sections | `validate`/facts gate on inference, never on LLM prose |

### 3.3 Hallucinated field names reaching humans

Validation drops unparseable, uncited, grammar-violating, or duplicate names; dropped
counts are published in facts; report marks model text as model output.

### 3.4 Supply chain

Pinned dependencies (uv.lock), Actions pinned by SHA, SBOM at release (v1.0 gate).

### 3.5 Confidentiality

Zero network egress by default (ADR-0004); remote LLM only via explicit opt-in,
banner-marked. Sessions live in user cache with default umask; sharing is manual.

## 4. Out of scope

Live capture attacks, a fully compromised analyst host, statistical DoS (hostile
captures built to maximize low coverage degrade to honest low-coverage reports).

## 5. Review cadence

Full review each minor release; immediate review on any change to parser caps or the
LLM input contract.
