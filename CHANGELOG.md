# Changelog

All notable changes to protodissect are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is SemVer.
facts.json schema has its own version field and compatibility policy.

## [Unreleased]

## [0.1.0] - 2026-09-30

### Added
- PCAP and PCAPNG readers (both endiannesses, micro + nanosecond), resource caps,
  Ethernet / raw IP / Linux SLL link layers, IPv4 + IPv6, TCP + UDP.
- Flow sessionization with client/server direction and naive TCP reassembly
  (retransmission dedup, gap notes).
- Deterministic structure inference: message clustering (length buckets + simhash),
  framing detection (length-prefixed, fixed-size, delimiter), constant/magic fields,
  length fields, u8/u16/u32/u64 LE/BE, epoch timestamps, sequence counters, strings,
  opaque runs.
- Lua dissector generation (TCP + UDP, port registration, framing-aware tree building).
- PROTOCOL.md specification generation; single-file offline report.html.
- Round-trip byte-coverage validation with a `validate --min-coverage` CI gate.
- Optional local LLM field naming (Ollama default, OpenAI-compatible opt-in),
  evidence-checked with drop-on-fail and provenance in facts.
- Byte-reproducible facts.json (schema v1); SQLite session store + blob cache.
- `demo` command with a bundled synthetic smartplug protocol capture.
- Full documentation: product spec, architecture, pipeline spec, ADRs, threat model,
  testing strategy, runbook, release process.
