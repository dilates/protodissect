# Roadmap

Milestones map to small releases; dates are targets.

## v0.1 - "demo to real capture" (M1-M4)

The thinnest end-to-end slice: synthetic demo in, real captures working, Lua out.

### M1 - pcap + flows
- [x] CLI skeleton, structured logging, `--version`
- [x] Classic PCAP reader (both endiannesses, micro + nanosecond) and PCAPNG reader
      (SHB/IDB/EPB/SPB), resource caps
- [x] Ethernet / raw IP / Linux SLL link layers, IPv4 + IPv6, TCP + UDP
- [x] Flow sessionization, client/server direction, naive TCP reassembly with
      retransmission dedup
- [x] SQLite session store + content-addressed blob cache
- Exit criteria: bundled demo capture round-trips, 10k-packet capture under 5s

### M2 - inference (deterministic core)
- [x] Message clustering per direction (length buckets + simhash merge)
- [x] Framing detection: length-prefixed, fixed-size, delimiter, mixed-with-note
- [x] Field inference: constants/magic, length fields, u8/u16/u32/u64 LE/BE,
      timestamps, sequence counters, strings, opaque runs
- [x] facts.json schema v1 (frozen), byte-reproducible
- Exit criteria: demo capture fields reproduced exactly, corpus case framing 100%

### M3 - outputs
- [x] Lua dissector generation (TCP + UDP, framing-aware, port registration)
- [x] PROTOCOL.md specification generation
- [x] report.html single-file offline report
- [x] Validation: round-trip byte coverage + `validate --min-coverage` gate
- [x] `demo` command with bundled synthetic smartplug protocol capture
- Release: v0.1.0

### M4 - naming + polish
- [x] LLM provider abstraction (Ollama default, OpenAI-compat opt-in, offline no-op)
- [x] Evidence-checked field naming, drop-on-fail, provenance in facts
- [x] Packaging: PyPI, GHCR image, docs
- Release: v0.1.0 final

## v0.2 - "breadth"

- [ ] USB captures (linktype 220) for device protocol RE
- [ ] TLS detection with per-flow skip notes (already partly in), keylog-file input
- [ ] Kaitai Struct output as a second target format
- [ ] Corpus expansion: 5+ real open protocol cases (MQTT subset, DNS-like, custom)
- [ ] Wireshark smoke CI job (load generated dissectors in a headless tshark)
- [ ] Multi-flow correlation (shared session ids across flows)

## v0.3 - "platform"

- [ ] Capture diffing: layout diff between two captures (fw-diff style facts diff)
- [ ] Ghidra linkage: pair inferred fields with firmware-side parsing functions
- [ ] Plugin API v1 (custom classifiers, custom output formats)
- [ ] MCP server surface for agent integration

## Beyond

- Streaming/live-capture mode (via tshark -w pipe)
- Encrypted-protocol structure (lengths only) with explicit "encrypted" framing
- Community protocol corpus with contribution workflow

## Metrics we keep honest

Corpus framing accuracy · field boundary F1 · round-trip coverage · reproducibility
rate · eval factuality (zero fabricated fields tolerated).
