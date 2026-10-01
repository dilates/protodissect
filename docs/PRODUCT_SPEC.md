# Product Specification - protodissect

| | |
|---|---|
| **Status** | Approved for M1-M4 |
| **Owner** | Product |
| **Last updated** | 2026-09-30 |

## 1. Problem statement

When you reverse engineer a network protocol (IoT device to cloud, game client to
server, industrial equipment, mobile app backends) the workflow today is: capture
traffic in Wireshark, stare at hex dumps, eyeball field boundaries, guess at length
fields, then hand-write a Lua dissector. Existing protocol analysis tools surface
entropy heatmaps or byte statistics but stop there. The gap between "I have a capture"
and "I have a dissector" is entire days of manual work.

protodissect closes that gap: captures go in, a working Wireshark dissector plus a
protocol specification come out.

## 2. Users and personas

| Persona | What they do | Success looks like |
|---|---|---|
| **Network RE analyst** | Reverse an undocumented IoT/game protocol from captures | A working dissector in minutes, not days |
| **Security researcher** | Document a protocol for a report or a CVE write-up | Clean PROTOCOL.md with evidence tables |
| **Firmware tester (QA)** | Detect protocol regressions between device firmware versions | CI gate on deterministic facts.json |
| **CTF player** | Understand a custom challenge protocol fast | Field layout + framing in one command |

## 3. Scope

### v1 includes

- CLI tool: `protodissect {infer, demo, validate, report, doctor}`
- Inputs: classic PCAP and PCAPNG (both endiannesses, micro and nanosecond),
  Ethernet, raw IPv4/IPv6, and Linux SLL link types
- TCP (with naive reassembly) and UDP flow sessionization
- Deterministic structure inference: framing detection (length-prefixed, fixed-size,
  delimiter), constant/magic detection, length fields, timestamps, sequence numbers,
  strings, opaque data
- Message type clustering per direction
- Lua dissector generation registered on the chosen port
- PROTOCOL.md specification generation
- Byte-coverage validation with a CI-friendly gate
- Optional local LLM field naming (Ollama default, OpenAI-compatible opt-in),
  evidence-checked and drop-on-fail
- Byte-reproducible facts.json (schema v1)

### v1 explicitly excludes (non-goals)

- **No decryption.** TLS/QUIC traffic is detected and skipped with a note. Decrypting
  captures is the user's job (Wireshark keylog files are a possible future input).
- **No stateful protocol semantics.** We infer structure, not intent. "This u32 is a
  length" is a deterministic observation; "this is a command to unlock a door" is an
  LLM hypothesis, clearly labeled.
- **No live capture.** File-based analysis only; live capture is Wireshark/tcpdump's job.
- **No cloud processing.** Local LLM only unless the user opts into a remote endpoint.

## 4. User stories (v1 acceptance)

1. As a RE analyst, I run one command on a 500-message capture and get a Lua dissector
   that Wireshark loads without errors.
2. As a QA engineer, I diff facts.json between two captures of different firmware and
   the field layout changes are visible in one file.
3. As an offline user, I run everything with no network; the LLM section is absent and
   the report says so.
4. As a skeptic, I click any LLM-proposed field name and see the evidence (offsets,
   value samples) that the field exists.
5. As a CI engineer, `protodissect validate --min-coverage 0.8` exits 0/1 on coverage.

## 5. Success metrics

| Metric | Target (v1.0) | Tracked how |
|---|---|---|
| Framing detection correctness on corpus | 100% | corpus CI, per case |
| Field boundary F1 on corpus | >= 0.85 | corpus CI |
| Round-trip byte coverage on corpus | >= 0.90 | corpus CI |
| Generated Lua loads in Wireshark | 100% of corpus cases | wireshark smoke job |
| Deterministic reproducibility | byte-identical facts.json re-runs | CI job |
| LLM naming factuality | zero fabricated fields tolerated | nightly eval |

## 6. Competitive positioning

PolySuite and bincover-style tools visualize entropy; Wireshark's Decode-As needs a
spec; hand-written dissectors need the spec too. The wedge is **capture to executable
dissector with a deterministic, auditable inference chain**. The LLM naming layer is a
convenience, not the product: the inference works with `--llm off`.

## 7. Distribution

Free, open source (BSD-3-Clause). PyPI + GHCR. No paid tier.

## 8. Open questions

- Q1: Kaitai Struct output as a second target format: v0.2 candidate.
- Q2: USB captures (linktype 220) for device RE: v0.2 candidate.
- Q3: Cross-capture field alignment (diff two captures' layouts, fw-diff style): v0.3.

## 9. Decision log (product level)

| Date | Decision | Rationale |
|---|---|---|
| 2026-09-30 | Lua dissector is the primary output | Wireshark ubiquity beats exotic formats |
| 2026-09-30 | Deterministic inference, LLM names only | credibility with the RE audience |
| 2026-09-30 | Local-first LLM, offline default | captures are sensitive |
