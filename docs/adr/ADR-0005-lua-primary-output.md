# ADR-0005: Lua dissector as the primary output

**Status:** Accepted · 2026-09-30

## Context

The deliverable must be immediately useful in the analyst's workflow. Candidates:
Wireshark Lua dissector, Kaitai Struct spec, C source for a custom decoder, JSON only.

## Decision

Wireshark Lua is the primary output (v1). PROTOCOL.md ships alongside. Kaitai Struct
output is a v0.2 roadmap item via the renderer extension point.

## Consequences

- Wireshark is where network RE happens; a dissector is instantly useful (filtering,
  coloring, statistics, exports) with zero build steps.
- Lua output is constrained to what Wireshark supports (desegment_len, DissectorTable,
  ProtoField types); exotic framings degrade to comments, never broken files.
- Generated files are deterministic and carry generation metadata (capture sha, facts
  sha) so analysts can trace a dissector back to its evidence.
