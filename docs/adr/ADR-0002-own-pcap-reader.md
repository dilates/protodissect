# ADR-0002: Own PCAP/PCAPNG reader with hard caps

**Status:** Accepted · 2026-09-30

## Context

Captures are untrusted files. Scapy and dpkt are the ecosystem defaults, but they parse
generously, pull large dependency trees, and do not expose the resource-cap posture we
need (THREAT_MODEL 3.1). Decompression-style bombs and pathological blocks are real.

## Decision

Implement a minimal reader for classic PCAP (both endiannesses, micro and nanosecond)
and PCAPNG (SHB/IDB/EPB/SPB; other blocks skipped with notes), with hard caps: packet
count, total bytes, per-packet size. Pure Python.

## Consequences

- We support the 95% case (Ethernet + raw IP + SLL, TCP/UDP) and say no to the rest
  with precise errors; the supported set is tested.
- Parser bugs remain possible, but pure Python bounds their blast radius to exceptions,
  which the reader converts to per-packet skip notes.
- Future formats (USB linktype 220) extend the same reader behind the same caps.
