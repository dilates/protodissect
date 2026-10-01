# ADR-0001: Python 3.11+ core

**Status:** Accepted · 2026-09-30

## Context

protodissect is heuristic-heavy (entropy scans, framing walks, clustering) with modest
compute. The team's prior tool (fw-diff) proved the stack.

## Decision

Python 3.11+ with typer/rich/PyYAML; zero parsing dependencies (own pcap reader).

## Consequences

- Fast iteration on heuristics; mypy strict + ruff + corpus tests hold quality.
- We accept that C-speed parsing is not free: the 10k-packet budget (ARCHITECTURE 7)
  is a tracked metric; a Rust pcap module is the escape hatch if profiling demands.
- scapy/dpkt rejected as dependencies: we only need link/IP/TCP/UDP decode, we want
  hard caps inside our own reader (untrusted input), and zero-dep installs help
  air-gapped analysts.
