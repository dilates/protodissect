# Pipeline Specification

| | |
|---|---|
| **Status** | M1-M4 normative; section 4 (inference) is the contract |
| **Owner** | Engineering |
| **Last updated** | 2026-09-30 |

## 1. Capture reading (pcap.py)

Formats: classic PCAP (magic `a1b2c3d4`, `d4c3b2a1`, nanosecond variants `a1b23c4d`,
`4d3cb2a1`) and PCAPNG (SHB 0x0A0D0D0A with byte-order magic, IDB, EPB, SPB; other
blocks skipped with a count note). Link types: Ethernet (1), raw IPv4/IPv6 (101/12),
Linux SLL (113). Unknown link types: honest error.

Resource caps (normative): max packets 1M, max captured bytes 1 GB, max packet size
snaplen, total decode time budget. Exceeding a cap truncates with a note, never a crash.

## 2. Flow sessionization (flows.py)

1. Decode link layer, then IPv4/IPv6, then TCP/UDP payloads.
2. Flow key: canonical bidirectional 5-tuple (min/max ordering of endpoints).
3. Direction: the endpoint with the lower port number is the server (well-known ports
   win ties). Direction is a heuristic used for clustering and naming; the dissector
   works in both directions.
4. TCP reassembly (naive, documented): per-flow, sort segments by seq (wrapping-aware),
   dedup exact overlaps, keep gaps as notes. Segments spanning segment boundaries are
   concatenated per direction. No OS-level semantics, no out-of-order waiting: capture
   order + seq order resolve everything.
5. Message splitting happens later (framing detection), so a "message" here is the
   reassembled directional byte stream. UDP datagrams are messages directly.

## 3. Message clustering (cluster.py)

Goal: group reassembled directional payloads into message types before field inference,
because fields only align within a type.

1. UDP: each datagram is a message.
2. TCP: framing is detected first (section 4.1) to split the stream into messages.
   Chicken-and-egg: framing detection runs on candidate splits, then clusters validate
   the split (a good split makes fields align).
3. Cluster by exact length, then merge buckets whose member messages have simhash
   similarity >= 0.9 over byte-value histograms (handles a varying counter/flags byte
   without splitting types).
4. Clusters under 3 messages are flagged `sparse`; inference still runs, confidence
   notes added.
5. Clusters are deterministic: stable sort by (dir, length, first-bytes).

## 4. Structure inference (structure.py + classify.py, normative)

Within one cluster of N messages, for each byte offset 0..min_len-1:

1. **Constants (magic):** all N values identical and the cluster has >= 3 messages:
   field type `magic` (or `constant` if not at offset 0..3).
2. **Integer scans:** for each width w in (1, 2, 4, 8) and endianness e in (little, big):
   interpret offset..offset+w as an integer per message, then classify:
   - `length`: value == remaining bytes after the field (>= 90% of messages), or value
     == total message length (>= 90%). `covers` records which.
   - `timestamp`: epoch-seconds range (2001-09-09 .. 2286), or milliseconds range
     (>= 1e12 and < 4e12), unix only.
   - `sequence`: strictly increasing (or decreasing) across capture-ordered messages
     in >= 95% of steps, distinct values >= 2.
   - `counter` (low-confidence): distinct values >= 2 and entropy in the medium band.
3. **Strings:** printable run (0x20..0x7E) of length >= 4 at this offset across >= 90%
   of messages: field type `string` with the observed max length.
4. **Opaque/data:** everything else; adjacent data fields merge.
5. **Variable tail:** offsets beyond the last stable field to the end of each message:
   `variable_tail` with average coverage.
6. **Field merge:** adjacent fields of the same type merge; magic fields never merge
   with anything.

Ordering rule: constants and length fields win over integers at overlapping offsets;
earlier offsets win ties; the field list is deterministic by construction.

### 4.1 Framing detection

Evaluated on the TCP stream (before clustering) and validated per cluster:

- `length_prefixed`: a length field whose value matches the remaining message bytes for
  >= 90% of candidate splits. Candidate messages are recovered by walking: read header,
  read value bytes, repeat. A walk that consumes the stream cleanly with >= 3 messages
  and < 5% slack wins.
- `fixed_size`: all messages identical length, >= 3 messages, and the length is not a
  common framing artifact.
- `delimiter`: a byte sequence (\r\n, \n, \x00) terminates >= 95% of messages and never
  appears inside payloads (escaped-delimiter protocols are noted, not split).
- `unknown`: none of the above; messages fall back to per-packet (UDP) or
  per-reassembly-chunk (TCP) with an honest note.

### 4.2 Coverage

Per cluster: bytes explained by fields / total bytes, averaged over messages. Per
capture: message-weighted mean. The `validate` gate compares against `--min-coverage`
(default 0.8) and exits 0/1 with a breakdown. Unexplained bytes are listed as
`variable_tail` or `gaps`, never hidden.

## 5. LLM field naming (explain.py)

Input per field: cluster hex samples (up to 8 aligned messages), the field's type,
offset, endianness, value samples, and the fields around it. Ask the model for a
short snake_case name plus a one-sentence description, citing the field id.

Validation (normative): name matches `[a-z][a-z0-9_]{2,40}`; no duplicate names within
a cluster; the response parses as JSON; every name cites the field id it belongs to.
Any failure drops that name (the deterministic type-based name like `u16_at_6` stays).
Provenance (model, prompt version, dropped counts) goes into facts.

The LLM never changes the layout. It can only name what inference proved.

## 6. Dissector generation (dissector.py)

Output: one Lua file per session, protocol name from `--protocol-name` (sanitized).

- `Proto` + `ProtoField` declarations: uint8/16/32/64 (base.DEC or base.HEX for
  magic), string, bytes, bool.
- TCP: `DissectorTable.get("tcp.port"):add(port, p)`; UDP: same on udp.port.
- Framing:
  - length_prefixed: dissector reads the length field, sets
    `pinfo.desegment_len` when the segment is short ( Wireshark-native reassembly),
    then builds the tree per message.
  - fixed_size: reads fixed chunks.
  - delimiter: `Deserializer`-style scan for the terminator.
  - unknown: per-packet tree building with a comment noting the limitation.
- Message types: first-match dispatch by magic field value, falling back to length.
- Generated files carry a "generated by protodissect" header, the input capture sha,
  and the facts sha; regeneration is deterministic.

Lua correctness is tested in CI (v0.2: headless tshark loads each generated file and
decodes the demo capture; v0.1: structural Lua validation + syntax lint via luac when
available).

## 7. Specification generation (spec.py)

PROTOCOL.md: overview (transport, ports, framing), per-type field tables
(offset, size, type, endian, coverage, name, description), hex sample blocks, coverage
summary, and the evidence appendix (which rule fired per field, value samples).
Deterministic content; identical inputs produce identical markdown.

## 8. Facts schema (facts.json, schema v1)

Frozen at v0.1 release, additive-only. Top-level keys: `schema_version`, `tool`,
`capture`, `config`, `flows`, `message_types`, `validation`, `naming?`. See
ARCHITECTURE section 3.3 and the docstring in facts.py. Deterministic serialization:
sorted keys, fixed separators, trailing newline.
