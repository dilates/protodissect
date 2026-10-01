# Getting Started - walkthrough

This guide walks a full protodissect session on the bundled synthetic smartplug
protocol, then shows the same flow on a real capture. (Commands match the shipped CLI;
concepts do not change between versions.)

## 1. Environment check

```bash
protodissect doctor
# python 3.12 ok · ollama reachable (optional, for field naming)
```

## 2. Try the demo (no capture needed)

```bash
protodissect demo --out out/
```

The demo generates a synthetic smartplug protocol capture (magic `PL`, message type,
sequence, length field, TLV payload, checksum) and runs the entire pipeline on it:
clustering, framing detection, field inference, LLM naming (if Ollama is running),
dissector generation, and the coverage gate. Look at what it finds: the magic field at
offset 0, the length field that explains the framing, the sequence counter.

## 3. Real capture

```bash
# capture traffic first (Wireshark, tcpdump, or your own tooling), then:
protodissect infer device-capture.pcap --port 9999 --protocol-name smartplug
```

What happens, in order (pipeline-spec sections 1-6):

1. **read** - PCAP/PCAPNG parsed with caps; link type detected (Ethernet, raw IP, SLL).
2. **flows** - TCP/UDP sessionized; client/server direction resolved; reassembled.
3. **cluster** - message types grouped per direction.
4. **infer** - framing detected (length-prefixed, fixed-size, or delimiter); magic,
   length fields, timestamps, sequence counters, strings, and opaque runs classified.
5. **name** - optional LLM pass names the fields with evidence; unvalidated names drop.
6. **validate** - byte coverage computed; `--min-coverage` gate enforced.

## 4. Load it in Wireshark

Copy the generated `smartplug.lua` into your plugins folder (Help > About Wireshark >
Folders on any platform) and restart Wireshark. The protocol appears; filter with
`smartplug`.

## 5. Gate it in CI

```bash
protodissect validate out/facts.json --min-coverage 0.9
echo $?
# 0 or 1, with a per-message-type breakdown
```

Because facts.json is byte-reproducible, diffing two captures of different firmware
versions shows the field layout changes in one file.

## 6. Where to go next

- Inference internals: design/pipeline-spec.md
- Anatomy of facts.json: docs/ARCHITECTURE.md section 3
- Hardening for hostile captures: THREAT_MODEL.md