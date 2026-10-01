# Glossary

| Term | Meaning |
|---|---|
| **Flow** | A bidirectional 5-tuple (proto, two endpoints) with reassembled byte streams |
| **Message** | One protocol message: a UDP datagram or a framing-split TCP chunk |
| **Message type (cluster)** | Group of messages whose fields align (same layout) |
| **Framing** | How message boundaries are found: length_prefixed, fixed_size, delimiter, unknown |
| **Magic field** | Constant bytes at a fixed offset identifying the protocol or message type |
| **Length field** | An integer field whose value matches message or remaining-payload length |
| **Coverage** | Share of captured bytes explained by inferred fields (round-trip) |
| **Variable tail** | Bytes after the last stable field, varying per message |
| **Facts (facts.json)** | The deterministic inference output; source of truth |
| **Naming** | LLM-proposed field names, evidence-checked and drop-on-fail |
| **Evidence** | Offsets, value samples, and the rule that fired, backing a field or name |
| **Session** | One analysis run: store dir + DB + blob references |
| **Blob store** | Content-addressed (sha256) artifact storage |
| **Dissector** | Wireshark Lua decoder generated from facts |
| **Simhash merge** | Clustering rule merging length buckets with similar byte histograms |
| **Eval** | Rubric-scored measurement of naming factuality/correctness vs ground truth |