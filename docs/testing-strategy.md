# Testing Strategy

| | |
|---|---|
| **Status** | Approved |
| **Owner** | QA / Engineering |

## 1. Principles

1. The deterministic core gets exact assertions; the LLM layer gets rubric evals.
2. Ground truth comes from synthetic protocols we generate ourselves (source + writer
   in-repo): we know the fields because we designed the protocol.
3. Reproducibility is a test: re-running a session produces byte-identical facts.json.

## 2. Test pyramid

| Layer | What | Gate |
|---|---|---|
| Unit | framing rules, field inference, clustering, coverage math, Lua generation | every PR, mypy strict + >90% coverage on core |
| Golden | fixed synthetic captures -> expected facts fragments | every PR |
| Corpus | end-to-end: generate protocol captures -> run pipeline -> assert expectations | every PR |
| Eval (LLM) | naming factuality vs ground-truth field names | nightly + release |
| Wireshark smoke | tshark loads generated Lua and decodes the demo capture | v0.2 job |
| Reproducibility | byte-identical facts.json on re-runs | every release |

## 3. Corpus

Synthetic protocol cases generated in-repo (no committed capture blobs):

| case | protocol shape | expected |
|---|---|---|
| `smartplug-demo` | magic + type + seq + length + TLV payload (TCP) | framing length_prefixed, fields exact |
| `fixed-telegram` | 16-byte fixed messages with constants + counter | framing fixed_size |
| `line-protocol` | \r\n-delimited ASCII key=value lines | framing delimiter, string fields |
| `endian-mix` | LE and BE u32 fields mixed | endianness classified |

Adding a case = protocol writer + expectations in tests/corpus; captures are generated
at test time, never committed.

## 4. Matching gates (field inference)

Field boundary F1 and framing accuracy per case; a regression blocks merge. Thresholds
(simhash merge 0.9, magic threshold, length tolerance 90%) are corpus-calibrated;
changing one requires a corpus run attached to the PR.

## 5. Explainer eval harness

Nightly (marker `eval`): every field has a ground-truth name (we wrote the protocol).
Graded: factuality (zero fabricated fields tolerated, automatic), correctness (does
the LLM name match the ground truth?), coverage (share of fields named). Scores per
model published in docs/evals/.

## 6. Wireshark smoke (v0.2)

Headless `tshark -X lua_script:generated.lua -r demo.pcap` must decode the demo
capture with the protocol tree populated; run in CI when tshark is available (skipif).

## 7. Fuzzing

Targets: pcap/pcapng block parsers (fed mutated captures), framing walker (fed mutated
streams). Crash-only assertions, nightly, corpus minimization on failure.

## 8. CI matrix

- Linux x (3.11, 3.12, 3.13): full suite
- Docs job: markdownlint + link check
- Reproducibility job: demo run twice, byte-compare facts.json

## 9. Release gate checklist (automated)

All layers green on the release commit, reproducibility job passed, eval scores >=
targets, CHANGELOG updated, schema diff reviewed if facts.json changed.
