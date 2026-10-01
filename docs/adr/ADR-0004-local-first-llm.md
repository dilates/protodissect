# ADR-0004: Local-first LLM providers

**Status:** Accepted · 2026-09-30

## Context

Captures contain sensitive traffic: credentials, tokens, internal hostnames. Sending
them to a cloud LLM is a non-starter for a large part of the RE audience.

## Decision

Default provider: local Ollama (OpenAI-compatible). llama.cpp, vLLM, and any
OpenAI-compatible endpoint work via explicit `--llm-url`. Zero default network egress;
offline mode is a supported configuration. Reports record provider, model, and prompt
version, and banner-mark remote usage.

## Consequences

- Naming quality depends on local hardware; docs publish minimum hardware and the tool
  degrades gracefully to `--llm off`.
- No telemetry, no API keys in core.

## Alternatives

- Cloud-first with a privacy tier: betrays the core audience. Rejected.
