# Security Policy

## Reporting a vulnerability

protodissect is a security tool; vulnerabilities in it are treated seriously.

- **Report privately:** open a GitHub security advisory (preferred) or email the
  address on the repository profile.
- Do not open a public issue for suspected vulnerabilities.
- Include: affected version, reproduction (crafted captures welcome, treated
  confidentially), impact assessment.

## Scope

**In scope:** parser memory/resource issues (caps bypass), path traversal in any
extraction path, facts/policy tampering vectors, LLM guardrail bypass (injection
affecting inference), secrets/telemetry leaks, dependency/build integrity.

**Out of scope:** crashes caused by obviously malformed local files in trusted
environments (welcome as bugs, not security issues), Wireshark's own vulnerabilities.

## Handling

- Acknowledgment within 72h; triage within 7 days.
- Coordinated disclosure, 90-day default embargo.
- Credit unless anonymity is preferred; CVE requested for exploitable issues.

## Supported versions

| Version | Supported |
|---|---|
| latest 0.x minor | yes |
| older | best-effort |

## Hardening notes

Run `protodissect` with caps enabled on untrusted captures (default). See
docs/THREAT_MODEL.md.