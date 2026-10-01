# Release Process

| | |
|---|---|
| **Owner** | Release manager (rotating) |
| **Cadence** | minor: ~every 6-8 weeks, patch: as needed |

## 1. Versioning

SemVer. Pre-1.0: minor releases may break CLI/flags (documented under Changed/Breaking
in CHANGELOG). facts.json schema versions independently (additive-only within a major).

## 2. Release train

1. Freeze: cut `release/x.y`; fixes only.
2. Release gate: full CI green (lint, types, corpus, reproducibility, docs).
3. CHANGELOG drafted from conventional commits.
4. Artifacts: PyPI sdist+wheel (trusted publishing), GHCR image, versioned docs build.
5. Signing: SBOM attached; artifacts signed.
6. Announce: GitHub Release with highlights and corpus score table when inference
   changed.

## 3. Hotfixes

Branch from the tag, cherry-pick, re-run the gate subset, patch bump.

## 4. Support windows

Pre-1.0: latest minor only. Post-1.0: latest + previous for 90 days.
