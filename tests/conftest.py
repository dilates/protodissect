"""Shared fixtures: isolated session cache per test."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Keep every test's session store inside a throwaway cache dir."""
    cache = tmp_path / "protodissect-cache"
    monkeypatch.setenv("PROTODISSECT_CACHE", str(cache))
    yield
