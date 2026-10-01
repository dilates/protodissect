"""CLI tests (typer runner)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from proto_dissect import __version__
from proto_dissect.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_demo_command(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(app, ["demo", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "facts.json").exists()
    assert (out / "smartplug.lua").exists()
    assert (out / "PROTOCOL.md").exists()
    assert (out / "report.html").exists()
    assert "message types" in result.output


def test_demo_reproducible(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    assert runner.invoke(app, ["demo", "--out", str(a), "--deterministic"]).exit_code == 0
    assert runner.invoke(app, ["demo", "--out", str(b), "--deterministic"]).exit_code == 0
    assert (a / "facts.json").read_bytes() == (b / "facts.json").read_bytes()


def test_demo_with_bad_llm_flag(tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", "--out", str(tmp_path), "--llm", "bogus"])
    assert result.exit_code != 0


def test_validate_gate(tmp_path: Path) -> None:
    out = tmp_path / "out"
    runner.invoke(app, ["demo", "--out", str(out)])
    facts = out / "facts.json"
    ok = runner.invoke(app, ["validate", str(facts), "--min-coverage", "0.5"])
    assert ok.exit_code == 0
    fail = runner.invoke(app, ["validate", str(facts), "--min-coverage", "1.1"])
    assert fail.exit_code == 1


def test_infer_missing_capture(tmp_path: Path) -> None:
    result = runner.invoke(app, ["infer", str(tmp_path / "nope.pcap")])
    assert result.exit_code == 2


def test_doctor() -> None:
    result = runner.invoke(app, ["doctor"])
    assert "protodissect doctor" in result.output


def test_sessions_lifecycle(tmp_path: Path) -> None:
    from proto_dissect.store import Store

    assert runner.invoke(app, ["demo", "--out", str(tmp_path / "o")]).exit_code == 0
    rows = Store().list_sessions()
    assert rows
    sid = rows[0]["id"]
    assert runner.invoke(app, ["sessions", "rm", sid]).exit_code == 0
    assert Store().list_sessions() == []


def test_plugins_list_empty() -> None:
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0
    assert "no plugins" in result.output
