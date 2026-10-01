"""protodissect CLI (typer). Exit codes: 0 ok, 1 gate failure, 2 usage/capture error."""

from __future__ import annotations

import json
import os
from importlib import metadata
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .explain import ExplainError, NamingConfig
from .log import setup_logging
from .models import FactsDoc

app = typer.Typer(
    name="protodissect",
    help="Turn packet captures into Wireshark dissectors, automatically.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True, style="red")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"protodissect {__version__}")
        raise typer.Exit(0)


@app.callback()
def _main(
    version: Annotated[
        bool | None, typer.Option("--version", callback=_version_callback, is_eager=True)
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "INFO",
    log_format: Annotated[str, typer.Option("--log-format")] = "json",
) -> None:
    os.environ["PROTODISSECT_LOG_FORMAT"] = log_format
    setup_logging(log_level)


PortOpt = Annotated[int | None, typer.Option("--port", help="protocol port (TCP+UDP)")]
NameOpt = Annotated[str, typer.Option("--protocol-name", help="protocol name for output files")]
OutOpt = Annotated[Path, typer.Option("--out", help="output directory")]
LlmOpt = Annotated[str, typer.Option("--llm", help="off | ollama | openai-compat")]
LlmModelOpt = Annotated[str, typer.Option("--llm-model")]
LlmUrlOpt = Annotated[str | None, typer.Option("--llm-url")]
DetOpt = Annotated[
    bool, typer.Option("--deterministic", help="no timestamps, content-derived session id")
]


def _naming(llm: str, model: str, url: str | None) -> NamingConfig:
    if llm.lower() not in ("off", "ollama", "openai-compat"):
        raise typer.BadParameter("--llm must be off | ollama | openai-compat")
    config = NamingConfig(provider=llm.lower(), url=url, model=model)
    if config.provider != "off":
        try:
            config.resolved_url()
        except ExplainError as exc:
            raise typer.BadParameter(str(exc)) from exc
    return config


@app.command()
def infer(
    capture: Annotated[Path, typer.Argument()],
    port: PortOpt = None,
    protocol_name: NameOpt = "unknown",
    out: OutOpt = Path("out"),
    llm: LlmOpt = "off",
    llm_model: LlmModelOpt = "llama3.1:8b",
    llm_url: LlmUrlOpt = None,
    deterministic: DetOpt = False,
    min_coverage: Annotated[float, typer.Option("--min-coverage")] = 0.8,
) -> None:
    """Infer a protocol structure from a capture and generate a Wireshark dissector."""
    from .pipeline import InferOptions, infer_capture

    opts = InferOptions(
        protocol_name=protocol_name,
        out_dir=out,
        naming=_naming(llm, llm_model, llm_url),
        deterministic=deterministic,
        min_coverage=min_coverage,
    )
    if port is not None:
        opts.tcp_port = port
        opts.udp_port = port
    try:
        result = infer_capture(capture, opts)
    except Exception as exc:  # pipeline errors surface as exit 2 (with type noted)
        from .log import get_logger

        get_logger("proto_dissect.cli").debug(str(exc))
        err_console.print(f"error: {exc}")
        raise typer.Exit(2) from exc

    _print_summary(result.facts)
    for name, path in result.artifacts.items():
        console.print(f"  [green]wrote[/green] {name} -> {path}")
    validation = result.facts.validation
    if validation.parse_ratio < min_coverage:
        err_console.print(
            f"coverage gate failed: {validation.parse_ratio:.1%} < {min_coverage:.0%}"
        )
        raise typer.Exit(1)


def _print_summary(doc: FactsDoc) -> None:
    v = doc.validation
    types = doc.message_types
    framing = types[0].framing if types else "unknown"
    named = sum(1 for t in types for f in t.fields if f.description)
    table = Table(title="protodissect")
    table.add_column("metric")
    table.add_column("value")
    table.add_row("message types", str(len(types)))
    table.add_row("framing", framing)
    table.add_row("messages parsed", f"{v.messages_parsed}/{v.messages_total}")
    table.add_row("classified bytes", f"{v.classified_ratio:.1%}")
    table.add_row("LLM-named fields", str(named) if doc.naming else "off")
    console.print(table)


@app.command()
def demo(
    out: OutOpt = Path("out"),
    llm: LlmOpt = "off",
    llm_model: LlmModelOpt = "llama3.1:8b",
    deterministic: DetOpt = False,
) -> None:
    """Run the full pipeline on a bundled synthetic smartplug capture."""
    from .demo import write_demo_pcap
    from .pipeline import InferOptions, infer_capture

    capture = out / "smartplug-capture.pcap"
    out.mkdir(parents=True, exist_ok=True)
    write_demo_pcap(capture)
    opts = InferOptions(
        protocol_name="smartplug",
        out_dir=out,
        tcp_port=9999,
        udp_port=9999,
        naming=_naming(llm, llm_model, None),
        deterministic=deterministic,
        min_coverage=0.8,
    )
    result = infer_capture(capture, opts)
    _print_summary(result.facts)
    for name, path in result.artifacts.items():
        console.print(f"  [green]wrote[/green] {name} -> {path}")


@app.command()
def validate(
    facts_path: Annotated[Path, typer.Argument()],
    min_coverage: Annotated[float, typer.Option("--min-coverage")] = 0.8,
) -> None:
    """Re-check the coverage gate from a facts.json file (CI-friendly)."""
    data = json.loads(facts_path.read_text())
    v = data.get("validation", {})
    ratio = float(v.get("parse_ratio", 0.0))
    classified = float(v.get("classified_ratio", 0.0))
    console.print(f"parse ratio: {ratio:.1%} · classified bytes: {classified:.1%}")
    if ratio < min_coverage:
        err_console.print(f"coverage gate failed: {ratio:.1%} < {min_coverage:.0%}")
        raise typer.Exit(1)
    console.print("[green]gate passed[/green]")


@app.command()
def doctor() -> None:
    """Verify the environment (python, optional Ollama)."""
    import sys
    import urllib.request

    table = Table(title="protodissect doctor")
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")
    table.add_row("python >= 3.11", "[green]ok[/green]", sys.version.split()[0])
    try:
        urllib.request.urlopen("http://127.0.0.1:11434/v1/models", timeout=2)
        table.add_row(
            "ollama (optional)",
            "[green]reachable[/green]",
            "field naming available with --llm ollama",
        )
    except OSError:
        table.add_row(
            "ollama (optional)",
            "[yellow]not reachable[/yellow]",
            "runs fine with --llm off (default)",
        )
    console.print(table)


sessions_app = typer.Typer(help="Session store operations", no_args_is_help=True)
app.add_typer(sessions_app, name="sessions")


@sessions_app.command("list")
def sessions_list() -> None:
    from .store import Store

    rows = Store().list_sessions()
    if not rows:
        console.print("no sessions")
        return
    table = Table()
    table.add_column("id")
    table.add_column("created")
    for row in rows:
        table.add_row(row["id"], row["created"])
    console.print(table)


@sessions_app.command("rm")
def sessions_rm(session_id: Annotated[str, typer.Argument()]) -> None:
    from .store import Store

    if Store().remove_session(session_id):
        console.print(f"removed {session_id}")
    else:
        err_console.print(f"session {session_id} not found")
        raise typer.Exit(2)


plugins_app = typer.Typer(help="Plugin discovery", no_args_is_help=True)
app.add_typer(plugins_app, name="plugins")


@plugins_app.command("list")
def plugins_list() -> None:
    found = 0
    for group in ("proto_dissect.classifiers", "proto_dissect.renderers", "proto_dissect.llm"):
        eps = metadata.entry_points(group=group)
        for ep in eps:
            found += 1
            console.print(f"{group:28s} {ep.name:20s} -> {ep.value}")
    if not found:
        console.print("no plugins installed (v0.2 extension points)")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
