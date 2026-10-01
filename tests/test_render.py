"""PROTOCOL.md + report.html renderer tests (single-file offline rule)."""

from __future__ import annotations

from pathlib import Path

import pytest

from proto_dissect.demo import write_demo_pcap
from proto_dissect.pipeline import InferOptions, infer_capture
from proto_dissect.report import generate_report_html
from proto_dissect.spec import generate_protocol_md


@pytest.fixture()
def doc(tmp_path: Path):
    capture = tmp_path / "c.pcap"
    write_demo_pcap(capture)
    result = infer_capture(
        capture,
        InferOptions(
            out_dir=tmp_path / "out", tcp_port=9999, deterministic=True, protocol_name="smartplug"
        ),
    )
    return result.facts


def test_protocol_md_structure(doc) -> None:
    md = generate_protocol_md(doc)
    assert md.startswith("# Smartplug protocol specification")
    assert "## Overview" in md
    assert "Transport: TCP" in md
    assert "Framing: length-prefixed" in md
    assert "| offset | size | type | name | coverage |" in md
    assert "## Validation" in md
    assert "## Evidence appendix" in md
    assert "re-parse cleanly" in md


def test_protocol_md_deterministic(doc) -> None:
    assert generate_protocol_md(doc) == generate_protocol_md(doc)


def test_report_html_offline(doc) -> None:
    page = generate_report_html(doc)
    assert "<!doctype html>" in page
    assert "http://" not in page and "https://" not in page  # ADR: no external URLs
    assert "T01" in page
    assert "coverage" in page.lower()


def test_report_html_escapes(doc) -> None:
    doc.message_types[0].notes.append('<script>alert("x")</script>')
    page = generate_report_html(doc)
    assert 'alert("x")' not in page
    assert "&lt;script&gt;" in page


def test_markdown_written_by_pipeline(doc, tmp_path: Path) -> None:
    md_path = Path(doc.session.config.get("_unused", tmp_path)) if False else None
    _ = md_path
    # the pipeline wrote it during the fixture run
    out = tmp_path / "out"
    assert (out / "PROTOCOL.md").exists()
    content = (out / "PROTOCOL.md").read_text()
    assert content.startswith("# Smartplug")
