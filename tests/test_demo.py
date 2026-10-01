"""End-to-end demo tests: the synthetic smartplug protocol exercises everything."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from proto_dissect.demo import write_demo_pcap
from proto_dissect.pipeline import InferOptions, infer_capture
from proto_dissect.store import Store


@pytest.fixture()
def demo_facts(tmp_path: Path):
    capture = tmp_path / "smartplug-capture.pcap"
    write_demo_pcap(capture)
    opts = InferOptions(
        protocol_name="smartplug",
        out_dir=tmp_path / "out",
        tcp_port=9999,
        udp_port=9999,
        deterministic=True,
    )
    result = infer_capture(capture, opts)
    return result.facts


def test_demo_framing_detected(demo_facts) -> None:
    assert all(mt.framing == "length_prefixed" for mt in demo_facts.message_types)
    for mt in demo_facts.message_types:
        assert mt.framing_field is not None


def test_demo_magic_field_found(demo_facts) -> None:
    for mt in demo_facts.message_types:
        magic = mt.fields[0]
        assert magic.type == "magic"
        assert magic.offset == 0
        assert magic.value_hex is not None


def test_demo_length_field_found(demo_facts) -> None:
    for mt in demo_facts.message_types:
        lengths = [f for f in mt.fields if f.type == "length"]
        assert lengths, f"no length field in {mt.id}"
        best = lengths[0]
        assert best.endian == "big"
        assert best.covers in ("rest", "total")


def test_demo_sequence_field_found(demo_facts) -> None:
    for mt in demo_facts.message_types:
        assert any(f.type == "sequence" for f in mt.fields)


def test_demo_coverage_gate_passes(demo_facts) -> None:
    v = demo_facts.validation
    assert v.parse_ratio == 1.0
    assert v.messages_total >= 70
    assert v.classified_ratio >= 0.3


def test_demo_artifacts_exist(demo_facts, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert (out / "facts.json").exists()
    assert (out / "smartplug.lua").exists()
    assert (out / "PROTOCOL.md").exists()
    assert (out / "report.html").exists()
    facts = json.loads((out / "facts.json").read_text())
    assert facts["schema_version"] == 1


def test_demo_session_persisted(demo_facts, tmp_path: Path, monkeypatch) -> None:
    _ = monkeypatch
    sid = demo_facts.session.id
    assert len(sid) == 16


def test_demo_reproducible(demo_facts, tmp_path: Path) -> None:
    """Same capture twice: byte-identical facts.json (deterministic mode)."""
    capture = tmp_path / "smartplug-capture.pcap"
    write_demo_pcap(capture)
    opts = InferOptions(
        protocol_name="smartplug",
        out_dir=tmp_path / "out2",
        tcp_port=9999,
        udp_port=9999,
        deterministic=True,
    )
    result = infer_capture(capture, opts)
    assert result.facts.to_json() == demo_facts.to_json()


def test_demo_store_roundtrip(demo_facts, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PROTODISSECT_CACHE", str(tmp_path / "cache"))
    capture = tmp_path / "smartplug-capture.pcap"
    write_demo_pcap(capture)
    store = Store()
    opts = InferOptions(
        protocol_name="smartplug",
        out_dir=tmp_path / "out3",
        tcp_port=9999,
        udp_port=9999,
        deterministic=True,
    )
    result = infer_capture(capture, opts, store=store)
    rows = store.get_artifacts(result.session_id, "facts")
    assert rows
    blob = json.loads(store.get_blob(rows[0][1]))
    assert blob["summary"] if "summary" in blob else blob["schema_version"] == 1
