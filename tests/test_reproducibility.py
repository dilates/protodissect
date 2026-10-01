"""facts.json byte-reproducibility gate (ARCHITECTURE principle 3)."""

from __future__ import annotations

from pathlib import Path

from proto_dissect.demo import write_demo_pcap
from proto_dissect.pipeline import InferOptions, infer_capture


def test_facts_byte_identical(tmp_path: Path) -> None:
    capture = tmp_path / "c.pcap"
    write_demo_pcap(capture)
    a = infer_capture(
        capture, InferOptions(out_dir=tmp_path / "a", tcp_port=9999, deterministic=True)
    )
    b = infer_capture(
        capture, InferOptions(out_dir=tmp_path / "b", tcp_port=9999, deterministic=True)
    )
    assert a.facts.to_json() == b.facts.to_json()
    written = (tmp_path / "a" / "facts.json").read_bytes()
    assert written == b.decode() if isinstance(b, bytes) else written == b.facts.to_json().encode()


def test_deterministic_session_id_stable(tmp_path: Path) -> None:
    capture = tmp_path / "c.pcap"
    write_demo_pcap(capture)
    a = infer_capture(
        capture, InferOptions(out_dir=tmp_path / "a", tcp_port=9999, deterministic=True)
    )
    b = infer_capture(
        capture, InferOptions(out_dir=tmp_path / "b", tcp_port=9999, deterministic=True)
    )
    assert a.facts.session.id == b.facts.session.id
    assert a.facts.session.created_utc is None


def test_nondeterministic_mode_has_uuid_and_time(tmp_path: Path) -> None:
    capture = tmp_path / "c.pcap"
    write_demo_pcap(capture)
    result = infer_capture(
        capture, InferOptions(out_dir=tmp_path / "a", tcp_port=9999, deterministic=False)
    )
    assert result.facts.session.created_utc is not None
    assert len(result.facts.session.id) == 16
