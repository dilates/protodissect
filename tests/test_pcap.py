"""PCAP/PCAPNG reader tests."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from proto_dissect.models import Packet
from proto_dissect.pcap import CaptureError, ResourceCaps, read_capture, write_pcap


def test_pcap_roundtrip_le(tmp_path: Path) -> None:
    p = tmp_path / "c.pcap"
    p.write_bytes(
        write_pcap([Packet(ts=1.5, data=b"\x00" * 20), Packet(ts=2.5, data=b"\xff" * 20)])
    )
    cap = read_capture(p)
    assert cap.format == "pcap"
    assert cap.linktype == 1
    assert cap.endianness == "little"
    assert len(cap.packets) == 2
    assert cap.packets[0].data[:1] == b"\x00"


def test_pcap_be_and_nanosecond(tmp_path: Path) -> None:
    # on-disk BE magics: a1b2c3d4 (microsecond), a1b23c4d (nanosecond)
    for magic_bytes in (bytes.fromhex("a1b2c3d4"), bytes.fromhex("a1b23c4d")):
        p = tmp_path / f"c{magic_bytes.hex()}.pcap"
        data = magic_bytes  # magic as stored on disk (big-endian file)
        data += struct.pack(">HHiIII", 2, 4, 0, 0, 262144, 1)  # rest is big-endian
        data += struct.pack(">IIII", 1, 0, 4, 4) + b"\x00" * 4
        p.write_bytes(data)
        cap = read_capture(p)
        assert cap.endianness == "big"
        assert len(cap.packets) == 1


def test_pcapng_epb(tmp_path: Path) -> None:
    # SHB body: byte-order magic first, then major, minor, section length
    shb = (
        struct.pack("<II", 0x0A0D0D0A, 28)
        + struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        + struct.pack("<I", 28)
    )  # trailing block length
    idb = struct.pack("<IIHHI", 0x00000001, 28, 1, 0, 262144) + b"\x00" * 12
    epb_body = struct.pack("<IIIII", 0, 0, 0, 8, 8) + b"\x7f" * 8
    epb_total = 4 + 4 + 20 + 8 + 4  # type + length + epb header + data + trailer
    epb = struct.pack("<II", 0x00000006, epb_total) + epb_body + struct.pack("<I", epb_total)
    p = tmp_path / "c.pcapng"
    p.write_bytes(shb + idb + epb)
    cap = read_capture(p)
    assert cap.format == "pcapng"
    assert cap.linktype == 1
    assert len(cap.packets) == 1
    assert cap.packets[0].data == b"\x7f" * 8


def test_caps_truncate_with_note(tmp_path: Path) -> None:
    p = tmp_path / "c.pcap"
    p.write_bytes(write_pcap([Packet(ts=1.0, data=b"\x00" * 100)] * 10))
    cap = read_capture(p, ResourceCaps(max_packets=3, max_bytes=1 << 30))
    assert len(cap.packets) == 3
    assert any("truncated" in n for n in cap.notes)


def test_bad_magic_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.pcap"
    p.write_bytes(b"NOT A PCAP FILE AT ALL........")
    with pytest.raises(CaptureError):
        read_capture(p)


def test_zero_packets_raises(tmp_path: Path) -> None:
    p = tmp_path / "empty.pcap"
    p.write_bytes(write_pcap([]))
    with pytest.raises(CaptureError, match="zero packets"):
        read_capture(p)


def test_deterministic_reads(tmp_path: Path) -> None:
    p = tmp_path / "c.pcap"
    packets = [Packet(ts=1.0 + i * 0.1, data=bytes([i]) * 32) for i in range(5)]
    p.write_bytes(write_pcap(packets))
    a, b = read_capture(p), read_capture(p)
    assert [(x.ts, x.data) for x in a.packets] == [(x.ts, x.data) for x in b.packets]
