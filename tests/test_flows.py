"""Flow sessionization + reassembly tests."""

from __future__ import annotations

import struct

from proto_dissect.flows import (
    FlowKey,
    _reassemble_tcp,
    decode_packets,
    sessionize,
)
from proto_dissect.models import Packet


def _eth_tcp(src: str, dst: str, sport: int, dport: int, seq: int, payload: bytes) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 8192, 0, 0)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp + payload),
        0,
        0x4000,
        64,
        6,
        0,
        bytes(int(x) for x in src.split(".")),
        bytes(int(x) for x in dst.split(".")),
    )
    return (
        b"\x02\x00\x00\x00\x00\x01"
        + b"\x02\x00\x00\x00\x00\x02"
        + struct.pack(">H", 0x0800)
        + ip
        + tcp
        + payload
    )


def _eth_udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp + payload),
        0,
        0x4000,
        64,
        17,
        0,
        bytes(int(x) for x in src.split(".")),
        bytes(int(x) for x in dst.split(".")),
    )
    return (
        b"\x02\x00\x00\x00\x00\x01"
        + b"\x02\x00\x00\x00\x00\x02"
        + struct.pack(">H", 0x0800)
        + ip
        + udp
        + payload
    )


def test_flowkey_canonical() -> None:
    a = FlowKey("tcp", "10.0.0.5", 51000, "10.0.0.9", 9999)
    b = FlowKey("tcp", "10.0.0.9", 9999, "10.0.0.5", 51000)
    assert a == b and hash(a) == hash(b)


def test_tcp_reassembly_dedups_retransmissions() -> None:
    p1 = Packet(ts=1.0, data=_eth_tcp("10.0.0.5", "10.0.0.9", 51000, 9999, 1000, b"AAAA"))
    p2 = Packet(ts=1.1, data=_eth_tcp("10.0.0.5", "10.0.0.9", 51000, 9999, 1000, b"AAAA"))
    p3 = Packet(ts=1.2, data=_eth_tcp("10.0.0.5", "10.0.0.9", 51000, 9999, 1004, b"BBBB"))
    decoded = decode_packets([p1, p2, p3], 1)
    flows = sessionize(decoded)
    assert len(flows) == 1
    msgs = flows[0].messages
    assert len(msgs) == 1  # one reassembled stream per direction
    assert msgs[0].data == b"AAAABBBB"  # retransmission deduped


def test_direction_resolution() -> None:
    p1 = Packet(ts=1.0, data=_eth_tcp("10.0.0.5", "10.0.0.9", 51000, 9999, 1000, b"A"))
    p2 = Packet(ts=1.1, data=_eth_tcp("10.0.0.9", "10.0.0.5", 9999, 51000, 5000, b"B"))
    decoded = decode_packets([p1, p2], 1)
    flows = sessionize(decoded)
    assert flows[0].client == "10.0.0.5:51000"
    assert flows[0].server == "10.0.0.9:9999"  # lower port is the server
    dirs = {m.dir for m in flows[0].messages}
    assert dirs == {"c2s", "s2c"}


def test_udp_datagrams_are_messages() -> None:
    udp_pkt = struct.pack(">HHHH", 51000, 9999, 8 + 4, 0) + b"ABCD"
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + 8 + 4,
        0,
        0x4000,
        64,
        17,
        0,
        bytes(int(x) for x in ["10", "0", "0", "5"]),
        bytes(int(x) for x in ["10", "0", "0", "9"]),
    )
    frame = (
        b"\x02\x00\x00\x00\x00\x01"
        + b"\x02\x00\x00\x00\x00\x02"
        + struct.pack(">H", 0x0800)
        + ip
        + udp_pkt
    )
    decoded = decode_packets([Packet(ts=1.0, data=frame)], 1)
    flows = sessionize(decoded)
    assert flows[0].proto == "udp"
    assert len(flows[0].messages) == 1
    assert flows[0].messages[0].data == b"ABCD"


def test_vlan_handled() -> None:
    tcp = struct.pack(">HHIIBBHHH", 51000, 9999, 1000, 0, 5 << 4, 0x18, 8192, 0, 0) + b"XY"
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + 20 + 2,
        0,
        0x4000,
        64,
        6,
        0,
        bytes(int(x) for x in ["10", "0", "0", "5"]),
        bytes(int(x) for x in ["10", "0", "0", "9"]),
    )
    frame = (
        b"\x02\x00\x00\x00\x00\x01"
        + b"\x02\x00\x00\x00\x00\x02"
        + struct.pack(">H", 0x8100)
        + struct.pack(">HH", 100, 0x0800)
        + ip
        + tcp
    )
    decoded = decode_packets([Packet(ts=1.0, data=frame)], 1)
    assert len(decoded) == 1


def test_reassemble_wrapping_seq() -> None:
    entries = [
        ("10.0.0.5", 51000, b"A" * 10, 1.0, 0xFFFFFFFF),
        ("10.0.0.5", 51000, b"B" * 10, 1.1, 9),
    ]
    msgs = _reassemble_tcp(entries, ("10.0.0.5", 51000), ("10.0.0.9", 9999), "f")
    data = b"".join(m.data for m in msgs)
    assert data == b"B" * 10 + b"A" * 10  # wrapped seq sorts after base
