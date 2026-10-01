"""Bundled demo: a synthetic smartplug protocol capture (docs/guides/getting-started.md).

The protocol is designed to exercise every inference rule:
- magic "PL" (constant detection)
- version byte (constant)
- message type byte (constant per cluster, discriminates types)
- sequence u16 big-endian (monotonic detection)
- length u16 big-endian == remaining bytes (length-prefixed framing detection)
- TLV payload with a variable-length settings string (variable tail)
- checksum u16 big-endian (constant-ish per message? no: varies -> data/counter)

The demo proves the whole pipeline works without a real capture.
"""

from __future__ import annotations

import struct
from pathlib import Path

from ..models import Packet

DEMO_PORT = 9999
DEMO_CLIENT_IP = "10.0.0.5"
DEMO_SERVER_IP = "10.0.0.9"

MAGIC = b"PL"
VERSION = 0x01
TYPE_STATUS = 0x01
TYPE_SET = 0x02
TYPE_ACK = 0x03

N_SET = 40
N_STATUS = 30
N_ACK = 15


def _checksum(data: bytes) -> int:
    return sum(data) & 0xFFFF


def _frame(mtype: int, seq: int, payload: bytes) -> bytes:
    header = MAGIC + bytes([VERSION, mtype]) + struct.pack(">HH", seq, len(payload) + 2)
    # ^ length covers everything after the length field, checksum included
    msg = header + payload
    return msg + struct.pack(">H", _checksum(msg))


def _set_message(seq: int, setting: str, value: int) -> bytes:
    value_bytes = setting.encode("ascii")
    payload = bytes([0x10, len(value_bytes)]) + value_bytes + struct.pack(">H", value)
    return _frame(TYPE_SET, seq, payload)


def _status_message(seq: int, uptime: int, power_w: int, temp: int) -> bytes:
    payload = struct.pack(">IHh", uptime, power_w, temp)
    return _frame(TYPE_STATUS, seq, payload)


def _ack_message(seq: int) -> bytes:
    return _frame(TYPE_ACK, seq, b"")


def build_messages() -> list[tuple[str, bytes]]:
    """(direction, message_bytes) in protocol order: the demo protocol story."""
    out: list[tuple[str, bytes]] = []
    c2s_seq = 1
    s2c_seq = 100
    for i in range(N_SET):
        settings = ["relay", "wifi_ssid", "led_brightness", "schedule", "overload_limit"]
        setting = settings[i % len(settings)]
        value = 40 + (i * 7) % 200
        out.append(("c2s", _set_message(c2s_seq, f"{setting}{i:03d}", value)))
        c2s_seq += 1
        if i % 3 == 0:
            out.append(("s2c", _ack_message(s2c_seq)))
            s2c_seq += 1
        if i % 2 == 0:
            out.append(
                (
                    "s2c",
                    _status_message(
                        s2c_seq, uptime=3600 + i * 60, power_w=40 + i % 25, temp=30 + i % 12
                    ),
                )
            )
            s2c_seq += 1
    return out


def _tcp_packet(
    src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, payload: bytes
) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 8192, 0, 0)
    return tcp + payload


def _ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0x4000, 64, proto, 0, src, dst)
    return header + payload


def _eth(payload: bytes) -> bytes:
    return (
        b"\x02\x00\x00\x00\x00\x01"
        + b"\x02\x00\x00\x00\x00\x02"
        + struct.pack(">H", 0x0800)
        + payload
    )


def build_demo_packets() -> list[Packet]:
    """Synthetic capture: one TCP flow, each message in its own segment."""
    packets: list[Packet] = []
    ts = 1_727_300_000.0
    c2s_seq = 1000
    s2c_seq = 5000
    for direction, msg in build_messages():
        if direction == "c2s":
            tcp = _tcp_packet(DEMO_CLIENT_IP, DEMO_SERVER_IP, 51000, DEMO_PORT, c2s_seq, msg)
            frame = _eth(_ipv4(DEMO_CLIENT_IP, DEMO_SERVER_IP, 6, tcp))
            c2s_seq += len(msg)
        else:
            tcp = _tcp_packet(DEMO_SERVER_IP, DEMO_CLIENT_IP, DEMO_PORT, 51000, s2c_seq, msg)
            frame = _eth(_ipv4(DEMO_SERVER_IP, DEMO_CLIENT_IP, 6, tcp))
            s2c_seq += len(msg)
        ts += 0.01
        packets.append(Packet(ts=ts, data=frame))
    return packets


def write_demo_pcap(path: Path) -> None:
    """Write the demo capture as a classic pcap file."""
    from ..pcap import write_pcap

    path.write_bytes(write_pcap(build_demo_packets()))
