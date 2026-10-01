"""PCAP and PCAPNG readers with hard resource caps (ADR-0002).

Untrusted input: every block is bounds-checked, per-block exceptions become skip
notes, and caps (packet count, total bytes) truncate with notes rather than crashing.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from .log import get_logger
from .models import Packet

log = get_logger("proto_dissect.pcap")

# classic pcap magics
PCAP_LE = 0xA1B2C3D4
PCAP_BE = 0xD4C3B2A1
PCAP_LE_NS = 0xA1B23C4D
PCAP_BE_NS = 0x4D3CB2A1

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_SPB = 0x00000003

DEFAULT_MAX_PACKETS = 1_000_000
DEFAULT_MAX_BYTES = 1 << 30  # 1 GiB of captured bytes


class CaptureError(ValueError):
    """Exit-code-2 condition: unusable capture."""


@dataclass
class ResourceCaps:
    max_packets: int = DEFAULT_MAX_PACKETS
    max_bytes: int = DEFAULT_MAX_BYTES


@dataclass
class CaptureData:
    packets: list[Packet]
    format: str  # pcap | pcapng
    linktype: int
    endianness: str
    notes: list[str]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_pcap(data: bytes, caps: ResourceCaps, notes: list[str]) -> tuple[list[Packet], int, str]:
    if len(data) < 24:
        raise CaptureError("pcap file shorter than the 24-byte global header")
    # on-disk magic bytes: a1b2c3d4 (LE us), d4c3b2a1 (BE us), a1b23c4d (LE ns),
    # 4d3cb2a1 (BE ns); struct.pack of the int constants collides across endiannesses
    disk = data[:4]
    table = {
        # a little-endian writer emits d4c3b2a1; big-endian emits a1b2c3d4
        b"\xd4\xc3\xb2\xa1": ("<", False),
        b"\xa1\xb2\xc3\xd4": (">", False),
        b"\x4d\x3c\xb2\xa1": ("<", True),
        b"\xa1\xb2\x3c\x4d": (">", True),
    }
    if disk not in table:
        raise CaptureError(f"not a classic pcap file (magic {data[:4].hex()})")
    endian, ns = table[disk]
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", data[4:24])
    packets: list[Packet] = []
    total = 0
    pos = 24
    parse_errors = 0
    while pos + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig = struct.unpack(endian + "IIII", data[pos : pos + 16])
        pos += 16
        if incl_len > len(data) - pos:
            parse_errors += 1
            break
        blob = data[pos : pos + incl_len]
        pos += incl_len
        total += incl_len
        ts = ts_sec + (ts_frac / 1e9 if ns else ts_frac / 1e6)
        if len(packets) < caps.max_packets and total <= caps.max_bytes:
            packets.append(Packet(ts=ts, data=blob))
        elif "truncated by caps" not in " ".join(notes):
            notes.append("truncated by caps")
        if incl_len > len(data):
            break
    if parse_errors:
        notes.append(f"{parse_errors} malformed trailing record(s) skipped")
    return packets, linktype, "little" if endian == "<" else "big"


def _iter_pcapng(
    data: bytes, caps: ResourceCaps, notes: list[str]
) -> tuple[list[Packet], int, str]:
    packets: list[Packet] = []
    linktype = 1
    endian = "<"
    endianness = "little"
    total = 0
    pos = 0
    parse_errors = 0
    while pos + 12 <= len(data):
        btype, blen = struct.unpack(endian + "II", data[pos : pos + 8])
        if blen < 12 or pos + blen > len(data):
            parse_errors += 1
            break
        body = data[pos + 8 : pos + blen - 4]
        if btype == PCAPNG_SHB:
            bom = struct.unpack("<I", body[:4])[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            endianness = "little" if endian == "<" else "big"
        elif btype == PCAPNG_IDB:
            lt, _res, _snap = struct.unpack(endian + "HHI", body[:8])
            linktype = lt
        elif btype == PCAPNG_EPB:
            _iface, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
            blob = body[20 : 20 + caplen]
            ts_raw = (ts_hi << 32) | ts_lo
            ts = ts_raw / 1e6  # default if_tsresol = 6 (microseconds)
            total += caplen
            if len(packets) < caps.max_packets and total <= caps.max_bytes:
                packets.append(Packet(ts=ts, data=blob))
            elif "truncated by caps" not in " ".join(notes):
                notes.append("truncated by caps")
        elif btype == PCAPNG_SPB:
            origlen = struct.unpack(endian + "I", body[:4])[0]
            blob = body[4 : 4 + min(origlen, len(body) - 4)]
            total += len(blob)
            if len(packets) < caps.max_packets and total <= caps.max_bytes:
                packets.append(Packet(ts=0.0, data=blob))
        pos += blen
    if parse_errors:
        notes.append(f"{parse_errors} malformed block(s) skipped")
    return packets, linktype, endianness


def read_capture(path: Path, caps: ResourceCaps | None = None) -> CaptureData:
    """Read a PCAP/PCAPNG file with resource caps; results are deterministic."""
    caps = caps or ResourceCaps()
    data = path.read_bytes()
    notes: list[str] = []
    pcap_magics = {
        b"\xa1\xb2\xc3\xd4",
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x4d\x3c\xb2\xa1",
    }
    if data[:4] in pcap_magics:
        packets, linktype, endianness = _iter_pcap(data, caps, notes)
        fmt = "pcap"
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        packets, linktype, endianness = _iter_pcapng(data, caps, notes)
        fmt = "pcapng"
    else:
        raise CaptureError("not a PCAP or PCAPNG file (unrecognized magic)")
    if not packets:
        raise CaptureError("capture contains zero packets")
    log.info(
        "capture read",
        extra={"stage": "read", "count": len(packets), "format": fmt},
    )
    return CaptureData(
        packets=packets, format=fmt, linktype=linktype, endianness=endianness, notes=notes
    )


def write_pcap(packets: list[Packet], linktype: int = 1) -> bytes:
    """Classic pcap writer (little-endian, microsecond) for tests and the demo."""
    out = struct.pack("<IHHiIII", PCAP_LE, 2, 4, 0, 0, 262144, linktype)
    for pkt in packets:
        sec = int(pkt.ts)
        usec = round((pkt.ts - sec) * 1e6) % 1_000_000
        out += struct.pack("<IIII", sec, usec, len(pkt.data), len(pkt.data))
        out += pkt.data
    return out
