"""Link-layer, IP, TCP, and UDP decoding + flow sessionization (pipeline-spec 2)."""

from __future__ import annotations

import struct

from .log import get_logger
from .models import Flow, Message, Packet

log = get_logger("proto_dissect.flows")

LINKTYPES = {1: "ethernet", 101: "raw_ip", 12: "raw_ip", 113: "linux_sll"}
KNOWN_LINKTYPES = set(LINKTYPES)

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
PROTO_TCP = 6
PROTO_UDP = 17
IPV6_EXT_HEADERS = {0, 43, 44, 51, 60}


class FlowError(ValueError):
    pass


class FlowKey:
    """Canonical bidirectional 5-tuple."""

    __slots__ = ("ep1", "ep2", "proto")

    def __init__(self, proto: str, ip_a: str, port_a: int, ip_b: str, port_b: int) -> None:
        a, b = (ip_a, port_a), (ip_b, port_b)
        self.proto = proto
        self.ep1, self.ep2 = min(a, b), max(a, b)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, FlowKey)
            and self.proto == other.proto
            and self.ep1 == other.ep1
            and self.ep2 == other.ep2
        )

    def __hash__(self) -> int:
        return hash((self.proto, self.ep1, self.ep2))


def _decode_ipv4(data: bytes) -> tuple[str, str, int, bytes] | None:
    if len(data) < 20:
        return None
    v_ihl = data[0]
    if v_ihl >> 4 != 4:
        return None
    ihl = (v_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    proto = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    return src, dst, proto, data[ihl:]


def _decode_ipv6(data: bytes) -> tuple[str, str, int, bytes] | None:
    if len(data) < 40:
        return None
    if data[0] >> 4 != 6:
        return None
    proto = data[6]
    src = _fmt_ipv6(data[8:24])
    dst = _fmt_ipv6(data[24:40])
    payload = data[40:]
    while proto in IPV6_EXT_HEADERS and len(payload) >= 8:
        proto = payload[0]
        ext_len = (payload[1] + 1) * 8
        if len(payload) < ext_len:
            return None
        payload = payload[ext_len:]
    return src, dst, proto, payload


def _fmt_ipv6(raw: bytes) -> str:
    parts = [struct.unpack(">H", raw[i : i + 2])[0] for i in range(0, 16, 2)]
    return ":".join(f"{p:x}" for p in parts)


def decode_packets(
    packets: list[Packet], linktype: int
) -> list[tuple[str, int, str, int, str, bytes, float, int]]:
    """Decode (proto, sport, sip, dport, dip, payload, ts, seq) tuples.

    seq is the TCP sequence (0 for UDP); reassembly needs it. Drops undecodable packets.
    """
    if linktype not in KNOWN_LINKTYPES:
        raise FlowError(f"unsupported linktype {linktype}; supported: {sorted(KNOWN_LINKTYPES)}")
    out: list[tuple[str, int, str, int, str, bytes, float, int]] = []
    for pkt in packets:
        data = pkt.data
        if linktype == 1:  # ethernet
            if len(data) < 14:
                continue
            ethertype = struct.unpack(">H", data[12:14])[0]
            if ethertype == ETHERTYPE_VLAN and len(data) >= 18:
                ethertype = struct.unpack(">H", data[16:18])[0]
                data = data[18:]  # strip MAC (14) + VLAN tag (4)
            else:
                data = data[14:]
            if ethertype == ETHERTYPE_IPV4:
                decoded = _decode_ipv4(data)
            elif ethertype == ETHERTYPE_IPV6:
                decoded = _decode_ipv6(data)
            else:
                continue
        elif linktype == 113:  # linux sll: 16-byte header
            if len(data) < 16:
                continue
            ethertype = struct.unpack(">H", data[14:16])[0]
            data = data[16:]
            decoded = (
                _decode_ipv4(data)
                if ethertype == ETHERTYPE_IPV4
                else (_decode_ipv6(data) if ethertype == ETHERTYPE_IPV6 else None)
            )
        else:  # raw ip
            decoded = _decode_ipv4(data) or _decode_ipv6(data)
        if decoded is None:
            continue
        src, dst, proto, payload = decoded
        ts = pkt.ts
        if proto == PROTO_TCP and len(payload) >= 20:
            sport, dport = struct.unpack(">HH", payload[:4])
            (seq,) = struct.unpack(">I", payload[4:8])
            doff = (payload[12] >> 4) * 4
            if doff < 20 or len(payload) < doff:
                continue
            out.append(
                (
                    "tcp",
                    int(sport),
                    str(src),
                    int(dport),
                    str(dst),
                    payload[doff:],
                    float(ts),
                    int(seq),
                )
            )
        elif proto == PROTO_UDP and len(payload) >= 8:
            sport, dport, ulen = struct.unpack(">HHH", payload[:6])
            if ulen < 8 or len(payload) < ulen:
                continue
            out.append(
                ("udp", int(sport), str(src), int(dport), str(dst), payload[8:ulen], float(ts), 0)
            )
    return out


def _server_is(ep1: tuple[str, int], ep2: tuple[str, int]) -> bool:
    """True when ep1 is the server: lower port wins (well-known-port heuristic)."""
    return ep1[1] < ep2[1]


def sessionize(
    decoded: list[tuple[str, int, str, int, str, bytes, float, int]],
) -> list[Flow]:
    """Group decoded packets into flows with directions and naive TCP reassembly."""
    # group raw packets per flow first
    grouped: dict[FlowKey, list[tuple[str, int, bytes, float, int]]] = {}
    for proto, sport, sip, dport, dip, payload, ts, seq in decoded:
        key = FlowKey(proto, str(sip), int(sport), str(dip), int(dport))
        grouped.setdefault(key, []).append((str(sip), int(sport), payload, ts, int(seq)))

    flows: list[Flow] = []
    for key in sorted(grouped, key=lambda k: (k.proto, k.ep1, k.ep2)):
        entries = grouped[key]
        server_ep = key.ep1 if _server_is(key.ep1, key.ep2) else key.ep2
        client_ep = key.ep2 if server_ep == key.ep1 else key.ep1
        flow = Flow(
            proto=key.proto,
            client=f"{client_ep[0]}:{client_ep[1]}",
            server=f"{server_ep[0]}:{server_ep[1]}",
        )
        if key.proto == "udp":
            for sip, sport, payload, ts, _seq in entries:
                direction = "c2s" if (sip, sport) == client_ep else "s2c"
                flow.messages.append(
                    Message(dir=direction, ts=ts, data=payload, flow_id=flow.flow_id)
                )
        else:
            flow.messages.extend(_reassemble_tcp(entries, client_ep, server_ep, flow.flow_id))
        flows.append(flow)
    return flows


def _reassemble_tcp(
    entries: list[tuple[str, int, bytes, float, int]],
    client_ep: tuple[str, int],
    server_ep: tuple[str, int],
    flow_id: str,
) -> list[Message]:
    """Naive per-direction reassembly: sort by seq, dedup overlaps, note gaps.

    The reassembled stream stays one message here; framing detection (structure.py)
    splits it into protocol messages next.
    """
    per_dir: dict[str, list[tuple[int, bytes, float]]] = {"c2s": [], "s2c": []}
    for sip, sport, payload, ts, seq in entries:
        direction = "c2s" if (sip, sport) == client_ep else "s2c"
        per_dir[direction].append((seq, payload, ts))

    messages: list[Message] = []
    for direction, segs in per_dir.items():
        if not segs:
            continue
        base = min(s[0] for s in segs)
        seen_spans: list[tuple[int, int]] = []
        ordered: list[tuple[int, bytes, float]] = []
        for seq, payload, ts in sorted(segs, key=lambda s: s[0]):
            rel = (seq - base) & 0xFFFFFFFF
            span = (rel, rel + len(payload))
            if any(not (span[1] <= a or span[0] >= b) for a, b in seen_spans):
                continue  # retransmission or partial overlap: skip
            seen_spans.append(span)
            ordered.append((rel, payload, ts))
        stream = b"".join(p for _r, p, _t in ordered)
        messages.append(Message(dir=direction, ts=ordered[0][2], data=stream, flow_id=flow_id))
    return messages


_ = 0xFFFFFFFF
