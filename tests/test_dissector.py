"""Lua dissector generation tests (syntax + determinism + content)."""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

from proto_dissect.cluster import cluster_messages
from proto_dissect.demo import DEMO_PORT, build_demo_packets
from proto_dissect.dissector import generate_dissector
from proto_dissect.models import Message
from proto_dissect.pcap import write_pcap
from proto_dissect.structure import build_message_type, detect_framing, split_stream


def _demo_types():
    packets = build_demo_packets()
    stream_c2s = b"".join(p.data for p in packets)  # not used; build via framing split
    import tempfile
    from pathlib import Path

    from proto_dissect.flows import decode_packets, sessionize

    tmp = Path(tempfile.mkdtemp())
    cap = tmp / "c.pcap"
    cap.write_bytes(write_pcap(packets))
    decoded = decode_packets([p for p in build_demo_packets()], 1)
    flows = sessionize(decoded)
    types = []
    for flow in flows:
        for direction in ("c2s", "s2c"):
            msgs = [m for m in flow.messages if m.dir == direction and m.data]
            if not msgs:
                continue
            framing, details = detect_framing(msgs[0].data, [])
            pieces = split_stream(msgs[0].data, framing, details)
            messages = [
                Message(dir=direction, ts=msgs[0].ts, data=p, flow_id=flow.flow_id) for p in pieces
            ]
            for cluster in cluster_messages(messages, framing):
                mt = build_message_type("", cluster, framing, None)
                types.append(mt)
    for idx, mt in enumerate(types, start=1):
        mt.id = f"T{idx:02d}"
        for fidx, f in enumerate(mt.fields, start=1):
            f.id = f"{mt.id}F{fidx:02d}"
    _ = stream_c2s
    return types


def test_generated_lua_content() -> None:
    types = _demo_types()
    lua = generate_dissector(
        "smartplug",
        types,
        tcp_port=DEMO_PORT,
        framing="length_prefixed",
        framing_details={"offset": 6, "width": 2, "endian": "big"},
    )
    assert 'Proto("smartplug"' in lua
    assert "ProtoField.uint16" in lua
    assert 'DissectorTable.get("tcp.port"):add(9999, p_smartplug)' in lua
    assert "desegment_len" in lua  # length-prefixed framing uses Wireshark reassembly
    assert lua.count("function p_smartplug.dissector") == 1


def test_generated_lua_is_deterministic() -> None:
    types = _demo_types()
    a = generate_dissector(
        "smartplug",
        types,
        tcp_port=9999,
        framing="length_prefixed",
        framing_details={"offset": 6, "width": 2, "endian": "big"},
    )
    b = generate_dissector(
        "smartplug",
        types,
        tcp_port=9999,
        framing="length_prefixed",
        framing_details={"offset": 6, "width": 2, "endian": "big"},
    )
    assert a == b


def test_unique_field_ids_in_lua() -> None:
    types = _demo_types()
    for idx, mt in enumerate(types, start=1):
        mt.id = f"T{idx:02d}"
        for fidx, f in enumerate(mt.fields, start=1):
            f.id = f"{mt.id}F{fidx:02d}"
            if f.name:
                f.name = f"{mt.id.lower()}_{f.name}"
    lua = generate_dissector("smartplug", types, tcp_port=9999)
    import re

    decls = re.findall(r"local (f_\w+) = ProtoField", lua)
    assert len(decls) == len(set(decls)), "duplicate field declarations would break Lua"
    names = re.findall(r'"smartplug\.(\w+)"', lua)
    assert len(names) == len(set(names))


def test_lua_syntax_valid_with_luac() -> None:
    luac = shutil.which("luac")
    if luac is None:
        pytest.skip("luac not installed")
    types = _demo_types()
    for idx, mt in enumerate(types, start=1):
        mt.id = f"T{idx:02d}"
        for fidx, f in enumerate(mt.fields, start=1):
            f.id = f"{mt.id}F{fidx:02d}"
            if f.name:
                f.name = f"{mt.id.lower()}_{f.name}"
    lua = generate_dissector(
        "smartplug",
        types,
        tcp_port=9999,
        udp_port=9999,
        framing="length_prefixed",
        framing_details={"offset": 6, "width": 2, "endian": "big"},
    )
    p = Path("/tmp") / "dissector_check.lua"
    p.write_text(lua)
    result = subprocess.run([luac, "-o", "/dev/null", str(p)], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()
    _ = struct


def test_safe_name_sanitization() -> None:
    from proto_dissect.dissector import _safe_name

    assert _safe_name("My-Protocol") == "my_protocol"
    assert _safe_name("1proto") == "proto_1proto"


import pytest  # noqa: E402


def test_field_type_and_base_map() -> None:
    from proto_dissect.dissector import _field_type_and_base
    from proto_dissect.models import InferredField

    magic = InferredField(type="magic", size=4, value_hex="504c0102")
    assert _field_type_and_base(magic)[0] == "bytes"
    seq = InferredField(type="sequence", size=2, endian="big")
    assert _field_type_and_base(seq) == ("uint16", "base.DEC")
    s = InferredField(type="string", size=8)
    assert _field_type_and_base(s) == ("string", "")
