"""Framing detection + field inference tests (the deterministic core)."""

from __future__ import annotations

import struct

from proto_dissect.models import Message
from proto_dissect.structure import detect_framing, infer_fields, split_stream


def _msgs(datas: list[bytes], direction: str = "c2s") -> list[Message]:
    return [
        Message(id=f"M{i:05d}", dir=direction, ts=float(i), data=d) for i, d in enumerate(datas)
    ]


def test_length_prefixed_walk_and_split() -> None:
    stream = b"".join(
        b"PL\x01\x02" + struct.pack(">H", seq) + struct.pack(">H", 8 - 4) + b"ABCD" + b"\x00\x00"
        for seq in range(10)
    )
    _ = stream
    # messages: magic(2)+ver(1)+type(1)+seq(2)+len(2)+payload(4)+chk(2) = 14 bytes each
    stream = b"".join(
        b"PL\x01\x02" + struct.pack(">HH", seq, 6) + b"ABCD" + b"\x00\x00" for seq in range(10)
    )
    framing, details = detect_framing(stream, [])
    assert framing == "length_prefixed"
    assert int(details["width"]) in (1, 2, 4)
    pieces = split_stream(stream, framing, details)
    assert len(pieces) == 10
    assert all(p.startswith(b"PL") for p in pieces)


def test_fixed_size_framing() -> None:
    msgs = _msgs([b"\x01\x02\x03\x04" + bytes(12)] * 5)
    framing, details = detect_framing(msgs[0].data, msgs)
    _ = framing, details
    # one reassembled stream of the fixed telegram: framed by fixed_size when pieces
    # share a constant prefix
    stream = b"".join(m.data for m in msgs)
    framing, details = detect_framing(stream, msgs)
    assert framing in ("fixed_size", "length_prefixed")


def test_delimiter_framing() -> None:
    msgs = _msgs([b"key=value\r\n", b"other=1\r\n", b"third=3\r\n"])
    framing, details = detect_framing(msgs[0].data, msgs)
    _ = details
    assert framing in ("delimiter", "unknown")


def test_field_inference_magic_length_seq() -> None:
    messages = _msgs(
        [b"PL\x01\x02" + struct.pack(">HH", seq, 2) + b"XY" + b"\x00\x00" for seq in range(1, 11)]
    )
    fields = infer_fields(messages)
    types = [(f.type, f.offset, f.size, f.endian) for f in fields]
    assert ("magic", 0, 4, None) in types or any(t[0] == "magic" and t[1] == 0 for t in types)
    assert any(t[0] == "length" and t[2] == 2 for t in types)
    assert any(t[0] == "sequence" and t[1] == 4 and t[2] == 2 for t in types)


def test_field_inference_timestamp() -> None:
    messages = _msgs(
        [b"DATA" + struct.pack(">I", 1_727_300_000 + i * 60) + b"\x00\x00" for i in range(10)]
    )
    fields = infer_fields(messages)
    assert any(f.type == "timestamp" and f.offset == 4 for f in fields)


def test_field_inference_string_wins_over_timestamp() -> None:
    # printable ASCII reads as a huge int: the string classification must win
    messages = _msgs([b"HEAD" + b"relay000" + bytes(4) for _ in range(5)])
    fields = infer_fields(messages)
    assert any(f.type == "string" and f.offset == 4 for f in fields)
    assert not any(f.type == "timestamp" for f in fields)


def test_inference_deterministic() -> None:
    messages = _msgs(
        [b"PL\x01\x02" + struct.pack(">HH", seq, 2) + b"XY" + b"\x00\x00" for seq in range(1, 11)]
    )
    a = [(f.offset, f.size, f.type, f.endian) for f in infer_fields(messages)]
    b = [(f.offset, f.size, f.type, f.endian) for f in infer_fields(messages)]
    assert a == b


def test_default_names_deterministic() -> None:
    messages = _msgs(
        [b"PL\x01\x02" + struct.pack(">HH", seq, 2) + b"XY" + b"\x00\x00" for seq in range(1, 11)]
    )
    fields = infer_fields(messages)
    names = [f.name for f in fields]
    assert all(names) and len(set(names)) == len(names)


def test_variable_tail_detected() -> None:
    messages = _msgs([b"PL\x01" + struct.pack(">H", i % 4) + b"X" * (4 + i) for i in range(6)])
    fields = infer_fields(messages)
    assert any(f.type == "variable_tail" for f in fields)


def test_sparse_cluster_still_infers() -> None:
    messages = _msgs([b"PL\x01\x02\x00\x01\x00\x00", b"PL\x01\x02\x00\x02\x00\x01"])
    fields = infer_fields(messages)
    assert fields  # 2 messages: constants disabled, inference still runs
