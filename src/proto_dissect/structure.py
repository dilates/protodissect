"""Structure inference (pipeline-spec 4): framing detection + field boundary inference.

This is the deterministic core. Same messages in, same fields out. The LLM naming
layer (explain.py) can only name what this module proves.
"""

from __future__ import annotations

from .classify import (
    MAGIC_OFFSET_MAX,
    MIN_MESSAGES_FOR_MAGIC,
    all_constant,
    is_length_field,
    is_sequence,
    is_string_run,
    is_timestamp,
)
from .models import InferredField, Message, MessageType


def detect_framing(stream: bytes, messages: list[Message]) -> tuple[str, dict[str, object]]:
    """Detect how message boundaries are found (pipeline-spec 4.1).

    Returns (framing_kind, details). For TCP streams the length-prefixed walk is the
    primary detector; UDP messages keep their datagram boundaries (framing refers to
    how a receiver would find boundaries).
    """
    best = _walk_length_prefixed(stream)
    if best is not None:
        offset, width, endian, consumed = best
        return "length_prefixed", {
            "offset": offset,
            "width": width,
            "endian": endian,
            "consumed": consumed,
        }
    if messages and len({len(m.data) for m in messages}) == 1 and len(messages) >= 3:
        return "fixed_size", {"size": len(messages[0].data)}
    for delim in (b"\r\n", b"\n", b"\x00"):
        hits = sum(1 for m in messages if m.data.endswith(delim))
        inside = sum(1 for m in messages if delim in m.data[: -len(delim)])
        if messages and hits / len(messages) >= 0.95 and inside == 0:
            return "delimiter", {"delimiter": delim.hex()}
    return "unknown", {}


def _walk_length_prefixed(
    stream: bytes, header_window: int = 16
) -> tuple[int, int, str, float] | None:
    """Try (offset, width, endian) length walks over a TCP stream; pick the best.

    A candidate wins when the walk consumes >= 95% of the stream with >= 3 messages
    AND every recovered piece shares a constant >= 2-byte prefix (magic). Without the
    prefix rule, a small constant byte (version, type) masquerades as a length field
    and garbage pieces tile the stream. Ties: larger width, then lower offset.
    """
    best: tuple[int, int, str, float] | None = None
    for offset in range(0, header_window):
        for width in (2, 4, 1):
            for endian in ("big", "little"):
                result = _walk_one(stream, offset, width, endian)
                if result is None:
                    continue
                consumed, magic_ok = result
                if consumed < 0.95 or not magic_ok:
                    continue
                if best is None or consumed > best[3] or (consumed == best[3] and width > best[1]):
                    best = (offset, width, endian, consumed)
    return best


def _walk_one(stream: bytes, offset: int, width: int, endian: str) -> tuple[float, bool] | None:
    """Walk one framing hypothesis; return (consumed ratio, constant-prefix ok)."""
    pos = 0
    count = 0
    consumed = 0
    pieces: list[bytes] = []
    while pos + offset + width <= len(stream):
        len_bytes = stream[pos + offset : pos + offset + width]
        value = int.from_bytes(len_bytes, "little" if endian == "little" else "big")
        msg_len = offset + width + value
        if msg_len <= 0 or pos + msg_len > len(stream):
            break
        pieces.append(stream[pos : pos + msg_len])
        pos += msg_len
        consumed += msg_len
        count += 1
        if count > 100_000:
            break
    if count < 3:
        return None
    prefix_ok = len({p[:2] for p in pieces}) == 1
    return consumed / len(stream), prefix_ok


def infer_fields(messages: list[Message]) -> list[InferredField]:
    """Infer fields for one cluster (pipeline-spec 4.2). Deterministic."""
    if not messages:
        return []
    min_len = min(len(m.data) for m in messages)
    ordered = sorted(messages, key=lambda m: m.ts)
    fields: list[InferredField] = []
    claimed: set[int] = set()

    # pass 1: constants (magic / constant); wider first so "PL" + version+type become
    # two 2-byte fields instead of four 1-byte fields
    for offset in range(min(min_len, MAGIC_OFFSET_MAX + 1)):
        for width in (4, 2, 1):
            if offset + width > min_len or offset in claimed:
                continue
            if len(messages) >= MIN_MESSAGES_FOR_MAGIC and all_constant(messages, offset, width):
                is_magic = offset <= MAGIC_OFFSET_MAX
                fields.append(
                    InferredField(
                        offset=offset,
                        size=width,
                        type="magic" if is_magic else "constant",
                        value_hex=messages[0].data[offset : offset + width].hex(),
                        evidence=["all_constant"],
                    )
                )
                for o in range(offset, offset + width):
                    claimed.add(o)
                break

    # pass 2: integer classifications per (offset, width, endian); widths ascending
    # (narrowest consistent classification wins: a u16 sequence must not be claimed as
    # a u64 "sequence" spanning the length field) and semantic order length > string
    # > timestamp > sequence (printable ASCII reads as a huge int: string must win)
    int_candidates: list[InferredField] = []
    for offset in range(min_len):
        if offset in claimed:
            continue
        done = False
        for width in (1, 2, 4, 8):
            if offset + width > min_len or any(o in claimed for o in range(offset, offset + width)):
                continue
            for endian in ("big", "little"):
                length = is_length_field(messages, offset, width, endian)
                if length is not None:
                    covers, ratio = length
                    int_candidates.append(
                        InferredField(
                            offset=offset,
                            size=width,
                            type="length",
                            endian=endian,
                            covers=covers,
                            coverage=ratio,
                            evidence=[f"length_match_{ratio:.2f}"],
                        )
                    )
                    done = True
                    break
                runs = [is_string_run(m.data, offset) for m in messages]
                printable = [r for r in runs if r is not None]
                if printable and len(printable) / len(messages) >= 0.90:
                    run = min(printable)
                    run = min(run, min_len - offset)
                    int_candidates.append(
                        InferredField(
                            offset=offset,
                            size=run,
                            type="string",
                            string_max=max(printable),
                            evidence=["printable_run"],
                        )
                    )
                    done = True
                    break
                samples = [
                    v for m in ordered if (v := _read(m.data, offset, width, endian)) is not None
                ]
                if samples and all(is_timestamp(v) for v in samples) and len(set(samples)) >= 2:
                    int_candidates.append(
                        InferredField(
                            offset=offset,
                            size=width,
                            type="timestamp",
                            endian=endian,
                            samples=samples,
                            evidence=["epoch_range"],
                        )
                    )
                    done = True
                    break
                if is_sequence(messages, offset, width, endian):
                    int_candidates.append(
                        InferredField(
                            offset=offset,
                            size=width,
                            type="sequence",
                            endian=endian,
                            samples=samples,
                            evidence=["monotonic"],
                        )
                    )
                    done = True
                    break
            if done:
                break

    # accept non-overlapping candidates, longest first, then lowest offset
    int_candidates.sort(key=lambda f: (-f.size, f.offset))
    accepted: list[InferredField] = []
    for cand in int_candidates:
        span = set(range(cand.offset, cand.offset + cand.size))
        if span & claimed:
            continue
        claimed |= span
        accepted.append(cand)
    fields.extend(accepted)

    # pass 4: fill gaps with data fields; merge adjacent
    fields.sort(key=lambda f: f.offset)
    merged: list[InferredField] = []
    for f in fields:
        if (
            merged
            and f.offset == merged[-1].offset + merged[-1].size
            and f.type == merged[-1].type == "data"
        ):
            merged[-1].size += f.size
            continue
        merged.append(f)
    cursor = 0
    result: list[InferredField] = []
    for f in merged:
        if f.offset > cursor:
            gap = f.offset - cursor
            result.append(
                InferredField(
                    offset=cursor,
                    size=gap,
                    type="data",
                    value_hex=messages[0].data[cursor : cursor + gap].hex(),
                    evidence=["gap_fill"],
                )
            )
        result.append(f)
        cursor = f.offset + f.size
    if cursor < min_len:
        result.append(
            InferredField(
                offset=cursor,
                size=min_len - cursor,
                type="data",
                value_hex=messages[0].data[cursor:min_len].hex(),
                evidence=["gap_fill"],
            )
        )

    # variable tail: bytes beyond min_len (lengths vary inside the cluster)
    max_len = max(len(m.data) for m in messages)
    if max_len > min_len:
        varying = min_len
        for m in messages:
            if len(m.data) > min_len:
                varying = min(varying, min_len)
        result.append(
            InferredField(
                offset=min_len,
                size=max_len - min_len,
                type="variable_tail",
                coverage=0.0,
                evidence=["beyond_min_length"],
            )
        )

    # deterministic default names + ids
    result.sort(key=lambda f: f.offset)
    for idx, f in enumerate(result, start=1):
        f.id = f"F{idx:04d}"
        if f.name is None:
            f.name = _default_name(f)
    return result


def _read(data: bytes, offset: int, width: int, endian: str) -> int | None:
    if offset + width > len(data):
        return None
    raw = data[offset : offset + width]
    return int.from_bytes(raw, "little" if endian == "little" else "big")


def _default_name(field: InferredField) -> str:
    if field.type == "magic":
        return f"magic_{field.offset:02d}"
    if field.type == "data" or field.type == "variable_tail":
        return f"{field.type}_{field.offset:02d}"
    if field.type in ("string",):
        return f"string_{field.offset:02d}"
    bits = field.size * 8
    endianness = field.endian or ""
    return f"{field.type}_{bits}{endianness[:1]}_{field.offset:02d}"


def build_message_type(
    type_id: str, cluster: list[Message], framing: str, framing_field: str | None
) -> MessageType:
    """Build a MessageType with inferred fields, samples, and notes."""
    mt = MessageType(
        id=type_id,
        dir=cluster[0].dir,
        count=len(cluster),
        length=len(cluster[0].data) if len({len(m.data) for m in cluster}) == 1 else None,
        framing=framing,
        framing_field=framing_field,
    )
    mt.fields = infer_fields(cluster)
    mt.sample_hex = [m.data.hex(" ") for m in cluster[:4]]
    mt.message_ids = [m.id for m in cluster]
    if len(cluster) < 3:
        mt.notes.append("sparse cluster (< 3 messages): constant detection disabled")
    if mt.length is None:
        mt.notes.append("variable length messages: variable_tail present")
    return mt


def _as_int(value: object) -> int:
    return value if isinstance(value, int) else int(str(value))


def split_stream(stream: bytes, framing: str, details: dict[str, object]) -> list[bytes]:
    """Split a reassembled TCP stream into messages per the detected framing.

    Deterministic; a length walk that cannot consume the stream falls back to
    reassembly-chunk-sized messages (honest unknown framing).
    """
    if framing == "length_prefixed":
        offset = _as_int(details.get("offset"))
        width = _as_int(details.get("width"))
        endian = str(details.get("endian", "big"))
        pieces: list[bytes] = []
        pos = 0
        while pos + offset + width <= len(stream):
            len_bytes = stream[pos + offset : pos + offset + width]
            value = int.from_bytes(len_bytes, "little" if endian == "little" else "big")
            msg_len = offset + width + value
            if msg_len <= 0 or pos + msg_len > len(stream):
                break
            pieces.append(stream[pos : pos + msg_len])
            pos += msg_len
        if pieces:
            return pieces
    if framing == "fixed_size":
        size = _as_int(details.get("size"))
        return [stream[i : i + size] for i in range(0, len(stream) - size + 1, size)]
    if framing == "delimiter":
        delim_hex = str(details["delimiter"])
        delim = bytes.fromhex(delim_hex)
        pieces = []
        for chunk in stream.split(delim):
            if chunk:
                pieces.append(chunk + delim)
        return pieces
    return [stream] if stream else []
