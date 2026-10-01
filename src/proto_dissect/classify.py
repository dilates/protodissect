"""Field type classification rules (pipeline-spec 4.2) - the deterministic core.

Rules, in priority order (earlier wins at overlapping offsets):
  magic       constant bytes at offset 0..3 with N >= 3 messages
  length      integer value == remaining bytes or == total message length (>= 90%)
  timestamp   unix epoch seconds or milliseconds range
  sequence    strictly monotonic across capture-ordered messages (>= 95% of steps)
  constant    single distinct value across the cluster
  string      printable run of length >= 4 in >= 90% of messages
  counter     multiple distinct values, medium entropy (low confidence)
  data        everything else (adjacent data fields merge)
"""

from __future__ import annotations

import math
from collections import Counter
from itertools import pairwise

from .models import Message

MAGIC_OFFSET_MAX = 3
LENGTH_MATCH_MIN = 0.90
SEQ_MONOTONIC_MIN = 0.95
STRING_PRINT_MIN = 0.90
MIN_MESSAGES_FOR_MAGIC = 3


def _entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _read_int(data: bytes, offset: int, width: int, endian: str) -> int | None:
    end = offset + width
    if end > len(data):
        return None
    return int.from_bytes(data[offset:end], "little" if endian == "little" else "big")


def is_length_field(
    messages: list[Message], offset: int, width: int, endian: str
) -> tuple[str, float] | None:
    """Return (covers, match_ratio) when the field is a length field, else None.

    `covers` is "rest" when the value matches remaining bytes after the field and
    "total" when it matches the whole message length.
    """
    rest_hits = 0
    total_hits = 0
    checked = 0
    for msg in messages:
        value = _read_int(msg.data, offset, width, endian)
        if value is None:
            continue
        checked += 1
        remaining = len(msg.data) - (offset + width)
        if value == remaining and remaining >= 0:
            rest_hits += 1
        if value == len(msg.data):
            total_hits += 1
    if checked == 0:
        return None
    if rest_hits / checked >= LENGTH_MATCH_MIN:
        return "rest", rest_hits / checked
    if total_hits / checked >= LENGTH_MATCH_MIN:
        return "total", total_hits / checked
    return None


def is_timestamp(value: int) -> bool:
    # unix epoch seconds: 2001-09-09 .. 2286 ; milliseconds: ~2001 .. 2096
    return 1_000_000_000 <= value < 2_000_000_000 or 1_000_000_000_000 <= value < 4_000_000_000_000


def is_sequence(messages: list[Message], offset: int, width: int, endian: str) -> bool:
    """Strictly monotonic across capture-ordered messages in >= 95% of steps."""
    values = []
    for msg in messages:
        v = _read_int(msg.data, offset, width, endian)
        if v is None:
            continue
        values.append(v)
    if len(values) < 2 or len(set(values)) < 2:
        return False
    inc = sum(1 for a, b in pairwise(values) if b > a)
    dec = sum(1 for a, b in pairwise(values) if b < a)
    steps = len(values) - 1
    return max(inc, dec) / steps >= SEQ_MONOTONIC_MIN


def is_string_run(data: bytes, offset: int, min_len: int = 4) -> int | None:
    """Length of the printable run at offset (>= min_len), else None."""
    run = 0
    for b in data[offset:]:
        if 0x20 <= b <= 0x7E:
            run += 1
        else:
            break
    return run if run >= min_len else None


def all_constant(messages: list[Message], offset: int, width: int) -> bool:
    values = set()
    for msg in messages:
        if offset + width > len(msg.data):
            return False
        values.add(msg.data[offset : offset + width])
    return len(values) == 1
