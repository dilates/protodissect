"""Round-trip validation (pipeline-spec 4.2, ADR-0007).

Coverage has two honest numbers:
- parse_ratio: share of messages that re-parse cleanly under the inferred structure
  (all fields within bounds; length-framed messages consumable end to end)
- classified_ratio: share of bytes covered by semantically classified fields
  (magic, length, timestamp, sequence, constant, string) vs opaque data
"""

from __future__ import annotations

from .models import MessageType, ValidationReport

SEMANTIC_TYPES = {"magic", "length", "timestamp", "sequence", "constant", "string"}


def _message_parses(message_data: bytes, mt: MessageType) -> bool:
    """A message parses when every fixed field fits inside its bounds and a length
    field, when present, agrees with the actual message length."""
    length_fields = [f for f in mt.fields if f.type == "length"]
    for field in mt.fields:
        if field.offset + field.size > len(message_data) and field.type != "variable_tail":
            return False
    for lf in length_fields:
        if lf.offset + lf.size > len(message_data):
            return False
        raw = message_data[lf.offset : lf.offset + lf.size]
        value = int.from_bytes(raw, "little" if lf.endian == "little" else "big")
        if lf.covers == "rest" and value != len(message_data) - lf.offset - lf.size:
            return False
        if lf.covers == "total" and value != len(message_data):
            return False
    return True


def validate(message_types: list[MessageType], all_messages: dict[str, bytes]) -> ValidationReport:
    """Validate every message type against its member messages (deterministic)."""
    total_messages = 0
    parsed = 0
    classified_bytes = 0
    total_bytes = 0
    per_type: dict[str, float] = {}

    for mt in message_types:
        type_total = 0
        type_parsed = 0
        for mid in mt.message_ids:
            data = all_messages.get(mid)
            if data is None:
                continue
            type_total += 1
            total_bytes += len(data)
            if _message_parses(data, mt):
                type_parsed += 1
                for field in mt.fields:
                    if field.type == "variable_tail":
                        continue
                    overlap_end = min(field.offset + field.size, len(data))
                    if field.offset < overlap_end:
                        if field.type in SEMANTIC_TYPES:
                            classified_bytes += overlap_end - field.offset
                        else:
                            # data fields count toward structure but not semantics
                            pass
        ratio = type_parsed / type_total if type_total else 0.0
        per_type[mt.id] = ratio
        total_messages += type_total
        parsed += type_parsed

    return ValidationReport(
        messages_total=total_messages,
        messages_parsed=parsed,
        classified_bytes=classified_bytes,
        total_bytes=total_bytes,
        per_type=per_type,
    )
