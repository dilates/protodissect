"""Core data model: packets, flows, clusters, inferred fields, facts document.

Deterministic by construction: to_dict emits only stable fields; FactsDoc.to_json is
byte-reproducible for identical inputs (ARCHITECTURE principle 3).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

FIELD_TYPES = (
    "magic",
    "constant",
    "length",
    "timestamp",
    "sequence",
    "counter",
    "string",
    "data",
    "variable_tail",
)
FRAMINGS = ("length_prefixed", "fixed_size", "delimiter", "unknown")


@dataclass
class Packet:
    ts: float
    data: bytes


@dataclass
class CaptureMeta:
    path: str
    sha256: str
    format: str  # pcap | pcapng
    linktype: int
    packet_count: int
    endianness: str  # little | big
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "format": self.format,
            "linktype": self.linktype,
            "packet_count": self.packet_count,
            "endianness": self.endianness,
            "notes": self.notes,
        }


@dataclass
class Message:
    """One protocol message: a UDP datagram or a framing-split TCP chunk."""

    id: str = ""
    dir: str = "c2s"  # c2s | s2c
    ts: float = 0.0
    data: bytes = b""
    flow_id: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "dir": self.dir,
            "ts": round(self.ts, 6),
            "len": len(self.data),
            "flow_id": self.flow_id,
        }


@dataclass
class Flow:
    proto: str  # tcp | udp
    client: str  # ip:port
    server: str
    messages: list[Message] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def flow_id(self) -> str:
        return f"{self.proto}:{self.client}->{self.server}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "proto": self.proto,
            "client": self.client,
            "server": self.server,
            "messages": [m.to_dict() for m in self.messages],
            "notes": self.notes,
        }


@dataclass
class InferredField:
    """One inferred field: an offset/size window plus its classification."""

    id: str = ""
    offset: int = 0
    size: int = 1
    type: str = "data"  # one of FIELD_TYPES
    endian: str | None = None  # little | big for integer fields
    value_hex: str | None = None  # for magic/constant
    covers: str | None = None  # for length fields: rest | total
    samples: list[int] = field(default_factory=list)  # integer samples across messages
    string_max: int | None = None  # for string fields
    coverage: float = 1.0
    name: str | None = None  # deterministic default; LLM may replace
    description: str | None = None  # LLM-provided
    evidence: list[str] = field(default_factory=list)  # rule ids that fired

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "offset": self.offset,
            "size": self.size,
            "type": self.type,
            "coverage": round(self.coverage, 4),
        }
        if self.endian:
            out["endian"] = self.endian
        if self.value_hex is not None:
            out["value_hex"] = self.value_hex
        if self.covers:
            out["covers"] = self.covers
        if self.samples:
            out["samples"] = self.samples[:8]
        if self.string_max is not None:
            out["string_max"] = self.string_max
        out["name"] = self.name
        if self.description:
            out["description"] = self.description
        if self.evidence:
            out["evidence"] = self.evidence
        return out


@dataclass
class MessageType:
    """A cluster of messages whose fields align."""

    id: str = ""
    dir: str = "c2s"
    count: int = 0
    length: int | None = None  # None when lengths vary
    framing: str = "unknown"  # one of FRAMINGS
    framing_field: str | None = None  # the length field id when framing is length_prefixed
    fields: list[InferredField] = field(default_factory=list)
    sample_hex: list[str] = field(default_factory=list)  # up to 4 message hex dumps
    message_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "dir": self.dir,
            "count": self.count,
            "length": self.length,
            "framing": self.framing,
            "framing_field": self.framing_field,
            "fields": [f.to_dict() for f in self.fields],
            "sample_hex": self.sample_hex,
            "message_ids": self.message_ids[:8],
            "notes": self.notes,
        }


@dataclass
class ValidationReport:
    """Round-trip validation: share of messages that re-parse cleanly + classified bytes."""

    messages_total: int
    messages_parsed: int
    classified_bytes: int
    total_bytes: int
    per_type: dict[str, float] = field(default_factory=dict)

    @property
    def parse_ratio(self) -> float:
        return self.messages_parsed / self.messages_total if self.messages_total else 0.0

    @property
    def classified_ratio(self) -> float:
        return self.classified_bytes / self.total_bytes if self.total_bytes else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "messages_total": self.messages_total,
            "messages_parsed": self.messages_parsed,
            "parse_ratio": round(self.parse_ratio, 4),
            "classified_bytes": self.classified_bytes,
            "total_bytes": self.total_bytes,
            "classified_ratio": round(self.classified_ratio, 4),
            "per_type": {k: round(v, 4) for k, v in sorted(self.per_type.items())},
        }


@dataclass
class NamingProvenance:
    provider: str = "off"
    model: str = ""
    prompt_version: str = "pv1"
    dropped: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "dropped": self.dropped,
        }


@dataclass
class SessionInfo:
    id: str
    created_utc: str | None
    capture: CaptureMeta
    config: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_utc": self.created_utc,
            "capture": self.capture.to_dict(),
            "config": self.config,
        }


@dataclass
class FactsDoc:
    """The deterministic deliverable (facts.json schema v1)."""

    schema_version: int
    tool_name: str
    tool_version: str
    session: SessionInfo
    flows: list[Flow]
    message_types: list[MessageType]
    validation: ValidationReport
    naming: NamingProvenance | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": {"name": self.tool_name, "version": self.tool_version},
            "session": self.session.to_dict(),
            "flows": [f.to_dict() for f in self.flows],
            "message_types": [t.to_dict() for t in self.message_types],
            "validation": self.validation.to_dict(),
            "naming": self.naming.to_dict() if self.naming else None,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2) + "\n"
