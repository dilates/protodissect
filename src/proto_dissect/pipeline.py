"""Pipeline orchestration: capture -> flows -> clusters -> inference -> naming ->
validation -> renderers (pipeline-spec 1-7)."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .cluster import cluster_messages
from .dissector import generate_dissector
from .explain import NamingConfig, name_fields
from .facts import build_facts
from .flows import decode_packets, sessionize
from .log import get_logger, stage
from .models import CaptureMeta, FactsDoc, Flow, Message, MessageType
from .pcap import CaptureData, ResourceCaps, read_capture, sha256_file
from .report import generate_report_html
from .spec import generate_protocol_md
from .store import Store, sha256_bytes
from .structure import build_message_type, detect_framing, split_stream
from .validate import validate

log = get_logger("proto_dissect.pipeline")


class PipelineError(RuntimeError):
    pass


class NoFlowsError(PipelineError):
    pass


def _default_out() -> Path:
    return Path("out")


def _default_naming() -> NamingConfig:
    return NamingConfig(provider="off")


@dataclass
class InferOptions:
    protocol_name: str = "unknown"
    tcp_port: int | None = None
    udp_port: int | None = None
    out_dir: Path = field(default_factory=_default_out)
    naming: NamingConfig = field(default_factory=_default_naming)
    deterministic: bool = False
    min_coverage: float = 0.8


@dataclass
class InferResult:
    facts: FactsDoc
    artifacts: dict[str, Path]
    session_id: str


def _flows_from_capture(capture: CaptureData) -> list[Flow]:
    decoded = decode_packets(capture.packets, capture.linktype)
    if not decoded:
        raise NoFlowsError(
            f"no TCP/UDP packets could be decoded from the capture (linktype {capture.linktype})"
        )
    flows = sessionize(decoded)
    return [f for f in flows if f.messages]


def _filter_flows(flows: list[Flow], tcp_port: int | None, udp_port: int | None) -> list[Flow]:
    """Keep flows touching the requested port (either side) when a port is given."""
    if tcp_port is None and udp_port is None:
        return flows

    def touches(flow: Flow) -> bool:
        port = int(flow.server.rsplit(":", 1)[-1])
        cport = int(flow.client.rsplit(":", 1)[-1])
        if flow.proto == "tcp" and tcp_port is not None:
            return port == tcp_port or cport == tcp_port
        if flow.proto == "udp" and udp_port is not None:
            return port == udp_port or cport == udp_port
        return False

    return [f for f in flows if touches(f)]


def infer_capture(
    capture_path: Path,
    opts: InferOptions,
    *,
    store: Store | None = None,
) -> InferResult:
    """Full pipeline from one capture file (deterministic core + optional naming)."""
    store = store or Store()
    caps = ResourceCaps()
    with stage(log, "read", count=1):
        capture = read_capture(Path(capture_path), caps)
        capture_sha = sha256_file(Path(capture_path))
    with stage(log, "flows", count=len(capture.packets)):
        all_flows = _flows_from_capture(capture)
        flows = _filter_flows(all_flows, opts.tcp_port, opts.udp_port)
        if not flows:
            port_hint = opts.tcp_port or opts.udp_port or "(any)"
            raise NoFlowsError(
                f"no flows touching port {port_hint}; check --tcp-port/--udp-port "
                "or drop the flag to analyze all flows"
            )
        log.info("flows selected", extra={"stage": "flows", "count": len(flows)})

    with stage(log, "cluster"):
        message_types: list[MessageType] = []
        split_messages: list[Message] = []  # ids assigned here; validation reads these
        msg_counter = 0
        for flow in flows:
            for direction in ("c2s", "s2c"):
                msgs = [m for m in flow.messages if m.dir == direction and m.data]
                if not msgs:
                    continue
                if flow.proto == "tcp" and len(msgs) == 1:
                    # reassembled stream: framing detection splits it into messages
                    stream = msgs[0].data
                    framing, details = detect_framing(stream, [])
                    pieces = split_stream(stream, framing, details)
                    messages = []
                    for piece in pieces:
                        msg_counter += 1
                        m = Message(
                            id=f"M{msg_counter:05d}",
                            dir=direction,
                            ts=msgs[0].ts,
                            data=piece,
                            flow_id=flow.flow_id,
                        )
                        messages.append(m)
                        split_messages.append(m)
                else:
                    for m in msgs:
                        msg_counter += 1
                        m.id = f"M{msg_counter:05d}"
                        split_messages.append(m)
                    messages = msgs
                    framing = "unknown"
                    details = {}
                if not messages:
                    continue
                for cluster in cluster_messages(messages, framing):
                    if len(cluster[0].data) == 0:
                        continue
                    mt = build_message_type("", cluster, framing, None)
                    mt.notes.extend(_framing_notes(framing, details))
                    message_types.append(mt)
        # framing details from the first length-prefixed flow (recorded per type below)
        flow_framing_details: dict[str, dict[str, object]] = _first_framing_details(flows)
        message_types.sort(key=lambda t: (t.dir, t.length or 0, t.id))
        for idx, mt in enumerate(message_types, start=1):
            mt.id = f"T{idx:02d}"
            for fidx, f in enumerate(mt.fields, start=1):
                f.id = f"{mt.id}F{fidx:02d}"  # globally unique: Lua declares once
                if f.name:
                    f.name = f"{mt.id.lower()}_{f.name}"  # unique filter names
        # length field linkage for framing
        for mt in message_types:
            if mt.framing == "length_prefixed":
                lf = next((f for f in mt.fields if f.type == "length"), None)
                if lf is not None:
                    mt.framing_field = lf.id

    with stage(log, "naming"):
        provenance = name_fields(message_types, opts.naming)

    all_messages = {m.id: m.data for m in split_messages}
    validation = validate(message_types, all_messages)

    if opts.deterministic:
        key = json.dumps([capture_sha, opts.naming.provider, opts.protocol_name], sort_keys=True)
        sid = sha256_bytes(key.encode())[:16]
        created = None
    else:
        sid = uuid.uuid4().hex[:16]
        created = datetime.now(UTC).isoformat(timespec="seconds")

    capture_meta = CaptureMeta(
        path=Path(capture_path).name,  # basename only: facts stay dir-independent
        sha256=capture_sha,
        format=capture.format,
        linktype=capture.linktype,
        packet_count=len(capture.packets),
        endianness=capture.endianness,
        notes=list(capture.notes),
    )
    config: dict[str, Any] = {
        "protocol_name": opts.protocol_name,
        "tcp_port": opts.tcp_port,
        "udp_port": opts.udp_port,
        "min_coverage": opts.min_coverage,
        "naming_provider": opts.naming.provider,
        "naming_model": opts.naming.model if opts.naming.provider != "off" else "",
        "deterministic": opts.deterministic,
    }
    doc = build_facts(
        session=(sid, created, capture_meta, config),
        flows=flows,
        message_types=message_types,
        validation=validation,
        naming=provenance if provenance.provider != "off" else None,
    )

    artifacts = _render_all(doc, opts.out_dir, opts, flow_framing_details)
    _persist(store, doc, capture_path, artifacts)
    return InferResult(facts=doc, artifacts=artifacts, session_id=sid)


def _render_all(
    doc: FactsDoc,
    out_dir: Path,
    opts: InferOptions,
    framing_details_map: dict[str, dict[str, object]] | None = None,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    proto = opts.protocol_name
    facts_path = out_dir / "facts.json"
    lua_path = out_dir / f"{_safe(proto)}.lua"
    md_path = out_dir / "PROTOCOL.md"
    html_path = out_dir / "report.html"
    facts_path.write_text(doc.to_json(), encoding="utf-8")
    framing = doc.message_types[0].framing if doc.message_types else "unknown"
    fmap = framing_details_map or {}
    framing_details = fmap.get(framing, {}) if doc.message_types else {}
    lua_path.write_text(
        generate_dissector(
            proto,
            doc.message_types,
            tcp_port=opts.tcp_port,
            udp_port=opts.udp_port,
            capture_sha=doc.session.capture.sha256,
            facts_sha=sha256_bytes(doc.to_json().encode()),
            framing=framing,
            framing_details=framing_details,
        ),
        encoding="utf-8",
    )
    md_path.write_text(generate_protocol_md(doc), encoding="utf-8")
    html_path.write_text(generate_report_html(doc), encoding="utf-8")
    return {
        "facts.json": facts_path,
        f"{_safe(proto)}.lua": lua_path,
        "PROTOCOL.md": md_path,
        "report.html": html_path,
    }


def _safe(name: str) -> str:
    import re

    safe = re.sub(r"[^a-z0-9_]", "_", name.lower())
    return safe if re.match(r"^[a-z]", safe) else "proto_" + safe


def _first_framing_details(flows: list[Flow]) -> dict[str, dict[str, object]]:
    """Framing walk details from the first TCP flow's stream (for the Lua generator)."""
    for flow in flows:
        for m in flow.messages:
            if flow.proto == "tcp" and m.data:
                framing, details = detect_framing(m.data, [])
                if framing == "length_prefixed":
                    return {framing: details}
    return {}


def _framing_notes(framing: str, details: dict[str, object]) -> list[str]:
    if framing == "length_prefixed":
        return [
            f"length field at offset {details.get('offset')} "
            f"({details.get('width')} bytes {details.get('endian')}-endian)"
        ]
    if framing == "fixed_size":
        return [f"fixed message size {details.get('size')}"]
    if framing == "delimiter":
        return [f"messages terminated by 0x{details.get('delimiter')}"]
    return ["framing undetermined: messages are reassembly chunks"]


def _persist(store: Store, doc: FactsDoc, capture_path: Path, artifacts: dict[str, Path]) -> None:
    try:
        sid = doc.session.id
        facts_sha = store.put_json(doc.to_dict())
        store.session_db(sid).close()
        store.add_artifact(sid, "facts", facts_sha)
        capture_sha = store.put_blob(capture_path.read_bytes())
        store.add_artifact(sid, "capture", capture_sha)
        log.info("session persisted", extra={"session": sid})
    except OSError as exc:
        log.warning("session persistence failed (non-fatal)", extra={"count": 1})
        log.debug(str(exc))
