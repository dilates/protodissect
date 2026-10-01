"""Lua Wireshark dissector generation (pipeline-spec 6, ADR-0005).

Emits a working Lua dissector from the inferred structure: ProtoField declarations
(globally unique ids), framing-aware message splitting (length_prefixed uses
pinfo.desegment_len for native Wireshark reassembly), message-type dispatch by magic
value, and TCP/UDP port registration. Deterministic: same facts in, same Lua out.
"""

from __future__ import annotations

import re

from .models import InferredField, MessageType

INT_TYPES = {1: "uint8", 2: "uint16", 4: "uint32", 8: "uint64"}


def _lua_string(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _safe_name(name: str) -> str:
    safe = re.sub(r"[^a-z0-9_]", "_", name.lower())
    return safe if re.match(r"^[a-z]", safe) else "proto_" + safe


def _field_type_and_base(f: InferredField) -> tuple[str, str]:
    if f.type in ("magic", "constant", "data", "variable_tail"):
        return "bytes", "base.HEX"
    if f.type == "string":
        return "string", ""
    width = f.size if f.size in INT_TYPES else 4
    return INT_TYPES[width], "base.DEC"


def _field_label(f: InferredField) -> str:
    name = f.name or f.id
    if f.type in ("magic", "constant") and f.value_hex:
        return f"{name} (magic = {f.value_hex.replace(' ', '')})"
    return f"{name} ({f.type})"


def _field_declarations(safe: str, message_types: list[MessageType]) -> list[str]:
    lines: list[str] = []
    for mt in message_types:
        for f in mt.fields:
            ftype, base = _field_type_and_base(f)
            lua_name = f"f_{safe}_{mt.id}_{f.id}"
            if ftype in ("uint8", "uint16", "uint32", "uint64"):
                lines.append(
                    f"local {lua_name} = ProtoField.{ftype}("
                    f'"{safe}.{f.name}", "{_lua_string(_field_label(f))}", {base})'
                )
            elif ftype == "string":
                lines.append(
                    f"local {lua_name} = ProtoField.string("
                    f'"{safe}.{f.name}", "{_lua_string(_field_label(f))}")'
                )
            else:
                lines.append(
                    f"local {lua_name} = ProtoField.bytes("
                    f'"{safe}.{f.name}", "{_lua_string(_field_label(f))}")'
                )
    return lines


def _type_dispatch(safe: str, message_types: list[MessageType]) -> str:
    """Dispatch by magic field value when it discriminates types, else 'default'."""
    magic_types = [
        mt
        for mt in message_types
        if mt.fields and mt.fields[0].type == "magic" and mt.fields[0].value_hex
    ]
    values = {(mt.fields[0].value_hex or "").replace(" ", "") for mt in magic_types}
    if len(magic_types) > 1 and len(values) == len(magic_types):
        size = magic_types[0].fields[0].size
        lines = [f"function {safe}_type(buf, off)", '    local t = "default"']
        for mt in magic_types:
            value = (mt.fields[0].value_hex or "").replace(" ", "")
            lines.append(
                f"    if tostring(buf(off, {size})):lower() == "
                f'"{value.lower()}" then t = "{mt.id}" end'
            )
        lines += ["    return t", "end", ""]
        return "\n".join(lines)
    return f'function {safe}_type(buf, off)\n    return "default"\nend\n'


def _add_fields_block(safe: str, mt: MessageType, indent: str = "        ") -> str:
    """Emit bounds-safe field extraction for one message type."""
    lines = [f'{indent}if t == "{mt.id}" then']
    for f in mt.fields:
        ftype, _base = _field_type_and_base(f)
        lua_name = f"f_{safe}_{mt.id}_{f.id}"
        guard = f"{indent}    if msg_len >= {f.offset + f.size} then"
        if ftype == "string":
            body = (
                f"{indent}        subtree:add({lua_name}, msg_buf({f.offset}, "
                f"msg_len - {f.offset}))"
            )
        else:
            body = f"{indent}        subtree:add({lua_name}, msg_buf({f.offset}, {f.size}))"
        lines += [guard, body, f"{indent}    end"]
    lines.append(f"{indent}end")
    return "\n".join(lines)


def _dissector_body(
    safe: str,
    message_types: list[MessageType],
    framing: str,
    details: dict[str, object],
) -> str:
    """The main dissector function; framing-aware message splitting."""
    len_field = next((f for mt in message_types for f in mt.fields if f.type == "length"), None)
    lines = [
        f"function p_{safe}.dissector(buf, pinfo, tree)",
        f'    pinfo.cols.protocol = "{_lua_string(safe)}"',
    ]
    if framing == "length_prefixed" and len_field is not None:
        lo, ls = len_field.offset, len_field.size
        endian = len_field.endian or "big"
        lines += [
            "    local offset = 0",
            f"    local len_offset, len_size = {lo}, {ls}",
            "    while offset < buf:len() do",
            "        local remaining = buf:len() - offset",
            "        if remaining < len_offset + len_size then",
            "            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT",
            "            return",
            "        end",
            "        local len_bytes = buf(offset + len_offset, len_size)",
            "        local len_val = 0",
            f"        -- read the length integer ({ls} bytes, {endian}-endian)",
            _lua_len_read(ls, endian),
            "        local msg_len = len_offset + len_size + len_val",
            "        if remaining < msg_len then",
            "            pinfo.desegment_len = msg_len - remaining",
            "            return",
            "        end",
            "        local msg_buf = buf(offset, msg_len)",
            f"        local t = {safe}_type(msg_buf, 0)",
            f'        local subtree = tree:add(p_{safe}, msg_buf(), "{{" .. t .. "}} message")',
            "        -- fields per message type",
        ]
        for mt in message_types:
            lines.append(_add_fields_block(safe, mt, indent="        "))
        lines += [
            "        offset = offset + msg_len",
            "    end",
            "end",
            "",
        ]
        # drop the placeholder empty line pairs
        return "\n".join(line for line in lines if line != "") + "\n"
    if framing == "fixed_size" and message_types:
        size = message_types[0].length or 0
        lines += [
            "    local offset = 0",
            f"    local msg_len = {size}",
            "    while offset + msg_len <= buf:len() do",
            "        local msg_buf = buf(offset, msg_len)",
            f"        local t = {safe}_type(msg_buf, 0)",
            f'        local subtree = tree:add(p_{safe}, msg_buf(), "{{" .. t .. "}} message")',
            "        -- fields per message type",
        ]
        for mt in message_types:
            lines.append(_add_fields_block(safe, mt, indent="        "))
        lines += ["        offset = offset + msg_len", "    end", "end", ""]
        return "\n".join(line for line in lines if line != "") + "\n"
    # delimiter / unknown: single tree per packet with an honest comment
    lines += [
        "    -- framing undetermined: one tree per packet; refine manually if needed",
        "    local subtree = tree:add(p_" + safe + ', buf(), "' + _lua_string(safe) + ' message")',
        "    -- fields per message type",
    ]
    for mt in message_types:
        lines.append(_add_fields_block(safe, mt, indent="    "))
    lines += ["end", ""]
    return "\n".join(line for line in lines if line != "") + "\n"


def _lua_len_read(size: int, endian: str) -> str:
    """Lua snippet reading a {size}-byte {endian}-endian integer into len_val."""
    if size == 1:
        return "        len_val = len_bytes:uint()"
    if size == 2:
        return (
            "        len_val = len_bytes:uint()"
            if endian == "big"
            else "        len_val = bit.bor(bit.lshift(len_bytes(1,1):uint(), 8), "
            "len_bytes(0,1):uint())"
        )
    if size == 4:
        return (
            "        len_val = len_bytes:uint()"
            if endian == "big"
            else "        len_val = bit.bor(bit.lshift(len_bytes(3,1):uint(), 24), "
            "bit.lshift(len_bytes(2,1):uint(), 16), bit.lshift(len_bytes(1,1):uint(), 8), "
            "len_bytes(0,1):uint())"
        )
    return "        len_val = len_bytes:uint()"


def generate_dissector(
    protocol_name: str,
    message_types: list[MessageType],
    *,
    tcp_port: int | None = None,
    udp_port: int | None = None,
    capture_sha: str = "",
    facts_sha: str = "",
    framing: str = "unknown",
    framing_details: dict[str, object] | None = None,
) -> str:
    """Generate a deterministic Lua dissector (same inputs, same output)."""
    safe = _safe_name(protocol_name)
    details = framing_details or {}
    declarations = _field_declarations(safe, message_types)
    field_refs = ", ".join(f"f_{safe}_{mt.id}_{f.id}" for mt in message_types for f in mt.fields)

    registration: list[str] = []
    if tcp_port is not None:
        registration.append(f'DissectorTable.get("tcp.port"):add({tcp_port}, p_{safe})')
    if udp_port is not None:
        registration.append(f'DissectorTable.get("udp.port"):add({udp_port}, p_{safe})')

    header = (
        "-- generated by protodissect; do not edit by hand\n"
        f"-- protocol: {protocol_name}\n"
        f"-- capture sha256: {capture_sha}\n"
        f"-- facts sha256: {facts_sha}\n"
    )
    parts = [
        header,
        f'local p_{safe} = Proto("{safe}", "{_lua_string(protocol_name)}")',
        "",
        "\n".join(declarations),
        "",
        f"p_{safe}.fields = {{ {field_refs} }}",
        "",
        _type_dispatch(safe, message_types),
        _dissector_body(safe, message_types, framing, details),
        f"function p_{safe}.init()",
        *["    " + line for line in registration],
        "end",
        "",
    ]
    return "\n".join(parts)
