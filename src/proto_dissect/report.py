"""Single-file offline HTML report (ADR-0010 style, no external URLs)."""

from __future__ import annotations

import html
from typing import Any

from .models import FactsDoc

_CSS = """
body{font-family:ui-monospace,Menlo,monospace;margin:2rem auto;max-width:64rem;
     color:#1a1a2e;background:#fafafa;line-height:1.5}
h1{font-size:1.4rem;border-bottom:2px solid #16213e;padding-bottom:.4rem}
h2{font-size:1.1rem;margin-top:2rem;color:#16213e}
h3{font-size:.95rem;margin-top:1.4rem}
table{border-collapse:collapse;width:100%;margin:.8rem 0;font-size:.85rem}
th,td{border:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#e8e8ef}
code,pre{background:#eee;padding:.05rem .3rem;border-radius:.25rem}
pre{padding:.6rem;overflow-x:auto;font-size:.75rem}
.meta{color:#555;font-size:.8rem}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:.6rem;font-size:.75rem;
       color:#fff}
.coverage{background:#12745a}
footer{margin-top:3rem;font-size:.75rem;color:#777;border-top:1px solid #ddd;padding-top:.6rem}
"""


def generate_report_html(doc: FactsDoc) -> str:
    e = html.escape
    s = doc.session
    v = doc.validation

    def coverage_badge(ratio: float) -> str:
        level = "coverage"
        color = "#12745a" if ratio >= 0.9 else ("#d48806" if ratio >= 0.7 else "#c0392b")
        return f'<span class="badge {level}" style="background:{color}">{ratio:.1%}</span>'

    type_rows: list[str] = []
    for mt in doc.message_types:
        field_rows = "".join(
            f"<tr><td><code>{e(f.id)}</code></td><td>{f.offset}</td><td>{f.size}</td>"
            f"<td>{e(f.type)}</td><td><code>{e(f.name or '')}</code></td>"
            f"<td>{f.coverage:.2f}</td>"
            f"<td><code>{e('; '.join(f.evidence))}</code></td></tr>"
            for f in mt.fields
        )
        samples = "".join(f"<pre>{e(hx)}</pre>" for hx in mt.sample_hex[:2])
        notes = "".join(f'<p class="meta">note: {e(n)}</p>' for n in mt.notes)
        names_prov = ""
        if any(f.description for f in mt.fields):
            names_prov = '<p class="meta">LLM descriptions present (see provenance)</p>'
        type_rows.append(
            f"<h3>{e(mt.id)} ({e(mt.dir)}, {mt.count} messages, {e(mt.framing)})</h3>"
            f"<table><tr><th>id</th><th>offset</th><th>size</th><th>type</th>"
            f"<th>name</th><th>coverage</th><th>evidence</th></tr>{field_rows}</table>"
            f"{names_prov}{notes}{samples}"
        )

    flow_rows = "".join(
        f"<tr><td>{e(f.flow_id)}</td><td>{len(f.messages)}</td></tr>" for f in doc.flows
    )

    naming = ""
    if doc.naming and doc.naming.provider != "off":
        prov: dict[str, Any] = doc.naming.to_dict()
        naming = (
            "<h2>Field naming provenance</h2>"
            f'<p class="meta">{e(str(prov))}</p>'
            "<p>Names are hypotheses validated against the capture; deterministic "
            "defaults remain in facts.json.</p>"
        )

    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>protodissect report</title><style>" + _CSS + "</style></head><body>"
        f"<h1>protodissect: {e(_proto_label(doc))}</h1>"
        f'<p class="meta">protodissect {e(doc.tool_version)} · capture '
        f"{e(s.capture.path)} · sha256 {e(s.capture.sha256[:16])}... · "
        f"{s.capture.packet_count} packets · session {e(s.id)}</p>"
        f"<p><b>Framing:</b> {e(doc.message_types[0].framing if doc.message_types else '?')} · "
        f"<b>Message types:</b> {len(doc.message_types)}</p>"
        f"<h2>Validation</h2>"
        f"<p>{v.messages_parsed}/{v.messages_total} messages re-parse cleanly "
        f"({v.parse_ratio:.1%}) · {coverage_badge(v.parse_ratio)}</p>"
        f"<p>{v.classified_bytes}/{v.total_bytes} bytes covered by classified fields "
        f"({v.classified_ratio:.1%})</p>"
        f"<p class='meta'>per-type: {e(str(v.per_type))}</p>"
        + naming
        + "<h2>Flows</h2><table><tr><th>flow</th><th>messages</th></tr>"
        + (flow_rows or "<tr><td>-</td></tr>")
        + "</table>"
        + "<h2>Field layout</h2>"
        + "".join(type_rows)
        + f"<footer>protodissect {e(doc.tool_version)} - single-file offline report. "
        "Field names from the LLM are annotated hypotheses; the layout itself is "
        "deterministic.</footer>"
        "</body></html>"
    )


def _proto_label(doc: FactsDoc) -> str:
    from .spec import _proto_label as label_fn
    from .spec import generate_protocol_md as _unused  # noqa: F401

    return label_fn(doc)
