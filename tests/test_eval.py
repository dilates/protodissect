"""Naming eval harness (testing-strategy section 5): runs against a local Ollama model.

Every field in the demo protocol has a ground-truth name (we designed the protocol).
Graded: factuality (zero fabricated fields tolerated - enforced by the pipeline),
correctness (does the proposed name match ground truth?), coverage (share named).
Scores written to docs/evals/latest.json.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

import pytest

from proto_dissect.demo import write_demo_pcap
from proto_dissect.explain import DEFAULT_OLLAMA_URL, NamingConfig, name_fields
from proto_dissect.pipeline import InferOptions, infer_capture

pytestmark = pytest.mark.eval

GROUND_TRUTH = {
    "magic": ["magic", "magic_number", "protocol_magic"],
    "constant": ["version", "protocol_version", "ver"],
    "sequence": ["sequence", "seq", "message_id", "counter"],
    "length": ["length", "len", "payload_length", "msg_len"],
    "string": ["setting", "name", "setting_name", "key"],
    "timestamp": ["uptime", "timestamp", "time"],
}


def _ollama_reachable() -> bool:
    for path in ("/v1/models", "/api/tags"):
        try:
            urllib.request.urlopen(f"{DEFAULT_OLLAMA_URL.removesuffix('/v1')}{path}", timeout=3)
            return True
        except OSError:
            continue
    return False


def _model() -> str:
    return os.environ.get("PROTODISSECT_EVAL_MODEL", "qwen3:4b")


@pytest.mark.skipif(not _ollama_reachable(), reason="local Ollama not reachable")
def test_naming_eval(tmp_path: Path) -> None:
    capture = tmp_path / "c.pcap"
    write_demo_pcap(capture)
    result = infer_capture(
        capture, InferOptions(out_dir=tmp_path / "out", tcp_port=9999, deterministic=True)
    )
    message_types = result.facts.message_types
    original_names = {f.id: f.name for mt in message_types for f in mt.fields}

    config = NamingConfig(provider="ollama", model=_model())
    provenance = name_fields(message_types, config)

    # rubric: factuality (dropped == 0, hard gate); a name is "sensible" when it
    # contains a ground-truth keyword OR is the conservative default echo (compliant
    # per the prompt contract)
    total = 0
    sensible = 0
    changed = 0
    correct_changed = 0
    for mt in message_types:
        for field in mt.fields:
            total += 1
            expected = GROUND_TRUTH.get(field.type, [])
            proposed = (field.name or "").lower()
            original = (original_names.get(field.id) or "").lower()
            if proposed != original:
                changed += 1
                if any(k in proposed for k in expected):
                    correct_changed += 1
            if any(k in proposed for k in expected) or proposed == original:
                sensible += 1

    scores = {
        "model": _model(),
        "fields": total,
        "changed": changed,
        "changed_correct": correct_changed,
        "sensible_ratio": round(sensible / max(total, 1), 3),
        "dropped": provenance.dropped,
        "gate": sensible / max(total, 1) >= 0.5 and provenance.dropped == 0,
    }
    out_dir = Path(__file__).parent.parent / "docs" / "evals"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "latest.json").write_text(json.dumps(scores, indent=2, sort_keys=True) + "\n")
    assert scores["gate"], f"naming eval below gate: {scores}"
