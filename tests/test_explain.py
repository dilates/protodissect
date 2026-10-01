"""LLM field naming guardrail tests (pipeline-spec 5, ADR-0003)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from proto_dissect.demo import write_demo_pcap
from proto_dissect.explain import ExplainError, NamingConfig, name_fields
from proto_dissect.pipeline import InferOptions, infer_capture


@pytest.fixture()
def demo_types(tmp_path: Path):
    capture = tmp_path / "c.pcap"
    write_demo_pcap(capture)
    result = infer_capture(
        capture, InferOptions(out_dir=tmp_path / "out", tcp_port=9999, deterministic=True)
    )
    return result.facts.message_types


def test_off_provider_is_noop(demo_types) -> None:
    prov = name_fields(demo_types, NamingConfig(provider="off"))
    assert prov.provider == "off"
    assert prov.dropped == 0


def test_valid_names_applied(demo_types, monkeypatch) -> None:
    mt = demo_types[0]
    field = mt.fields[0]
    raw = json.dumps(
        {
            "fields": [
                {
                    "id": field.id,
                    "name": "protocol_magic",
                    "description": "Magic constant identifying the protocol.",
                }
            ]
        }
    )
    config = _with_fake_response(raw, monkeypatch)
    prov = name_fields([mt], config)
    assert field.name == "protocol_magic"
    assert field.description == "Magic constant identifying the protocol."
    assert prov.dropped == 0
    assert prov.model == "fake-model"


def test_grammar_violation_dropped(demo_types, monkeypatch) -> None:
    mt = demo_types[0]
    field = mt.fields[0]
    original = field.name
    raw = json.dumps({"fields": [{"id": field.id, "name": "Not a valid name!"}]})
    prov = name_fields([mt], _with_fake_response(raw, monkeypatch))
    assert field.name == original  # deterministic default kept
    assert prov.dropped == 1


def test_uncited_field_dropped(demo_types, monkeypatch) -> None:
    mt = demo_types[0]
    field = mt.fields[0]
    raw = json.dumps({"fields": [{"id": "F9999", "name": "made_up_field"}]})
    prov = name_fields([mt], _with_fake_response(raw, monkeypatch))
    assert field.name != "made_up_field"
    assert prov.dropped == 1


def test_duplicate_names_dropped(demo_types, monkeypatch) -> None:
    mt = demo_types[0]
    if len(mt.fields) < 2:
        pytest.skip("need two fields")
    f1, f2 = mt.fields[0], mt.fields[1]
    raw = json.dumps(
        {"fields": [{"id": f1.id, "name": "same_name"}, {"id": f2.id, "name": "same_name"}]}
    )
    prov = name_fields([mt], _with_fake_response(raw, monkeypatch))
    assert prov.dropped >= 1
    # exactly one field got the name
    named = [f for f in mt.fields if f.name == "same_name"]
    assert len(named) == 1


def test_unparseable_output_drops_all(demo_types, monkeypatch) -> None:
    mt = demo_types[0]
    original = [f.name for f in mt.fields]
    prov = name_fields([mt], _with_fake_response("not json", monkeypatch))
    assert [f.name for f in mt.fields] == original
    assert prov.dropped == len(mt.fields)


def test_offline_config_requires_url() -> None:
    with pytest.raises(ExplainError):
        NamingConfig(provider="openai-compat").resolved_url()


def _with_fake_response(raw: str, monkeypatch: pytest.MonkeyPatch) -> NamingConfig:
    """Patch the chat transport to return a canned response (auto-cleaned)."""
    import proto_dissect.explain as ex

    monkeypatch.setattr(ex, "_chat", lambda *a, **k: raw)
    return NamingConfig(provider="openai-compat", url="http://127.0.0.1:1/v1", model="fake-model")


def test_chat_url_error_wrapped(monkeypatch) -> None:
    import urllib.request

    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(ExplainError, match="unreachable"):
        from proto_dissect.explain import _chat

        _chat("http://127.0.0.1:1/v1", "m", "s", "u", None, 1)
