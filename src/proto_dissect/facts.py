"""Facts document assembly (facts.json schema v1, frozen)."""

from __future__ import annotations

from typing import Any

from . import __version__
from .models import (
    CaptureMeta,
    FactsDoc,
    Flow,
    MessageType,
    NamingProvenance,
    SessionInfo,
    ValidationReport,
)

SCHEMA_VERSION = 1


def build_facts(
    session: tuple[str, str | None, CaptureMeta, dict[str, Any]],
    flows: list[Flow],
    message_types: list[MessageType],
    validation: ValidationReport,
    naming: NamingProvenance | None,
) -> FactsDoc:
    """Assemble the facts document from pipeline output (deterministic)."""
    sid, created, capture_meta, config = session
    return FactsDoc(
        schema_version=SCHEMA_VERSION,
        tool_name="protodissect",
        tool_version=__version__,
        session=SessionInfo(id=sid, created_utc=created, capture=capture_meta, config=dict(config)),
        flows=flows,
        message_types=message_types,
        validation=validation,
        naming=naming,
    )
