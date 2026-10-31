"""Generic fallback normalizer.

When no vendor signature matches, we STILL want a CEMv1 to hand to the
Investigation Graph — the pipeline must never stop because vendor
detection was ambiguous. This normalizer emits a `generic` event per
input record and preserves the raw fields for downstream artefact
discovery.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List

from nivxforge.investigation.cem import (
    CanonicalEvent,
    CanonicalEventModel,
    EventKind,
    Process,
    VendorAdapter,
)
from ..parser import ParsedInput
from .base import make_provenance


class GenericNormalizer(VendorAdapter):
    vendor = "Generic"
    adapter_id = "generic"

    def can_parse(self, raw_input: str) -> bool:  # pragma: no cover
        return True

    def normalize(self, parsed: ParsedInput) -> CanonicalEventModel:
        prov = make_provenance(self.adapter_id, self.vendor, confidence=0.5)
        events: List[CanonicalEvent] = []
        for rec in parsed.records or []:
            if not isinstance(rec, dict):
                rec = {"_value": rec}
            cmd_line = _first_cmd_like(rec)
            process = None
            if cmd_line:
                process = Process(command_line=cmd_line, provenance=prov)
            events.append(CanonicalEvent(
                event_id=str(uuid.uuid4()),
                kind=EventKind.generic,
                process=process,
                raw=rec,
                provenance=prov,
            ))
        # If parsed.records was empty but text present — still emit
        # one placeholder event so downstream stages can operate on
        # raw text via artifact discovery.
        if not events and parsed.text:
            events.append(CanonicalEvent(
                event_id=str(uuid.uuid4()),
                kind=EventKind.generic,
                process=Process(command_line=parsed.text, provenance=prov),
                raw={"_text": parsed.text[:8000]},
                provenance=prov,
            ))
        return CanonicalEventModel(
            vendor=self.vendor,
            vendor_route=self.adapter_id,
            events=events,
            provenance=prov,
        )


_CMD_KEYS = (
    "command_line", "CommandLine", "commandline", "cmdline", "cmdLine",
    "process_command_line", "processCommandLine",
    "ScriptBlockText", "EncodedCommand", "Payload",
)


def _first_cmd_like(rec: Dict[str, Any]) -> str | None:
    # Case-insensitive to catch cmdLine / CMDLine / etc.
    lower_map = {k.lower(): k for k in rec.keys()}
    for target in _CMD_KEYS:
        hit = lower_map.get(target.lower())
        if hit and isinstance(rec[hit], str) and rec[hit].strip():
            return rec[hit]
    # nested one level
    for v in rec.values():
        if isinstance(v, dict):
            hit = _first_cmd_like(v)
            if hit:
                return hit
    return None


__all__ = ["GenericNormalizer"]
