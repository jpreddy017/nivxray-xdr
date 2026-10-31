"""Adapter STUB · Generic JSON events (Phase 1)."""
from __future__ import annotations

from v2.adapters.base import BaseAdapter
from v2.adapters.registry import register


@register
class JsonEventsAdapter(BaseAdapter):
    name = "json_events"
    version = "0.1.0-stub"
    supported_formats = ("json", "jsonl", "ndjson")
    capabilities = frozenset({"stream"})
    cem_version = "v1"
