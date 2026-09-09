"""Adapter STUB · CMD (Phase 1)."""
from __future__ import annotations

from v2.adapters.base import BaseAdapter
from v2.adapters.registry import register


@register
class CmdAdapter(BaseAdapter):
    name = "cmd"
    version = "0.1.0-stub"
    supported_formats = ("bat", "cmd", "text")
    capabilities = frozenset({"single-shot"})
    cem_version = "v1"
