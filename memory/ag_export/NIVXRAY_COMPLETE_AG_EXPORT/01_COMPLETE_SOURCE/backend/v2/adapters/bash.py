"""Adapter STUB · Bash (Phase 1)."""
from __future__ import annotations

from v2.adapters.base import BaseAdapter
from v2.adapters.registry import register


@register
class BashAdapter(BaseAdapter):
    name = "bash"
    version = "0.1.0-stub"
    supported_formats = ("sh", "bash", "text")
    capabilities = frozenset({"single-shot"})
    cem_version = "v1"
