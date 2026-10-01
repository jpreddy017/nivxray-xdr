"""Adapter STUB · PowerShell (Phase 1)."""
from __future__ import annotations

from v2.adapters.base import BaseAdapter
from v2.adapters.registry import register


@register
class PowerShellAdapter(BaseAdapter):
    name = "powershell"
    version = "0.1.0-stub"
    supported_formats = ("ps1", "psm1", "text")
    capabilities = frozenset({"single-shot", "encoded-command"})
    cem_version = "v1"
