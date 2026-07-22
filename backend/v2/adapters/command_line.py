"""Adapter STUB · Command Line (Phase 1).

Wraps the raw-string input path that `/api/rc5/parse` already
accepts. Zero logic here — the RC5 endpoint continues to serve its
existing behaviour unchanged. Adapter logic ships in a later phase
under `NIVX_FLAG_ADAPTERS=shadow`.
"""
from __future__ import annotations

from v2.adapters.base import BaseAdapter
from v2.adapters.registry import register


@register
class CommandLineAdapter(BaseAdapter):
    name = "command_line"
    version = "0.1.0-stub"
    supported_formats = ("text",)
    capabilities = frozenset({"single-shot"})
    cem_version = "v1"
