"""UAIE · Capability Profiles.

Profiles group plugins so the orchestrator can filter which capabilities
apply to a given investigation:

    minimal      · fastest smoke path — decoders only
    enterprise   · production analyst default (decoders + analyzers +
                   family builders)
    malware      · deep malware analysis (adds PE, CS, RC4, XOR-brute,
                   shellcode analyzer, evidence emitters)
    memory       · memory-image workflows
    office       · Office document workflows
    powershell   · PowerShell-heavy loaders
    network      · PCAP / DNS / HTTP-focused
    universal    · every registered plugin (default when no profile set)

Profile membership is stamped by ``capability_adapter.adapt_and_register``
via the ``profiles=`` argument and looked up here.

Usage
─────
    from services.uaie.capability_profiles import recognizers_for

    recs = recognizers_for("malware")   # only malware-profile plugins
    orch = Orchestrator(recognizers=recs)
"""
from __future__ import annotations

from typing  import List

from .recognizer import Recognizer
from . import plugins as _plugin_registry


PROFILES = (
    "minimal", "enterprise", "malware", "memory",
    "office",  "powershell", "network",  "universal",
)


def plugins_for(profile: str) -> List[dict]:
    """All plugin dicts belonging to the requested profile."""
    profile = (profile or "universal").lower()
    out: List[dict] = []
    for p in _plugin_registry.all_plugins():
        ps = p.get("profiles") or ["universal"]
        if profile == "universal" or profile in ps:
            out.append(p)
    return out


def recognizers_for(profile: str) -> List[Recognizer]:
    return [p["recognizer"] for p in plugins_for(profile)]


def summarise() -> dict:
    """Diagnostic: {profile → [plugin_name, ...]} for the health dashboard."""
    out: dict = {p: [] for p in PROFILES}
    for p in _plugin_registry.all_plugins():
        for prof in (p.get("profiles") or ["universal"]):
            if prof in out:
                out[prof].append(p["name"])
    return out


__all__ = ["PROFILES", "plugins_for", "recognizers_for", "summarise"]
