"""v2/ikb — Investigation Knowledge Base.

Structured corpus of Windows-internals & telemetry-source knowledge that
powers the deterministic engine. Not a documentation library — a
machine-readable corpus consumed by:

    · signals.py         — context-aware detection rules
    · attack_story.py    — richer sentence generation
    · explainability.py  — negative reasoning ("why isn't this X?")
    · Phase 6 ingestion  — auto-normalisation & source detection

Schema (`schema.py`):
    KBEntry
      id              — canonical stable id, e.g. "windows_binary:svchost.exe"
      kind            — windows_binary | windows_event | telemetry_source |
                        registry_key | mitre_technique | enterprise_baseline
      label           — human-friendly display name
      category        — sub-classification (service_host, error_reporting, …)
      normal_behavior — expected parents, children, paths, cmdlines, network, …
      common_abuse    — list of {pattern, reason, mitre[], severity}
      detection_guidance
      false_positives — legitimate-usage patterns that mimic abuse
      mitre           — technique IDs this KB entry relates to
      correlation_rules — hints for the correlation engine
      references      — external documentation URLs

Public API:
    from v2.ikb import lookup, all_entries, ENTRIES
    entry = lookup("windows_binary:svchost.exe")
"""
from .schema import KBEntry, KIND_CHOICES
from .entries import ENTRIES, lookup, all_entries

__all__ = ["KBEntry", "KIND_CHOICES", "ENTRIES", "lookup", "all_entries"]
