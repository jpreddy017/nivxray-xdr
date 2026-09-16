"""Malware Family Intelligence plugins (RC2.1a).

Each family plugin subclasses `FamilyPlugin` (see `_base.py`), defines a
weighted signature table, and emits a rich `FamilyHint` with:
    - confidence (calibrated 0.0-1.0)
    - structured `evidence_items` list
    - per-family MITRE techniques
    - auto-generated YARA rule suggestion
    - optional AtomicRedTeam pointer

Family plugins never transform bytes. `PluginResult.output == payload`.
The orchestrator's existing `emitted_signals` branch adds them to the
trace, and the `family-identified` terminal state fires when confidence
>= 0.8.
"""
from __future__ import annotations
