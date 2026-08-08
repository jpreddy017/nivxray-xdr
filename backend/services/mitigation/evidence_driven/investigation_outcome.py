"""Investigation-Outcome schema · the single structured input the
Evidence-Driven Recommendation Engine consumes.

Per user directive (2026-02-04):

    The Recommendation Engine must consume the Workspace's already-
    produced investigation outcome — NOT re-run analysis on the
    original payload.  Workspace discovers → Engine reasons over
    what Workspace discovered.

This module defines the STABLE contract between the two systems.
The Workspace is free to construct an ``InvestigationOutcome`` from
its own SSOT/RTE/UAIE surfaces however it likes — this schema is
the only thing the engine promises to consume.

Schema is deliberately additive: unknown keys are silently ignored,
missing keys default to empty collections.  The engine never fails
because a Workspace revision left a field out.
"""
from __future__ import annotations

from typing import Any, Dict, List

INVESTIGATION_OUTCOME_SCHEMA_VERSION = 1


def empty_outcome() -> Dict[str, Any]:
    """A default outcome shape — useful for tests + as documentation
    of every field the engine consumes."""
    return {
        "schema_version": INVESTIGATION_OUTCOME_SCHEMA_VERSION,

        # ── Verdict ─────────────────────────────────────────────
        "verdict":  {"severity": "informational", "one_liner": ""},

        # ── 1. Observed Evidence ─────────────────────────────────
        "processes":       [],
        "commands":        [],
        "files":           [],
        "registry_keys":   [],
        "users":           [],
        "hosts":           [],
        "artifacts":       [],
        "output_text":     "",

        # ── 2. Detection Types ───────────────────────────────────
        "detection_types": [],   # ["signature","behavioural",...]

        # ── 3. Behaviors (Workspace-detected, not string-matched) ─
        "behaviors":       [],   # ["execution","persistence","c2",...]

        # ── 4. MITRE ATT&CK ──────────────────────────────────────
        "mitre_techniques": [],  # ["T1059.001","T1055",...]

        # ── 5. Malware Intelligence ──────────────────────────────
        "malware": {
            "family":       None,
            "capabilities": [],
        },

        # ── 6. APT / Threat-Actor Intelligence ───────────────────
        "apt": {
            "group":      None,
            "confidence": "",     # "" | "low" | "medium" | "high"
        },

        # ── 7. LOLBAS / Tool Intelligence ────────────────────────
        "lolbas_hits":     [],

        # ── 8. IOC / Infrastructure ──────────────────────────────
        "iocs": {
            "ips":     [],
            "domains": [],
            "urls":    [],
            "hashes":  [],
        },

        # ── 9. Attack Pattern / Correlation ──────────────────────
        "attack_pattern": {
            "obfuscation_layers": 0,
            "kill_chain_phases":  [],
        },

        # ── 10. Impact ────────────────────────────────────────────
        "impacts":          [],  # ["data_encrypted","credential_exposed",...]
        "reached_shellcode": False,

        # ── 11. Scope & Criticality ──────────────────────────────
        "scope": {
            "affected_hosts":              0,
            "privileged_users_affected":   0,
            "critical_assets_affected":    0,
        },

        # ── 12. Confidence ───────────────────────────────────────
        "detection_confidence":       "low",     # low|medium|high|confirmed
        "false_positive_indicators":  [],
    }


__all__ = ["INVESTIGATION_OUTCOME_SCHEMA_VERSION", "empty_outcome"]
