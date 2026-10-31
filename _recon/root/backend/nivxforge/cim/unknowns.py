"""ADR-0009 §2.2 · Deterministic Unknowns generator.

Rules are pure functions over a `FactSubstrate`. Each rule returns
`Optional[Unknown]`. The composer runs all rules in a fixed order so
the output list is reproducible for a given input.

New rules require a real-world observation entry in `REAL_WORLD_LOG.md`
(governance discipline).
"""
from __future__ import annotations

from typing import Optional, List

from nivxforge.cim.fact_substrate import FactSubstrate
from nivxforge.cim.models import Unknown


def _rule_no_process_telemetry(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    if not fs.telemetry_processes:
        return Unknown(
            id=next_id,
            text="Parent process unknown — no process telemetry supplied.",
            rule_id="U-RULE-NO-PROCESS",
        )
    return None


def _rule_no_commandline(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    # Commandline is inferrable from the input text if it starts with an exe/cmd shape.
    has_cmdline = False
    if fs.input_text:
        lower = fs.input_text[:200].lower()
        for m in ("powershell", "cmd.exe", "cmd ", "certutil", "wscript", "mshta", "rundll32"):
            if m in lower:
                has_cmdline = True
                break
    if not has_cmdline and not fs.telemetry_processes:
        return Unknown(
            id=next_id,
            text="Execution command line unknown — artifact did not include a shell/exec invocation.",
            rule_id="U-RULE-NO-CMDLINE",
        )
    return None


def _rule_no_network_telemetry(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    if not fs.telemetry_network:
        return Unknown(
            id=next_id,
            text="No network telemetry — connection outcome cannot be confirmed from this evidence.",
            rule_id="U-RULE-NO-NETWORK",
        )
    return None


def _rule_no_memory_evidence(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    if not fs.telemetry_memory:
        return Unknown(
            id=next_id,
            text="Memory evidence unavailable — in-memory execution artifacts not present.",
            rule_id="U-RULE-NO-MEMORY",
        )
    return None


def _rule_no_user_context(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    if not fs.telemetry_authentication and not fs.telemetry_processes:
        return Unknown(
            id=next_id,
            text="User account context unknown — no authentication or process-owner telemetry.",
            rule_id="U-RULE-NO-USER",
        )
    return None


def _rule_no_registry_state(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    if not fs.telemetry_registry:
        return Unknown(
            id=next_id,
            text="Registry state unknown — no registry telemetry supplied.",
            rule_id="U-RULE-NO-REGISTRY",
        )
    return None


def _rule_no_authentication_logs(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    if not fs.telemetry_authentication:
        return Unknown(
            id=next_id,
            text="Authentication logs unavailable — cannot confirm identity vector.",
            rule_id="U-RULE-NO-AUTH",
        )
    return None


def _rule_no_initial_access(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    # Heuristic: no MITRE technique from the Initial Access tactic and no delivery telemetry.
    ia_present = any((h.tactic or "").lower() == "initial-access" for h in fs.mitre_hits)
    if not ia_present:
        return Unknown(
            id=next_id,
            text="Initial access vector unknown — no delivery-phase evidence in the supplied data.",
            rule_id="U-RULE-NO-INITIAL-ACCESS",
        )
    return None


def _rule_no_file_artifacts(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    has_hash_ioc = any(i.kind == "hash" for i in fs.iocs)
    if not fs.telemetry_files and not has_hash_ioc:
        return Unknown(
            id=next_id,
            text="No file artifacts observed — hash-based hunting is not possible with this evidence.",
            rule_id="U-RULE-NO-FILES",
        )
    return None


def _rule_no_time_window(fs: FactSubstrate, next_id: str) -> Optional[Unknown]:
    if not fs.telemetry_processes and not fs.telemetry_network:
        return Unknown(
            id=next_id,
            text="Activity time window unknown — no timestamped telemetry provided.",
            rule_id="U-RULE-NO-TIMEWINDOW",
        )
    return None


# Fixed rule order — do NOT reorder without a new REAL_WORLD_LOG.md entry.
_RULES = (
    _rule_no_process_telemetry,
    _rule_no_commandline,
    _rule_no_network_telemetry,
    _rule_no_memory_evidence,
    _rule_no_user_context,
    _rule_no_registry_state,
    _rule_no_authentication_logs,
    _rule_no_initial_access,
    _rule_no_file_artifacts,
    _rule_no_time_window,
)


def generate_unknowns(fs: FactSubstrate) -> List[Unknown]:
    """Run all rules in order; return the deterministic list of Unknowns."""
    out: List[Unknown] = []
    for i, rule in enumerate(_RULES, start=1):
        next_id = f"U-{i:03d}"
        u = rule(fs, next_id)
        if u is not None:
            out.append(u)
    return out
