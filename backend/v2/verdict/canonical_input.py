"""Canonical Verdict Input Contract — ADR-004 Step 1 Phase 3.

Owner directive (2026-08-10):
    "Do NOT make Engine A's EvidenceGraph shape the permanent canonical
     contract. Define a canonical verdict-input representation derived
     from the existing canonical investigation/evidence model. Legacy
     Engine A/B/D adapters may translate into that representation for
     parity testing, but the new canonical contract must not depend on
     any legacy verdict engine."

This module defines that canonical contract.

Design principles
─────────────────
1. **Source-of-truth**: `CanonicalVerdictInput` is derived from
   `v2.investigation.model.InvestigationModel` — the pre-existing
   9-bucket evidence model. No legacy verdict engine's shape leaks in.

2. **Engine-agnostic**: A `CanonicalVerdictInput` must be scorable by
   any verdict engine that speaks it. Adapters translate INTO this
   shape (from EvidenceGraph, RC5 Behaviors, PowerShell semantics, etc.)
   but never FROM it into a legacy shape at the boundary.

3. **Deterministic**: Same InvestigationModel bytes → same
   CanonicalVerdictInput bytes. No I/O, no LLM, no wall-clock.

4. **Preservation-first**: This contract does NOT redesign scoring or
   change any label semantics. Preserves Suspicious-as-floor and
   Runtime Dependent (per ADR-004 Step 1 owner directives).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# ══════════════════════════════════════════════════════════════════
# The canonical event shape — one per unit-of-observation
# ══════════════════════════════════════════════════════════════════
@dataclass
class CanonicalEvent:
    """One canonicalised observation of a process / file / network /
    registry / auth event. Any of the 9 InvestigationModel buckets can
    project into this shape.

    Field taxonomy is INTENTIONALLY the subset of engine C's
    (`v2/verdict/engine.py::score`) contract needed to make its
    detectors fire — because C is the ADR-004 canonical target — but
    it is populated from the InvestigationModel, not from EvidenceGraph.
    """
    # Identity & lane
    event_id:  str = ""
    lane:      str = ""             # "process" | "file" | "network" | "registry" | "auth"
    ts:        str = ""

    # Command / action / target
    command:   str = ""             # full command line if applicable
    action:    str = ""             # short verb (created / executed / deleted / beacon / …)
    target:    str = ""             # file path / registry key / URL / IP

    # Process context
    parent:    str = ""             # parent binary head (lower-case)
    process:   str = ""             # current binary head (lower-case)
    child:     str = ""             # child binary head (lower-case)
    user:      str = ""
    hostname:  str = ""

    # Signal enrichment
    mitre:     list[str]  = field(default_factory=list)   # ["T1003","T1055", …]
    rule_ids:  list[str]  = field(default_factory=list)   # ["MDE-DEFENDER-T1003", …]

    # File / network attributes
    sha256:    str = ""
    url:       str = ""
    domain:    str = ""
    ip_dst:    str = ""

    # Registry
    reg_path:      str = ""
    reg_persist:   bool = False

    # Threat intel
    ti_verdict:    str = ""         # "malicious" / "suspicious" / "benign" / ""
    ti_family:     str = ""

    # Free-form provenance (kept for explainability; NEVER used for scoring)
    source_bucket: str = ""         # which InvestigationModel bucket it came from
    provenance:    dict[str, Any] = field(default_factory=dict)

    def to_v2_event(self) -> dict[str, Any]:
        """Project into the shape `v2/verdict/engine.py::score(event, ctx)` wants.

        This is a PURE view — no scoring, no side effects. It exists
        so the canonical wrapper can invoke the v2 engine without the
        engine learning anything about our canonical schema.
        """
        return {
            "event_id":   self.event_id,
            "cmdline":    self.command,
            "command":    self.command,
            "action":     self.action,
            "target":     self.target,
            "lane":       self.lane,
            "mitre":      list(self.mitre),
            "rule_id":    (self.rule_ids[0] if self.rule_ids else None),
            "entity":     {"iid": f"{self.lane}:{self.process}"} if self.process else {},
            "parent":     ({"iid": self.parent, "name": self.parent}
                                if self.parent else {}),
            "signature":  {},   # populated only when signing telemetry is present
        }


# ══════════════════════════════════════════════════════════════════
# The canonical batch shape — one per case
# ══════════════════════════════════════════════════════════════════
@dataclass
class CanonicalVerdictInput:
    """The single canonical shape all verdict engines consume.

    A case has:
      · a set of `CanonicalEvent`s (from any/all 9 buckets), and
      · a small envelope of case-level metadata (incident, coverage)
        that engines can consult for corroboration but NEVER to score
        a single event by itself.
    """
    schema_version: str = "1.0"
    events:         list[CanonicalEvent]  = field(default_factory=list)
    incident_id:    str = ""
    detection_sources: list[str] = field(default_factory=list)
    coverage:       dict[str, bool] = field(default_factory=dict)

    # Optional pre-computed aggregations — populated by the builder for
    # convenience. Engines MAY use these for correlation, but MUST NOT
    # treat them as required inputs (fall-back to lane counts if absent).
    n_processes:   int = 0
    n_files:       int = 0
    n_network:     int = 0
    n_registry:    int = 0
    n_auth:        int = 0
    n_ti_hits:     int = 0

    # Free-form raw text preserved (only for explainability; NEVER for
    # scoring). Kept so legacy consumers that expect an `input_text`
    # field for logging can extract it without a special API.
    raw_text_normalised: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════
# THE canonical builder · InvestigationModel → CanonicalVerdictInput
# ══════════════════════════════════════════════════════════════════
_MITRE_BY_LOLBIN: dict[str, list[str]] = {
    # Deterministic lolbin → MITRE technique base map.
    # Extend here (not in detector logic) so scoring engines stay pure.
    "powershell":  ["T1059.001"],
    "pwsh":        ["T1059.001"],
    "cmd":         ["T1059.003"],
    "wscript":     ["T1059.005"],
    "cscript":     ["T1059.005"],
    "mshta":       ["T1218.005"],
    "rundll32":    ["T1218.011"],
    "regsvr32":    ["T1218.010"],
    "certutil":    ["T1140", "T1105"],
    "bitsadmin":   ["T1197", "T1105"],
    "msiexec":     ["T1218.007"],
    "wmic":        ["T1047"],
    "schtasks":    ["T1053.005"],
}

_MITRE_BY_KEYWORD: list[tuple[str, list[str]]] = [
    ("lsass",                     ["T1003.001"]),
    ("reg save",                  ["T1003.002"]),
    ("comsvcs.dll",               ["T1003.001"]),
    ("procdump",                  ["T1003.001"]),
    ("vssadmin",                  ["T1490"]),
    ("wbadmin",                   ["T1490"]),
    ("-encodedcommand",           ["T1027", "T1059.001"]),
    ("set-mppreference -disable", ["T1562.001"]),
    ("windefend",                 ["T1562.001"]),
    ("eventfilter",               ["T1546.003"]),
    ("commandlineeventconsumer",  ["T1546.003"]),
    ("register-scheduledtask",    ["T1053.005"]),
    ("iex ",                      ["T1059.001"]),
    ("invoke-expression",         ["T1059.001"]),
    ("downloadstring",            ["T1059.001", "T1105"]),
    ("amsiutils",                 ["T1562.001"]),
]


def _mitre_for_command(cmd: str) -> list[str]:
    """Deterministic MITRE tagging for a command string.

    NOT a scoring change — this ENRICHES the canonical input so scoring
    engines can consume a well-tagged event. Every keyword mapping is
    ATT&CK-documented; adding a new mapping is a one-line change.
    """
    if not cmd:
        return []
    low = cmd.lower()
    out: set[str] = set()

    # Head-token → technique
    head = low.split(None, 1)[0].split("\\")[-1]
    head = head.rsplit(".exe", 1)[0]
    for k, v in _MITRE_BY_LOLBIN.items():
        if head == k:
            out.update(v)
            break

    # Keyword → technique
    for kw, techs in _MITRE_BY_KEYWORD:
        if kw in low:
            out.update(techs)

    return sorted(out)


def _bin_head(cmd: str) -> str:
    """Extract the binary head (lower-case, .exe stripped) from a
    command line. Deterministic; no regex-per-event on hot path."""
    if not cmd:
        return ""
    head = cmd.strip().split(None, 1)[0]
    head = head.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return head.lower().rsplit(".exe", 1)[0]


def from_investigation_model(m) -> CanonicalVerdictInput:
    """Build the canonical verdict input from the canonical investigation
    model. This is the ONLY canonical builder.

    Legacy adapters (`from_evidence_graph`, `from_rc5_behaviors`,
    `from_ps_semantic`) exist for parity testing during migration but
    are NOT the architectural default; they must not evolve into
    permanent contracts.

    Args:
        m: A `v2.investigation.model.InvestigationModel` instance.
    """
    from v2.investigation.model import InvestigationModel
    if not isinstance(m, InvestigationModel):
        raise TypeError(
            "from_investigation_model requires an InvestigationModel; "
            "for legacy inputs use the appropriate `from_*` adapter."
        )

    events: list[CanonicalEvent] = []
    ev_id = 0

    def _nid() -> str:
        nonlocal ev_id
        ev_id += 1
        return f"E-{ev_id:04d}"

    # ── Process events ────────────────────────────────────────────
    for p in m.processes:
        cmd = p.command_line or p.process
        events.append(CanonicalEvent(
            event_id=_nid(),
            lane="process",
            ts=p.ts,
            command=cmd,
            action=(cmd.split(None, 1)[0] if cmd else ""),
            parent=_bin_head(p.parent),
            process=_bin_head(p.process),
            child=_bin_head(p.child),
            user=p.user,
            hostname=p.hostname,
            mitre=_mitre_for_command(cmd),
            source_bucket="process_activity",
        ))

    # ── File events ────────────────────────────────────────────────
    for f in m.files:
        events.append(CanonicalEvent(
            event_id=_nid(),
            lane="file",
            ts=f.ts,
            action=f.action,
            target=f.path,
            hostname=f.hostname,
            sha256=f.sha256,
            source_bucket="file_activity",
        ))

    # ── Network events ─────────────────────────────────────────────
    for n in m.network:
        events.append(CanonicalEvent(
            event_id=_nid(),
            lane="network",
            ts=n.ts,
            action=n.direction or "outbound",
            target=(n.url or n.domain or n.dst),
            url=n.url,
            domain=n.domain,
            ip_dst=n.dst,
            source_bucket="network_activity",
            provenance={"classification": n.classification},
        ))

    # ── Registry events ────────────────────────────────────────────
    for r in m.registry:
        events.append(CanonicalEvent(
            event_id=_nid(),
            lane="registry",
            ts=r.ts,
            action=r.action,
            target=r.path,
            reg_path=r.path,
            reg_persist=r.is_persistence,
            hostname=r.hostname,
            source_bucket="registry_activity",
        ))

    # ── Auth events ────────────────────────────────────────────────
    for a in m.auth:
        events.append(CanonicalEvent(
            event_id=_nid(),
            lane="auth",
            ts=a.ts,
            action=a.kind,
            target=a.dst_host,
            user=a.user,
            hostname=a.src_host,
            source_bucket="authentication_activity",
        ))

    # ── Threat intelligence — attached to any event that references
    # the same IOC, plus captured as a case-level tally.
    n_ti = len([t for t in m.ti
                    if (t.verdict or "").lower() in ("malicious", "suspicious")])
    for t in m.ti:
        events.append(CanonicalEvent(
            event_id=_nid(),
            lane="ti",
            action="ti_hit",
            target=t.value,
            ti_verdict=t.verdict,
            ti_family=t.family,
            source_bucket="threat_intel",
            provenance={"source": t.source, "detection_name": t.detection_name},
        ))

    return CanonicalVerdictInput(
        schema_version="1.0",
        events=events,
        incident_id=m.incident.incident_id,
        detection_sources=list(m.incident.detection_sources),
        coverage=m._coverage(),
        n_processes=len(m.processes),
        n_files=len(m.files),
        n_network=len(m.network),
        n_registry=len(m.registry),
        n_auth=len(m.auth),
        n_ti_hits=n_ti,
        raw_text_normalised=(m.raw_text or "")[:4000],
    )


# ══════════════════════════════════════════════════════════════════
# Legacy adapters — PARITY REFERENCES ONLY
# ══════════════════════════════════════════════════════════════════
def from_commands(cmds: list[str]) -> CanonicalVerdictInput:
    """Shim: build a CanonicalVerdictInput from a plain command list.

    Used by tests / the diff report where no full InvestigationModel
    has been assembled. NOT a permanent contract.
    """
    m_events: list[CanonicalEvent] = []
    for i, cmd in enumerate(cmds, start=1):
        m_events.append(CanonicalEvent(
            event_id=f"E-{i:04d}",
            lane="process",
            command=cmd,
            action=(cmd.split(None, 1)[0] if cmd else ""),
            process=_bin_head(cmd),
            mitre=_mitre_for_command(cmd),
            source_bucket="commands_shim",
        ))
    return CanonicalVerdictInput(
        schema_version="1.0",
        events=m_events,
        n_processes=len(cmds),
        raw_text_normalised="\n".join(cmds)[:4000],
    )


__all__ = [
    "CanonicalEvent",
    "CanonicalVerdictInput",
    "from_investigation_model",
    "from_commands",
]
