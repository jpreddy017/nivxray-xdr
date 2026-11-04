"""R28.10 · Capability Discovery Report — pure derivation from
``OrchestratorResult`` + ``Capability Registry`` + ``Termination
Certificate``.  Analyst-facing "what happened and why".

Four sections per artifact:

    1. Applicable Capabilities   (registry says they *could* run here)
    2. Executed                  (planner actually ran them)
    3. Produced                  (new artifact types that surfaced)
    4. Not Applicable            (with human-readable reason)

Plus a global Coverage Summary + Termination block.

DESIGN INVARIANT — this file writes ZERO new state.  If a field
cannot be derived from existing tracking, the missing tracking
belongs in the orchestrator, not here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ArtifactDiscoverySection:
    artifact_uri:            str
    artifact_type:           str
    applicable_capabilities: List[str]  = field(default_factory=list)
    executed:                List[str]  = field(default_factory=list)
    produced_types:          List[str]  = field(default_factory=list)
    not_applicable:          List[Dict[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class CoverageSummary:
    registered:            int = 0
    applicable:            int = 0
    executed:              int = 0
    produced_new_artifacts: int = 0
    produced_evidence:     int = 0
    remaining_applicable:  int = 0


@dataclass(frozen=True)
class TerminationSection:
    fixed_point:  bool           = False
    reason:       str            = ""
    meta:         Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilityDiscoveryReport:
    per_artifact: List[ArtifactDiscoverySection] = field(default_factory=list)
    coverage:     CoverageSummary = field(default_factory=CoverageSummary)
    termination:  TerminationSection = field(default_factory=TerminationSection)

    def as_text(self) -> str:
        """Render the analyst-facing plain-text view (four sections
        per artifact + coverage + termination)."""
        lines: List[str] = ["Capability Discovery Report", "═" * 32, ""]
        for sec in self.per_artifact:
            lines.append(f"Artifact:  {sec.artifact_type}")
            lines.append(f"  URI:     {sec.artifact_uri[-16:]}")
            lines.append("")
            lines.append("  Applicable Capabilities")
            for c in sec.applicable_capabilities:
                lines.append(f"    ✓ {c}")
            if not sec.applicable_capabilities:
                lines.append("    · (none applicable)")
            lines.append("")
            lines.append("  Executed")
            for c in sec.executed:
                lines.append(f"    ✓ {c}")
            if not sec.executed:
                lines.append("    · (none executed)")
            lines.append("")
            lines.append("  Produced")
            for t in sec.produced_types:
                lines.append(f"    • {t}")
            if not sec.produced_types:
                lines.append("    · (no new artifacts)")
            lines.append("")
            lines.append("  Not Applicable")
            for na in sec.not_applicable[:20]:
                lines.append(f"    • {na.get('capability')}")
                lines.append(f"      Reason: {na.get('reason')}")
            if not sec.not_applicable:
                lines.append("    · (all registered capabilities applied)")
            lines.append("")
        c = self.coverage
        lines.append("Coverage Summary")
        lines.append("─" * 32)
        lines.append(f"  Registered:            {c.registered}")
        lines.append(f"  Applicable:            {c.applicable}")
        lines.append(f"  Executed:              {c.executed}")
        lines.append(f"  Produced New Artifacts: {c.produced_new_artifacts}")
        lines.append(f"  Produced Evidence:      {c.produced_evidence}")
        lines.append(f"  Remaining Applicable:   {c.remaining_applicable}")
        lines.append("")
        lines.append("Termination")
        lines.append("─" * 32)
        lines.append(f"  Fixed Point: {'YES' if self.termination.fixed_point else 'NO'}")
        lines.append(f"  Reason:      {self.termination.reason}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# Builder
# ══════════════════════════════════════════════════════════════════
def build_discovery_report(orchestrator_result) -> CapabilityDiscoveryReport:
    """Pure derivation — no side effects.

    The Capability Registry is the union of TWO first-class registries
    the orchestrator consults on every artifact:

      * ``services.uaie.contract`` — modern contract-registered
        capabilities (``CapabilityContract`` + ``impl``).
      * ``services.uaie.capability`` — legacy per-artifact-type
        registry (``_REGISTRY`` keyed by ``requires_artifact_type``).

    Both must be counted, otherwise the report shows nonsense math
    (executed >> applicable) because most executed capabilities are
    still registered via the legacy path.
    """
    from .contract   import all_contracts, applicable_contracts
    from .capability import _REGISTRY as _LEGACY_REG, for_type as _legacy_for_type

    artifacts = getattr(orchestrator_result, "artifacts", {}) or {}
    ledger    = getattr(orchestrator_result, "ledger",    None)
    evidence  = getattr(orchestrator_result, "evidence",  []) or []
    termcert  = getattr(orchestrator_result,
                          "termination_certificate", None)

    # ── Build "executed" map: artifact_uri → [capability names] ──
    # Also collect skipped per URI so "applicable" reflects everything
    # the orchestrator considered — not just what the current registry
    # snapshot advertises for the declared type.  This keeps the math
    # coherent when a capability runs by virtue of a matched-type union
    # even though its ``requires_artifact_type`` list doesn't include
    # the artifact's declared type verbatim.
    executed_by_uri: Dict[str, List[str]] = {}
    skipped_by_uri:  Dict[str, List[str]] = {}
    produced_by_uri: Dict[str, List[str]] = {}
    # ``Ledger`` exposes iteration + ``snapshot()``; there is no
    # ``.entries`` attribute.  Iterate directly and fall back to
    # ``snapshot`` for objects that only expose the serialised form.
    if ledger is None:
        entries = []
    else:
        try:
            entries = list(ledger)
        except TypeError:
            try:
                entries = list(ledger.snapshot())
            except Exception:
                entries = []
    for ent in entries:
        act = getattr(ent, "action", "")
        uri  = getattr(ent, "artifact_uri", None) or ""
        actor = getattr(ent, "actor", "") or ""
        if act == "schedule_skip" and actor and uri:
            skipped_by_uri.setdefault(uri, []).append(actor)
            continue
        if act != "execute":
            continue
        if actor:
            executed_by_uri.setdefault(uri, []).append(actor)
        # Collect the types of every produced child.
        for c_uri in (getattr(ent, "children_uris", None) or
                        getattr(ent, "child_uris", None) or []):
            child = artifacts.get(c_uri)
            if child is not None:
                produced_by_uri.setdefault(uri, []).append(
                    getattr(child, "artifact_type", "unknown"))

    # ── Registry snapshot ────────────────────────────────────────
    try:
        all_ct = list(all_contracts())
    except Exception:
        all_ct = []
    # Union both registries by capability *name*.  Contract IDs and
    # legacy capability names share the same reverse-DNS convention
    # (``transformer.byte_array_xor_loop`` etc.) so a set-union by
    # string is safe and de-dupes double-registered plugins.
    contract_names = {c.id for c in all_ct}
    legacy_names: set = set()
    for _t, caps in _LEGACY_REG.items():
        for cap in caps:
            n = getattr(cap, "name", None)
            if n:
                legacy_names.add(n)
    total_registered = len(contract_names | legacy_names)
    ct_by_id = {c.id: c for c in all_ct}
    # Set of artifact types present in this investigation.
    present_types = {getattr(a, "artifact_type", "")
                       for a in artifacts.values()}

    # ── Per-artifact sections ────────────────────────────────────
    per: List[ArtifactDiscoverySection] = []
    total_applicable = 0
    total_executed   = 0
    remaining_applicable = 0
    for uri, a in artifacts.items():
        atype = getattr(a, "artifact_type", "unknown")
        # Applicable = every capability the orchestrator considered
        # for this artifact — that is: contract-registered for the
        # declared type ∪ legacy-registered for the declared type ∪
        # every capability observed executing OR being skipped against
        # this URI in the ledger.  The last two clauses close the gap
        # opened by the matched-type union in the orchestrator: caps
        # can legitimately execute on an artifact whose *declared*
        # type isn't in their ``requires_artifact_type`` list because
        # a recognizer promoted a secondary type.
        applicable_set: set = set()
        try:
            for c in applicable_contracts(atype):
                applicable_set.add(c.id)
        except Exception:
            pass
        try:
            for cap in _legacy_for_type(atype):
                n = getattr(cap, "name", None)
                if n:
                    applicable_set.add(n)
        except Exception:
            pass
        applicable_set.update(executed_by_uri.get(uri, []))
        applicable_set.update(skipped_by_uri.get(uri, []))
        applicable = sorted(applicable_set)
        exec_list  = sorted(set(executed_by_uri.get(uri, [])))
        produced   = sorted(set(produced_by_uri.get(uri, [])))
        total_applicable += len(applicable)
        total_executed   += len(exec_list)
        # Not-applicable = every registered capability minus applicable
        not_appl: List[Dict[str, str]] = []
        appl_set = applicable_set
        for ct in all_ct:
            if ct.id in appl_set:
                continue
            requires = list(getattr(ct, "requires", []) or [])
            if not requires:
                continue
            reason: str
            if "*" in requires:
                # universal — should always be applicable; skip
                continue
            missing = [r for r in requires
                          if r not in present_types and r != atype]
            if missing:
                reason = ("Requires artifact type: " +
                          " / ".join(missing))
            else:
                reason = "Not selected by the planner for this artifact"
            not_appl.append({"capability": ct.id, "reason": reason})
        # Applicable-but-not-executed → tally for remaining
        remaining_applicable += len(
            [x for x in applicable if x not in exec_list])
        per.append(ArtifactDiscoverySection(
            artifact_uri            = uri,
            artifact_type           = atype,
            applicable_capabilities = applicable,
            executed                = exec_list,
            produced_types          = produced,
            not_applicable          = sorted(not_appl,
                                              key=lambda d: d["capability"])[:20],
        ))

    # ── Coverage summary ────────────────────────────────────────
    produced_new_artifacts = sum(len(v) for v in produced_by_uri.values())
    coverage = CoverageSummary(
        registered            = total_registered,
        applicable            = total_applicable,
        executed              = total_executed,
        produced_new_artifacts = produced_new_artifacts,
        produced_evidence     = len(evidence),
        remaining_applicable  = remaining_applicable,
    )

    # ── Termination ─────────────────────────────────────────────
    fp = bool(getattr(termcert, "fixed_point", False)) if termcert else False
    reason = ""
    if fp:
        reason = ("No remaining capability can produce a new "
                    "analyzable artifact.")
    elif termcert is not None:
        reason = (getattr(termcert, "reason", None) or
                    "Queue drained without full applicability coverage.")
    else:
        reason = "No termination certificate emitted."
    termination = TerminationSection(
        fixed_point=fp, reason=reason, meta={},
    )
    return CapabilityDiscoveryReport(
        per_artifact=per, coverage=coverage, termination=termination,
    )


__all__ = [
    "ArtifactDiscoverySection", "CoverageSummary", "TerminationSection",
    "CapabilityDiscoveryReport", "build_discovery_report",
]
