"""Round 32 · Process / Command-line / LOLBAS capabilities.

Reuses existing NivXRay engines:
  * ``lolbas.scan_lolbas`` — LOLBAS argv pattern matcher.
  * ``smart_decoder.smart_decode`` — encoded-command decoder chain.
  * ``decoders.ioc_extractor._extract_all`` — IOC extractor.

None of these capabilities fabricate process telemetry.  When the
incident does not carry endpoint telemetry (network-only alert, e.g.
Snort golden), each capability honestly returns PARTIAL or
INSUFFICIENT and emits a NOT_OBSERVED finding — the gap remains
open for a future EDR feed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from services.investigator.capabilities.base import (
    Capability, EvidenceSufficiency, fid, now_iso,
)
from services.investigator.models import Finding


def _process_from_canonical(canonical: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not canonical:
        return {}
    return canonical.get("process") or {}


# ── Process ancestry ────────────────────────────────────────────────

class ProcessAncestryCapability(Capability):
    id = "process_ancestry"
    name = "Process Ancestry"
    engine = "nivxray::investigator::process_ancestry"
    category = "endpoint"
    investigation_question = (
        "What is the parent-child execution chain for the process(es) "
        "on this incident, and is any relationship anomalous "
        "(e.g., Office → shell, browser → interpreter)?"
    )
    evidence_requirements = ("canonical.process.name", "canonical.process.parent")
    availability = "cap-full"
    gaps_closed_hint = ("process_lineage.absent",)

    # Deterministic anomaly patterns.  Any of these observed → SUSPICIOUS.
    _ANOMALY_PARENTS = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msaccess.exe", "acrord32.exe", "acrobat.exe", "chrome.exe",
        "firefox.exe", "iexplore.exe", "msedge.exe",
    }
    _ANOMALY_CHILDREN = {
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "msiexec.exe",
    }

    def check_evidence(self, incident, canonical):
        proc = _process_from_canonical(canonical)
        if not proc.get("name"):
            return "INSUFFICIENT", "no process telemetry on canonical evidence"
        if not proc.get("parent") and not proc.get("parent_name"):
            return "PARTIAL", "process observed but no parent lineage"
        return "SUFFICIENT", "process + parent available"

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        proc = _process_from_canonical(canonical)
        proc_name = str(proc.get("name") or "").lower()
        parent = proc.get("parent") or {}
        if isinstance(parent, str):
            parent_name = parent.lower()
        else:
            parent_name = str(parent.get("name") or proc.get("parent_name") or "").lower()

        if not proc_name:
            return [Finding(
                finding_id=fid(f"{incident_id}|proc_anc|none"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="process_ancestry",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED", confidence=0,
                summary="No process telemetry observed for this incident.",
                evidence_refs=[],
                reasoning=(
                    "canonical evidence carries no process.name — "
                    "endpoint plane not correlated (likely network-only alert)."
                ),
                created_at=now_iso(),
            )], []

        anomalous = (parent_name in self._ANOMALY_PARENTS
                        and proc_name in self._ANOMALY_CHILDREN)
        state = "CORRELATED" if anomalous else "OBSERVED"
        summary = (
            f"Anomalous parent→child: {parent_name} → {proc_name}"
            if anomalous else
            f"Process ancestry: {parent_name or '(unknown)'} → {proc_name}"
        )
        return [Finding(
            finding_id=fid(f"{incident_id}|proc_anc|{parent_name}|{proc_name}"),
            tenant_id=tenant_id, incident_id=incident_id,
            execution_id=pivot.pivot_id,
            capability=self.id, engine=self.engine,
            kind="process_ancestry",
            subject_kind="process", subject_value=proc_name,
            state=state,
            confidence=75 if anomalous else 50,
            summary=summary,
            evidence_refs=[canonical.get("event_id")] if canonical else [],
            reasoning=(
                f"Observed process.name={proc_name}, parent={parent_name}. "
                + ("Parent∈anomaly-set ∧ child∈anomaly-set → suspicious lineage."
                    if anomalous else
                    "No known anomaly pattern for this parent-child pair.")
            ),
            created_at=now_iso(),
            provenance={"parent": parent_name, "child": proc_name,
                          "anomaly_matched": anomalous},
        )], []


# ── Command-line decoding ───────────────────────────────────────────

class CommandLineDecodeCapability(Capability):
    id = "commandline_decode"
    name = "Command-Line Decoding"
    engine = "nivxray::investigator::commandline_decode"
    category = "endpoint"
    investigation_question = (
        "Does the observed command line carry encoded content that, "
        "once decoded, reveals additional URLs / IPs / behaviour?"
    )
    evidence_requirements = ("canonical.process.commandline",)
    availability = "cap-full"

    def check_evidence(self, incident, canonical):
        proc = _process_from_canonical(canonical)
        cli = proc.get("commandline") or proc.get("command_line")
        if cli:
            return "SUFFICIENT", "command line present"
        return "INSUFFICIENT", "no process.commandline on canonical evidence"

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        proc = _process_from_canonical(canonical)
        cli = str(proc.get("commandline") or proc.get("command_line") or "").strip()
        if not cli:
            return [Finding(
                finding_id=fid(f"{incident_id}|cli|none"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="commandline_decode",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED", confidence=0,
                summary="No command line observed to decode.",
                evidence_refs=[], reasoning="canonical evidence lacks commandline.",
                created_at=now_iso(),
            )], []

        # Reuse existing decoder infrastructure.
        try:
            from smart_decoder import smart_decode
            decoded = smart_decode(cli)
        except Exception as ex:
            return [Finding(
                finding_id=fid(f"{incident_id}|cli|err|{cli[:40]}"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="commandline_decode",
                subject_kind="commandline", subject_value=cli[:80],
                state="UNKNOWN", confidence=0,
                summary="Command-line decoder raised.",
                evidence_refs=[canonical.get("event_id")] if canonical else [],
                reasoning=f"smart_decode: {type(ex).__name__}: {ex}",
                created_at=now_iso(),
            )], []

        stages = decoded.get("stages") or decoded.get("chain") or []
        state = "CORRELATED" if len(stages) > 1 else "OBSERVED"
        return [Finding(
            finding_id=fid(f"{incident_id}|cli|{cli[:80]}|{len(stages)}"),
            tenant_id=tenant_id, incident_id=incident_id,
            execution_id=pivot.pivot_id,
            capability=self.id, engine=self.engine,
            kind="commandline_decode",
            subject_kind="commandline", subject_value=cli[:120],
            state=state,
            confidence=min(40 + 10 * len(stages), 85),
            summary=(
                f"Command line decoded through {len(stages)} stage(s)."
                if stages else "Command line observed; no encoded stage detected."
            ),
            evidence_refs=[canonical.get("event_id")] if canonical else [],
            reasoning=(
                f"smart_decode produced {len(stages)} stage(s). "
                f"Provenance chain preserved."
            ),
            created_at=now_iso(),
            provenance={"stage_count": len(stages),
                          "engine": decoded.get("engine") or "smart_decoder"},
        )], []


# ── LOLBAS lookup ───────────────────────────────────────────────────

class LolbasLookupCapability(Capability):
    id = "lolbas_lookup"
    name = "LOLBAS Lookup"
    engine = "nivxray::investigator::lolbas_lookup"
    category = "endpoint"
    investigation_question = (
        "Is the executable or command line a known Living-off-the-Land binary, "
        "and what is its documented capability?"
    )
    evidence_requirements = ("canonical.process.name OR canonical.process.commandline",)
    availability = "cap-full"

    def check_evidence(self, incident, canonical):
        proc = _process_from_canonical(canonical)
        if proc.get("name") or proc.get("commandline") or proc.get("command_line"):
            return "SUFFICIENT", "process name or command line present"
        return "INSUFFICIENT", "no process telemetry to LOLBAS-scan"

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        proc = _process_from_canonical(canonical)
        text = " ".join(str(x) for x in (
            proc.get("name"), proc.get("commandline") or proc.get("command_line"),
        ) if x)
        if not text:
            return [Finding(
                finding_id=fid(f"{incident_id}|lolbas|none"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="lolbas_lookup",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED", confidence=0,
                summary="No process name / command line to scan for LOLBAS.",
                evidence_refs=[], reasoning="no endpoint text available.",
                created_at=now_iso(),
            )], []

        try:
            from lolbas import scan_lolbas
            hits = scan_lolbas(text)
        except Exception as ex:
            return [Finding(
                finding_id=fid(f"{incident_id}|lolbas|err"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="lolbas_lookup",
                subject_kind="incident", subject_value=incident_id,
                state="UNKNOWN", confidence=0,
                summary="LOLBAS scanner raised.",
                evidence_refs=[canonical.get("event_id")] if canonical else [],
                reasoning=f"scan_lolbas: {type(ex).__name__}: {ex}",
                created_at=now_iso(),
            )], []

        if not hits:
            return [Finding(
                finding_id=fid(f"{incident_id}|lolbas|clean"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="lolbas_lookup",
                subject_kind="commandline", subject_value=text[:120],
                state="NOT_OBSERVED", confidence=0,
                summary="No LOLBAS binary observed in process context.",
                evidence_refs=[canonical.get("event_id")] if canonical else [],
                reasoning="scan_lolbas returned zero hits.",
                created_at=now_iso(),
            )], []

        findings: List[Finding] = []
        for h in hits[:10]:
            binary = str(h.get("binary") or "")
            findings.append(Finding(
                finding_id=fid(f"{incident_id}|lolbas|{binary}"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="lolbas_lookup",
                subject_kind="lolbin", subject_value=binary,
                state="CORRELATED", confidence=70,
                summary=f"LOLBAS binary observed: {binary} · purposes={h.get('purposes')}",
                evidence_refs=[canonical.get("event_id")] if canonical else [],
                reasoning=(
                    f"scan_lolbas matched binary={binary} against pattern; "
                    f"MITRE hint: {h.get('mitre')}."
                ),
                created_at=now_iso(),
                provenance={"purposes": h.get("purposes"),
                             "mitre":    h.get("mitre"),
                             "url":      h.get("url"),
                             "snippet":  h.get("snippet")},
            ))
        return findings, []
