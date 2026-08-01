"""P1-02d · Investigation Truth Model (§1.1.20).

The single canonical projection every surface consumes.

    Observation → Finding → Hypothesis → Validation → Decision → Recommendation

Every downstream module (Story · Executive Summary · Reports · Verdict
· Timeline · Ledger · Notebook · Exports · API) reads from
`cio.truth`. If any surface renders something not in the truth model,
it is out-of-spec and must be brought back into projection.

Design principles:

  * **Pure derivation** — `build_truth(cio) → InvestigationTruth` is a
    total function of the CIO. Deterministic. Idempotent. Replayable.
  * **Traceability** — every layer carries `source_node_ids: List[str]`
    that points back into `cio.evidence_graph.nodes`.
  * **No new detections** — this composer does NOT introduce new
    evidence; it only re-organises what the engine already knows.
  * **CIO Supremacy** — `cio.verdict`, `cio.evidence_graph`,
    `cio.decode_chain`, `cio.metadata.osint`, and `cio.metadata.shellcode`
    are the sole inputs. No side-channels.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ────────────────────────── Six canonical layers ────────────────────

class Observation(BaseModel):
    """A raw fact recovered from the input. One node = one observation."""
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str                             # ioc | decoded_fragment | lolbin | mitre_technique | behaviour | family_match
    label: str
    value: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    source_node_ids: List[str] = Field(default_factory=list)
    provenance: str = ""


class Finding(BaseModel):
    """A curated conclusion drawn from ≥ 1 observations."""
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str                            # analyst-facing headline
    severity: str                         # critical | high | medium | low | info
    detail: str = ""
    source_observation_ids: List[str] = Field(default_factory=list)
    source_node_ids: List[str] = Field(default_factory=list)
    tactic: Optional[str] = None          # MITRE tactic tag if applicable
    technique_id: Optional[str] = None    # T1197, T1059.001, …


class Hypothesis(BaseModel):
    """A possible explanation. Explicitly tracked so we can validate /
    refute it. `status` starts as `proposed`; `validated`, `refuted`,
    or `inconclusive` after Validation runs."""
    model_config = ConfigDict(extra="forbid")

    id: str
    statement: str
    status: str                           # proposed | validated | refuted | inconclusive
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_finding_ids: List[str] = Field(default_factory=list)
    counter_finding_ids: List[str] = Field(default_factory=list)
    rationale: str = ""


class Validation(BaseModel):
    """The evidence-check that promotes/demotes a Hypothesis. Cites
    the exact observations / findings that shifted the verdict."""
    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    outcome: str                          # validated | refuted | inconclusive
    supporting_evidence: List[str] = Field(default_factory=list)  # observation/finding ids
    counter_evidence: List[str] = Field(default_factory=list)
    escalation_rule: Optional[str] = None
    detail: str = ""


class Decision(BaseModel):
    """The single verdict — same content as `cio.verdict`, restated
    here so every truth-consumer reads one shape."""
    model_config = ConfigDict(extra="forbid")

    label: str                            # Malicious | Suspicious | Runtime Dependent | Informational | Undetermined
    confidence_pct: int = Field(ge=0, le=100)
    reason: str
    escalation_rule: Optional[str] = None
    confidence_breakdown: Dict[str, int] = Field(default_factory=dict)
    engine: str = "unified-verdict-engine-v1"


class Recommendation(BaseModel):
    """A concrete analyst action derived from Decision + Findings."""
    model_config = ConfigDict(extra="forbid")

    id: str
    action: str                           # contain | hunt | investigate | notify | allow
    priority: str                         # p0 | p1 | p2 | p3
    detail: str
    playbook_ref: Optional[str] = None    # link to internal playbook / MDR SOP


class InvestigationTruth(BaseModel):
    """The canonical projection. `cio.truth` = `build_truth(cio).model_dump()`."""
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    observations: List[Observation] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    validations: List[Validation] = Field(default_factory=list)
    decision: Optional[Decision] = None
    recommendations: List[Recommendation] = Field(default_factory=list)


# ────────────────────────── Composer ────────────────────────────────

_SEVERITY_FROM_CLASS = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "context":  "info",
    "mitigating": "info",
}


def _severity_of_contributor(c: Dict[str, Any]) -> str:
    return _SEVERITY_FROM_CLASS.get((c.get("evidence_class") or "").lower(), "info")


def _mk_observations(cio) -> List[Observation]:
    obs: List[Observation] = []
    graph = getattr(cio, "evidence_graph", None)
    if not graph:
        return obs
    for n in graph.nodes:
        if n.kind == "artifact":
            continue
        # Skip pure synthetic wrappers — they surface as findings later.
        if (n.attrs or {}).get("synthetic") and n.kind == "behaviour":
            continue
        obs.append(Observation(
            id=f"O-{n.id}",
            kind=n.kind,
            label=n.label or n.value or n.id,
            value=n.value or "",
            confidence=float(n.confidence),
            source_node_ids=[n.id],
            provenance=n.provenance or "",
        ))
    return obs


def _mk_findings(cio, obs_by_node: Dict[str, str]) -> List[Finding]:
    """One finding per top-N verdict contributor + one per synthetic
    behaviour node + one per active escalation rule."""
    findings: List[Finding] = []
    v = getattr(cio, "verdict", None) or {}
    contribs = (v.get("contributors") or [])[:12]
    for i, c in enumerate(contribs):
        nid = c.get("node_id") or ""
        source_obs = obs_by_node.get(nid)
        findings.append(Finding(
            id=f"F-{i+1:03d}",
            title=c.get("label") or c.get("kind") or "Contributor",
            severity=_severity_of_contributor(c),
            detail=(
                f"{c.get('kind')} · class={c.get('evidence_class')} · "
                f"weight={c.get('weight')} · confidence={c.get('confidence')} · "
                f"source={c.get('source')}"
            ),
            source_observation_ids=[source_obs] if source_obs else [],
            source_node_ids=[nid] if nid else [],
            tactic=None,
            technique_id=(nid if (c.get("kind") == "mitre_technique" and nid.startswith("T")) else None),
        ))

    # Synthetic behaviour signals → dedicated findings for explainability.
    graph = getattr(cio, "evidence_graph", None)
    if graph:
        for n in graph.nodes:
            attrs = n.attrs or {}
            if not attrs.get("synthetic"):
                continue
            sig = attrs.get("signal") or n.value
            findings.append(Finding(
                id=f"F-SYN-{n.id}",
                title=n.label,
                severity="high" if n.value != "mitigating_signal" else "info",
                detail=(
                    f"synthetic signal · {sig} · confidence {n.confidence:.2f}"
                    + (f" · chain_depth={attrs.get('chain_depth')}" if attrs.get('chain_depth') else "")
                    + (f" · cluster_size={attrs.get('cluster_size')}" if attrs.get('cluster_size') else "")
                ),
                source_node_ids=[n.id],
            ))

    return findings


def _mk_hypotheses(cio, findings: List[Finding]) -> List[Hypothesis]:
    """Deterministic hypothesis derivation from the CIO's metadata:

      * If cio.metadata.shellcode → "Attacker delivered <family> shellcode"
      * If any BITS / IEX / LOLBIN attack-chain kind present → "Attacker
        used LOLBAS-based downloader chain"
      * If any confirmed_malicious_* → "Communication with known-bad
        infrastructure"
    Every hypothesis cites the finding ids that support it. Status is
    `validated` if the decision label is Malicious, else `proposed`."""
    v = getattr(cio, "verdict", None) or {}
    md = getattr(cio, "metadata", None) or {}
    decision_label = v.get("label") or "Undetermined"
    hypotheses: List[Hypothesis] = []
    finding_ids_by_kind: Dict[str, List[str]] = {}
    for f in findings:
        finding_ids_by_kind.setdefault(f.title.split(" ·")[0].lower(), []).append(f.id)

    def _fids_matching(*keywords: str) -> List[str]:
        out: List[str] = []
        for f in findings:
            t = (f.title or "").lower() + " " + (f.detail or "").lower()
            if any(k in t for k in keywords):
                out.append(f.id)
        return out

    sc = md.get("shellcode")
    if isinstance(sc, dict) and sc.get("is_shellcode"):
        fam = sc.get("family") or "Generic shellcode"
        supporting = _fids_matching("shellcode", "iex", "encoded_powershell", "compression")
        hypotheses.append(Hypothesis(
            id="H-SHELLCODE",
            statement=f"Attacker deployed {fam} via encoded PowerShell → GZIP → IEX loader.",
            status="validated" if decision_label == "Malicious" else "proposed",
            confidence=min(0.99, float(v.get("confidence") or 0.0)),
            supporting_finding_ids=supporting,
            rationale=(
                f"Terminal decoder layer decompressed to {sc.get('size', '?')} bytes of "
                f"{sc.get('arch') or 'unknown-arch'} shellcode."
            ),
        ))

    lolbas_evidence = _fids_matching("lolbin", "bitsadmin", "rundll32", "regsvr32",
                                     "mshta", "wmic", "invoke-expression")
    if lolbas_evidence:
        hypotheses.append(Hypothesis(
            id="H-LOLBAS-DOWNLOADER",
            statement="Attacker used a LOLBAS-based downloader chain to stage a payload.",
            status="validated" if decision_label == "Malicious" else "proposed",
            confidence=min(0.95, float(v.get("confidence") or 0.0)),
            supporting_finding_ids=lolbas_evidence,
            rationale="LOLBIN / signed-binary-proxy behaviour observed with network-bound intent.",
        ))

    c2_evidence = _fids_matching("confirmed_malicious", "known_c2", "network_beacon")
    if c2_evidence:
        hypotheses.append(Hypothesis(
            id="H-C2",
            statement="Communication with known-malicious infrastructure occurred.",
            status="validated" if decision_label == "Malicious" else "proposed",
            confidence=min(0.95, float(v.get("confidence") or 0.0)),
            supporting_finding_ids=c2_evidence,
            rationale="Threat-intel or OSINT provider flagged an observed IOC as malicious.",
        ))

    # Fallback single hypothesis if we found nothing but still have a verdict
    if not hypotheses and v.get("label") and v.get("label") != "Undetermined":
        hypotheses.append(Hypothesis(
            id="H-GENERIC",
            statement=f"Input matches a {v.get('label').lower()} pattern.",
            status="proposed",
            confidence=min(0.90, float(v.get("confidence") or 0.0)),
            supporting_finding_ids=[f.id for f in findings[:4]],
            rationale=v.get("reason", ""),
        ))
    return hypotheses


def _mk_validations(cio, hypotheses: List[Hypothesis], findings: List[Finding]) -> List[Validation]:
    v = getattr(cio, "verdict", None) or {}
    esc_rule = v.get("escalation_rule")
    # Mitigating (counter) evidence
    mitigating_finding_ids = [f.id for f in findings if f.severity == "info"
                              and ("mitigating" in f.detail.lower()
                                   or "internal_ip" in f.detail.lower()
                                   or "signed_microsoft" in f.detail.lower()
                                   or "benign_parent" in f.detail.lower()
                                   or "enterprise_allowlist" in f.detail.lower())]
    out: List[Validation] = []
    for h in hypotheses:
        out.append(Validation(
            hypothesis_id=h.id,
            outcome=h.status,
            supporting_evidence=h.supporting_finding_ids,
            counter_evidence=mitigating_finding_ids,
            escalation_rule=esc_rule,
            detail=(
                f"Verdict engine reported {v.get('label')} at {v.get('confidence_pct')}%. "
                + (f"Escalation rule '{esc_rule}' fired. " if esc_rule else "")
                + f"{len(h.supporting_finding_ids)} supporting findings, "
                + f"{len(mitigating_finding_ids)} counter findings."
            ),
        ))
    return out


def _mk_decision(cio) -> Optional[Decision]:
    v = getattr(cio, "verdict", None) or {}
    if not v:
        return None
    return Decision(
        label=v.get("label") or "Undetermined",
        confidence_pct=int(v.get("confidence_pct") or 0),
        reason=v.get("reason") or "",
        escalation_rule=v.get("escalation_rule"),
        confidence_breakdown=v.get("confidence_breakdown") or {},
        engine=v.get("engine") or "unified-verdict-engine-v1",
    )


def _mk_recommendations(cio, decision: Optional[Decision],
                        hypotheses: List[Hypothesis]) -> List[Recommendation]:
    if not decision:
        return []
    recs: List[Recommendation] = []
    label = decision.label

    if label == "Malicious":
        recs.append(Recommendation(
            id="R-CONTAIN",
            action="contain",
            priority="p0",
            detail=(
                "Isolate the affected host from the network and preserve volatile memory. "
                "Block the extracted C2 indicators at the perimeter and endpoint layers."
            ),
            playbook_ref="MDR-SOP-001-endpoint-containment",
        ))
        recs.append(Recommendation(
            id="R-HUNT",
            action="hunt",
            priority="p1",
            detail=(
                "Hunt for the same execution chain and extracted IOCs across the estate over "
                "the past 30 days. Correlate against parent-process / user-SID entities."
            ),
            playbook_ref="MDR-SOP-014-lateral-hunt",
        ))
        recs.append(Recommendation(
            id="R-NOTIFY",
            action="notify",
            priority="p1",
            detail=(
                "Notify the customer with the Investigation Truth Model summary, the extracted "
                "IOCs, and the confidence-breakdown chart. Attach the STIX bundle."
            ),
        ))
    elif label == "Suspicious":
        recs.append(Recommendation(
            id="R-INVESTIGATE",
            action="investigate",
            priority="p2",
            detail=(
                "Escalate to Tier-2 for a deeper investigation. Retrieve process-tree and "
                "network telemetry around the observation window."
            ),
        ))
    elif label == "Runtime Dependent":
        recs.append(Recommendation(
            id="R-VERIFY",
            action="investigate",
            priority="p3",
            detail=(
                "Verdict depends on runtime context. Confirm whether the command executed "
                "and inspect the target host for artefacts of the observed behaviour."
            ),
        ))
    else:
        recs.append(Recommendation(
            id="R-ALLOW",
            action="allow",
            priority="p3",
            detail=(
                "No high-signal evidence recovered. Retain the investigation for future "
                "correlation but no immediate action required."
            ),
        ))
    return recs


def build_truth(cio) -> InvestigationTruth:
    """Pure `CIO → InvestigationTruth` derivation. Deterministic."""
    observations = _mk_observations(cio)
    obs_by_node: Dict[str, str] = {o.source_node_ids[0]: o.id
                                    for o in observations
                                    if o.source_node_ids}
    findings = _mk_findings(cio, obs_by_node)
    hypotheses = _mk_hypotheses(cio, findings)
    validations = _mk_validations(cio, hypotheses, findings)
    decision = _mk_decision(cio)
    recommendations = _mk_recommendations(cio, decision, hypotheses)
    return InvestigationTruth(
        observations=observations,
        findings=findings,
        hypotheses=hypotheses,
        validations=validations,
        decision=decision,
        recommendations=recommendations,
    )


__all__ = [
    "Observation", "Finding", "Hypothesis", "Validation",
    "Decision", "Recommendation", "InvestigationTruth", "build_truth",
]
