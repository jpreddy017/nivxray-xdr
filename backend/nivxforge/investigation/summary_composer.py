"""ADR-0014 · Slice-D · Backend Summary Composer (§1.1.4, §1.1.9, §1.1.18).

Reads the Canonical Investigation Object and produces a rich, structured
`Summary` object that becomes the single source of truth for every UI
surface (Story lens · Report lens · Executive View · SOC View · DFIR
View · future AI narrative overlay).

Governance:
    §1.1.4  — Lab + Workspace consume the SAME summary
    §1.1.9  — Backend owns summary; UI never composes prose
    §1.1.18 — Event → Process Chain → Host/User → Timeline →
              High-confidence Evidence → Scope → Impact → Recommendations

Pure function of the CIO. No network. No LLM. No frontend logic.
Deterministic: same CIO in → identical Summary out.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from nivxforge.investigation.models import CIO
from nivxforge.investigation.ioc_classifier import classify


# ─── Structured sub-objects ────────────────────────────────────────

class KeyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    label: str
    weight: int = Field(ge=0, le=10)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_node_ids: List[str] = Field(default_factory=list)


class Unknown(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    category: str  # gate | incomplete_decode | enrichment_failed | insufficient_context
    description: str
    confidence_impact: float = Field(default=0.0, ge=-1.0, le=0.0)


class Recommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    priority: str  # critical | high | medium | low | informational
    action: str
    rationale: str
    evidence_node_ids: List[str] = Field(default_factory=list)


class AttackChainStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: int
    label: str
    node_id: Optional[str] = None
    tactic: Optional[str] = None


class EvidenceDigest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_nodes: int
    contributors: int
    not_counted: int
    by_kind: Dict[str, int] = Field(default_factory=dict)


class EntitiesDigest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hosts: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    external_domains: List[str] = Field(default_factory=list)
    external_ips: List[str] = Field(default_factory=list)
    lolbins: List[str] = Field(default_factory=list)


class MitreDigest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    techniques: List[Dict[str, str]] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    coverage: int = 0


class TimelineDigest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    steps: int
    verdict_step_id: Optional[str] = None


class ReportSections(BaseModel):
    """Structured sections for the Report Lens (§1.1.18 ordering)."""
    model_config = ConfigDict(extra="forbid")
    what_happened: str = ""
    what_we_found: str = ""
    what_we_dont_know: str = ""
    what_to_do: str = ""


# ─── Root Summary object ───────────────────────────────────────────

class Summary(BaseModel):
    """The single, canonical summary consumed by every UI surface."""
    model_config = ConfigDict(extra="forbid")

    # ── Prose (deterministic templating, event-first §1.1.18) ─────
    executive: str = ""          # C-level: 1-2 sentences
    analyst: str = ""            # Analyst-facing: 2-4 short paragraphs
    technical: str = ""          # Technical: deep bullet list + chain detail
    attack_story: str = ""       # Kill-chain narrative

    # ── Structured (backbone for all lenses) ──────────────────────
    key_findings: List[KeyFinding] = Field(default_factory=list)
    unknowns: List[Unknown] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_digest: EvidenceDigest
    attack_chain: List[AttackChainStep] = Field(default_factory=list)
    entities_digest: EntitiesDigest
    mitre_digest: MitreDigest
    timeline_digest: TimelineDigest
    report_sections: ReportSections

    # ── Provenance ────────────────────────────────────────────────
    composer_version: str = "slice-d-v1"


# ─── Composition helpers ───────────────────────────────────────────

def _digest_evidence(cio: CIO) -> EvidenceDigest:
    by_kind: Dict[str, int] = defaultdict(int)
    for n in cio.evidence_graph.nodes:
        by_kind[n.kind] += 1
    verdict = cio.verdict or {}
    return EvidenceDigest(
        total_nodes=len(cio.evidence_graph.nodes),
        contributors=len(verdict.get("contributors") or []),
        not_counted=len(verdict.get("not_counted") or []),
        by_kind=dict(by_kind),
    )


def _digest_entities(cio: CIO) -> EntitiesDigest:
    hosts, users, hashes, ext_domains, ext_ips, lolbins = [], [], [], [], [], []
    for n in cio.evidence_graph.nodes:
        if n.kind == "lolbin" and n.value:
            lolbins.append(n.value)
        if n.kind == "ioc":
            ik = (n.attrs or {}).get("ioc_kind", "")
            v = n.value or ""
            r = classify(v, ioc_kind=ik)
            if r.category == "external_ioc":
                if ik in ("hash", "md5", "sha1", "sha256"):
                    hashes.append(v)
                elif ik == "ip":
                    ext_ips.append(v)
                else:
                    ext_domains.append(v)
    # Parse host=/user= from input_text lines emitted by ingress_gate
    for line in (cio.input_text or "").splitlines():
        for tok in line.split():
            if tok.startswith("host="):
                hosts.append(tok.split("=", 1)[1])
            elif tok.startswith("user="):
                users.append(tok.split("=", 1)[1])
    return EntitiesDigest(
        hosts=sorted(set(hosts)),
        users=sorted(set(users)),
        hashes=sorted(set(hashes)),
        external_domains=sorted(set(ext_domains)),
        external_ips=sorted(set(ext_ips)),
        lolbins=sorted(set(lolbins)),
    )


def _digest_mitre(cio: CIO) -> MitreDigest:
    techs = []
    tactics = set()
    for n in cio.evidence_graph.nodes:
        if n.kind == "mitre_technique":
            tid = n.value or ""
            attrs = n.attrs or {}
            tactic = attrs.get("tactic") or ""
            name = attrs.get("name") or ""
            techs.append({"id": tid, "name": name, "tactic": tactic})
            if tactic:
                tactics.add(tactic)
    return MitreDigest(
        techniques=techs,
        tactics=sorted(tactics),
        coverage=len(tactics),
    )


def _digest_timeline(cio: CIO) -> TimelineDigest:
    verdict_step_id = None
    for s in cio.reasoning_steps:
        if s.rule == "verdict.compute":
            verdict_step_id = s.step_id
            break
    return TimelineDigest(
        steps=len(cio.reasoning_steps),
        verdict_step_id=verdict_step_id,
    )


def _build_attack_chain(cio: CIO) -> List[AttackChainStep]:
    """Order: decoded_fragment nodes → behaviour nodes → verdict node."""
    chain: List[AttackChainStep] = []
    order = 1
    for n in cio.evidence_graph.nodes:
        if n.kind == "decoded_fragment":
            chain.append(AttackChainStep(order=order, label=n.label, node_id=n.id))
            order += 1
    for n in cio.evidence_graph.nodes:
        if n.kind == "behaviour":
            chain.append(AttackChainStep(order=order, label=n.label, node_id=n.id))
            order += 1
    for n in cio.evidence_graph.nodes:
        if n.kind == "verdict":
            chain.append(AttackChainStep(order=order, label=f"Verdict: {n.value or ''}", node_id=n.id))
            order += 1
            break
    return chain


def _build_key_findings(cio: CIO) -> List[KeyFinding]:
    verdict = cio.verdict or {}
    contributors = verdict.get("contributors") or []
    findings: List[KeyFinding] = []
    for i, c in enumerate(contributors[:10]):
        findings.append(KeyFinding(
            id=f"kf-{i+1:03d}",
            label=c.get("label", "") or c.get("kind", ""),
            weight=int(c.get("weight", 0)),
            confidence=float(c.get("confidence", 0.0)),
            evidence_node_ids=[c.get("node_id", "")] if c.get("node_id") else [],
        ))
    return findings


def _build_unknowns(cio: CIO) -> List[Unknown]:
    unknowns: List[Unknown] = []
    verdict = cio.verdict or {}
    if not (verdict.get("contributors") or []):
        unknowns.append(Unknown(
            id="uk-001",
            category="insufficient_context",
            description=("No high-signal evidence recovered from the input; "
                         "no reasoning step produced a verdict-driving contribution."),
            confidence_impact=-0.5,
        ))
    # If decode chain is present but no external IOC / MITRE, note that
    if cio.decode_chain and not any(
        n.kind in ("mitre_technique",) for n in cio.evidence_graph.nodes
    ):
        unknowns.append(Unknown(
            id="uk-002",
            category="gate",
            description="Payload decoded but no ATT&CK technique matched — "
                        "rule coverage may be incomplete.",
            confidence_impact=-0.15,
        ))
    return unknowns


def _priority_from_label(label: str) -> str:
    return {
        "Malicious":         "critical",
        "Suspicious":        "high",
        "Runtime Dependent": "medium",
        "Informational":     "low",
        "Undetermined":      "informational",
    }.get(label, "informational")


def _build_recommendations(cio: CIO) -> List[Recommendation]:
    verdict = cio.verdict or {}
    label = verdict.get("label", "Undetermined")
    priority = _priority_from_label(label)
    recs: List[Recommendation] = []

    contributors = verdict.get("contributors") or []
    contrib_ids = [c.get("node_id", "") for c in contributors if c.get("node_id")][:5]

    if label == "Malicious":
        recs.append(Recommendation(
            id="rc-001", priority=priority,
            action="Isolate affected hosts and block the identified indicators at the perimeter.",
            rationale="Verdict is Malicious with confirmed dominant evidence.",
            evidence_node_ids=contrib_ids,
        ))
        recs.append(Recommendation(
            id="rc-002", priority="high",
            action="Preserve host artefacts and start forensic triage for the affected users.",
            rationale="Preservation supports downstream IR and post-incident review.",
            evidence_node_ids=contrib_ids,
        ))
    elif label == "Suspicious":
        recs.append(Recommendation(
            id="rc-001", priority=priority,
            action="Investigate the recovered indicators in threat-intel and correlate against your environment.",
            rationale="High-signal evidence recovered but no dominant driver — verify before containment.",
            evidence_node_ids=contrib_ids,
        ))
    elif label == "Runtime Dependent":
        recs.append(Recommendation(
            id="rc-001", priority=priority,
            action="Sandbox the terminal payload and observe runtime behaviour before deciding on containment.",
            rationale="Evidence indicates obfuscation with plausible malicious intent; static analysis is inconclusive.",
            evidence_node_ids=contrib_ids,
        ))
    elif label == "Informational":
        recs.append(Recommendation(
            id="rc-001", priority=priority,
            action="Retain the artefact and this analysis; close as Informational.",
            rationale="Only vendor-infrastructure or benign context observed; no high-signal evidence.",
            evidence_node_ids=[],
        ))
    else:
        recs.append(Recommendation(
            id="rc-001", priority=priority,
            action="Verify submission context (host, user, process) and re-run with fuller artefact.",
            rationale="Verdict undetermined — insufficient evidence to reach an actionable conclusion.",
            evidence_node_ids=[],
        ))
    return recs


# ─── Prose composition (deterministic templating, §1.1.18 ordered) ─

def _prose_executive(cio: CIO, findings: List[KeyFinding], entities: EntitiesDigest, mitre: MitreDigest) -> str:
    verdict = cio.verdict or {}
    label = verdict.get("label", "Undetermined")
    conf_pct = verdict.get("confidence_pct", 0)
    top = findings[0].label if findings else "no high-signal evidence"
    host_txt = f" on {entities.hosts[0]}" if entities.hosts else ""
    return (
        f"Verdict: {label} (confidence {conf_pct}%). "
        f"Top driver: {top}{host_txt}. "
        f"{mitre.coverage} ATT&CK tactic(s) observed."
    )


def _prose_analyst(cio: CIO, findings: List[KeyFinding], chain: List[AttackChainStep],
                    entities: EntitiesDigest, mitre: MitreDigest, recs: List[Recommendation]) -> str:
    verdict = cio.verdict or {}
    label = verdict.get("label", "Undetermined")
    parts: List[str] = []

    # 1 · Event
    if chain:
        parts.append("Event: " + " → ".join(step.label for step in chain[:6]) + ".")
    else:
        parts.append(f"Event: {cio.input_kind} artifact analysed.")

    # 2 · Process chain / decode chain
    if cio.decode_chain:
        parts.append(f"Decode chain: {len(cio.decode_chain)} layer(s) recovered.")

    # 3 · Host / User
    hu_parts = []
    if entities.hosts:
        hu_parts.append(f"host(s) {', '.join(entities.hosts[:3])}")
    if entities.users:
        hu_parts.append(f"user(s) {', '.join(entities.users[:3])}")
    if hu_parts:
        parts.append("Observed on " + " · ".join(hu_parts) + ".")

    # 4 · Timeline (compact)
    if cio.reasoning_steps:
        parts.append(f"Timeline: {len(cio.reasoning_steps)} deterministic reasoning steps.")

    # 5 · High-confidence evidence
    if findings:
        top_lines = ", ".join(f.label for f in findings[:5])
        parts.append(f"Key evidence: {top_lines}.")

    # 6 · Scope
    if entities.external_domains or entities.external_ips or entities.hashes:
        scope_parts = []
        if entities.external_domains:
            scope_parts.append(f"{len(entities.external_domains)} external domain(s)")
        if entities.external_ips:
            scope_parts.append(f"{len(entities.external_ips)} external IP(s)")
        if entities.hashes:
            scope_parts.append(f"{len(entities.hashes)} hash(es)")
        parts.append("Scope: " + ", ".join(scope_parts) + ".")

    # 7 · Impact (derived from verdict label)
    impact_map = {
        "Malicious":         "Confirmed malicious activity — active containment warranted.",
        "Suspicious":        "Probable malicious activity — verification before containment.",
        "Runtime Dependent": "Ambiguous static evidence — sandbox to disambiguate.",
        "Informational":     "No malicious activity indicated; retain for correlation.",
        "Undetermined":      "Insufficient evidence to reach a verdict.",
    }
    parts.append("Impact: " + impact_map.get(label, "Undetermined."))

    # 8 · Recommendations (first two)
    if recs:
        rec_lines = " · ".join(r.action for r in recs[:2])
        parts.append("Recommended action: " + rec_lines)

    return " ".join(parts)


def _prose_technical(cio: CIO, findings: List[KeyFinding], mitre: MitreDigest) -> str:
    lines: List[str] = []
    if cio.decode_chain:
        for layer in cio.decode_chain:
            lines.append(f"L{layer.get('idx', '?')} · {layer.get('op', '')} → "
                         f"{layer.get('output_kind', '')}")
    for f in findings[:10]:
        lines.append(f"finding · {f.label} · weight={f.weight} · conf={int(f.confidence*100)}%")
    for t in mitre.techniques[:8]:
        lines.append(f"ATT&CK · {t.get('id','')} · {t.get('name','')} · {t.get('tactic','')}")
    return "\n".join(lines)


def _prose_attack_story(chain: List[AttackChainStep], entities: EntitiesDigest) -> str:
    if not chain:
        return "No attack chain recovered."
    steps = " → ".join(f"{s.order}. {s.label}" for s in chain)
    host_txt = f" (host: {entities.hosts[0]})" if entities.hosts else ""
    return f"Attack chain{host_txt}: {steps}."


# ─── Public entry ──────────────────────────────────────────────────

def compose_summary(cio: CIO) -> Summary:
    """Compose the canonical Summary from a CIO. Pure function."""
    ev_digest = _digest_evidence(cio)
    ent_digest = _digest_entities(cio)
    mitre_digest = _digest_mitre(cio)
    timeline_digest = _digest_timeline(cio)
    attack_chain = _build_attack_chain(cio)
    key_findings = _build_key_findings(cio)
    unknowns = _build_unknowns(cio)
    recommendations = _build_recommendations(cio)

    exec_prose = _prose_executive(cio, key_findings, ent_digest, mitre_digest)
    analyst_prose = _prose_analyst(cio, key_findings, attack_chain,
                                    ent_digest, mitre_digest, recommendations)
    technical_prose = _prose_technical(cio, key_findings, mitre_digest)
    attack_story = _prose_attack_story(attack_chain, ent_digest)

    report_sections = ReportSections(
        what_happened=analyst_prose,
        what_we_found=("Key findings: " + ", ".join(f.label for f in key_findings[:5])
                       if key_findings else "No high-signal findings."),
        what_we_dont_know=("Unknowns: " + " · ".join(u.description for u in unknowns[:3])
                           if unknowns else "No open unknowns."),
        what_to_do=("Actions: " + " · ".join(r.action for r in recommendations)
                    if recommendations else "No actions required."),
    )

    return Summary(
        executive=exec_prose,
        analyst=analyst_prose,
        technical=technical_prose,
        attack_story=attack_story,
        key_findings=key_findings,
        unknowns=unknowns,
        recommendations=recommendations,
        confidence=cio.confidence,
        evidence_digest=ev_digest,
        attack_chain=attack_chain,
        entities_digest=ent_digest,
        mitre_digest=mitre_digest,
        timeline_digest=timeline_digest,
        report_sections=report_sections,
    )


__all__ = [
    "compose_summary", "Summary",
    "KeyFinding", "Unknown", "Recommendation", "AttackChainStep",
    "EvidenceDigest", "EntitiesDigest", "MitreDigest", "TimelineDigest",
    "ReportSections",
]
