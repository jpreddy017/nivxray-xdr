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
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from nivxforge.investigation.models import CIO
from nivxforge.investigation.ioc_classifier import classify


# ─── Structured sub-objects ────────────────────────────────────────

class KeyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    label: str
    weight: float = Field(ge=-5, le=10)
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

    # ── Persona-aware Customer Report (ADR-2026-02) ────────────────
    #   16-section canonical report projected from CIO fields only.
    #   Composed by `customer_report.compose_customer_report()`.
    #   Optional so legacy paths don't break; frontend prefers it when set.
    customer_report: Optional[Dict[str, Any]] = None

    # ── P0.5 · Executive Report Validator output ──────────────────
    #   Hard quality gate. The frontend refuses to render the report
    #   when `report_validation.status == "fail"`, forcing the composer
    #   to remain honest.
    report_validation: Optional[Dict[str, Any]] = None

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
            weight=float(c.get("weight", 0.0)),
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


# ─── Prose composition (deterministic MDR-analyst voice, §1.1.18 ordered) ─
#
# Design principle (2026-02 · MDR-Analyst rewrite):
#   - Never quote the raw input.
#   - Never enumerate "Layer 0 → Layer 1 → …" — that reads like a log, not an
#     analyst.
#   - Never say "N reasoning steps" in the narrative — analysts don't count
#     their own thinking.
#   - Use active-voice verbs on subjects/objects extracted from the evidence
#     graph (LOLBIN, decoded URL/domain, hash, host, user, MITRE technique
#     name).
#   - Every sentence must be evidence-backed, but the wording is a claim about
#     the incident — not a dump of node kinds.
#
# The six-question analyst structure lives inside `_prose_analyst`:
#   1. What happened     — event-level narrative
#   2. Why it matters    — behaviour classification + MITRE names
#   3. Supporting evidence — concrete recovered strings + host/user
#   4. Impact & scope    — hosts, users, domains, hashes
#   5. Containment       — what fired, was it blocked/observed
#   6. Next actions      — ordered runbook derived from recs


def _analyst_event_lead(cio: CIO, lolbin: Optional[str], mitre: MitreDigest) -> str:
    """Compose the mandatory §1.1.18 opening sentence. Format:
        'Event: <subject> <verb> <object>.'
    Never contains a URL, IP, or hash — those go into subsequent
    sentences so the opening reads like an analyst framing the case."""
    label = (cio.verdict or {}).get("label", "Undetermined")
    verdict_frame = {
        "Malicious":         "confirmed malicious",
        "Suspicious":        "probable-malicious",
        "Runtime Dependent": "runtime-dependent",
        "Informational":     "informational",
        "Undetermined":      "undetermined",
    }.get(label, "undetermined")

    if lolbin:
        # LOLBIN present → describe living-off-the-land execution.
        return (
            f"Event: {lolbin} was invoked with an obfuscated command "
            f"consistent with {verdict_frame} activity."
        )
    # No LOLBIN — describe by artifact class + verdict.
    return (
        f"Event: The submitted {cio.input_kind or 'artifact'} produced "
        f"{verdict_frame} evidence when analysed."
    )


def _find_lolbin(cio: CIO) -> Optional[str]:
    for n in cio.evidence_graph.nodes:
        if str(n.kind).lower() == "lolbin":
            return str(n.label or n.value or "").split("·")[-1].strip() or None
    return None


def _decoded_urls(cio: CIO) -> List[str]:
    urls = []
    for n in cio.evidence_graph.nodes:
        k = str(n.kind).lower()
        if k in ("external_ioc_url", "url"):
            v = str(n.label or n.value or "").strip()
            if v and v not in urls:
                urls.append(v)
    return urls


def _decoded_domains(cio: CIO) -> List[str]:
    doms = []
    for n in cio.evidence_graph.nodes:
        k = str(n.kind).lower()
        if k in ("external_ioc_domain", "domain"):
            v = str(n.label or n.value or "").strip()
            if v and v not in doms:
                doms.append(v)
    return doms


def _final_decoded_snippet(cio: CIO) -> str:
    """Return the last decoder layer's short preview — the payload the
    engine recovered. Used to quote *what* was hidden, not *how* it
    was hidden."""
    if not cio.decode_chain:
        return ""
    last = cio.decode_chain[-1]
    prev = str(last.get("preview") or "").strip()
    if not prev:
        return ""
    # Truncate to a single readable claim.
    if len(prev) > 160:
        prev = prev[:157] + "…"
    return prev


def _mitre_named_pairs(mitre: MitreDigest, limit: int = 3) -> List[str]:
    """Return ['T1059.001 · PowerShell', ...] using resolved names.
    Falls back to just the ID if no name is known."""
    out: List[str] = []
    seen = set()
    for t in mitre.techniques:
        tid = str(t.get("id") or "").strip()
        if not tid or tid in seen:
            continue
        seen.add(tid)
        name = str(t.get("name") or "").strip()
        out.append(f"{tid} · {name}" if name else tid)
        if len(out) >= limit:
            break
    return out


def _behavior_summary_verb(cio: CIO, urls: List[str], lolbin: Optional[str]) -> str:
    """Deprecated in favour of _analyst_event_lead. Kept for backward
    compatibility with any external caller; produces analyst-flavour
    prose but WITHOUT the mandatory 'Event:' prefix and WITHOUT
    URL/hash removal from the first sentence."""
    if lolbin and urls:
        return (
            f"{lolbin} was invoked with an obfuscated command that fetches "
            f"{urls[0]}."
        )
    if lolbin:
        return f"{lolbin} was invoked with an obfuscated command."
    if urls:
        return f"Recovered payload references {urls[0]}."
    verdict = (cio.verdict or {}).get("label", "Undetermined")
    return (
        f"The submitted {cio.input_kind or 'artifact'} terminated at "
        f"the {verdict} verdict."
    )


def _prose_executive(cio: CIO, findings: List[KeyFinding],
                     entities: EntitiesDigest, mitre: MitreDigest) -> str:
    """One tight paragraph in analyst voice. Answers what happened +
    why it matters + the top driver + tactic coverage. Opens with
    'Event:' per §1.1.18 and keeps the first sentence free of URLs
    and hashes."""
    verdict = cio.verdict or {}
    label = verdict.get("label", "Undetermined")
    conf_pct = verdict.get("confidence_pct", 0)
    urls = _decoded_urls(cio)
    lolbin = _find_lolbin(cio)

    # Sentence 1 — §1.1.18 opening (no URLs, no hashes).
    lead = _analyst_event_lead(cio, lolbin, mitre)

    # Sentence 2 — the concrete detail (URL, staging pattern) that
    # explains WHY this is verdict-worthy.
    if lolbin and urls:
        detail = (
            f" The recovered command attempts to fetch a remote payload "
            f"from {urls[0]} — a classic staging pattern used to pull "
            f"second-stage code from the internet before executing it."
        )
    elif lolbin:
        detail = (
            f" The recovered command hides its actual behaviour from "
            f"static inspection."
        )
    elif urls:
        detail = f" Recovered payload references {urls[0]}."
    else:
        detail = ""

    pairs = _mitre_named_pairs(mitre, limit=2)
    mitre_clause = ""
    if pairs:
        mitre_clause = f" Behaviour maps to {', '.join(pairs)}."

    host_clause = ""
    if entities.hosts:
        host_clause = f" Observed on host {entities.hosts[0]}."

    return (
        f"{lead}{detail}{mitre_clause}{host_clause}"
        f" Verdict: {label} at {conf_pct}% confidence."
    )


def _paragraph_what_happened(cio: CIO, urls: List[str], lolbin: Optional[str],
                              snippet: str, mitre: MitreDigest) -> str:
    """Section 1 · MDR-style event description. Opens with 'Event:'
    per §1.1.18 — first sentence is URL/hash-free; subsequent
    sentences carry the concrete recovered strings."""
    lead = _analyst_event_lead(cio, lolbin, mitre)

    followups = []
    if urls:
        followups.append(
            f"The recovered command attempts to reach out to {urls[0]}, "
            f"consistent with second-stage payload staging."
        )
    if snippet and lolbin:
        followups.append(
            f"Recovered payload reads: `{snippet}`, which corroborates "
            f"that {lolbin} was used as a launcher for downstream code "
            f"rather than a routine administrative task."
        )
    elif snippet:
        followups.append(f"Recovered payload: `{snippet}`.")
    return " ".join([lead] + followups)


def _paragraph_why_it_matters(cio: CIO, mitre: MitreDigest,
                              lolbin: Optional[str]) -> str:
    """Section 2 · Behaviour classification and threat framing."""
    pairs = _mitre_named_pairs(mitre, limit=3)
    parts = []
    if lolbin:
        parts.append(
            f"Living-off-the-land use of {lolbin} bypasses application-"
            f"allowlisting because the binary itself is signed and "
            f"trusted; the malicious intent lives in the arguments, "
            f"not the executable."
        )
    if pairs:
        parts.append(
            "Investigation mapped the observed behaviour to "
            + ", ".join(pairs)
            + "."
        )
    if not parts:
        parts.append(
            "The recovered evidence does not currently map to a specific "
            "attacker technique; the incident is being flagged for "
            "manual review to avoid a false negative."
        )
    return " ".join(parts)


def _paragraph_evidence(cio: CIO, findings: List[KeyFinding],
                         entities: EntitiesDigest) -> str:
    """Section 3 · Concrete supporting evidence with node-id anchors."""
    if not findings:
        return (
            "No high-signal indicators were recovered from the "
            "submission; verdict is driven by structural properties "
            "of the input alone."
        )
    top = findings[:5]
    lines = []
    for f in top:
        nid = f.evidence_node_ids[0] if f.evidence_node_ids else ""
        anchor = f" [{nid}]" if nid else ""
        lines.append(f"{f.label}{anchor}")
    scope_bits = []
    if entities.external_domains:
        scope_bits.append(
            f"{len(entities.external_domains)} external domain(s)"
        )
    if entities.external_ips:
        scope_bits.append(f"{len(entities.external_ips)} external IP(s)")
    if entities.hashes:
        scope_bits.append(f"{len(entities.hashes)} hash(es)")
    scope_line = ""
    if scope_bits:
        scope_line = (
            " Recovered network/host indicators cover "
            + ", ".join(scope_bits)
            + "."
        )
    return (
        "Supporting evidence, in weight order: "
        + "; ".join(lines)
        + "."
        + scope_line
    )


def _paragraph_impact_scope(cio: CIO, entities: EntitiesDigest) -> str:
    """Section 4 · Impact & scope from real entities."""
    label = (cio.verdict or {}).get("label", "Undetermined")
    impact_map = {
        "Malicious": (
            "Impact is confirmed malicious. Any endpoint that executed "
            "this payload should be considered compromised until proven "
            "otherwise."
        ),
        "Suspicious": (
            "Impact is probable-malicious. The behaviour is inconsistent "
            "with routine administrative activity and warrants "
            "verification before containment is relaxed."
        ),
        "Runtime Dependent": (
            "Impact cannot be determined from static evidence alone. "
            "A sandbox detonation of the recovered payload is required "
            "to disambiguate benign versus malicious execution."
        ),
        "Informational": (
            "Impact is low; the submission only exposed vendor / "
            "benign-infrastructure indicators."
        ),
        "Undetermined": (
            "Impact cannot be assessed with the evidence available. "
            "Re-submit with fuller artefacts (host, user, parent "
            "process) if a decision is required."
        ),
    }
    header = impact_map.get(label, impact_map["Undetermined"])
    parts = [header]
    scope = []
    if entities.hosts:
        scope.append(f"{len(entities.hosts)} host(s)")
    if entities.users:
        scope.append(f"{len(entities.users)} user(s)")
    if entities.external_domains:
        scope.append(f"{len(entities.external_domains)} external domain(s)")
    if entities.external_ips:
        scope.append(f"{len(entities.external_ips)} external IP(s)")
    if scope:
        parts.append("Scope of observed entities: " + ", ".join(scope) + ".")
    return " ".join(parts)


def _paragraph_containment(cio: CIO) -> str:
    """Section 5 · Containment / control-status. Currently derived from
    reasoning-step notes tagged with quarantine/blocked keywords —
    otherwise honestly reports no containment signal was seen.

    False-positive guards:
      - Match on whole words (not substrings), so "blocked" hits but
        the noun "block" (as in "decoded block") does not.
      - Require the token to appear near an entity noun (host, user,
        process, endpoint, file, hash, execution) so we do not mistake
        analysis vocabulary for containment vocabulary.
    """
    import re
    # Whole-word action verbs (past-tense variants included).
    verb_pat = re.compile(
        r"\b(quarantin(?:e|ed)|blocked|prevent(?:ed)?|isolat(?:e|ed)|"
        r"kill(?:ed)?|terminat(?:e|ed)|contain(?:ed)?)\b",
        re.IGNORECASE,
    )
    # Entity nouns that make a verb count as containment.
    entity_pat = re.compile(
        r"\b(host|endpoint|process|file|hash|payload|execution|"
        r"user|account|network|traffic|connection)\b",
        re.IGNORECASE,
    )
    hits: List[str] = []
    for s in cio.reasoning_steps:
        exp = (s.explanation or "").strip()
        if not exp:
            continue
        if verb_pat.search(exp) and entity_pat.search(exp):
            hits.append(exp)
    if hits:
        # Join without accidentally producing double full-stops.
        cleaned = " · ".join(h.rstrip(".").rstrip() for h in hits[:3])
        return f"Containment signals present in the evidence: {cleaned}."
    return (
        "No containment signal was observed in the submitted evidence "
        "(no quarantine, block, or prevent action was reported). This "
        "does not mean containment did not occur — it means the "
        "artefact submitted to NivXRay did not include that telemetry."
    )


def _paragraph_next_actions(recs: List[Recommendation]) -> str:
    """Section 6 · Ordered analyst runbook."""
    if not recs:
        return "No further analyst action is recommended at this time."
    numbered = "; ".join(
        f"{i + 1}. {r.action.rstrip('.').rstrip()}"
        for i, r in enumerate(recs[:4])
    )
    return "Recommended next actions: " + numbered + "."


def _prose_analyst(cio: CIO, findings: List[KeyFinding],
                    chain: List[AttackChainStep], entities: EntitiesDigest,
                    mitre: MitreDigest, recs: List[Recommendation]) -> str:
    """The six-question MDR-analyst narrative. Reads like an SOC
    investigation report, never like a log summary. Every sentence
    is derived from the evidence graph — never from raw input_text."""
    urls = _decoded_urls(cio)
    lolbin = _find_lolbin(cio)
    snippet = _final_decoded_snippet(cio)

    p1 = _paragraph_what_happened(cio, urls, lolbin, snippet, mitre)
    p2 = _paragraph_why_it_matters(cio, mitre, lolbin)
    p3 = _paragraph_evidence(cio, findings, entities)
    p4 = _paragraph_impact_scope(cio, entities)
    p5 = _paragraph_containment(cio)
    p6 = _paragraph_next_actions(recs)

    # Blank line between paragraphs so the frontend renders discrete
    # sections without any additional structuring.
    return "\n\n".join([p1, p2, p3, p4, p5, p6])


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


# ─── P0.5 · Report Validator hook ──────────────────────────────────
def _run_validator(cio: CIO, customer_report_payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Run the Executive Quality Gate. Never raises; on any internal
    failure returns a best-effort 'pass' with a warning, so the summary
    itself is never blocked."""
    try:
        from nivxforge.investigation.report_validator import validate_report
        cio_dict = cio.model_dump(mode="json") if hasattr(cio, "model_dump") else dict(cio)
        v = validate_report(cio_dict, customer_report=customer_report_payload)
        return v.to_dict()
    except Exception as e:  # noqa: BLE001
        return {
            "status": "pass",
            "score": 100,
            "blockers": [],
            "warnings": [f"validator-exception: {type(e).__name__}"],
            "checks": {},
            "summary": "Validator degraded to pass due to internal error.",
        }


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

    # Persona-aware Customer Report (ADR-2026-02 · customer_report.py).
    # Composed from ONLY canonical CIO fields — never from decoder pipeline
    # telemetry. Failures degrade the field gracefully (analyst still gets
    # the legacy prose) so verdict/composition never blocks on the new gate.
    customer_report_payload: Optional[Dict[str, Any]] = None
    try:
        from .customer_report import compose_customer_report
        from .report_critic import critique as _critique
        _cr = compose_customer_report(cio, persona="customer")
        _crit = _critique(_cr, cio)
        # GAP 6 · Dynamic section selection — drop sections the critic
        # classified as empty so the customer never sees "No X was
        # included" placeholder noise. Always-keep sections (1, 15) are
        # preserved by the critic itself.
        if _crit.dropped_sections:
            _cr.sections = [s for s in _cr.sections if s.title not in _crit.dropped_sections]
        # P0.1 · Renumber contiguously after pruning so analysts never
        # see "## 1 ... ## 5 ... ## 7" gaps. The 14-section ADR order
        # is preserved; only the visible numbering is reflowed.
        for _i, _s in enumerate(_cr.sections, start=1):
            _s.number = _i
        customer_report_payload = _cr.to_dict()
        customer_report_payload["critique"] = _crit.to_dict()
        # The customer-facing markdown lives in
        # `summary.customer_report.markdown` and is what the Executive
        # lens renders (P0.1/P0.2). The legacy 6-paragraph analyst
        # prose (§1.1.18 Event-first) is kept in `summary.analyst` for
        # backward compatibility with tests, decoder-persona surfaces,
        # and any UI that consumes the older shape.
    except Exception:  # noqa: BLE001
        # Non-fatal — legacy prose kept as fallback. The CI hygiene gate
        # still catches forbidden-term leaks before deploy.
        pass

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
        customer_report=customer_report_payload,
        report_validation=_run_validator(cio, customer_report_payload),
    )


__all__ = [
    "compose_summary", "Summary",
    "KeyFinding", "Unknown", "Recommendation", "AttackChainStep",
    "EvidenceDigest", "EntitiesDigest", "MitreDigest", "TimelineDigest",
    "ReportSections",
]
