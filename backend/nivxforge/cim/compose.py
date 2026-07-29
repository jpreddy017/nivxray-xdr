"""ADR-0009 §2.6 · CIM Composer.

Consumes a `FactSubstrate`, produces a valid `Investigation`. This module
NEVER imports from routers/ops.py, NEVER parses HTTP JSON, NEVER touches
the network or the DB. Pure function of its input.
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Tuple

from nivxforge.cim.fact_substrate import FactSubstrate, IOCRecord
from nivxforge.cim.models import (
    Investigation,
    InvestigationSource,
    Executive,
    Evidence,
    EvidenceSource,
    Assessment,
    AnalysisStage,
    Recommendation,
    Entity,
    Relationship,
    ThreatIntelHit,
    AttackTechnique,
    Confidence,
)
from nivxforge.cim.unknowns import generate_unknowns
from nivxforge.cim.validators import validate


# ─── Confidence mapping helpers ─────────────────────────────────────────────

def _map_ioc_confidence(rec: IOCRecord) -> Confidence:
    """ADR-0008 stage-2 gated IOCs are Strongly Inferred; stage-1-only are Possible."""
    if "context" in rec.stage_passed and "syntactic" in rec.stage_passed:
        return "Strongly Inferred"
    if "syntactic" in rec.stage_passed:
        return "Possible"
    return "Possible"


def _verdict_to_confidence(pct: int) -> Confidence:
    if pct >= 85:
        return "Confirmed"
    if pct >= 60:
        return "Strongly Inferred"
    if pct >= 30:
        return "Possible"
    return "Unknown"


# ─── Composer ───────────────────────────────────────────────────────────────

def from_facts(fs: FactSubstrate) -> Investigation:
    """Build an `Investigation` from canonical facts.

    Every returned `Investigation` has passed `validators.validate()`.
    """
    # ── ID allocators ────────────────────────────────────────────────
    ev_seq = 0
    a_seq = 0
    r_seq = 0
    e_seq = 0
    rel_seq = 0
    ti_seq = 0
    t_seq = 0

    def next_ev() -> str:
        nonlocal ev_seq
        ev_seq += 1
        return f"EV-{ev_seq:03d}"

    def next_a() -> str:
        nonlocal a_seq
        a_seq += 1
        return f"A-{a_seq:03d}"

    def next_r() -> str:
        nonlocal r_seq
        r_seq += 1
        return f"R-{r_seq:03d}"

    def next_e() -> str:
        nonlocal e_seq
        e_seq += 1
        return f"E-{e_seq:03d}"

    def next_rel() -> str:
        nonlocal rel_seq
        rel_seq += 1
        return f"REL-{rel_seq:03d}"

    def next_ti() -> str:
        nonlocal ti_seq
        ti_seq += 1
        return f"TI-{ti_seq:03d}"

    # ── Evidence · Entities from IOCs ────────────────────────────────
    ioc_ev_ids: List[str] = []
    ioc_entity_ids: List[str] = []
    evidence_list: List[Evidence] = []
    entity_list: List[Entity] = []

    for rec in fs.iocs:
        ev_id = next_ev()
        ent_id = next_e()
        evidence_list.append(Evidence(
            id=ev_id,
            type=f"ioc.{rec.kind}",  # ioc.ip / ioc.domain / ioc.url / ioc.hash / ioc.email
            source=EvidenceSource(producer="ioc_extractor", producer_version="ADR-0008"),
            raw_value=rec.value,
            normalized_value=rec.normalized_value or rec.value,
            confidence=_map_ioc_confidence(rec),
            context_snippet=rec.context_snippet or None,
        ))
        entity_list.append(Entity(
            id=ent_id,
            kind={"ip": "ip", "domain": "domain", "url": "url",
                  "hash": "hash", "email": "email_addr"}.get(rec.kind, "domain"),
            value=rec.value,
            normalized_value=rec.normalized_value,
            role="observed",
            evidence=[ev_id],
        ))
        ioc_ev_ids.append(ev_id)
        ioc_entity_ids.append(ent_id)

    # ── Evidence from decoder layers ─────────────────────────────────
    decode_ev_ids: List[str] = []
    for lyr in fs.decoder_chain:
        ev_id = next_ev()
        evidence_list.append(Evidence(
            id=ev_id,
            type="decoder.layer",
            source=EvidenceSource(producer="decoder", producer_version="pipeline"),
            raw_value=lyr.op,
            normalized_value=f"L{lyr.idx}·{lyr.op}",
            confidence="Confirmed",  # decoder actually ran and produced output
            context_snippet=lyr.output_preview[:120] if lyr.output_preview else None,
        ))
        decode_ev_ids.append(ev_id)

    # ── Evidence from MITRE hits ─────────────────────────────────────
    mitre_ev_by_tid: Dict[str, str] = {}
    for hit in fs.mitre_hits:
        if hit.technique_id in mitre_ev_by_tid:
            continue  # dedup at evidence layer too
        ev_id = next_ev()
        evidence_list.append(Evidence(
            id=ev_id,
            type="mitre.technique",
            source=EvidenceSource(producer="mitre_mapper"),
            raw_value=hit.technique_id,
            normalized_value=hit.technique_id,
            confidence="Strongly Inferred",
            context_snippet=hit.provenance or None,
        ))
        mitre_ev_by_tid[hit.technique_id] = ev_id

    # ── Evidence from TI hits ────────────────────────────────────────
    ti_ev_ids: List[str] = []
    ti_hits: List[ThreatIntelHit] = []
    for hit in fs.ti_hits:
        ev_id = next_ev()
        evidence_list.append(Evidence(
            id=ev_id,
            type="ti.provider_hit",
            source=EvidenceSource(producer=f"ti::{hit.provider}"),
            raw_value=f"{hit.provider}:{hit.label}",
            normalized_value=hit.label,
            confidence="Strongly Inferred",
            context_snippet=hit.subject or None,
        ))
        ti_hits.append(ThreatIntelHit(
            id=next_ti(),
            provider=hit.provider,
            label=hit.label,
            evidence=[ev_id],
        ))
        ti_ev_ids.append(ev_id)

    # ── AttackTechnique list (deduplicated by construction) ──────────
    attack: List[AttackTechnique] = []
    seen_tids: set = set()
    for hit in fs.mitre_hits:
        if hit.technique_id in seen_tids:
            continue
        seen_tids.add(hit.technique_id)
        attack.append(AttackTechnique(
            id=hit.technique_id,
            name=hit.name,
            tactic=hit.tactic,
            evidence=[mitre_ev_by_tid[hit.technique_id]],
        ))

    # ── Assessments ──────────────────────────────────────────────────
    # Verdict assessment — anchored by whatever evidence exists.
    assessments: List[Assessment] = []
    verdict_evidence_pool: List[str] = list(
        set(ioc_ev_ids[:5] + decode_ev_ids[:3] + ti_ev_ids[:3] + list(mitre_ev_by_tid.values())[:3])
    )
    if not verdict_evidence_pool and evidence_list:
        # No obvious signal buckets — anchor on first evidence.
        verdict_evidence_pool = [evidence_list[0].id]

    if fs.verdict and verdict_evidence_pool:
        v_id = next_a()
        assessments.append(Assessment(
            id=v_id,
            statement=fs.verdict.label,
            kind="verdict",
            confidence=_verdict_to_confidence(fs.verdict.confidence_pct),
            evidence=verdict_evidence_pool,
            rationale=" · ".join(fs.verdict.reasons[:3]) if fs.verdict.reasons else None,
        ))
        # Cross-link Evidence.supports back to the Assessment
        for ev in evidence_list:
            if ev.id in verdict_evidence_pool:
                ev.supports.append(v_id)

    # Category / family assessments — anchored on TI + MITRE
    family_ev = ti_ev_ids[:3] + list(mitre_ev_by_tid.values())[:2]
    if family_ev:
        fam_labels = [h.label for h in fs.ti_hits if h.label]
        if fam_labels:
            fa_id = next_a()
            assessments.append(Assessment(
                id=fa_id,
                statement=f"Threat family observed: {fam_labels[0]}",
                kind="family",
                confidence="Strongly Inferred",
                evidence=family_ev,
                rationale=f"Multiple TI sources reference {fam_labels[0]}." if len(fam_labels) > 1 else None,
            ))
            for ev in evidence_list:
                if ev.id in family_ev:
                    ev.supports.append(fa_id)

    # If we somehow have zero assessments but do have evidence, emit a minimal
    # "activity observed" assessment so the merge-gates don't leave the CIM
    # empty (validators still enforce at least one completed stage separately).
    if not assessments and evidence_list:
        a_id = next_a()
        assessments.append(Assessment(
            id=a_id,
            statement="Artifact processed; no verdict-grade evidence produced.",
            kind="behavior",
            confidence="Unknown",
            evidence=[evidence_list[0].id],
        ))
        evidence_list[0].supports.append(a_id)

    # ── Recommendations (evidence-backed, §2.1.d) ────────────────────
    recommendations: List[Recommendation] = []
    if ioc_ev_ids:
        rec_id = next_r()
        recommendations.append(Recommendation(
            id=rec_id,
            kind="hunt",
            text="Sweep environment for the extracted IOCs across EDR / DNS / proxy logs.",
            evidence=ioc_ev_ids[:5],
        ))
    if fs.verdict and fs.verdict.confidence_pct >= 60:
        rec_id = next_r()
        anchor = list(set(ti_ev_ids[:3] + list(mitre_ev_by_tid.values())[:2] + ioc_ev_ids[:2]))
        if not anchor and evidence_list:
            anchor = [evidence_list[0].id]
        if anchor:
            recommendations.append(Recommendation(
                id=rec_id,
                kind="immediate",
                text="Preserve forensic evidence and consider host isolation pending confirmation.",
                evidence=anchor,
            ))

    # ── Stages_executed (AnalysisStage) ──────────────────────────────
    stages: List[AnalysisStage] = []
    stage_ev_map: Dict[str, List[str]] = {
        "decode": decode_ev_ids,
        "ioc_extract": ioc_ev_ids,
        "mitre_map": list(mitre_ev_by_tid.values()),
        "ti_enrich": ti_ev_ids,
    }
    if fs.stages:
        for st in fs.stages:
            stages.append(AnalysisStage(
                name=st.name if st.name in {
                    "normalize", "input_detect", "decode", "deobfuscate",
                    "ioc_extract", "ti_enrich", "behavior", "mitre_map",
                    "reasoning", "pe_static", "office_parse", "pdf_parse",
                    "url_analyze", "sysmon_parse", "email_parse",
                    "sigma_match", "yara_match", "verdict_gate",
                } else "reasoning",
                status=st.status if st.status in {"completed", "skipped", "failed", "error"} else "completed",
                reason=st.reason,
                duration_ms=st.duration_ms,
                evidence_produced=stage_ev_map.get(st.name, []),
            ))
    # Guarantee at least one completed stage (validator invariant #7) —
    # if we have any evidence at all, decode/ioc_extract must have run.
    if not any(s.status == "completed" for s in stages) and evidence_list:
        stages.append(AnalysisStage(
            name="ioc_extract" if ioc_ev_ids else "decode",
            status="completed",
            evidence_produced=(ioc_ev_ids or decode_ev_ids),
        ))

    # ── Unknowns (deterministic, §2.2) ───────────────────────────────
    unknowns = generate_unknowns(fs)

    # ── Executive headline ───────────────────────────────────────────
    verdict_a = next((a for a in assessments if a.kind == "verdict"), None)
    executive = Executive(
        verdict=verdict_a.statement if verdict_a else "No verdict",
        confidence=verdict_a.confidence if verdict_a else "Unknown",
        family=next((h.label for h in fs.ti_hits if h.label), None),
        category=None,  # ADR-0007 will fill this
        business_impact=None,
        evidence_quality=(
            "High" if len(evidence_list) >= 8 else
            "Medium" if len(evidence_list) >= 3 else
            "Low"
        ),
        summary=(fs.reasoning_notes[0] if fs.reasoning_notes else None),
        references=[a.id for a in assessments],
    )

    # ── Relationships from decoder chain (L0 → L1 → …) ───────────────
    # These are entity-linked when we can — for now emit them only when
    # we have entities to link (skip otherwise to avoid dangling refs).
    relationships: List[Relationship] = []
    if len(entity_list) >= 2 and decode_ev_ids:
        # Very light default — connect first URL/domain entity to the first IP entity.
        first_by_kind: Dict[str, str] = {}
        for ent in entity_list:
            first_by_kind.setdefault(ent.kind, ent.id)
        pairs: List[Tuple[str, str, str]] = []
        if "url" in first_by_kind and "domain" in first_by_kind:
            pairs.append((first_by_kind["url"], first_by_kind["domain"], "resolves_via"))
        if "domain" in first_by_kind and "ip" in first_by_kind:
            pairs.append((first_by_kind["domain"], first_by_kind["ip"], "resolves_to"))
        for src, tgt, kind in pairs:
            relationships.append(Relationship(
                id=next_rel(),
                source=src,
                target=tgt,
                kind=kind,
                evidence=[decode_ev_ids[0]] if decode_ev_ids else [],
            ))

    # ── Assemble ─────────────────────────────────────────────────────
    inv = Investigation(
        id=str(uuid.uuid4()),
        source=InvestigationSource(
            surface=fs.source_surface,
            endpoint=fs.source_endpoint,
            correlation_id=fs.correlation_id,
        ),
        executive=executive,
        assessments=assessments,
        evidence=evidence_list,
        timeline=[],  # populated by parsers with real telemetry
        entities=entity_list,
        relationships=relationships,
        threat_intel=ti_hits,
        attack=attack,
        stages_executed=stages,
        decode_chain=[
            {"idx": l.idx, "op": l.op, "input_kind": l.input_kind,
             "output_kind": l.output_kind, "preview": l.output_preview}
            for l in fs.decoder_chain
        ],
        unknowns=unknowns,
        recommendations=recommendations,
        report=None,
        provenance=[],
    )

    # ── Prune orphan evidence (defensive · validators.validate() then re-checks)
    # A cleaner design would refuse to emit orphans in the first place — but for
    # robustness with future stage_ev populators, we drop unreferenced evidence
    # here so the composer never fails on transient orphans it can trivially fix.
    referenced: set = set()
    for a in inv.assessments:
        referenced.update(a.evidence)
    for r in inv.recommendations:
        referenced.update(r.evidence)
    for u in inv.unknowns:
        referenced.update(u.evidence)
    for t in inv.timeline:
        referenced.update(t.evidence)
    for rel in inv.relationships:
        referenced.update(rel.evidence)
    for th in inv.threat_intel:
        referenced.update(th.evidence)
    for at in inv.attack:
        referenced.update(at.evidence)
    for ent in inv.entities:
        referenced.update(ent.evidence)
    for st in inv.stages_executed:
        referenced.update(st.evidence_produced)
    inv.evidence = [e for e in inv.evidence if e.id in referenced]

    # ── Validate all §2.8 invariants ─────────────────────────────────
    validate(inv)
    return inv
