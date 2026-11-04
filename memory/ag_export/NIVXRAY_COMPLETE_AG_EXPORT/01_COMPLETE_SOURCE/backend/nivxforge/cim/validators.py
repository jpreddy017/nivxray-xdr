"""ADR-0009 §2.8 · CIM invariant validators.

Runs after `compose.from_facts()` produces an `Investigation`. Any
violation raises `CIMValidationError` — the endpoint surfaces that as
HTTP 500 with a governance error code, never a silent partial CIM.
"""
from __future__ import annotations

from nivxforge.cim.models import Investigation, CIMValidationError


def validate(inv: Investigation) -> None:
    """Enforce every ADR-0009 §2.8 invariant. Raises on the FIRST violation."""

    # (1) schema_version present + supported
    if inv.schema_version != "1.0":
        raise CIMValidationError(
            "CIM-VALID-SCHEMA",
            f"unsupported schema_version {inv.schema_version!r} (composer supports 1.0)",
        )

    # (2) Every Assessment.evidence non-empty · (3) Recommendation.evidence non-empty
    # Both are already enforced by Pydantic min_length=1 — but re-assert for
    # defensive clarity and clearer error text.
    for a in inv.assessments:
        if not a.evidence:
            raise CIMValidationError(
                "CIM-VALID-ASSESSMENT-EVIDENCE",
                f"Assessment {a.id} has empty evidence — every conclusion must be evidence-backed.",
            )
    for r in inv.recommendations:
        if not r.evidence:
            raise CIMValidationError(
                "CIM-VALID-RECOMMENDATION-EVIDENCE",
                f"Recommendation {r.id} has empty evidence — unsupported advice.",
            )

    # (4) Every Evidence.supports / .contradicts references existing Assessment.id
    a_ids = {a.id for a in inv.assessments}
    for ev in inv.evidence:
        for aref in ev.supports:
            if aref not in a_ids:
                raise CIMValidationError(
                    "CIM-VALID-DANGLING-SUPPORT",
                    f"Evidence {ev.id}.supports references unknown Assessment {aref}",
                )
        for aref in ev.contradicts:
            if aref not in a_ids:
                raise CIMValidationError(
                    "CIM-VALID-DANGLING-CONTRADICT",
                    f"Evidence {ev.id}.contradicts references unknown Assessment {aref}",
                )

    # (5) NO ORPHAN EVIDENCE · every Evidence.id must be referenced somewhere.
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
    # Evidence produced by stages is a form of reference too — a stage's
    # output evidence is "displayed as a standalone artifact" via
    # stages_executed.evidence_produced.
    for st in inv.stages_executed:
        referenced.update(st.evidence_produced)

    for ev in inv.evidence:
        if ev.id not in referenced:
            raise CIMValidationError(
                "CIM-VALID-ORPHAN-EVIDENCE",
                f"Evidence {ev.id} is not referenced by any Assessment, "
                f"Recommendation, Unknown, TimelineFact, Relationship, "
                f"ThreatIntelHit, AttackTechnique, Entity, or AnalysisStage — dead data.",
            )

    # (6) AttackTechnique list deduplicated
    seen: set = set()
    for at in inv.attack:
        if at.id in seen:
            raise CIMValidationError(
                "CIM-VALID-ATTACK-DEDUP",
                f"AttackTechnique {at.id} appears more than once — must be deduplicated.",
            )
        seen.add(at.id)

    # (7) At least one completed stage for non-empty input.
    # (An investigation with zero completed stages is a governance failure —
    # we did nothing but still emitted a CIM.)
    if not any(s.status == "completed" for s in inv.stages_executed):
        raise CIMValidationError(
            "CIM-VALID-NO-COMPLETED-STAGE",
            "stages_executed contains no 'completed' stage — the CIM should not exist.",
        )

    # (8) Relationship endpoints refer to existing Entity.id
    e_ids = {e.id for e in inv.entities}
    for rel in inv.relationships:
        if rel.source not in e_ids:
            raise CIMValidationError(
                "CIM-VALID-DANGLING-REL-SOURCE",
                f"Relationship {rel.id}.source references unknown Entity {rel.source}",
            )
        if rel.target not in e_ids:
            raise CIMValidationError(
                "CIM-VALID-DANGLING-REL-TARGET",
                f"Relationship {rel.id}.target references unknown Entity {rel.target}",
            )
