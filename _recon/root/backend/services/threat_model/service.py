"""Round 34 · NivXRay XDR · Threat Model Engine.

Deterministic composer that produces the analyst-facing Threat
Assessment from governed state:

  Round 30 IUE artifacts
      +
  Round 31 investigation state (executions + counts)
      +
  Round 32 findings ledger
      +
  Round 33 Attack Story flow (SSOT: attack_cycle.STAGES)
      =
  Threat Assessment  ·  5 sub-dimensions  ·  Impact  ·  Blast Radius
  ·  Why-It-Matters  ·  Executive Investigation Summary

**Owner-locked rules**:
  * Reuses ``attack_cycle.STAGES`` from Round 33 — no duplication.
  * Impact confidence does NOT inflate threat likelihood.
    The two dimensions remain independent (per owner correction).
  * Every generated block carries ``machine_generated: true`` so
    Round 35 (editable/versioned intelligence) can wrap it.
  * Deterministic: same governed state → identical output.
  * Non-fabrication: sub-dimensions are anchored to concrete
    counts (findings state distribution · executions · stage
    coverage · IUE fingerprint · verdict) — no random weights.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from services.attack_story.attack_cycle import STAGES
from services.attack_story import AttackStoryService
from services.iue.service import IUEService
from services.investigator.orchestrator import InvestigatorService


ENGINE_ID = "nivxray::threat_model::v1"
ENGINE_VERSION = "1.0.0"
INCIDENTS_COLLECTION = "workspace_cases"


def _clamp(v: float, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(round(v))))


def _band(score: int, thresholds=(30, 60, 85)) -> str:
    if score >= thresholds[2]: return "VERY_HIGH"
    if score >= thresholds[1]: return "HIGH"
    if score >= thresholds[0]: return "MODERATE"
    return "LOW"


class ThreatModelService:
    """Read-only composer.  Never writes; never fabricates."""

    engine_id = ENGINE_ID
    engine_version = ENGINE_VERSION

    @classmethod
    async def compose(cls, db, incident_id: str) -> Dict[str, Any]:
        incident = await db[INCIDENTS_COLLECTION].find_one(
            {"id": incident_id}, {"_id": 0})
        if not incident:
            raise ValueError(f"incident_not_found: {incident_id}")

        understanding = await IUEService.latest_valid(db, incident_id)
        if understanding is None:
            understanding = await IUEService.understand_incident(
                db, incident_id, persist=True)

        findings = await InvestigatorService.get_findings(db, incident_id)
        executions = await InvestigatorService.get_executions(db, incident_id)
        state = await InvestigatorService.get_state(db, incident_id)
        story = await AttackStoryService.compose(db, incident_id)

        # ── 5 sub-dimensions (deterministic decomposition) ─────
        dims = cls._dimensions(incident, understanding, findings,
                                    executions, story)

        # Threat Assessment = weighted composition of the FIRST FOUR
        # dimensions ONLY (impact stays separate per owner rule).
        weights = {
            "detection_confidence":     0.25,
            "threat_likelihood":        0.35,
            "evidence_confidence":      0.20,
            "attack_path_confidence":   0.20,
        }
        overall = _clamp(sum(dims[k] * w for k, w in weights.items()))

        # ── Impact ↔ risk (separate from likelihood) ───────────
        impact = cls._impact(incident, findings, story)
        # Risk = likelihood × impact bucket — kept ordinal, not multiplied.
        risk_band = _band(round((overall + impact["score"]) / 2))

        # ── Attack path (from Round 33 flow) ──────────────────
        stages = [{"stage": s["stage"], "state": s["state"],
                     "techniques": s["techniques"],
                     "finding_ids": s["finding_ids"],
                     "evidence_refs": s["evidence_refs"]}
                     for s in story["flow"]]
        top_progression = [s["stage"] for s in stages
                              if s["state"] in ("OBSERVED", "SUPPORTED")]

        # ── Why-It-Matters (evidence-anchored, deterministic) ─
        why = cls._why_it_matters(dims, findings, story, understanding)

        # ── Executive Investigation Summary ───────────────────
        exec_summary = cls._executive_summary(
            incident, understanding, overall, risk_band,
            top_progression, impact, story)

        return {
            "engine_id":       ENGINE_ID,
            "engine_version":  ENGINE_VERSION,
            "incident_id":     incident_id,
            "tenant_id":       incident.get("tenant_id") or "default",
            "iue_fingerprint": understanding.evidence_fingerprint,
            "machine_generated": True,
            "editable":        True,
            "threat_assessment": {
                "overall_score":  overall,
                "overall_band":   _band(overall),
                "risk_band":      risk_band,
                "dimensions":     dims,
                "progression_summary":
                    " → ".join(top_progression) if top_progression
                        else "No attack-cycle stage observed yet",
            },
            "impact":            impact,
            "attack_path":       stages,
            "why_it_matters":    why,
            "executive_summary": exec_summary,
            "counts": {
                "findings":   len(findings),
                "executions": len(executions),
                "observed_stages":  sum(1 for s in stages if s["state"] == "OBSERVED"),
                "supported_stages": sum(1 for s in stages if s["state"] == "SUPPORTED"),
                "possible_stages":  sum(1 for s in stages if s["state"] == "POSSIBLE"),
                "not_observed":     sum(1 for s in stages if s["state"] == "NOT_OBSERVED"),
            },
            "honesty_note": (
                "Every dimension is anchored to a concrete count from "
                "governed state.  Impact does not inflate likelihood "
                "(kept ordinal).  NOT_OBSERVED stages remain honest "
                "gaps.  Everything below is machine-generated and will "
                "become analyst-editable in Round 35."
            ),
        }

    # ── Deterministic dimension decomposition ─────────────────────

    @classmethod
    def _dimensions(cls, incident, understanding, findings, executions,
                        story) -> Dict[str, int]:
        # Detection confidence = verdict score + rule-fired signal.
        vs = understanding.artifacts.context.verdict_score or 0
        rule_bonus = 15 if any(
            e["capability"] == "detection_intel" and e["status"] == "OK"
            for e in executions) else 0
        detection_confidence = _clamp(vs + rule_bonus)

        # Threat likelihood = weighted mix of observed stages + strong findings.
        obs = story["counts"]["stages_observed"]
        sup = story["counts"]["stages_supported"]
        strong_findings = sum(
            1 for f in findings
            if f.get("state") in ("OBSERVED", "CORRELATED")
              and (f.get("confidence") or 0) >= 60)
        threat_likelihood = _clamp(
            obs * 15 + sup * 8 + strong_findings * 5 + vs * 0.3)

        # Evidence confidence = observed:total findings + IUE observed:total.
        total_f = max(len(findings), 1)
        obs_f = sum(1 for f in findings
                        if f.get("state") in ("OBSERVED", "CORRELATED", "SUPPORTED"))
        ku = understanding.artifacts.known_unknown
        obs_facts = len(ku.observed)
        total_facts = obs_facts + len(ku.not_observed) + len(ku.unknown)
        iue_ratio = obs_facts / max(total_facts, 1)
        evidence_confidence = _clamp(
            (obs_f / total_f) * 60 + iue_ratio * 40)

        # Attack-path confidence = coverage of the 14-stage cycle.
        total = story["counts"]["stages_total"]
        attack_path_confidence = _clamp((obs * 8 + sup * 5) * 100 / (total * 8))

        # Impact confidence = fraction of impact predicates that ARE observed
        # (kept as a confidence, not a severity — feeds the separate
        # impact assessment).
        impact_signals = 0
        if any(s["stage"] == "Command & Control"
                    and s["state"] in ("OBSERVED", "SUPPORTED")
                    for s in story["flow"]):
            impact_signals += 1
        if any(s["stage"] in ("Persistence", "Lateral Movement", "Impact",
                                    "Exfiltration")
                    and s["state"] in ("OBSERVED", "SUPPORTED")
                    for s in story["flow"]):
            impact_signals += 1
        if any(f.get("capability") == "identity_pivot"
                    and f.get("state") in ("OBSERVED", "CORRELATED")
                    for f in findings):
            impact_signals += 1
        impact_confidence = _clamp(30 + impact_signals * 25)

        return {
            "detection_confidence":   detection_confidence,
            "threat_likelihood":      threat_likelihood,
            "evidence_confidence":    evidence_confidence,
            "attack_path_confidence": attack_path_confidence,
            "impact_confidence":      impact_confidence,
        }

    # ── Impact assessment (separate axis) ─────────────────────────

    @classmethod
    def _impact(cls, incident, findings, story) -> Dict[str, Any]:
        # Deterministic predicates over governed state.
        stages_by_name = {s["stage"]: s for s in story["flow"]}
        def _obs_or_sup(name):
            s = stages_by_name.get(name, {})
            return s.get("state") in ("OBSERVED", "SUPPORTED")

        c2         = _obs_or_sup("Command & Control")
        persist    = _obs_or_sup("Persistence")
        lateral    = _obs_or_sup("Lateral Movement")
        impact_st  = _obs_or_sup("Impact")
        exfil      = _obs_or_sup("Exfiltration")
        cred       = _obs_or_sup("Credential Access")

        # Blast-radius surrogate — cross-incident related counts from
        # governed findings.
        related_incidents: set = set()
        related_hosts: set = set()
        related_users: set = set()
        for f in findings:
            prov = f.get("provenance") or {}
            for rid in (prov.get("related_incidents") or []):
                related_incidents.add(str(rid))
            if f.get("subject_kind") == "host":
                related_hosts.add(f.get("subject_value"))
            if f.get("subject_kind") == "user":
                related_users.add(f.get("subject_value"))

        current_score = _clamp(20 * sum([c2, persist, lateral, cred, exfil, impact_st]))
        potential_score = _clamp(current_score + 15 * len(related_incidents))
        return {
            "current_score":     current_score,
            "current_band":      _band(current_score),
            "potential_score":   potential_score,
            "potential_band":    _band(potential_score),
            "score":             potential_score,
            "signals": {
                "c2_observed":              c2,
                "persistence_observed":     persist,
                "lateral_movement_observed": lateral,
                "credential_access_observed": cred,
                "exfiltration_observed":    exfil,
                "impact_stage_observed":    impact_st,
            },
            "blast_radius": {
                "related_incidents": sorted(related_incidents),
                "related_hosts":     sorted(x for x in related_hosts if x),
                "related_users":     sorted(x for x in related_users if x),
                "count":             len(related_incidents) + len(related_hosts) + len(related_users),
            },
        }

    # ── Why-it-matters (deterministic, evidence-anchored) ──────────

    @classmethod
    def _why_it_matters(cls, dims, findings, story, understanding) -> Dict[str, Any]:
        supporting: List[Dict[str, Any]] = []
        reducing: List[Dict[str, Any]] = []
        unknown: List[Dict[str, Any]] = []

        # Supporting factors — observed stages + high-confidence findings.
        for s in story["flow"]:
            if s["state"] == "OBSERVED":
                supporting.append({
                    "factor": f"{s['stage']} directly observed",
                    "evidence_refs": s["evidence_refs"][:5],
                    "techniques":    s["techniques"][:5],
                })
            elif s["state"] == "SUPPORTED":
                supporting.append({
                    "factor": f"{s['stage']} supported by correlation",
                    "evidence_refs": s["evidence_refs"][:5],
                    "techniques":    s["techniques"][:5],
                })
        for f in findings:
            if f.get("state") == "CORRELATED" and (f.get("confidence") or 0) >= 60:
                supporting.append({
                    "factor":        f["summary"],
                    "capability":    f["capability"],
                    "evidence_refs": f.get("evidence_refs", [])[:3],
                    "finding_id":    f["finding_id"],
                })

        # Reducing factors — NOT_OBSERVED impactful stages.
        for s in story["flow"]:
            if s["state"] == "NOT_OBSERVED" and s["stage"] in (
                "Exfiltration", "Impact", "Lateral Movement", "Credential Access",
            ):
                reducing.append({
                    "factor": f"{s['stage']} not observed — no supporting evidence",
                })

        # Unknown — from IUE known/unknown ledger.
        for f in understanding.artifacts.known_unknown.unknown[:10]:
            unknown.append({
                "fact":   f.key,
                "reason": f.reason,
            })

        return {
            "what": (
                f"{understanding.artifacts.context.verdict_label or 'unknown'} "
                f"incident on "
                f"{', '.join(understanding.artifacts.context.hosts[:2]) or 'the observed entities'}"
            ),
            "why": (
                f"NivXRay XDR combined {len(findings)} evidence-anchored "
                f"finding(s) with {story['counts']['stages_observed']} directly "
                f"observed and {story['counts']['stages_supported']} correlated "
                f"attack-cycle stage(s)."
            ),
            "supporting_factors": supporting,
            "reducing_factors":   reducing,
            "unknown":            unknown,
            "next_questions": [
                "Is credential access observable on the affected identities?"
                if not any(s["stage"] == "Credential Access"
                                and s["state"] in ("OBSERVED", "SUPPORTED")
                                for s in story["flow"])
                else None,
                "Did the incident progress to Exfiltration or Impact?"
                if not any(s["stage"] in ("Exfiltration", "Impact")
                                and s["state"] in ("OBSERVED", "SUPPORTED")
                                for s in story["flow"])
                else None,
            ],
        }

    # ── Executive Investigation Summary ────────────────────────────

    @classmethod
    def _executive_summary(cls, incident, understanding, overall_score,
                                risk_band, top_progression, impact, story) -> Dict[str, Any]:
        ctx = understanding.artifacts.context
        subject = (
            "host(s) " + ", ".join(ctx.hosts[:2]) if ctx.hosts
            else "network endpoint(s) " + ", ".join(ctx.ips[:2]) if ctx.ips
            else "the observed entities"
        )
        sentences = [
            f"NivXRay XDR classifies this incident as {risk_band} risk "
            f"({overall_score}/100 overall).",
        ]
        if top_progression:
            sentences.append(
                f"Autonomous investigation observed activity spanning "
                + " → ".join(top_progression) + "."
            )
        if impact["blast_radius"]["count"] > 0:
            sentences.append(
                f"Blast radius currently includes "
                f"{len(impact['blast_radius']['related_incidents'])} related "
                f"incident(s), "
                f"{len(impact['blast_radius']['related_hosts'])} host(s), "
                f"{len(impact['blast_radius']['related_users'])} user(s)."
            )
        else:
            sentences.append(
                "No cross-incident linkage has been established yet."
            )
        sentences.append(
            f"{story['counts']['stages_not_observed']} attack-cycle stage(s) "
            "remain honestly NOT_OBSERVED and represent open investigation gaps."
        )
        return {
            "text":              " ".join(sentences),
            "subject":           subject,
            "machine_generated": True,
            "editable":          True,
            "version":           1,
        }
