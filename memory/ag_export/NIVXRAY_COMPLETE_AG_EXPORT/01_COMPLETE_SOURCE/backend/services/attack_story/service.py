"""Round 33 · NivXRay XDR · Attack Story + AttackFlow engine.

Consumes Round 30 IUE artifacts + Round 31 investigation state +
Round 32 findings ledger + engine_executions and emits a
14-stage AttackFlow with the four-state grammar
(OBSERVED · SUPPORTED · POSSIBLE · NOT_OBSERVED) plus an
evidence-backed narrative.

**Owner-locked rules (Round 33 gate)**:
  * The Attack Story explains evidence; it does not manufacture it.
  * Every non-``NOT_OBSERVED`` stage must be traceable to a real
    finding, canonical event, or correlation match.
  * The stage list comes from ``attack_cycle.STAGES`` — do NOT
    duplicate.
  * Deterministic: same governed state → identical output.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from services.attack_story.attack_cycle import (
    STAGES, STAGE_INDEX, TACTIC_TO_STAGE, TECHNIQUE_TO_TACTIC,
    normalize_tactic, stages_for_technique,
)
from services.iue.service import IUEService
from services.investigator.orchestrator import InvestigatorService


ENGINE_ID = "nivxray::attack_story::v1"
ENGINE_VERSION = "1.0.0"

INCIDENTS_COLLECTION = "workspace_cases"
CANONICAL_COLLECTION = "xdr_canonical_evidence"
CORRELATION_MATCHES_COLLECTION = "xdr_correlation_matches"


class AttackStoryService:
    """Round 33 attack-story projector.  Read-only over governed state.

    Entry point:  ``await AttackStoryService.compose(db, incident_id)``.
    """
    engine_id = ENGINE_ID
    engine_version = ENGINE_VERSION

    @classmethod
    async def compose(cls, db, incident_id: str) -> Dict[str, Any]:
        incident = await db[INCIDENTS_COLLECTION].find_one(
            {"id": incident_id}, {"_id": 0})
        if not incident:
            raise ValueError(f"incident_not_found: {incident_id}")

        pipe = incident.get("xdr_pipeline") or {}
        canonical_id = pipe.get("canonical_event_id")
        canonical = None
        if canonical_id:
            canonical = await db[CANONICAL_COLLECTION].find_one(
                {"event_id": canonical_id}, {"_id": 0})
        ice_ids = pipe.get("ice_matches") or []
        ice_matches: List[Dict[str, Any]] = []
        if ice_ids:
            async for m in db[CORRELATION_MATCHES_COLLECTION].find(
                {"match_id": {"$in": ice_ids}}, {"_id": 0}
            ):
                ice_matches.append(m)
        ice_matches.sort(key=lambda m: str(m.get("match_id") or ""))

        # Latest IUE understanding is the anchor for POSSIBLE stages.
        understanding = await IUEService.latest_valid(db, incident_id)
        if understanding is None:
            understanding = await IUEService.understand_incident(
                db, incident_id, persist=True)

        # Round 32 findings ledger + executions.
        findings = await InvestigatorService.get_findings(db, incident_id)
        executions = await InvestigatorService.get_executions(db, incident_id)

        # Round 38.1 · SSOT · AttackTechniqueEvidence is the ONLY source
        # for ATT&CK state.  Attack Story no longer decides
        # OBSERVED/SUPPORTED/HYPOTHESIZED itself — it projects the
        # canonical model onto the 14-stage attack cycle.
        from services.attack_evidence import compose_attack_evidence
        atk_ev = await compose_attack_evidence(db, incident_id)

        flow = cls._build_flow(
            incident, canonical, ice_matches, findings, executions,
            atk_ev.get("techniques") or [])
        narrative = cls._build_narrative(
            incident, canonical, understanding, findings, flow)

        return {
            "engine_id":       ENGINE_ID,
            "engine_version":  ENGINE_VERSION,
            "incident_id":     incident_id,
            "tenant_id":       incident.get("tenant_id") or "default",
            "iue_fingerprint": understanding.evidence_fingerprint,
            "flow":            flow,
            "narrative":       narrative,
            "counts": {
                "stages_total":         len(flow),
                "stages_observed":       sum(1 for s in flow if s["state"] == "OBSERVED"),
                "stages_supported":      sum(1 for s in flow if s["state"] == "SUPPORTED"),
                "stages_possible":       sum(1 for s in flow if s["state"] == "POSSIBLE"),
                "stages_not_observed":   sum(1 for s in flow if s["state"] == "NOT_OBSERVED"),
                "findings":              len(findings),
                "executions":            len(executions),
            },
            "honesty_note": (
                "Every OBSERVED/SUPPORTED/POSSIBLE stage traces to at "
                "least one governed finding, canonical event, or "
                "correlation match.  NOT_OBSERVED stages remain honest "
                "gaps for future investigation."
            ),
        }

    # ── AttackFlow (14-stage state projection) ───────────────────
    @classmethod
    def _build_flow(cls, incident: Dict[str, Any],
                        canonical: Optional[Dict[str, Any]],
                        ice_matches: List[Dict[str, Any]],
                        findings: List[Dict[str, Any]],
                        executions: List[Dict[str, Any]],
                        atk_techniques: Optional[List[Dict[str, Any]]] = None
                          ) -> List[Dict[str, Any]]:
        """Deterministic 14-stage projection.

        Round 38.2 · Attack Story consumes ``AttackTechniqueEvidence``
        directly — no independent OBSERVED/SUPPORTED decisions on
        techniques.  Findings still contribute at the stage level
        (a capability finding without a technique still meaningfully
        promotes a stage).

        State mapping from AttackTechniqueEvidence.state:
          OBSERVED     → stage OBSERVED
          SUPPORTED    → stage SUPPORTED
          HYPOTHESIZED → stage POSSIBLE
          SUPPRESSED   → ignored (never surfaced)
          NOT_OBSERVED → ignored (default)
        """
        # 1. Collect (stage, evidence_ref, source_kind, technique_id)
        observed: Dict[str, List[Dict[str, Any]]] = {s: [] for s in STAGES}
        supported: Dict[str, List[Dict[str, Any]]] = {s: [] for s in STAGES}
        possible: Dict[str, List[Dict[str, Any]]] = {s: [] for s in STAGES}

        canonical_id = (canonical or {}).get("event_id")

        # ── Round 38.2 · Canonical AttackTechniqueEvidence ──────────
        # This is the SSOT.  Its state governs the stage state.
        state_to_bucket = {
            "OBSERVED":     observed,
            "SUPPORTED":    supported,
            "HYPOTHESIZED": possible,
        }
        for t in (atk_techniques or []):
            tid = t.get("technique_id")
            tstate = t.get("state")
            bucket = state_to_bucket.get(tstate)
            if not tid or bucket is None:
                continue
            tactic = t.get("tactic_id") or t.get("tactic_name") or ""
            stage = normalize_tactic(tactic) if tactic else None
            evidence_ref = (t.get("evidence_ids") or [canonical_id])[0]
            targets = ([stage] if stage
                          else stages_for_technique(str(tid)))
            for st in targets:
                if not st:
                    continue
                bucket[st].append({
                    "technique_id": tid,
                    "evidence_ref": evidence_ref,
                    "source":       "attack_technique_evidence",
                    "confidence":   t.get("confidence"),
                })

        # Findings — the ledger provides the strongest signal.
        # Rule: a finding with state OBSERVED against a technique-mapped
        # subject promotes the stage to OBSERVED; CORRELATED / INFERRED
        # findings promote to SUPPORTED.  NOT_OBSERVED / UNKNOWN findings
        # do NOT promote.
        for f in findings:
            state = f.get("state") or ""
            if state in ("NOT_OBSERVED", "UNKNOWN", "CONTRADICTED"):
                continue
            capability = f.get("capability") or ""
            fid = f.get("finding_id")
            eref = (f.get("evidence_refs") or [None])[0]

            # Deterministic capability → stage hints.
            cap_stage_hints = {
                "lolbas_lookup":       "Defense Evasion",
                "commandline_decode":  "Execution",
                "process_ancestry":    "Execution",
                "network_pivot":       "Command & Control",
                "dns_pivot":           "Command & Control",
                "identity_pivot":      "Credential Access",
                "file_reputation":     "Execution",
                "detection_intel":     None,   # generic — no direct stage
                "historical_correlation": None,
                "correlation":         None,
                "mitre_expansion":     None,
            }
            hint = cap_stage_hints.get(capability)
            if hint:
                bucket = observed if state == "OBSERVED" else supported
                bucket[hint].append({
                    "capability":   capability,
                    "finding_id":   fid,
                    "state":        state,
                    "evidence_ref": eref,
                    "source":       "finding",
                })

            # If the finding carries an explicit MITRE payload in
            # provenance (mitre_expansion), fold it in too.
            prov = f.get("provenance") or {}
            for tid in prov.get("added_techniques", []) or []:
                for st in stages_for_technique(str(tid)):
                    supported[st].append({
                        "technique_id": str(tid).upper(),
                        "finding_id":   fid,
                        "evidence_ref": eref,
                        "source":       "finding.mitre_expansion",
                    })

        # 2. Emit deterministic order (14 stages).
        out: List[Dict[str, Any]] = []
        for idx, stage in enumerate(STAGES):
            if observed[stage]:
                state = "OBSERVED"
                anchors = observed[stage]
            elif supported[stage]:
                state = "SUPPORTED"
                anchors = supported[stage]
            elif possible[stage]:
                state = "POSSIBLE"
                anchors = possible[stage]
            else:
                state = "NOT_OBSERVED"
                anchors = []
            # Deterministic sort of anchors.
            anchors_sorted = sorted(
                (a for a in anchors if a),
                key=lambda a: (str(a.get("technique_id") or ""),
                                    str(a.get("finding_id") or ""),
                                    str(a.get("evidence_ref") or ""),
                                    str(a.get("source") or "")),
            )
            techniques = sorted({str(a["technique_id"])
                                     for a in anchors_sorted
                                     if a.get("technique_id")})
            evidence_refs = sorted({str(a["evidence_ref"])
                                         for a in anchors_sorted
                                         if a.get("evidence_ref")})
            finding_ids = sorted({str(a["finding_id"])
                                     for a in anchors_sorted
                                     if a.get("finding_id")})
            out.append({
                "index":         idx + 1,
                "stage":         stage,
                "state":         state,
                "techniques":    techniques,
                "evidence_refs": evidence_refs,
                "finding_ids":   finding_ids,
                "anchor_count":  len(anchors_sorted),
            })
        return out

    # ── Narrative (evidence-backed sentences per non-NOT_OBSERVED stage) ─
    @classmethod
    def _build_narrative(cls, incident: Dict[str, Any],
                             canonical: Optional[Dict[str, Any]],
                             understanding,
                             findings: List[Dict[str, Any]],
                             flow: List[Dict[str, Any]]) -> Dict[str, Any]:
        ctx = understanding.artifacts.context
        exec_summary_bits: List[str] = []
        # Header: what/where/verdict.
        subj_bits: List[str] = []
        if ctx.hosts:  subj_bits.append(f"host(s) {', '.join(ctx.hosts[:2])}")
        if ctx.users:  subj_bits.append(f"user(s) {', '.join(ctx.users[:2])}")
        if not subj_bits and ctx.ips:
            subj_bits.append(f"network endpoint(s) {', '.join(ctx.ips[:2])}")
        subject = " · ".join(subj_bits) if subj_bits else "the incident's entities"

        verdict_label = (ctx.verdict_label or "unknown").upper()
        verdict_score = ctx.verdict_score if ctx.verdict_score is not None else "—"

        exec_summary_bits.append(
            f"NivXRay XDR observed a {verdict_label} incident affecting "
            f"{subject} (verdict score {verdict_score})."
        )

        observed_stages = [s for s in flow if s["state"] == "OBSERVED"]
        supported_stages = [s for s in flow if s["state"] == "SUPPORTED"]
        possible_stages = [s for s in flow if s["state"] == "POSSIBLE"]
        not_observed = [s for s in flow if s["state"] == "NOT_OBSERVED"]

        if observed_stages:
            exec_summary_bits.append(
                "Directly observed activity spans: "
                + ", ".join(s["stage"] for s in observed_stages) + "."
            )
        if supported_stages:
            exec_summary_bits.append(
                "Correlated evidence additionally supports: "
                + ", ".join(s["stage"] for s in supported_stages) + "."
            )
        if possible_stages:
            exec_summary_bits.append(
                "Possible additional stages (not yet evidence-anchored): "
                + ", ".join(s["stage"] for s in possible_stages) + "."
            )
        if not_observed:
            exec_summary_bits.append(
                f"{len(not_observed)} attack-cycle stage(s) remain honestly "
                "NOT_OBSERVED with no supporting evidence."
            )

        # Per-stage sentences — only for non-NOT_OBSERVED stages,
        # deterministic wording.
        sentences: List[Dict[str, Any]] = []
        for s in flow:
            if s["state"] == "NOT_OBSERVED":
                continue
            reasons: List[str] = []
            if s["techniques"]:
                reasons.append(
                    f"ATT&CK technique(s) {', '.join(s['techniques'][:4])}"
                )
            if s["finding_ids"]:
                reasons.append(f"{len(s['finding_ids'])} evidence-anchored finding(s)")
            if s["evidence_refs"]:
                reasons.append(f"{len(s['evidence_refs'])} evidence reference(s)")
            sentences.append({
                "stage": s["stage"],
                "state": s["state"],
                "text": (
                    f"{s['state']} · {s['stage']}: "
                    + ("supported by " + " · ".join(reasons)
                          if reasons else
                          "supported by governed evidence.")
                ),
                "evidence_refs": s["evidence_refs"],
                "finding_ids":   s["finding_ids"],
            })

        return {
            "executive_summary": " ".join(exec_summary_bits),
            "sentences": sentences,
        }
