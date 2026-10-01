"""Round 32 · Historical + Correlation + MITRE capabilities.

These reuse existing NivXRay data collections:
  * ``xdr_canonical_evidence``  (Evidence Plane)
  * ``xdr_correlation_matches`` (Round 11 ICE output)
  * ``workspace_cases``         (incidents SSOT)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from services.investigator.capabilities.base import (
    Capability, EvidenceSufficiency, fid, now_iso,
)
from services.investigator.models import Finding, PivotAction


# ── Historical correlation ──────────────────────────────────────────

class HistoricalCorrelationCapability(Capability):
    id = "historical_correlation"
    name = "Historical Correlation"
    engine = "nivxray::investigator::historical_correlation"
    category = "history"
    investigation_question = (
        "Have the entities in this incident been seen previously in the "
        "environment or in other incidents?"
    )
    evidence_requirements = ("canonical.network.*.ip OR incident.iocs.ip",)
    availability = "cap-full"
    gaps_closed_hint = ("cross_evidence.no_correlation",)

    def check_evidence(self, incident: Dict[str, Any],
                          canonical: Optional[Dict[str, Any]],
                         ) -> Tuple[EvidenceSufficiency, str]:
        ips: List[str] = []
        if canonical:
            net = canonical.get("network") or {}
            for side in ("src", "dst"):
                ip = (net.get(side) or {}).get("ip")
                if ip:
                    ips.append(str(ip))
        iocs = (incident.get("iocs") or {})
        ips.extend(iocs.get("ip") or iocs.get("ips") or [])
        if ips:
            return "SUFFICIENT", f"{len(ips)} IP entity(ies) available for probe"
        return "INSUFFICIENT", "no IP entity in canonical evidence or iocs"

    async def execute(self, db, pivot: PivotAction,
                        incident: Dict[str, Any],
                        canonical: Optional[Dict[str, Any]],
                       ) -> Tuple[List[Finding], List[str]]:
        findings: List[Finding] = []
        evidence_ids: List[str] = []
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        pipe = incident.get("xdr_pipeline") or {}
        current_evt = pipe.get("canonical_event_id")

        probes: List[Tuple[str, str]] = []
        if canonical:
            net = canonical.get("network") or {}
            for side in ("src", "dst"):
                ip = (net.get(side) or {}).get("ip")
                if ip:
                    probes.append((f"network.{side}.ip", str(ip)))
        # Deterministic order.
        probes = sorted(set(probes))

        for field, ip in probes:
            cursor = db["xdr_canonical_evidence"].find(
                {field: ip}, {"_id": 0, "event_id": 1, "timestamp": 1},
            ).sort("timestamp", 1)
            prior: List[str] = []
            async for d in cursor:
                evt = d.get("event_id")
                if evt and evt != current_evt:
                    prior.append(str(evt))

            if not prior:
                findings.append(Finding(
                    finding_id=fid(f"{incident_id}|hist|{field}|{ip}|none"),
                    tenant_id=tenant_id, incident_id=incident_id,
                    execution_id=pivot.pivot_id,
                    capability=self.id, engine=self.engine,
                    kind="prior_sighting",
                    subject_kind="ipv4" if "." in ip else "ipv6",
                    subject_value=ip,
                    state="NOT_OBSERVED", confidence=0,
                    summary=f"No prior sightings of {ip} in canonical evidence.",
                    evidence_refs=[current_evt] if current_evt else [],
                    reasoning=(
                        f"Queried {field}=={ip} across xdr_canonical_evidence; "
                        f"no events other than the current incident's."
                    ),
                    created_at=now_iso(),
                    provenance={"query_field": field, "query_value": ip},
                ))
                continue

            findings.append(Finding(
                finding_id=fid(
                    f"{incident_id}|hist|{field}|{ip}|{','.join(sorted(prior))}"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="prior_sighting",
                subject_kind="ipv4" if "." in ip else "ipv6",
                subject_value=ip,
                state="CORRELATED",
                confidence=min(30 + 10 * len(prior), 90),
                summary=(
                    f"{ip} was previously observed in {len(prior)} "
                    f"canonical event{'s' if len(prior) != 1 else ''}."
                ),
                evidence_refs=([current_evt] + prior[:20]) if current_evt
                                    else prior[:20],
                reasoning=(
                    f"Queried {field}=={ip}; prior events "
                    f"{sorted(prior)[:5]}"
                    + (" (truncated)" if len(prior) > 5 else "")
                    + "."
                ),
                created_at=now_iso(),
                provenance={"query_field": field,
                             "query_value": ip,
                             "prior_event_ids": sorted(prior)[:50]},
            ))
            evidence_ids.extend(prior)
        return findings, evidence_ids


# ── Correlation capability ──────────────────────────────────────────

class CorrelationCapability(Capability):
    id = "correlation"
    name = "Cross-Evidence Correlation"
    engine = "nivxray::investigator::correlation"
    category = "correlation"
    investigation_question = (
        "What correlation rules link this evidence to other observations?"
    )
    evidence_requirements = ("incident.xdr_pipeline.ice_matches",)
    availability = "cap-full"
    gaps_closed_hint = ("cross_evidence.no_correlation",)

    def check_evidence(self, incident, canonical):
        pipe = incident.get("xdr_pipeline") or {}
        ice = pipe.get("ice_matches") or []
        if ice:
            return "SUFFICIENT", f"{len(ice)} correlation match(es) present"
        return "INSUFFICIENT", "no correlation matches on incident"

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        pipe = incident.get("xdr_pipeline") or {}
        ice_ids: List[str] = pipe.get("ice_matches") or []
        matches: List[Dict[str, Any]] = []
        if ice_ids:
            async for m in db["xdr_correlation_matches"].find(
                {"match_id": {"$in": ice_ids}}, {"_id": 0}
            ):
                matches.append(m)
        matches.sort(key=lambda m: str(m.get("match_id") or ""))

        if not matches:
            return [Finding(
                finding_id=fid(f"{incident_id}|corr|none"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="correlation",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED", confidence=0,
                summary="No correlation matches found for this incident.",
                evidence_refs=[], reasoning="ice_matches empty.",
                created_at=now_iso(),
            )], []

        findings: List[Finding] = []
        for m in matches:
            mid = str(m.get("match_id") or m.get("id"))
            rule_id = m.get("rule_id")
            findings.append(Finding(
                finding_id=fid(f"{incident_id}|corr|{mid}"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="correlation",
                subject_kind="correlation_match", subject_value=mid,
                state="CORRELATED", confidence=70,
                summary=(
                    f"Correlation rule {rule_id or '(unknown)'} "
                    f"matched this evidence."
                ),
                evidence_refs=[mid],
                reasoning=(
                    f"xdr_correlation_matches[{mid}] triggered by rule "
                    f"{rule_id}."
                ),
                created_at=now_iso(),
                provenance={"rule_id": rule_id, "match": {
                    k: v for k, v in m.items()
                    if k in ("engine_id", "matched_fields", "mitre")
                }},
            ))
        return findings, [str(m.get("match_id") or m.get("id"))
                            for m in matches if m.get("match_id") or m.get("id")]


# ── MITRE expansion ─────────────────────────────────────────────────

class MitreExpansionCapability(Capability):
    id = "mitre_expansion"
    name = "MITRE ATT&CK Expansion"
    engine = "nivxray::investigator::mitre_expansion"
    category = "mitre"
    investigation_question = (
        "What additional ATT&CK techniques are supported by correlation "
        "beyond those directly attributed to the detection signature?"
    )
    evidence_requirements = ("incident.mitre OR correlation.mitre",)
    availability = "cap-full"
    gaps_closed_hint = ("mitre_expansion.signature_only",)

    def check_evidence(self, incident, canonical):
        has_mitre = bool(incident.get("mitre"))
        pipe = incident.get("xdr_pipeline") or {}
        has_ice = bool(pipe.get("ice_matches"))
        if has_mitre or has_ice:
            return "SUFFICIENT", "signature-derived or correlation MITRE present"
        return "PARTIAL", "no MITRE attribution surface — will emit NOT_OBSERVED"

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        pipe = incident.get("xdr_pipeline") or {}
        ice_ids = pipe.get("ice_matches") or []
        matches: List[Dict[str, Any]] = []
        if ice_ids:
            async for m in db["xdr_correlation_matches"].find(
                {"match_id": {"$in": ice_ids}}, {"_id": 0}
            ):
                matches.append(m)
        matches.sort(key=lambda m: str(m.get("match_id") or ""))

        already = {
            str((m.get("technique_id") or m.get("technique") or "")).upper()
            for m in (incident.get("mitre") or []) if isinstance(m, dict)
        }
        extra: List[str] = []
        for m in matches:
            for tech in (m.get("mitre") or []):
                tid = None
                if isinstance(tech, dict):
                    tid = tech.get("technique_id") or tech.get("technique")
                else:
                    tid = str(tech) if tech else None
                if not tid:
                    continue
                tid = str(tid).upper()
                if tid in already or tid in extra:
                    continue
                extra.append(tid)

        if not extra:
            return [Finding(
                finding_id=fid(f"{incident_id}|mitre_exp|none"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="mitre_expansion",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED", confidence=0,
                summary="No additional MITRE techniques beyond signature-derived set.",
                evidence_refs=[],
                reasoning=(
                    f"Scanned {len(matches)} correlation match(es); no "
                    f"technique beyond the {len(already)} already mapped."
                ),
                created_at=now_iso(),
            )], []

        return [Finding(
            finding_id=fid(f"{incident_id}|mitre_exp|{','.join(sorted(extra))}"),
            tenant_id=tenant_id, incident_id=incident_id,
            execution_id=pivot.pivot_id,
            capability=self.id, engine=self.engine,
            kind="mitre_expansion",
            subject_kind="incident", subject_value=incident_id,
            state="CORRELATED", confidence=60,
            summary=(
                f"Correlation added {len(extra)} MITRE technique(s) "
                f"beyond signature-derived attribution."
            ),
            evidence_refs=[str(m.get("match_id"))
                                for m in matches if m.get("match_id")],
            reasoning=f"Correlation contributed techniques: {sorted(extra)}",
            created_at=now_iso(),
            provenance={"added_techniques": sorted(extra)},
        )], []


# ── Detection intelligence ──────────────────────────────────────────

class DetectionIntelCapability(Capability):
    id = "detection_intel"
    name = "Detection / Rule Intelligence"
    engine = "nivxray::investigator::detection_intel"
    category = "detection"
    investigation_question = (
        "What rule fired, on which engine, and what does the rule itself "
        "assert about this evidence?"
    )
    evidence_requirements = ("incident.xdr_pipeline.detection_rule_id",)
    availability = "cap-full"

    def check_evidence(self, incident, canonical):
        pipe = incident.get("xdr_pipeline") or {}
        if pipe.get("detection_rule_id"):
            return "SUFFICIENT", "detection rule id linked to incident"
        return "INSUFFICIENT", "no detection rule linked to incident"

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        pipe = incident.get("xdr_pipeline") or {}
        rule_id = pipe.get("detection_rule_id")
        veee = (pipe.get("veee") or {})
        engine_id = veee.get("engine_id") or pipe.get("engine_id")
        summary_bits = [f"Detection rule: {rule_id}"]
        if engine_id:
            summary_bits.append(f"Engine: {engine_id}")
        if veee.get("label"):
            summary_bits.append(f"Verdict: {veee['label']}")
        return [Finding(
            finding_id=fid(f"{incident_id}|det|{rule_id}"),
            tenant_id=tenant_id, incident_id=incident_id,
            execution_id=pivot.pivot_id,
            capability=self.id, engine=self.engine,
            kind="detection_intel",
            subject_kind="rule", subject_value=str(rule_id),
            state="OBSERVED", confidence=85,
            summary=" · ".join(summary_bits),
            evidence_refs=[pipe.get("canonical_event_id")] if pipe.get("canonical_event_id") else [],
            reasoning=(
                "Detection rule fired against the canonical evidence; "
                "verdict engine already governed the resulting label."
            ),
            created_at=now_iso(),
            provenance={"rule_id": rule_id, "engine_id": engine_id,
                          "veee_label": veee.get("label"),
                          "veee_score": veee.get("score")},
        )], []
