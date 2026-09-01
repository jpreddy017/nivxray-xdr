"""Round 31 · Capability base contract.

Round 32 (Capability Fabric v0) will register the full plugin set.
Round 31 defines the *interface* and ships two evidence-safe
reference capabilities so the loop is testable end-to-end.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.investigator.models import (
    CapabilityAvailability, PivotAction, Finding,
)


def _fid(payload: str) -> str:
    return "fnd_" + hashlib.sha256(payload.encode()).hexdigest()[:20]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Capability:
    """A pluggable investigation capability.

    Contract (owner-locked):
      * ``id`` is stable across runs.
      * ``availability`` honestly reports whether the capability is
        wired to a real engine.  When ``cap-unavailable`` the selector
        skips the pivot and records the reason — it never fabricates.
      * ``execute`` returns ``(findings, evidence_ids)`` and must
        never invent an ``OBSERVED`` finding for a fact it did not
        directly read from canonical evidence.
    """
    id: str = "capability::base"
    engine: str = "nivxray::investigator::capability::base"
    availability: CapabilityAvailability = "cap-unavailable"
    unavailable_reason: str = "Not registered."

    async def execute(self, db, pivot: PivotAction,
                        incident: Dict[str, Any],
                        canonical: Optional[Dict[str, Any]],
                       ) -> tuple[List[Finding], List[str]]:
        raise NotImplementedError


# ── Registry ────────────────────────────────────────────────────────

_REGISTRY: Dict[str, Capability] = {}


def register_capability(cap: Capability) -> None:
    _REGISTRY[cap.id] = cap


def get_capability(capability_id: str) -> Optional[Capability]:
    return _REGISTRY.get(capability_id)


def all_capabilities() -> Dict[str, Capability]:
    return dict(_REGISTRY)


# ── Reference capabilities (Round 31 built-ins) ─────────────────────

class HistoricalCorrelationCapability(Capability):
    """Deterministic prior-sighting probe.

    Reads ``xdr_canonical_evidence`` for previous appearances of the
    incident's network entities.  A prior sighting IS legitimate new
    knowledge (§13 · Cross-incident intelligence) — its evidence
    state is ``CORRELATED``, not ``OBSERVED``.
    """
    id = "historical_correlation"
    engine = "nivxray::investigator::historical_correlation"
    availability: CapabilityAvailability = "cap-full"

    async def execute(self, db, pivot: PivotAction,
                        incident: Dict[str, Any],
                        canonical: Optional[Dict[str, Any]],
                       ) -> tuple[List[Finding], List[str]]:
        from services.iue.service import CANONICAL_COLLECTION
        findings: List[Finding] = []
        evidence_ids: List[str] = []
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]

        # Probe network IPs (deterministic — sorted).
        pipe = incident.get("xdr_pipeline") or {}
        current_evt = pipe.get("canonical_event_id")

        def _ips_from_canonical() -> List[tuple[str, str]]:
            out: List[tuple[str, str]] = []
            if not canonical:
                return out
            net = canonical.get("network") or {}
            for side in ("src", "dst"):
                ip = (net.get(side) or {}).get("ip")
                if ip:
                    out.append((f"network.{side}.ip", str(ip)))
            return sorted(set(out))

        for field, ip in _ips_from_canonical():
            cursor = db[CANONICAL_COLLECTION].find(
                {field: ip}, {"_id": 0, "event_id": 1, "timestamp": 1},
            ).sort("timestamp", 1)
            prior_events: List[str] = []
            async for d in cursor:
                evt = d.get("event_id")
                if evt and evt != current_evt:
                    prior_events.append(str(evt))
            if not prior_events:
                # Honestly emit NOT_OBSERVED — the probe was made.
                fid = _fid(f"{incident_id}|hist|{field}|{ip}|none")
                findings.append(Finding(
                    finding_id=fid,
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    execution_id=pivot.pivot_id,
                    capability=self.id, engine=self.engine,
                    kind="prior_sighting",
                    subject_kind="ipv4" if "." in ip else "ipv6",
                    subject_value=ip,
                    state="NOT_OBSERVED",
                    confidence=0,
                    summary=f"No prior sightings of {ip} in canonical evidence.",
                    evidence_refs=[current_evt] if current_evt else [],
                    reasoning=(
                        f"Queried {field}=={ip} across xdr_canonical_evidence; "
                        f"zero events other than the current incident's."
                    ),
                    created_at=_now_iso(),
                    provenance={"query_field": field, "query_value": ip},
                ))
                continue

            fid = _fid(f"{incident_id}|hist|{field}|{ip}|{','.join(sorted(prior_events))}")
            findings.append(Finding(
                finding_id=fid,
                tenant_id=tenant_id,
                incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="prior_sighting",
                subject_kind="ipv4" if "." in ip else "ipv6",
                subject_value=ip,
                state="CORRELATED",
                confidence=min(30 + 10 * len(prior_events), 90),
                summary=(
                    f"{ip} was previously observed in "
                    f"{len(prior_events)} canonical event"
                    f"{'s' if len(prior_events) != 1 else ''}."
                ),
                evidence_refs=[current_evt] + prior_events if current_evt
                                  else list(prior_events),
                reasoning=(
                    f"Queried {field}=={ip}; prior sightings found "
                    f"at events {sorted(prior_events)[:5]}"
                    + (" (truncated)" if len(prior_events) > 5 else "")
                    + "."
                ),
                created_at=_now_iso(),
                provenance={"query_field": field,
                             "query_value": ip,
                             "prior_event_ids": sorted(prior_events)},
            ))
            evidence_ids.extend(prior_events)

        return findings, evidence_ids


class MitreExpansionCapability(Capability):
    """Deterministic MITRE expansion probe.

    Reads correlation matches associated with the incident and folds
    their MITRE techniques into a finding.  A finding here is
    ``CORRELATED`` — it never promotes a technique to ``OBSERVED``
    unless canonical evidence already carries it.
    """
    id = "mitre_expansion"
    engine = "nivxray::investigator::mitre_expansion"
    availability: CapabilityAvailability = "cap-full"

    async def execute(self, db, pivot: PivotAction,
                        incident: Dict[str, Any],
                        canonical: Optional[Dict[str, Any]],
                       ) -> tuple[List[Finding], List[str]]:
        findings: List[Finding] = []
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]

        # Pull correlation matches deterministically.
        pipe = incident.get("xdr_pipeline") or {}
        ice_ids: List[str] = pipe.get("ice_matches") or []
        matches: List[Dict[str, Any]] = []
        if ice_ids:
            async for m in db["xdr_correlation_matches"].find(
                {"match_id": {"$in": ice_ids}}, {"_id": 0}
            ):
                matches.append(m)
        matches.sort(key=lambda m: str(m.get("match_id") or ""))

        # Techniques already present on incident.mitre — evidence-derived.
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
                if tid in already:
                    continue
                if tid not in extra:
                    extra.append(tid)

        if not extra:
            fid = _fid(f"{incident_id}|mitre_exp|none")
            findings.append(Finding(
                finding_id=fid,
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="mitre_expansion",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED",
                confidence=0,
                summary="No additional MITRE techniques found beyond signature-derived set.",
                evidence_refs=[],
                reasoning=(
                    f"Scanned {len(matches)} correlation match(es); no "
                    f"technique beyond the {len(already)} already mapped "
                    f"from evidence."
                ),
                created_at=_now_iso(),
            ))
        else:
            fid = _fid(f"{incident_id}|mitre_exp|{','.join(sorted(extra))}")
            findings.append(Finding(
                finding_id=fid,
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="mitre_expansion",
                subject_kind="incident", subject_value=incident_id,
                state="CORRELATED",
                confidence=60,
                summary=(
                    f"Correlation added {len(extra)} MITRE technique(s) "
                    f"beyond signature-derived attribution."
                ),
                evidence_refs=[str(m.get("match_id"))
                                    for m in matches if m.get("match_id")],
                reasoning=(
                    f"Correlation matches contributed techniques: "
                    f"{sorted(extra)}"
                ),
                created_at=_now_iso(),
                provenance={"added_techniques": sorted(extra)},
            ))
        return findings, []


class UnavailableCapability(Capability):
    """Marker capability — honestly skipped by the selector."""

    def __init__(self, cap_id: str, engine_name: str, reason: str) -> None:
        self.id = cap_id
        self.engine = engine_name
        self.availability = "cap-unavailable"
        self.unavailable_reason = reason

    async def execute(self, db, pivot: PivotAction,
                        incident: Dict[str, Any],
                        canonical: Optional[Dict[str, Any]],
                       ) -> tuple[List[Finding], List[str]]:
        raise RuntimeError("Unavailable capability must not be executed.")


# ── Register built-ins + Round 32 handoff stubs ─────────────────────

def _seed_registry() -> None:
    if _REGISTRY:
        return
    register_capability(HistoricalCorrelationCapability())
    register_capability(MitreExpansionCapability())
    # Round 32 will replace these with real engines.
    for cap_id, engine_name, reason in (
        ("process_ancestry",
          "nivxray::investigator::process_ancestry",
          "Endpoint process ancestry engine not registered (Round 32)."),
        ("identity_pivot",
          "nivxray::investigator::identity_pivot",
          "Identity plane engine not registered (Round 32)."),
        ("file_reputation",
          "nivxray::investigator::file_reputation",
          "File reputation engine not registered (Round 32)."),
        ("network_pivot",
          "nivxray::investigator::network_pivot",
          "Network pivot engine not registered (Round 32)."),
    ):
        register_capability(UnavailableCapability(cap_id, engine_name, reason))


_seed_registry()
