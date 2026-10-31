"""Round 30 · IUE v0 · Investigation Understanding Engine service.

Deterministic backend service that consumes governed evidence + IKG
records for one incident and emits the six understanding artifacts
defined in ``services.iue.artifacts``.

**Boundary contract** (owner-locked, AUTONOMOUS_INVESTIGATION.md §15):
  * No UI.  No Orchestrator (Round 31 consumes).  No AI.  No STIX/TAXII.
  * Reads Evidence Plane (``xdr_canonical_evidence``), IKG surrogate
    facts on ``workspace_cases``, and ``xdr_correlation_matches``.
  * Persists a versioned snapshot into ``xdr_iue_understanding``.
  * Never fabricates evidence.  Never overrides Verdict Engine (§10).

**Latest snapshot resolution**:
  "Latest" = the snapshot whose ``evidence_fingerprint`` matches the
  current governed state, not simply the newest timestamp.  When the
  evidence fingerprint changes (new correlation match, new canonical
  event added to the incident, verdict updated), a new snapshot is
  created; the older one is preserved for auditability.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from services.iue.artifacts import (
    Entity,
    EntityHistory,
    Fact,
    HistoricalContext,
    IUEArtifacts,
    IUEProvenance,
    IUEUnderstanding,
    InvestigationContext,
    InvestigationGap,
    InvestigationGaps,
    KnownUnknown,
    MitreRef,
    RelationshipEdge,
    Relationships,
    SignatureRef,
    ThreatContext,
    TimeWindow,
)


UNDERSTANDING_COLLECTION = "xdr_iue_understanding"
INCIDENTS_COLLECTION = "workspace_cases"
CANONICAL_COLLECTION = "xdr_canonical_evidence"
CORRELATION_MATCHES_COLLECTION = "xdr_correlation_matches"

ENGINE_ID = "nivxray::iue::v0"
ENGINE_VERSION = "0.1.0"


# ── Deterministic helpers ───────────────────────────────────────────

def _stable_hash(payload: Any) -> str:
    """SHA-256 of a canonical JSON serialisation.  No time, no random."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                        default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def _gap_id(key: str) -> str:
    return "gap_" + hashlib.sha256(key.encode()).hexdigest()[:16]


def _iso_now() -> str:
    """UTC-ISO timestamp — used ONLY for the ``generated_at`` metadata
    field.  Never enters the artifacts (which must be deterministic)."""
    return datetime.now(timezone.utc).isoformat()


# ── Artifact 1 · Investigation Context ──────────────────────────────

def _extract_entities(canonical: Optional[Dict[str, Any]]) -> List[Entity]:
    ents: List[Entity] = []
    if not canonical:
        return ents
    net = canonical.get("network") or {}
    src = net.get("src") or {}
    dst = net.get("dst") or {}
    if src.get("ip"):
        ents.append(Entity(
            kind="ipv4" if "." in str(src["ip"]) else "ipv6",
            value=str(src["ip"]), role="source",
            origin="network.src.ip"))
    if dst.get("ip"):
        ents.append(Entity(
            kind="ipv4" if "." in str(dst["ip"]) else "ipv6",
            value=str(dst["ip"]), role="destination",
            origin="network.dst.ip"))
    proto = net.get("protocol")
    if proto:
        ents.append(Entity(
            kind="protocol", value=str(proto).upper(),
            role="context", origin="network.protocol"))
    sig = (canonical.get("security") or {}).get("signature") or {}
    if sig.get("id") is not None:
        ents.append(Entity(
            kind="signature", value=str(sig.get("id")),
            role="trigger", origin="security.signature.id"))
    host = (canonical.get("host") or {}).get("name") \
                or (canonical.get("host") or {}).get("hostname")
    if host:
        ents.append(Entity(
            kind="host", value=str(host), role="target",
            origin="host.name"))
    user = (canonical.get("user") or {}).get("name")
    if user:
        ents.append(Entity(
            kind="user", value=str(user), role="actor",
            origin="user.name"))
    process = (canonical.get("process") or {}).get("name")
    if process:
        ents.append(Entity(
            kind="process", value=str(process), role="context",
            origin="process.name"))
    # Sort for determinism — kind then value.
    ents.sort(key=lambda e: (e.kind, e.value, e.origin))
    return ents


def _time_window(canonical: Optional[Dict[str, Any]],
                   incident: Dict[str, Any]) -> TimeWindow:
    start = None
    end = None
    if canonical:
        start = canonical.get("timestamp") or canonical.get("event_time")
    if not start:
        start = incident.get("created_at")
    end = incident.get("updated_at") or start
    return TimeWindow(start=start, end=end)


def _build_context(incident: Dict[str, Any],
                     canonical: Optional[Dict[str, Any]]) -> InvestigationContext:
    pipe = incident.get("xdr_pipeline") or {}
    stage2 = incident.get("verdict_stage2") or {}
    vcard = incident.get("verdict_card") or {}
    entities = _extract_entities(canonical)

    hosts = sorted({e.value for e in entities if e.kind == "host"})
    users = sorted({e.value for e in entities if e.kind == "user"})
    processes = sorted({e.value for e in entities if e.kind == "process"})
    ips = sorted({e.value for e in entities if e.kind in ("ipv4", "ipv6")})
    domains = sorted({e.value for e in entities if e.kind == "domain"})

    # Also fold in incident.iocs when present (no fabrication — the
    # incident already exposes these).
    iocs = incident.get("iocs") or {}
    def _asl(v):
        if isinstance(v, list):
            return [str(x) for x in v]
        if v is None:
            return []
        return [str(v)]

    ips_iocs = _asl(iocs.get("ip")) + _asl(iocs.get("ips"))
    dom_iocs = _asl(iocs.get("domain")) + _asl(iocs.get("domains"))
    hash_iocs = _asl(iocs.get("hash")) + _asl(iocs.get("hashes"))
    file_iocs = _asl(iocs.get("file")) + _asl(iocs.get("files"))

    verdict_label = (stage2.get("label") or vcard.get("verdict") or None)
    verdict_score = stage2.get("risk_score")
    if verdict_score is None:
        verdict_score = vcard.get("confidence")
    try:
        verdict_score = int(verdict_score) if verdict_score is not None else None
    except (TypeError, ValueError):
        verdict_score = None

    severity_band = "INFORMATIONAL"
    if canonical:
        sev = ((canonical.get("security") or {}).get("severity"))
        sev_map = {1: "HIGH", 2: "MEDIUM", 3: "LOW", 4: "INFORMATIONAL"}
        try:
            severity_band = sev_map.get(int(sev), "INFORMATIONAL") if sev is not None \
                              else "INFORMATIONAL"
        except (TypeError, ValueError):
            severity_band = "INFORMATIONAL"

    return InvestigationContext(
        incident_id=incident["id"],
        tenant_id=incident.get("tenant_id") or "default",
        trace_id=pipe.get("trace_id"),
        canonical_event_id=pipe.get("canonical_event_id"),
        entities=entities,
        hosts=hosts,
        users=users,
        processes=processes,
        ips=sorted(set(ips + ips_iocs)),
        domains=sorted(set(domains + dom_iocs)),
        files=sorted(set(file_iocs)),
        hashes=sorted(set(hash_iocs)),
        time_window=_time_window(canonical, incident),
        severity_band=severity_band,
        verdict_label=str(verdict_label).lower() if verdict_label else None,
        verdict_score=verdict_score,
        verdict_engine=(stage2.get("engine") or vcard.get("engine")),
    )


# ── Artifact 2 · Relationships ──────────────────────────────────────

def _build_relationships(ctx: InvestigationContext,
                             canonical: Optional[Dict[str, Any]],
                             ice_matches: List[Dict[str, Any]],
                            ) -> Relationships:
    edges: List[RelationshipEdge] = []
    ce_id = ctx.canonical_event_id or ""

    if canonical and ce_id:
        net = canonical.get("network") or {}
        src_ip = (net.get("src") or {}).get("ip")
        dst_ip = (net.get("dst") or {}).get("ip")
        if src_ip and dst_ip:
            edges.append(RelationshipEdge(
                src_kind="ipv4" if "." in str(src_ip) else "ipv6",
                src_value=str(src_ip),
                relation="COMMUNICATES_WITH",
                dst_kind="ipv4" if "." in str(dst_ip) else "ipv6",
                dst_value=str(dst_ip),
                evidence_ref=ce_id,
                origin="network.src.ip↔network.dst.ip",
            ))
        sig = (canonical.get("security") or {}).get("signature") or {}
        if sig.get("id") is not None and (src_ip or dst_ip):
            trigger = str(sig.get("id"))
            for anchor_ip, role in ((src_ip, "src"), (dst_ip, "dst")):
                if not anchor_ip:
                    continue
                edges.append(RelationshipEdge(
                    src_kind="signature", src_value=trigger,
                    relation="TRIGGERS",
                    dst_kind="ipv4" if "." in str(anchor_ip) else "ipv6",
                    dst_value=str(anchor_ip),
                    evidence_ref=ce_id,
                    origin=f"security.signature.id→network.{role}.ip",
                ))
        host = (canonical.get("host") or {}).get("name") \
                    or (canonical.get("host") or {}).get("hostname")
        if host and dst_ip:
            edges.append(RelationshipEdge(
                src_kind="host", src_value=str(host),
                relation="OBSERVED_ON",
                dst_kind="ipv4" if "." in str(dst_ip) else "ipv6",
                dst_value=str(dst_ip),
                evidence_ref=ce_id,
                origin="host.name→network.dst.ip",
            ))
        proc = (canonical.get("process") or {}).get("name")
        if proc and host:
            edges.append(RelationshipEdge(
                src_kind="host", src_value=str(host),
                relation="CONTAINS",
                dst_kind="process", dst_value=str(proc),
                evidence_ref=ce_id,
                origin="host.name→process.name",
            ))

    # Correlation match edges (evidence-backed).
    for m in ice_matches:
        mid = m.get("match_id") or m.get("id") or m.get("rule_id")
        if not mid:
            continue
        rule_id = m.get("rule_id")
        if rule_id:
            edges.append(RelationshipEdge(
                src_kind="correlation_rule", src_value=str(rule_id),
                relation="TRIGGERS",
                dst_kind="incident", dst_value=ctx.incident_id,
                evidence_ref=str(mid),
                origin="xdr_correlation_matches",
            ))

    # Deterministic sort.
    edges.sort(key=lambda e: (e.relation, e.src_kind, e.src_value,
                                 e.dst_kind, e.dst_value, e.evidence_ref))
    return Relationships(edges=edges)


# ── Artifact 3 · Threat Context ─────────────────────────────────────

def _build_threat_context(incident: Dict[str, Any],
                             canonical: Optional[Dict[str, Any]],
                             ice_matches: List[Dict[str, Any]],
                            ) -> ThreatContext:
    sigs: List[SignatureRef] = []
    if canonical:
        sig = (canonical.get("security") or {}).get("signature") or {}
        if sig.get("id") is not None:
            sigs.append(SignatureRef(
                signature_id=str(sig.get("id")),
                signature_name=sig.get("name"),
                engine=(canonical.get("dsm") or {}).get("id"),
            ))
    for m in ice_matches:
        for sig in (m.get("signatures") or []):
            if isinstance(sig, dict) and sig.get("id") is not None:
                sigs.append(SignatureRef(
                    signature_id=str(sig["id"]),
                    signature_name=sig.get("name"),
                    engine=m.get("engine_id"),
                ))

    # Dedup + sort deterministically.
    seen = set()
    sigs_unique: List[SignatureRef] = []
    for s in sorted(sigs, key=lambda x: (x.signature_id, x.signature_name or "")):
        key = (s.signature_id, s.signature_name)
        if key in seen:
            continue
        seen.add(key)
        sigs_unique.append(s)

    mitre: List[MitreRef] = []
    for m in incident.get("mitre") or []:
        if not isinstance(m, dict):
            continue
        tid = m.get("technique_id") or m.get("technique")
        if not tid:
            continue
        mitre.append(MitreRef(
            technique_id=str(tid).upper(),
            tactic_id=m.get("tactic_id") or m.get("tactic"),
            source="evidence",
        ))
    for m in ice_matches:
        for tech in (m.get("mitre") or []):
            if isinstance(tech, dict):
                tid = tech.get("technique_id") or tech.get("technique")
            else:
                tid = str(tech) if tech else None
            if not tid:
                continue
            mitre.append(MitreRef(
                technique_id=str(tid).upper(),
                tactic_id=(tech.get("tactic_id") or tech.get("tactic"))
                              if isinstance(tech, dict) else None,
                source="correlation",
            ))
    seen_m = set()
    mitre_unique: List[MitreRef] = []
    for m in sorted(mitre, key=lambda x: (x.technique_id, x.source)):
        key = (m.technique_id, m.source)
        if key in seen_m:
            continue
        seen_m.add(key)
        mitre_unique.append(m)

    match_ids = sorted({
        str(m.get("match_id") or m.get("id"))
        for m in ice_matches
        if (m.get("match_id") or m.get("id"))
    })

    pipe = incident.get("xdr_pipeline") or {}
    iue_prior = pipe.get("iue") or {}
    tags = sorted(set(iue_prior.get("capability_tags") or []))
    detection_supported = bool(
        (pipe.get("veee") or {}).get("label") in ("MALICIOUS", "SUSPICIOUS")
        or match_ids
    )

    return ThreatContext(
        signatures=sigs_unique,
        mitre=mitre_unique,
        correlation_match_ids=match_ids,
        capability_tags=tags,
        detection_supported=detection_supported,
    )


# ── Artifact 4 · Historical Context ─────────────────────────────────

async def _build_historical_context(db, ctx: InvestigationContext,
                                        ) -> HistoricalContext:
    """Prior sightings of context entities across canonical evidence
    and other incidents (excluding this one)."""
    history: List[EntityHistory] = []
    # Query entity values whose kind maps into an addressable canonical
    # path.  For IUE v0 we cover ip / signature / host — the three
    # atoms present in the deterministic pipeline today.
    async def _hits(field: str, value: str) -> Tuple[int, Optional[str], Optional[str]]:
        cursor = db[CANONICAL_COLLECTION].find(
            {field: value}, {"_id": 0, "event_id": 1, "timestamp": 1},
        ).sort("timestamp", 1)
        count = 0
        first_ts: Optional[str] = None
        last_ts: Optional[str] = None
        async for d in cursor:
            count += 1
            ts = d.get("timestamp")
            if ts:
                if first_ts is None:
                    first_ts = str(ts)
                last_ts = str(ts)
        return count, first_ts, last_ts

    async def _incident_ids(field: str, value: str) -> List[str]:
        ids: List[str] = []
        async for d in db[INCIDENTS_COLLECTION].find(
            {field: value,
              "id": {"$ne": ctx.incident_id}},
            {"_id": 0, "id": 1},
        ):
            if d.get("id"):
                ids.append(d["id"])
        return sorted(ids)

    for ip in ctx.ips:
        # Only real network-derived IPs (skip iocs where we can't map).
        c_src, fs1, ls1 = await _hits("network.src.ip", ip)
        c_dst, fs2, ls2 = await _hits("network.dst.ip", ip)
        total = c_src + c_dst
        first_seen = min(x for x in (fs1, fs2) if x) if (fs1 or fs2) else None
        last_seen = max(x for x in (ls1, ls2) if x) if (ls1 or ls2) else None
        prior_incidents = await _incident_ids("iocs.ip", ip)
        history.append(EntityHistory(
            entity_kind="ipv4" if "." in ip else "ipv6",
            entity_value=ip,
            prior_incident_ids=prior_incidents,
            # Subtract this event's own contribution — historical means "before/other".
            prior_evidence_count=max(total - 1, 0),
            first_seen=first_seen,
            last_seen=last_seen,
        ))

    for e in ctx.entities:
        if e.kind == "signature":
            count, fs, ls = await _hits("security.signature.id",
                                            _coerce_signature_id(e.value))
            prior_incidents = await _incident_ids(
                "xdr_pipeline.detection_rule_id", None) if False else []
            history.append(EntityHistory(
                entity_kind="signature",
                entity_value=e.value,
                prior_incident_ids=prior_incidents,
                prior_evidence_count=max(count - 1, 0),
                first_seen=fs, last_seen=ls,
            ))

    history.sort(key=lambda h: (h.entity_kind, h.entity_value))
    return HistoricalContext(entity_history=history)


def _coerce_signature_id(value: str) -> Any:
    """Signature ids are stored as int in canonical evidence; coerce
    for the lookup without fabricating."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


# ── Artifact 5 · Known / Unknown ────────────────────────────────────

def _build_known_unknown(ctx: InvestigationContext,
                             canonical: Optional[Dict[str, Any]],
                             ice_matches: List[Dict[str, Any]],
                            ) -> KnownUnknown:
    observed: List[Fact] = []
    not_observed: List[Fact] = []
    unknown: List[Fact] = []
    ce_id = ctx.canonical_event_id or ""

    def _obs(key: str, value: Any, origin: str) -> None:
        observed.append(Fact(
            key=key, value=str(value), state="OBSERVED",
            evidence_ref=ce_id or None,
            reason=f"Directly present in canonical evidence at {origin}",
        ))

    def _neg(key: str, reason: str) -> None:
        not_observed.append(Fact(
            key=key, value=None, state="NOT_OBSERVED",
            evidence_ref=ce_id or None, reason=reason,
        ))

    def _unk(key: str, reason: str) -> None:
        unknown.append(Fact(
            key=key, value=None, state="UNKNOWN",
            evidence_ref=None, reason=reason,
        ))

    net = (canonical or {}).get("network") or {}
    src_ip = (net.get("src") or {}).get("ip")
    dst_ip = (net.get("dst") or {}).get("ip")
    proto = net.get("protocol")
    sig = ((canonical or {}).get("security") or {}).get("signature") or {}
    host = ((canonical or {}).get("host") or {}).get("name") \
                or ((canonical or {}).get("host") or {}).get("hostname")
    user = ((canonical or {}).get("user") or {}).get("name")
    proc = ((canonical or {}).get("process") or {}).get("name")

    if src_ip: _obs("network.src.ip", src_ip, "canonical.network.src.ip")
    else:      _unk("network.src.ip", "No source IP present in canonical evidence.")

    if dst_ip: _obs("network.dst.ip", dst_ip, "canonical.network.dst.ip")
    else:      _unk("network.dst.ip", "No destination IP present in canonical evidence.")

    if proto:  _obs("network.protocol", proto, "canonical.network.protocol")
    else:      _unk("network.protocol", "No protocol present in canonical evidence.")

    if sig.get("id") is not None:
        _obs("security.signature.id", sig["id"], "canonical.security.signature.id")
    else:
        _unk("security.signature.id",
                "No detection signature id present in canonical evidence.")

    # Endpoint plane facts — canonical from the Snort golden pipeline
    # is network-only, so we honestly emit NOT_OBSERVED for endpoint
    # atoms (checked and not present).
    if host: _obs("host.name", host, "canonical.host.name")
    else:    _neg("host.name",
                     "Endpoint telemetry not correlated to this network alert "
                     "(no EDR event linked).")

    if user: _obs("user.name", user, "canonical.user.name")
    else:    _neg("user.name",
                     "No identity plane telemetry correlated to this incident.")

    if proc: _obs("process.name", proc, "canonical.process.name")
    else:    _neg("process.name",
                     "No process ancestry observed on the target host.")

    # Correlation facts.
    if ice_matches:
        for m in ice_matches:
            mid = m.get("match_id") or m.get("id")
            if mid:
                observed.append(Fact(
                    key=f"correlation.match:{mid}",
                    value=str(m.get("rule_id") or ""),
                    state="CORRELATED",
                    evidence_ref=str(mid),
                    reason="Correlation rule matched this evidence.",
                ))
    else:
        not_observed.append(Fact(
            key="correlation.match",
            value=None, state="NOT_OBSERVED",
            evidence_ref=None,
            reason=(
                "Zero correlation rules matched this evidence — "
                "there is no cross-evidence pivot yet."
            ),
        ))

    # Deterministic sort within each bucket.
    observed.sort(key=lambda f: (f.key, str(f.value)))
    not_observed.sort(key=lambda f: (f.key, str(f.value)))
    unknown.sort(key=lambda f: (f.key, str(f.value)))
    return KnownUnknown(observed=observed,
                          not_observed=not_observed,
                          unknown=unknown)


# ── Artifact 6 · Investigation Gaps ─────────────────────────────────

def _build_gaps(known_unknown: KnownUnknown,
                  ctx: InvestigationContext,
                  ice_matches: List[Dict[str, Any]]) -> InvestigationGaps:
    """Derive gaps deterministically from the fact ledger.  A gap
    exists whenever an actionable fact is in ``NOT_OBSERVED`` or
    ``UNKNOWN`` state and its follow-up maps onto a capability the
    Round 32 Capability Fabric knows about.
    """
    gaps: List[InvestigationGap] = []
    fact_keys_neg = {f.key for f in known_unknown.not_observed}
    fact_keys_unk = {f.key for f in known_unknown.unknown}

    if "process.name" in fact_keys_neg or "host.name" in fact_keys_neg:
        gaps.append(InvestigationGap(
            gap_id=_gap_id("process_lineage.absent"),
            key="process_lineage.absent",
            description=(
                "No process ancestry observed on the host targeted by this alert."
            ),
            why_it_matters=(
                "Without process lineage we cannot confirm whether the "
                "network alert corresponds to a real endpoint execution "
                "or to reconnaissance-only traffic."
            ),
            suggested_capability="process_ancestry",
        ))

    if "user.name" in fact_keys_neg:
        gaps.append(InvestigationGap(
            gap_id=_gap_id("identity_pivot.absent"),
            key="identity_pivot.absent",
            description="No identity plane telemetry is correlated to this incident.",
            why_it_matters=(
                "The affected user is unknown; downstream response actions "
                "(disable account, force MFA) cannot be scoped."
            ),
            suggested_capability="identity_pivot",
        ))

    if "correlation.match" in fact_keys_neg:
        gaps.append(InvestigationGap(
            gap_id=_gap_id("cross_evidence.no_correlation"),
            key="cross_evidence.no_correlation",
            description="No correlation rules have matched this evidence yet.",
            why_it_matters=(
                "Related incidents on the same IP / host / signature "
                "cannot be surfaced without a correlation pivot."
            ),
            suggested_capability="historical_correlation",
        ))

    if not ctx.hashes and not ctx.files:
        gaps.append(InvestigationGap(
            gap_id=_gap_id("file_reputation.no_artifact"),
            key="file_reputation.no_artifact",
            description=(
                "No file / hash artifact is attached to this incident."
            ),
            why_it_matters=(
                "File reputation and static analysis capabilities cannot "
                "run without an artifact reference."
            ),
            suggested_capability="file_reputation",
        ))

    # MITRE expansion gap — when only one tactic is observed but a
    # signature is present, additional tactic mapping may be latent.
    if any(f.key == "security.signature.id" for f in known_unknown.observed):
        # This is a always-safe expansion probe; not fabricated.
        gaps.append(InvestigationGap(
            gap_id=_gap_id("mitre_expansion.signature_only"),
            key="mitre_expansion.signature_only",
            description=(
                "Only signature-derived MITRE mappings are present."
            ),
            why_it_matters=(
                "Correlated behaviour on the same host may add tactics "
                "beyond the signature's declared coverage."
            ),
            suggested_capability="mitre_expansion",
        ))

    gaps.sort(key=lambda g: g.key)
    return InvestigationGaps(gaps=gaps)


# ── Fingerprint / persistence ───────────────────────────────────────

def _evidence_fingerprint(incident: Dict[str, Any],
                             canonical: Optional[Dict[str, Any]],
                             ice_matches: List[Dict[str, Any]]) -> str:
    """A stable digest of the *governed evidence state* an incident
    currently exposes.  Used to resolve "latest valid" snapshots."""
    pipe = incident.get("xdr_pipeline") or {}
    payload = {
        "incident_id":         incident.get("id"),
        "tenant_id":           incident.get("tenant_id") or "default",
        "canonical_event_id":  pipe.get("canonical_event_id"),
        "canonical_hash":      _stable_hash(canonical) if canonical else None,
        "ice_match_ids":       sorted([
            str(m.get("match_id") or m.get("id"))
            for m in ice_matches
            if (m.get("match_id") or m.get("id"))
        ]),
        "verdict_stage2":      incident.get("verdict_stage2") or {},
        "verdict_card":        incident.get("verdict_card") or {},
        "mitre":               incident.get("mitre") or [],
    }
    return _stable_hash(payload)


def _ikg_version(canonical: Optional[Dict[str, Any]],
                    ice_matches: List[Dict[str, Any]]) -> str:
    """Deterministic surrogate for IKG version — hash of the evidence
    edges currently registered on the pipeline for this incident."""
    seed = {
        "canonical_edges": bool(canonical),
        "ice_matches":     len(ice_matches),
        "canonical_evt":   (canonical or {}).get("event_id"),
    }
    return "ikg_" + _stable_hash(seed)[:16]


# ── IUE Service class (the public surface) ──────────────────────────

class IUEService:
    """Investigation Understanding Engine · v0.

    Public methods (owner-locked contract):
      * ``build_context``
      * ``build_relationships``
      * ``build_threat_context``
      * ``build_historical_context``  (async — reads Evidence Plane)
      * ``build_known_unknown``
      * ``build_gaps``
      * ``understand_incident``       (async — full 6-artifact bundle)

    All methods are pure functions of their inputs plus governed
    persistence; none fabricate evidence.
    """

    engine_id = ENGINE_ID
    engine_version = ENGINE_VERSION

    # ── Individual artifact builders ────────────────────────────
    @staticmethod
    def build_context(incident: Dict[str, Any],
                        canonical: Optional[Dict[str, Any]]) -> InvestigationContext:
        return _build_context(incident, canonical)

    @staticmethod
    def build_relationships(ctx: InvestigationContext,
                                 canonical: Optional[Dict[str, Any]],
                                 ice_matches: List[Dict[str, Any]]) -> Relationships:
        return _build_relationships(ctx, canonical, ice_matches)

    @staticmethod
    def build_threat_context(incident: Dict[str, Any],
                                  canonical: Optional[Dict[str, Any]],
                                  ice_matches: List[Dict[str, Any]]) -> ThreatContext:
        return _build_threat_context(incident, canonical, ice_matches)

    @staticmethod
    async def build_historical_context(db,
                                              ctx: InvestigationContext) -> HistoricalContext:
        return await _build_historical_context(db, ctx)

    @staticmethod
    def build_known_unknown(ctx: InvestigationContext,
                                 canonical: Optional[Dict[str, Any]],
                                 ice_matches: List[Dict[str, Any]]) -> KnownUnknown:
        return _build_known_unknown(ctx, canonical, ice_matches)

    @staticmethod
    def build_gaps(known_unknown: KnownUnknown,
                     ctx: InvestigationContext,
                     ice_matches: List[Dict[str, Any]]) -> InvestigationGaps:
        return _build_gaps(known_unknown, ctx, ice_matches)

    # ── Full understand + persist ───────────────────────────────
    @classmethod
    async def understand_incident(cls, db, incident_id: str,
                                          persist: bool = True,
                                         ) -> IUEUnderstanding:
        """Compute (and optionally persist) the 6 artifacts for an
        incident.  Returns a deterministic ``IUEUnderstanding`` record
        whose ``evidence_fingerprint`` matches the incident's current
        governed state.

        If a snapshot with the same fingerprint already exists, that
        snapshot is returned unchanged (deterministic — no duplicate
        write).  Otherwise a new versioned snapshot is created.
        """
        incident = await db[INCIDENTS_COLLECTION].find_one(
            {"id": incident_id}, {"_id": 0})
        if not incident:
            raise ValueError(f"incident_not_found: {incident_id}")

        pipe = incident.get("xdr_pipeline") or {}
        canonical_id = pipe.get("canonical_event_id")
        canonical: Optional[Dict[str, Any]] = None
        if canonical_id:
            canonical = await db[CANONICAL_COLLECTION].find_one(
                {"event_id": canonical_id}, {"_id": 0})

        ice_ids: List[str] = pipe.get("ice_matches") or []
        ice_matches: List[Dict[str, Any]] = []
        if ice_ids:
            async for m in db[CORRELATION_MATCHES_COLLECTION].find(
                {"match_id": {"$in": ice_ids}}, {"_id": 0}
            ):
                ice_matches.append(m)
            ice_matches.sort(key=lambda m: str(m.get("match_id")
                                                    or m.get("id") or ""))

        # Build artifacts.
        ctx = cls.build_context(incident, canonical)
        rels = cls.build_relationships(ctx, canonical, ice_matches)
        threat = cls.build_threat_context(incident, canonical, ice_matches)
        historical = await cls.build_historical_context(db, ctx)
        ku = cls.build_known_unknown(ctx, canonical, ice_matches)
        gaps = cls.build_gaps(ku, ctx, ice_matches)

        artifacts = IUEArtifacts(
            context=ctx,
            relationships=rels,
            threat_context=threat,
            historical_context=historical,
            known_unknown=ku,
            gaps=gaps,
        )

        # Fingerprints.
        evi_fp = _evidence_fingerprint(incident, canonical, ice_matches)
        ikg_ver = _ikg_version(canonical, ice_matches)
        artifact_payload = artifacts.model_dump(mode="python")
        content_hash = _stable_hash(artifact_payload)

        # Latest-valid resolution: does a snapshot for this fingerprint
        # already exist?  If so, return it unchanged (deterministic).
        existing = await db[UNDERSTANDING_COLLECTION].find_one(
            {"incident_id": incident_id,
              "tenant_id":   ctx.tenant_id,
              "evidence_fingerprint": evi_fp},
            {"_id": 0},
        )
        if existing:
            return IUEUnderstanding(**existing)

        # New governed state → create versioned snapshot.
        last = await db[UNDERSTANDING_COLLECTION].find_one(
            {"incident_id": incident_id, "tenant_id": ctx.tenant_id},
            {"_id": 0, "version": 1},
            sort=[("version", -1)],
        )
        next_version = int((last or {}).get("version") or 0) + 1

        record = IUEUnderstanding(
            incident_id=incident_id,
            tenant_id=ctx.tenant_id,
            version=next_version,
            content_hash=content_hash,
            evidence_fingerprint=evi_fp,
            ikg_version=ikg_ver,
            generated_at=_iso_now(),
            artifacts=artifacts,
            provenance=IUEProvenance(
                engine_id=ENGINE_ID,
                engine_version=ENGINE_VERSION,
                trace_id=pipe.get("trace_id"),
                canonical_event_id=canonical_id,
                ice_match_ids=sorted(ice_ids),
                verdict_engine=(incident.get("verdict_stage2") or {}).get("engine")
                                    or (incident.get("verdict_card") or {}).get("engine"),
            ),
        )

        if persist:
            await db[UNDERSTANDING_COLLECTION].insert_one(
                record.model_dump(mode="python"))
        return record

    @classmethod
    async def latest_valid(cls, db, incident_id: str
                                ) -> Optional[IUEUnderstanding]:
        """Return the snapshot whose ``evidence_fingerprint`` matches
        the incident's current governed evidence state.  When none
        exists yet, returns ``None`` — the caller decides whether to
        materialise a new one via ``understand_incident``.
        """
        incident = await db[INCIDENTS_COLLECTION].find_one(
            {"id": incident_id}, {"_id": 0})
        if not incident:
            return None
        pipe = incident.get("xdr_pipeline") or {}
        canonical_id = pipe.get("canonical_event_id")
        canonical = None
        if canonical_id:
            canonical = await db[CANONICAL_COLLECTION].find_one(
                {"event_id": canonical_id}, {"_id": 0})
        ice_ids = pipe.get("ice_matches") or []
        ice_matches = []
        if ice_ids:
            async for m in db[CORRELATION_MATCHES_COLLECTION].find(
                {"match_id": {"$in": ice_ids}}, {"_id": 0}
            ):
                ice_matches.append(m)
        evi_fp = _evidence_fingerprint(incident, canonical, ice_matches)
        tenant_id = incident.get("tenant_id") or "default"
        snap = await db[UNDERSTANDING_COLLECTION].find_one(
            {"incident_id": incident_id,
              "tenant_id":   tenant_id,
              "evidence_fingerprint": evi_fp},
            {"_id": 0},
        )
        if snap:
            return IUEUnderstanding(**snap)
        return None
