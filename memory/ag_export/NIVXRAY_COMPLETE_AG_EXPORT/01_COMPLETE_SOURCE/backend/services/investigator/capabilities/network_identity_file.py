"""Round 32 · Network / DNS / IOC / File / Identity capabilities.

Reuses existing NivXRay data collections and utilities:
  * ``xdr_canonical_evidence``  — network + endpoint observations.
  * ``workspace_cases``          — cross-incident pivots.
  * ``decoders.ioc_extractor``   — extracts IOCs from text.

None of these capabilities call external reputation APIs — that
stays behind the governed enrichment plane (deferred).  When an
external lookup would be needed but is not wired, the finding
honestly carries state=UNKNOWN.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from services.investigator.capabilities.base import (
    Capability, EvidenceSufficiency, fid, now_iso,
)
from services.investigator.models import Finding


# ── Network pivot ───────────────────────────────────────────────────

class NetworkPivotCapability(Capability):
    id = "network_pivot"
    name = "Network Pivot"
    engine = "nivxray::investigator::network_pivot"
    category = "network"
    investigation_question = (
        "What other canonical evidence involves the same network endpoints, "
        "and how rare is the destination in the environment?"
    )
    evidence_requirements = ("canonical.network.*.ip",)
    availability = "cap-full"
    gaps_closed_hint = ()

    def check_evidence(self, incident, canonical):
        if not canonical:
            return "INSUFFICIENT", "no canonical evidence"
        net = canonical.get("network") or {}
        for side in ("src", "dst"):
            if (net.get(side) or {}).get("ip"):
                return "SUFFICIENT", "network endpoint present"
        return "INSUFFICIENT", "no network endpoints in canonical evidence"

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        pipe = incident.get("xdr_pipeline") or {}
        current_evt = pipe.get("canonical_event_id")

        findings: List[Finding] = []
        net = (canonical or {}).get("network") or {}
        for side in ("src", "dst"):
            ip = (net.get(side) or {}).get("ip")
            if not ip:
                continue
            # Prevalence across canonical evidence.
            prev = await db["xdr_canonical_evidence"].count_documents(
                {f"network.{side}.ip": ip})
            # Cross-incident linkage.
            related_ids: List[str] = []
            async for d in db["workspace_cases"].find(
                {"iocs.ip": ip, "id": {"$ne": incident_id}},
                {"_id": 0, "id": 1},
            ):
                if d.get("id"):
                    related_ids.append(d["id"])
            related_ids = sorted(set(related_ids))
            # Rare vs. common heuristic — evidence-derived, deterministic.
            rare = prev <= 3
            state = "CORRELATED" if related_ids else (
                "OBSERVED" if prev >= 1 else "NOT_OBSERVED")
            findings.append(Finding(
                finding_id=fid(
                    f"{incident_id}|net|{side}|{ip}|{prev}|"
                    f"{','.join(related_ids)}"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="network_pivot",
                subject_kind="ipv4" if "." in ip else "ipv6",
                subject_value=ip,
                state=state,
                confidence=min(40 + 10 * len(related_ids) + (20 if rare else 0), 90),
                summary=(
                    f"{ip} ({side}): prevalence={prev} event(s); "
                    f"{len(related_ids)} related incident(s)"
                    + (" · RARE" if rare else "")
                ),
                evidence_refs=([current_evt] if current_evt else [])
                                    + related_ids[:10],
                reasoning=(
                    f"Counted network.{side}.ip=={ip} in xdr_canonical_evidence "
                    f"({prev}); cross-referenced workspace_cases.iocs.ip "
                    f"({len(related_ids)} other incident(s))."
                ),
                created_at=now_iso(),
                provenance={"side": side, "prevalence": prev,
                             "related_incidents": related_ids,
                             "rare": rare},
            ))
        return findings, []


# ── DNS pivot ───────────────────────────────────────────────────────

class DnsPivotCapability(Capability):
    id = "dns_pivot"
    name = "DNS Pivot"
    engine = "nivxray::investigator::dns_pivot"
    category = "network"
    investigation_question = (
        "What domains are associated with this incident and how prevalent "
        "are they across the environment?"
    )
    evidence_requirements = ("incident.iocs.domain OR canonical.dns.query",)
    availability = "cap-full"

    def _domains(self, incident, canonical) -> List[str]:
        doms: List[str] = []
        iocs = incident.get("iocs") or {}
        for k in ("domain", "domains"):
            v = iocs.get(k) or []
            if isinstance(v, list):
                doms.extend([str(x) for x in v])
            elif v:
                doms.append(str(v))
        if canonical:
            dns = canonical.get("dns") or {}
            q = dns.get("query")
            if q:
                doms.append(str(q))
        return sorted({d for d in doms if d})

    def check_evidence(self, incident, canonical):
        return ("SUFFICIENT", "domain entity(ies) present") if self._domains(incident, canonical) \
                else ("INSUFFICIENT", "no domain entities on incident or canonical")

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        domains = self._domains(incident, canonical)
        if not domains:
            return [Finding(
                finding_id=fid(f"{incident_id}|dns|none"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="dns_pivot",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED", confidence=0,
                summary="No domain entities observed.",
                evidence_refs=[], reasoning="no domain IOCs / dns query.",
                created_at=now_iso(),
            )], []

        findings: List[Finding] = []
        for dom in domains[:20]:
            related_ids: List[str] = []
            async for d in db["workspace_cases"].find(
                {"iocs.domain": dom, "id": {"$ne": incident_id}},
                {"_id": 0, "id": 1},
            ):
                if d.get("id"):
                    related_ids.append(d["id"])
            related_ids = sorted(set(related_ids))
            state = "CORRELATED" if related_ids else "OBSERVED"
            findings.append(Finding(
                finding_id=fid(f"{incident_id}|dns|{dom}|{','.join(related_ids)}"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="dns_pivot",
                subject_kind="domain", subject_value=dom,
                state=state, confidence=min(45 + 10 * len(related_ids), 85),
                summary=(
                    f"{dom}: {len(related_ids)} other incident(s) reference this domain"
                    if related_ids else
                    f"{dom}: first observation in the environment"
                ),
                evidence_refs=related_ids[:10],
                reasoning=(
                    f"Cross-referenced workspace_cases.iocs.domain=={dom}; "
                    f"{len(related_ids)} other incidents."
                ),
                created_at=now_iso(),
                provenance={"related_incidents": related_ids},
            ))
        return findings, []


# ── IOC pivot ───────────────────────────────────────────────────────

class IocPivotCapability(Capability):
    id = "ioc_pivot"
    name = "IOC Pivot"
    engine = "nivxray::investigator::ioc_pivot"
    category = "intelligence"
    investigation_question = (
        "What IOCs (hash / url / email) are extractable from this "
        "incident's evidence, and where else have they been seen?"
    )
    evidence_requirements = (
        "canonical.* text OR incident.iocs.* OR canonical.security.signature.name",
    )
    availability = "cap-full"

    def _collect_text(self, incident, canonical) -> str:
        bits: List[str] = []
        if canonical:
            sig = ((canonical.get("security") or {}).get("signature") or {})
            if sig.get("name"):
                bits.append(str(sig["name"]))
            proc = canonical.get("process") or {}
            if proc.get("commandline"):
                bits.append(str(proc["commandline"]))
        iocs = incident.get("iocs") or {}
        for v in iocs.values():
            if isinstance(v, list):
                bits.extend(str(x) for x in v)
            elif v:
                bits.append(str(v))
        return " ".join(bits)

    def check_evidence(self, incident, canonical):
        text = self._collect_text(incident, canonical)
        return ("SUFFICIENT", f"{len(text)} chars of text to scan") if text \
                else ("INSUFFICIENT", "no scannable text on evidence or iocs")

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        text = self._collect_text(incident, canonical)
        if not text:
            return [], []
        try:
            from decoders.ioc_extractor import _extract_all
            extracted = _extract_all(text)
        except Exception as ex:
            return [Finding(
                finding_id=fid(f"{incident_id}|ioc|err"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="ioc_pivot",
                subject_kind="incident", subject_value=incident_id,
                state="UNKNOWN", confidence=0,
                summary="IOC extractor raised.",
                evidence_refs=[], reasoning=f"_extract_all: {type(ex).__name__}: {ex}",
                created_at=now_iso(),
            )], []

        counts = {k: len(v) for k, v in (extracted or {}).items() if isinstance(v, list)}
        total = sum(counts.values())
        if total == 0:
            return [Finding(
                finding_id=fid(f"{incident_id}|ioc|none"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="ioc_pivot",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED", confidence=0,
                summary="No IOCs extractable from incident text.",
                evidence_refs=[],
                reasoning="_extract_all returned zero entities across kinds.",
                created_at=now_iso(),
            )], []

        return [Finding(
            finding_id=fid(f"{incident_id}|ioc|{sorted(counts.items())}"),
            tenant_id=tenant_id, incident_id=incident_id,
            execution_id=pivot.pivot_id,
            capability=self.id, engine=self.engine,
            kind="ioc_pivot",
            subject_kind="incident", subject_value=incident_id,
            state="OBSERVED", confidence=60,
            summary=(
                f"Extracted {total} IOC(s): "
                f"{', '.join(f'{k}={v}' for k, v in sorted(counts.items()) if v)}"
            ),
            evidence_refs=[canonical.get("event_id")] if canonical else [],
            reasoning="ioc_extractor scanned canonical text + incident.iocs.",
            created_at=now_iso(),
            provenance={"counts": counts},
        )], []


# ── File reputation ─────────────────────────────────────────────────

class FileReputationCapability(Capability):
    id = "file_reputation"
    name = "File / Hash Reputation"
    engine = "nivxray::investigator::file_reputation"
    category = "artifact"
    investigation_question = (
        "What files / hashes are attached to this incident, and how "
        "prevalent are they across the environment?"
    )
    evidence_requirements = ("incident.iocs.hash OR incident.iocs.file",)
    availability = "cap-full"
    gaps_closed_hint = ("file_reputation.no_artifact",)

    def _hashes(self, incident) -> List[str]:
        iocs = incident.get("iocs") or {}
        h: List[str] = []
        for k in ("hash", "hashes", "sha256", "sha1", "md5"):
            v = iocs.get(k) or []
            if isinstance(v, list):
                h.extend([str(x) for x in v])
            elif v:
                h.append(str(v))
        return sorted({x for x in h if x})

    def check_evidence(self, incident, canonical):
        return ("SUFFICIENT", "file/hash entities present") if self._hashes(incident) \
                else ("INSUFFICIENT", "no hash / file entity on incident")

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        hashes = self._hashes(incident)
        if not hashes:
            return [Finding(
                finding_id=fid(f"{incident_id}|file|none"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="file_reputation",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED", confidence=0,
                summary="No file / hash artifact attached to this incident.",
                evidence_refs=[], reasoning="incident.iocs carries no hash entries.",
                created_at=now_iso(),
            )], []

        findings: List[Finding] = []
        for h in hashes[:20]:
            related_ids: List[str] = []
            async for d in db["workspace_cases"].find(
                {"$or": [{"iocs.hash": h}, {"iocs.sha256": h}],
                  "id": {"$ne": incident_id}},
                {"_id": 0, "id": 1},
            ):
                if d.get("id"):
                    related_ids.append(d["id"])
            related_ids = sorted(set(related_ids))
            state = "CORRELATED" if related_ids else "UNKNOWN"
            findings.append(Finding(
                finding_id=fid(f"{incident_id}|file|{h}|{','.join(related_ids)}"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="file_reputation",
                subject_kind="hash", subject_value=h,
                state=state,
                confidence=min(30 + 10 * len(related_ids), 80),
                summary=(
                    f"{h[:20]}…: {len(related_ids)} related incident(s)"
                    if related_ids else
                    f"{h[:20]}…: no cross-incident linkage; external reputation "
                    "not wired (enrichment deferred)."
                ),
                evidence_refs=related_ids[:10],
                reasoning=(
                    "Cross-referenced workspace_cases.iocs.hash; no external "
                    "reputation API called (governed enrichment plane deferred)."
                ),
                created_at=now_iso(),
                provenance={"related_incidents": related_ids},
            ))
        return findings, []


# ── Identity pivot ──────────────────────────────────────────────────

class IdentityPivotCapability(Capability):
    id = "identity_pivot"
    name = "Identity Pivot"
    engine = "nivxray::investigator::identity_pivot"
    category = "identity"
    investigation_question = (
        "What identity (user / session / privilege level) is linked to "
        "this incident, and where else is it observed?"
    )
    evidence_requirements = ("canonical.user.name OR incident.iocs.user",)
    availability = "cap-full"
    gaps_closed_hint = ("identity_pivot.absent",)

    def _users(self, incident, canonical) -> List[str]:
        users: List[str] = []
        if canonical:
            u = (canonical.get("user") or {}).get("name")
            if u:
                users.append(str(u))
        iocs = incident.get("iocs") or {}
        for k in ("user", "users"):
            v = iocs.get(k) or []
            if isinstance(v, list):
                users.extend([str(x) for x in v])
            elif v:
                users.append(str(v))
        return sorted({u for u in users if u})

    def check_evidence(self, incident, canonical):
        u = self._users(incident, canonical)
        return ("SUFFICIENT", f"{len(u)} user entity(ies)") if u \
                else ("INSUFFICIENT", "no user entity on canonical or incident")

    async def execute(self, db, pivot, incident, canonical):
        tenant_id = incident.get("tenant_id") or "default"
        incident_id = incident["id"]
        users = self._users(incident, canonical)
        if not users:
            return [Finding(
                finding_id=fid(f"{incident_id}|id|none"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="identity_pivot",
                subject_kind="incident", subject_value=incident_id,
                state="NOT_OBSERVED", confidence=0,
                summary="No identity telemetry correlated to this incident.",
                evidence_refs=[],
                reasoning=(
                    "canonical.user.name missing and iocs.user empty — "
                    "identity plane not wired for this incident."
                ),
                created_at=now_iso(),
            )], []

        findings: List[Finding] = []
        for user in users[:10]:
            related_ids: List[str] = []
            async for d in db["workspace_cases"].find(
                {"iocs.user": user, "id": {"$ne": incident_id}},
                {"_id": 0, "id": 1},
            ):
                if d.get("id"):
                    related_ids.append(d["id"])
            related_ids = sorted(set(related_ids))
            state = "CORRELATED" if related_ids else "OBSERVED"
            findings.append(Finding(
                finding_id=fid(f"{incident_id}|id|{user}|{','.join(related_ids)}"),
                tenant_id=tenant_id, incident_id=incident_id,
                execution_id=pivot.pivot_id,
                capability=self.id, engine=self.engine,
                kind="identity_pivot",
                subject_kind="user", subject_value=user,
                state=state, confidence=min(40 + 10 * len(related_ids), 80),
                summary=(
                    f"User {user}: observed on this incident"
                    + (f"; {len(related_ids)} other incident(s)."
                        if related_ids else ".")
                ),
                evidence_refs=related_ids[:10],
                reasoning=(
                    "Cross-referenced workspace_cases.iocs.user; NivXRay "
                    "identity plane authentication log ingest deferred — "
                    "no assumption of compromise made."
                ),
                created_at=now_iso(),
                provenance={"related_incidents": related_ids},
            ))
        return findings, []
