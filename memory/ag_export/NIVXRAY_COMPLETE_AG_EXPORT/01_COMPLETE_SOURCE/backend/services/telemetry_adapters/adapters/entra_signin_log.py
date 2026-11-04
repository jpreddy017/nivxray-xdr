"""
Microsoft Entra ID (formerly Azure AD) Sign-in Log adapter.

Normalises Entra sign-in log records into NivXRay XDR
`CanonicalEvent`s.  Vendor field names never leak past this
file.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable

from ..framework import (
    CanonicalEvent, EvidenceCapability, Provenance, SourceKind,
)


class EntraSignInLogAdapter:
    name         = "entra.signin-log"
    source_kind  = SourceKind.IDENTITY
    vendor       = "entra"
    version      = "0.1.0"

    def declares(self) -> EvidenceCapability:
        return EvidenceCapability(
            provides = (
                "identity.user.sign_in",
                "identity.mfa.attempt",
                "identity.conditional_access.result",
                "context.ip", "context.user_agent",
                "context.device.compliance",
                "context.geolocation.city_country",
                "context.risk.detected_level",
            ),
            does_not_provide = (
                "context.geolocation.precise",
                "endpoint.process",
                "endpoint.filesystem",
                "identity.password.change",   # tenant-level audit log, not sign-in
            ),
            caveats = (
                "Entra risk detection is best-effort; the tenant must "
                "have Identity Protection enabled for risk fields.",
                "Sign-in logs do NOT include admin-tier operations; "
                "wire the Entra Audit Log adapter separately when "
                "available.",
            ),
        )

    async def normalise(
        self, raw_events: Iterable[dict[str, Any]]
    ) -> list[CanonicalEvent]:
        out: list[CanonicalEvent] = []
        for raw in raw_events or []:
            if not isinstance(raw, dict):
                continue
            event_id = raw.get("id") or ""
            when     = raw.get("createdDateTime")
            status   = raw.get("status") or {}
            outcome  = "SUCCESS" if status.get("errorCode") in (0, "0") else "FAILURE"
            loc      = raw.get("location") or {}
            dev      = raw.get("deviceDetail") or {}
            risk_lvl = raw.get("riskLevelDuringSignIn") \
                            or raw.get("riskLevelAggregated")

            actor = {
                "id":    raw.get("userId"),
                "name":  raw.get("userDisplayName") or raw.get("userPrincipalName"),
                "email": raw.get("userPrincipalName"),
                "type":  "User",
            }
            target = {
                "id":   raw.get("appId"),
                "name": raw.get("appDisplayName"),
                "type": "Application",
            }
            ctx = {
                "ip":            raw.get("ipAddress"),
                "user_agent":    raw.get("userAgent"),
                "device_id":     dev.get("deviceId"),
                "device_compliance": dev.get("isCompliant"),
                "geo_city":      loc.get("city"),
                "geo_country":   loc.get("countryOrRegion"),
                "authn_provider":"entra-id",
                "risk_level":    risk_lvl,
                "conditional_access":
                    [ca.get("displayName") for ca in
                        (raw.get("appliedConditionalAccessPolicies") or [])
                        if isinstance(ca, dict)],
            }
            canon_id = event_id or _fingerprint(when, actor, target, ctx)
            out.append(CanonicalEvent(
                canonical_id = canon_id,
                source_kind  = SourceKind.IDENTITY,
                action       = "identity.user.sign_in",
                actor        = actor,
                target       = target,
                context      = ctx,
                outcome      = outcome,
                severity_hint = risk_lvl,
                tags         = ("vendor:entra", "entra_signin_log"),
                provenance   = Provenance(
                    source_id         = "entra.signin-log",
                    vendor            = "entra",
                    adapter_name      = self.name,
                    adapter_version   = self.version,
                    raw_ref           = event_id or "no-id",
                    ingested_at       = _now(),
                    source_event_time = when,
                ),
            ))
        return out


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(*parts: Any) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(repr(p).encode())
    return "entra:" + h.hexdigest()[:16]
