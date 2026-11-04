"""
Okta System Log adapter.

Normalises Okta's System Log v1 API records (documented at
https://developer.okta.com/docs/reference/api/system-log/) into
NivXRay XDR `CanonicalEvent`s.  Vendor field names never leak
past this file.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable

from ..framework import (
    CanonicalEvent, EvidenceCapability, Provenance, SourceKind,
)


class OktaSystemLogAdapter:
    name         = "okta.system-log"
    source_kind  = SourceKind.IDENTITY
    vendor       = "okta"
    version      = "0.1.0"

    def declares(self) -> EvidenceCapability:
        return EvidenceCapability(
            provides = (
                "identity.user.sign_in",
                "identity.user.session.start",
                "identity.mfa.attempt",
                "identity.password.change",
                "identity.admin.action",
                "context.ip", "context.user_agent",
                "context.geolocation.city_country",
            ),
            does_not_provide = (
                "context.geolocation.precise",  # no GPS
                "endpoint.process",
                "endpoint.filesystem",
            ),
            caveats = (
                "Okta returns geolocation from IP; treat as coarse.",
                "eventType strings evolve — adapter enumerates known "
                "families and passes unknown ones through as generic "
                "actions with source vendor tag.",
            ),
        )

    async def normalise(
        self, raw_events: Iterable[dict[str, Any]]
    ) -> list[CanonicalEvent]:
        out: list[CanonicalEvent] = []
        for raw in raw_events or []:
            if not isinstance(raw, dict):
                continue
            event_id  = raw.get("uuid") or raw.get("eventId") or ""
            event_ty  = raw.get("eventType") or "identity.unknown"
            when      = raw.get("published") or raw.get("eventTime")
            outcome   = ((raw.get("outcome") or {}).get("result") or "").upper() or None
            severity  = raw.get("severity") or None
            actor_raw  = raw.get("actor") or {}
            target_raw = raw.get("target") or []
            client     = raw.get("client") or {}
            debug_ctx  = (raw.get("debugContext") or {})

            actor = {
                "id":         actor_raw.get("id"),
                "name":       actor_raw.get("displayName")
                                    or actor_raw.get("alternateId"),
                "type":       actor_raw.get("type"),
                "email":      actor_raw.get("alternateId"),
            }
            target = _first_target(target_raw)
            geo = (client.get("geographicalContext") or {})
            ctx = {
                "ip":            client.get("ipAddress"),
                "user_agent":    (client.get("userAgent") or {}).get("rawUserAgent"),
                "device_id":     (client.get("device") or None),
                "geo_city":      geo.get("city"),
                "geo_country":   geo.get("country"),
                "authn_provider":(debug_ctx.get("debugData") or {}).get("authnRequestId"),
            }
            canon_id = event_id or _fingerprint(event_ty, when, actor, target)
            out.append(CanonicalEvent(
                canonical_id = canon_id,
                source_kind  = SourceKind.IDENTITY,
                action       = _map_action(event_ty),
                actor        = actor,
                target       = target,
                context      = ctx,
                outcome      = outcome,
                severity_hint = severity,
                tags         = ("vendor:okta", f"okta_event_type:{event_ty}"),
                provenance   = Provenance(
                    source_id         = "okta.system-log",
                    vendor            = "okta",
                    adapter_name      = self.name,
                    adapter_version   = self.version,
                    raw_ref           = event_id or "no-uuid",
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
    return "okta:" + h.hexdigest()[:16]


def _first_target(target_raw: list[dict[str, Any]] | None) -> dict[str, Any]:
    if not target_raw:
        return {}
    t = target_raw[0] if isinstance(target_raw, list) else target_raw
    if not isinstance(t, dict):
        return {}
    return {
        "id":     t.get("id"),
        "name":   t.get("displayName") or t.get("alternateId"),
        "type":   t.get("type"),
    }


_ACTION_MAP = {
    "user.session.start":       "identity.user.session.start",
    "user.authentication.auth": "identity.user.sign_in",
    "user.mfa.factor.activate": "identity.mfa.attempt",
    "user.account.lock":        "identity.user.locked",
    "user.account.unlock":      "identity.user.unlocked",
    "user.password.change":     "identity.password.change",
    "policy.evaluate_sign_on":  "identity.policy.evaluated",
}


def _map_action(event_type: str) -> str:
    # Prefix match on canonical Okta event families; keep the
    # original type as a tag for downstream forensic reference.
    ev = event_type or ""
    for prefix, canonical in _ACTION_MAP.items():
        if ev.startswith(prefix):
            return canonical
    return f"identity.raw:{ev or 'unknown'}"
