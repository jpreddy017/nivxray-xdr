"""
AWS CloudTrail adapter.

Normalises CloudTrail management-plane records into NivXRay XDR
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


class AwsCloudTrailAdapter:
    name         = "aws.cloudtrail"
    source_kind  = SourceKind.CLOUD
    vendor       = "aws-cloudtrail"
    version      = "0.1.0"

    def declares(self) -> EvidenceCapability:
        return EvidenceCapability(
            provides = (
                "cloud.api_call",
                "cloud.iam.role.assume",
                "cloud.iam.user.action",
                "cloud.resource.mutation",
                "context.ip", "context.user_agent",
                "context.geolocation.region_only",
                "identity.assumed_role",
            ),
            does_not_provide = (
                "cloud.data_plane",           # S3 GetObject etc. — separate feed
                "endpoint.process",
                "identity.password.change",
                "context.geolocation.city_country",
            ),
            caveats = (
                "AWS region is a coarse geographic hint, not a city.",
                "Some CloudTrail events are delivered 5-15 min after "
                "the source event; adapter preserves both timestamps "
                "so downstream correlation can honour the delay.",
                "recipientAccountId != userIdentity.accountId for "
                "cross-account calls; adapter emits both.",
            ),
        )

    async def normalise(
        self, raw_events: Iterable[dict[str, Any]]
    ) -> list[CanonicalEvent]:
        out: list[CanonicalEvent] = []
        for raw in raw_events or []:
            if not isinstance(raw, dict):
                continue
            event_id  = raw.get("eventID") or ""
            when      = raw.get("eventTime")
            outcome   = "FAILURE" if raw.get("errorCode") else "SUCCESS"
            source    = raw.get("eventSource") or ""
            action_nm = raw.get("eventName") or "cloud.unknown"
            uid       = raw.get("userIdentity") or {}
            session   = (uid.get("sessionContext") or {})
            issuer    = (session.get("sessionIssuer") or {})

            actor = {
                "id":     uid.get("arn") or uid.get("principalId"),
                "name":   uid.get("userName") or issuer.get("userName"),
                "type":   uid.get("type"),
                "account_id": uid.get("accountId"),
                "assumed_role": issuer.get("arn"),
            }
            target = {
                "id":     raw.get("resources") and
                                _first_resource_arn(raw.get("resources")) or None,
                "name":   action_nm,
                "type":   source,
                "recipient_account_id": raw.get("recipientAccountId"),
            }
            ctx = {
                "ip":            raw.get("sourceIPAddress"),
                "user_agent":    raw.get("userAgent"),
                "aws_region":    raw.get("awsRegion"),
                "request_id":    raw.get("requestID"),
                "error_code":    raw.get("errorCode"),
                "error_message": raw.get("errorMessage"),
            }
            canon_id = event_id or _fingerprint(source, action_nm, when, actor)
            out.append(CanonicalEvent(
                canonical_id = canon_id,
                source_kind  = SourceKind.CLOUD,
                action       = f"cloud.api_call:{source}:{action_nm}",
                actor        = actor,
                target       = target,
                context      = ctx,
                outcome      = outcome,
                severity_hint = None,
                tags         = ("vendor:aws-cloudtrail",
                                     f"cloudtrail_event_name:{action_nm}"),
                provenance   = Provenance(
                    source_id         = "aws.cloudtrail",
                    vendor            = "aws-cloudtrail",
                    adapter_name      = self.name,
                    adapter_version   = self.version,
                    raw_ref           = event_id or "no-event-id",
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
    return "aws:" + h.hexdigest()[:16]


def _first_resource_arn(resources: list[dict[str, Any]] | None) -> str | None:
    if not resources:
        return None
    r = resources[0]
    if not isinstance(r, dict):
        return None
    return r.get("ARN") or r.get("arn")
