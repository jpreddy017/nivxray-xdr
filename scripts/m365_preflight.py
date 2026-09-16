#!/usr/bin/env python3
"""Microsoft 365 preflight — reproducible acceptance, not an opinion.

Run this once the owner-side Entra app registration exists. It answers ONE
question with evidence: has NivX actually obtained genuine Microsoft
telemetry and carried it into the authoritative evidence path?

    python3 scripts/m365_preflight.py

Configuration is read from the environment and NEVER printed, logged,
echoed or written anywhere:

    M365_TENANT_ID          Microsoft directory (tenant) GUID
    M365_CLIENT_ID          application (client) id of the Entra app
    M365_CLIENT_SECRET      client secret  (or the certificate variables)
    M365_CERT_THUMBPRINT    certificate mode (recognised, not implemented)
    M365_CONTENT_TYPES      optional, default Audit.Exchange,
                            Audit.AzureActiveDirectory,Audit.General
    M365_PUBLISHER_ID       optional, defaults to the tenant GUID
    NIVX_INGEST_URL         .../api/xdr/ingest/telemetry
    NIVX_INGEST_TOKEN       collector API key (scope collectors.enroll)
    NIVX_COLLECTOR_ID       collector enrolled with authorized_sources
                            ["m365-unified-audit"]
    NIVX_TENANT_ID          the NivX tenant that owns that collector

Reported states — exactly one is final:

    CONFIGURATION_INCOMPLETE     required settings are missing
    CONFIGURATION_VALID         settings present and internally consistent
    SOURCE_REACHABILITY_FAILED  Microsoft endpoints unreachable
    AUTHENTICATION_FAILED       Microsoft rejected the credential
    PERMISSION_OR_CONSENT_FAILED  authenticated, but not authorized
    SUBSCRIPTION_FAILED         subscription could not be established
    RETRIEVED_NO_CONTENT        authorized, but the tenant returned no
                                content (often: audit logging disabled, or
                                simply a quiet window) — NOT a proof
    RETRIEVED_BUT_NOT_ACCEPTED  Microsoft telemetry obtained, but NivX did
                                not accept it — NOT a proof
    REAL_SOURCE_PROVEN          genuine Microsoft records were retrieved
                                AND accepted into the authoritative path

OAuth success alone is never REAL_SOURCE_PROVEN.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, "/app/apps/nivxray-xdr-collector")

DEFAULT_CONTENT_TYPES = "Audit.Exchange,Audit.AzureActiveDirectory,Audit.General"
REQUIRED = ("M365_TENANT_ID", "M365_CLIENT_ID")


def _present(name: str) -> bool:
    return bool((os.environ.get(name) or "").strip())


def _report(state: str, detail: dict) -> int:
    print(json.dumps({"state": state, **detail}, indent=2, default=str))
    print(f"\nPREFLIGHT STATE: {state}")
    return 0 if state == "REAL_SOURCE_PROVEN" else 1


async def run() -> int:                                     # noqa: C901
    from framework.delivery import IngestClient, IngestOutcome
    from framework.m365_activity import M365ManagementActivityConnector
    from framework.oauth2 import TokenError

    missing = [n for n in REQUIRED if not _present(n)]
    credential_mode = ("client_secret" if _present("M365_CLIENT_SECRET")
                       else "certificate" if _present("M365_CERT_THUMBPRINT")
                       else "none")
    if credential_mode == "none":
        missing.append("M365_CLIENT_SECRET (or M365_CERT_THUMBPRINT)")
    if missing:
        return _report("CONFIGURATION_INCOMPLETE", {
            "missing": missing,
            "note": "no value is read from chat or source control; set "
                    "these in the collector's server-side environment"})

    content_types = [c.strip() for c in (
        os.environ.get("M365_CONTENT_TYPES") or DEFAULT_CONTENT_TYPES
    ).split(",") if c.strip()]
    conn = M365ManagementActivityConnector(
        tenant_id=os.environ.get("NIVX_TENANT_ID") or "default",
        identity=os.environ.get("NIVX_COLLECTOR_ID") or "m365-preflight",
        config={
            "microsoft_tenant_id": os.environ["M365_TENANT_ID"],
            "publisher_identifier": os.environ.get("M365_PUBLISHER_ID") or "",
            "content_types": content_types,
            # Sovereign clouds (GCC High / DoD) publish different endpoints,
            # so both are overridable; they default to Microsoft commercial.
            **({"base_url": os.environ["M365_BASE_URL"]}
               if _present("M365_BASE_URL") else {}),
            **({"authority": os.environ["M365_AUTHORITY"]}
               if _present("M365_AUTHORITY") else {}),
            "credentials": {
                "client_id": os.environ["M365_CLIENT_ID"],
                "client_secret": os.environ.get("M365_CLIENT_SECRET") or "",
                "certificate_thumbprint":
                    os.environ.get("M365_CERT_THUMBPRINT") or "",
            },
            "lookback_minutes": int(os.environ.get("M365_LOOKBACK_MINUTES")
                                    or 60)})

    config_view = {
        "microsoft_tenant_id_set": True,
        "credential_mode": credential_mode,
        "content_types": content_types,
        "nivx_ingest_configured": _present("NIVX_INGEST_URL"),
        "nivx_collector_id_set": _present("NIVX_COLLECTOR_ID"),
        "secret_values_printed": False,
    }
    print("CONFIGURATION_VALID")
    print(json.dumps(config_view, indent=2))

    # ── 1 · credential ───────────────────────────────────────────
    try:
        await conn.tokens.token()
    except TokenError as e:
        state = ("SOURCE_REACHABILITY_FAILED"
                 if e.code in ("TOKEN_ENDPOINT_UNREACHABLE",
                               "TOKEN_ENDPOINT_THROTTLED_OR_DOWN")
                 else "AUTHENTICATION_FAILED")
        return _report(state, {"configuration": config_view,
                               "code": e.code, "microsoft_error": e.message})

    # ── 2 · authorization + subscription ─────────────────────────
    probe = await conn.test_connection()
    if not probe.get("ok"):
        code = probe.get("status_code")
        state = ("PERMISSION_OR_CONSENT_FAILED" if code in (401, 403)
                 else "SOURCE_REACHABILITY_FAILED"
                 if probe.get("code") == "ENDPOINT_UNREACHABLE"
                 else "SUBSCRIPTION_FAILED")
        return _report(state, {
            "configuration": config_view, "probe": probe,
            "note": ("ActivityFeed.Read must be granted as an APPLICATION "
                     "permission and admin consent must be recorded"
                     if state == "PERMISSION_OR_CONSENT_FAILED" else "")})

    await conn.start()
    if not conn.subscriptions_started:
        return _report("SUBSCRIPTION_FAILED", {
            "configuration": config_view,
            "last_error": conn.metrics.last_error})

    # ── 3 · genuine retrieval ────────────────────────────────────
    envelopes = await conn.collect()
    retrieval = {
        "subscriptions_started": conn.subscriptions_started,
        "blobs_read": conn.blobs_read,
        "blobs_expired": conn.blobs_expired,
        "records_retrieved": len(envelopes),
        "last_error": conn.metrics.last_error,
    }
    if not envelopes:
        return _report("RETRIEVED_NO_CONTENT", {
            "configuration": config_view, "retrieval": retrieval,
            "note": ("authorized, but Microsoft returned no records for the "
                     "window; confirm unified audit logging is enabled and "
                     "that activity exists — an empty feed is not a proof")})

    # ── 4 · carried into the authoritative path ──────────────────
    client = IngestClient()
    if not client.configured():
        return _report("RETRIEVED_BUT_NOT_ACCEPTED", {
            "configuration": config_view, "retrieval": retrieval,
            "note": "NIVX_INGEST_URL is not set, so nothing was carried "
                    "into the authoritative evidence path"})
    result = await client.deliver(envelopes)
    if result.get("outcome") != IngestOutcome.OK:
        return _report("RETRIEVED_BUT_NOT_ACCEPTED", {
            "configuration": config_view, "retrieval": retrieval,
            "ingest": result,
            "note": "genuine Microsoft telemetry was obtained but the "
                    "authoritative ingest did not accept it"})

    sample = envelopes[0]
    return _report("REAL_SOURCE_PROVEN", {
        "configuration": config_view,
        "retrieval": retrieval,
        "ingest": result,
        "evidence": {
            "declared_source": sample.declared_source,
            "record_reference": sample.raw.get("_m365_acquisition", {}).get(
                "recordReference"),
            "content_id": sample.raw.get("_m365_acquisition", {}).get(
                "contentId"),
            "content_created_is_blob_availability": sample.raw.get(
                "_m365_acquisition", {}).get("contentCreated"),
            "activity_time_from_microsoft": sample.source_timestamp,
            "workload": sample.raw.get("Workload"),
            "operation": sample.raw.get("Operation"),
        },
        "basis": ("records were retrieved from the configured Microsoft "
                  "service and accepted by the authoritative NivX ingest; "
                  "OAuth success alone would not have produced this state")})


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
