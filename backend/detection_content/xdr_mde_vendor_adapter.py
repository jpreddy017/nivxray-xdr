"""
Round 28.x.2 · Microsoft Defender for Endpoint adapter.
========================================================

MDE authenticates via Azure AD OAuth2 client-credential grant
against the tenant-specific token endpoint, then calls the
Defender for Endpoint API at `api.securitycenter.microsoft.com`.

Owner-locked acceptance gate: this file is the ONLY thing added.
No protected file above the adapter boundary mentions MDE or
Defender — enforced by canary test.
"""
from __future__ import annotations

import json as _json
import logging
from typing import Any, Optional

from .xdr_vendor_adapter  import VendorAdapter
from .xdr_vendor_registry import register_vendor

log = logging.getLogger("nivxray.xdr.mde")

MDE_API   = "https://api.securitycenter.microsoft.com"
MDE_TOKEN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"


@register_vendor
class MdeVendor(VendorAdapter):
    vendor_key = "mde"

    @classmethod
    def metadata(cls) -> dict:
        return {
            "vendor_key":     cls.vendor_key,
            "display_name":   "Microsoft Defender for Endpoint",
            "lifecycle":      "PRODUCTION",
            "credential_schema": [
                {"key": "tenant_id",     "label": "Azure Tenant ID",
                    "kind": "text",       "required": True},
                {"key": "client_id",     "label": "App Client ID",
                    "kind": "text",       "required": True},
                {"key": "client_secret", "label": "App Client Secret",
                    "kind": "secret",     "required": True,
                    "note": "Client-credential grant · write-only."},
            ],
            "capability_ids": [
                "edr.isolate_endpoint", "edr.block_hash",
                "edr.contain_process",  "edr.disable_user",
                "edr.revoke_token",
            ],
            "notes": "Second real BYO-EDR vendor via VendorAdapter.",
        }

    async def _call(self, method, url, headers=None, body=None) -> dict:
        if not self._connector:
            return {"ok": False, "reason": "NO_LIVE_TENANT",
                        "detail": "no HTTP connector wired"}
        return await self._connector(method, url, headers or {}, body)

    async def _mint_token(self) -> dict:
        tenant = self._credentials.get("tenant_id")
        cid    = self._credentials.get("client_id")
        sec    = self._credentials.get("client_secret")
        if not (tenant and cid and sec):
            return {"ok": False, "reason": "NO_LIVE_TENANT",
                        "detail": "tenant_id / client_id / client_secret missing"}
        resp = await self._call(
            "POST", MDE_TOKEN.format(tenant=tenant),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"client_id={cid}&client_secret={sec}&scope={MDE_SCOPE}"
                    "&grant_type=client_credentials")
        if not resp.get("ok"):
            return resp
        tok = (resp.get("json") or {}).get("access_token")
        if not tok:
            return {"ok": False, "reason": "AUTHENTICATION_FAILED",
                        "detail": "no access_token in Azure AD response"}
        return {"ok": True, "reason": "AVAILABLE", "token": tok}

    async def connect(self) -> dict:
        r = await self._mint_token()
        if not r.get("ok"):
            return {"ok": False, "reason": r.get("reason") or "VENDOR_ERROR",
                        "detail": r.get("detail"), "vendor_reference": None}
        self._token = r["token"]
        return {"ok": True, "reason": "AVAILABLE",
                    "detail": "MDE oauth2 healthcheck ok"}

    async def capabilities(self) -> list[dict]:
        return [
            {"action_id": "ENDPOINT_ISOLATE",
              "capability_id": "edr.isolate_endpoint",
              "state": "AVAILABLE",
              "detail": "POST /api/machines/{id}/isolate"},
            {"action_id": "BLOCK_HASH",
              "capability_id": "edr.block_hash",
              "state": "AVAILABLE",
              "detail": "POST /api/indicators (Sha256/Block)"},
            {"action_id": "PROCESS_KILL",
              "capability_id": "edr.contain_process",
              "state": "NOT_SUPPORTED",
              "detail": "MDE does not expose a direct process-kill API"},
            {"action_id": "DISABLE_USER",
              "capability_id": "edr.disable_user",
              "state": "NOT_SUPPORTED",
              "detail": "Requires Entra ID; not this adapter"},
            {"action_id": "REVOKE_TOKEN",
              "capability_id": "edr.revoke_token",
              "state": "NOT_SUPPORTED",
              "detail": "Requires Entra ID; not this adapter"},
        ]

    async def ingest_incidents(self, *, since_cursor: Optional[str]) -> dict:
        c = await self.connect()
        if not c.get("ok"):
            return {"events": [], "next_cursor": since_cursor,
                        "error": c.get("detail")}
        headers = {"Authorization": f"Bearer {self._token}"}
        query = ""
        if since_cursor:
            query = f"?$filter=alertCreationTime gt {since_cursor}"
        r = await self._call("GET", f"{MDE_API}/api/alerts{query}",
                                    headers=headers)
        if not r.get("ok"):
            return {"events": [], "next_cursor": since_cursor,
                        "error": r.get("detail")}
        alerts = (r.get("json") or {}).get("value") or []
        events = [self._mde_to_incident(a) for a in alerts]
        new_cursor = max((a.get("alertCreationTime") for a in alerts
                                 if a.get("alertCreationTime")),
                              default=since_cursor)
        return {"events": events, "next_cursor": new_cursor, "error": None}

    def _mde_to_incident(self, alert: dict) -> dict:
        return {
            "incident_id":       alert.get("incidentId") or alert.get("id"),
            "detection_time":    _iso_ms(alert.get("firstEventTime")
                                                 or alert.get("alertCreationTime")),
            "modification_time": _iso_ms(alert.get("lastUpdateTime")
                                                 or alert.get("alertCreationTime")),
            "severity":          (alert.get("severity") or "medium").lower(),
            "status":            alert.get("status") or "new",
            "description":       alert.get("description") or alert.get("title"),
            "hosts":             [alert.get("machineId")] if alert.get("machineId") else [],
            "users":             [alert.get("relatedUser", {}).get("userName")]
                                        if isinstance(alert.get("relatedUser"), dict)
                                            and alert.get("relatedUser", {}).get("userName")
                                        else [],
            "mitre_tactics_ids_and_names":
                sorted({t for t in alert.get("mitreTechniques") or [] if t}),
            "alerts": [{
                "alert_id":                alert.get("id"),
                "detection_timestamp":     _iso_ms(alert.get("firstEventTime")),
                "event_type":              alert.get("category"),
                "severity":                (alert.get("severity") or "medium").lower(),
                "description":             alert.get("title"),
                "host_name":               alert.get("computerDnsName"),
                "user_name":               alert.get("relatedUser", {}).get("userName")
                                                if isinstance(alert.get("relatedUser"), dict) else None,
                "action_file_sha256":      alert.get("sha256"),
                "action_process_image_sha256": alert.get("sha256"),
            }],
            "key_artifacts": [{"type": "sha256", "value": alert["sha256"]}]
                                    if alert.get("sha256") else [],
        }

    async def execute_action(self, action_id: str, params: dict) -> dict:
        c = await self.connect()
        if not c.get("ok"):
            return {"ok": False, "vendor_action_id": None,
                        "detail": c.get("detail"), "http_status": None}
        headers = {"Authorization": f"Bearer {self._token}",
                       "Content-Type":  "application/json"}
        target = params.get("target") or {}
        if action_id == "ENDPOINT_ISOLATE":
            mid = target.get("id") or target.get("value")
            if not mid:
                return {"ok": False, "vendor_action_id": None,
                            "detail": "no machineId supplied", "http_status": 400}
            body = _json.dumps({"Comment": "NivXRay isolate",
                                        "IsolationType": "Full"})
            r = await self._call("POST",
                    f"{MDE_API}/api/machines/{mid}/isolate",
                    headers=headers, body=body)
            return _mde_result(r)
        if action_id == "BLOCK_HASH":
            sha256 = target.get("value")
            if not sha256:
                return {"ok": False, "vendor_action_id": None,
                            "detail": "no sha256 supplied", "http_status": 400}
            body = _json.dumps({
                "indicatorValue": sha256, "indicatorType": "FileSha256",
                "action": "Block", "title": "NivXRay block",
                "severity": "High"})
            r = await self._call("POST", f"{MDE_API}/api/indicators",
                                        headers=headers, body=body)
            return _mde_result(r)
        return {"ok": False, "vendor_action_id": None,
                    "detail": f"{action_id} not supported by MDE adapter",
                    "http_status": None}


def _iso_ms(iso: Optional[str]) -> Optional[int]:
    import datetime as _dt
    if not iso: return None
    try:
        return int(_dt.datetime.fromisoformat(
            iso.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def _mde_result(r: dict) -> dict:
    if not r.get("ok"):
        return {"ok": False, "vendor_action_id": None,
                    "detail": r.get("detail"), "http_status": r.get("http_status")}
    payload = r.get("json") or {}
    return {"ok": True,
                "vendor_action_id": payload.get("id"),
                "detail": r.get("detail") or f"HTTP {r.get('http_status')}",
                "http_status": r.get("http_status")}
