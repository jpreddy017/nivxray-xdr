"""
Round 28.x.2 · SentinelOne adapter.
====================================

SentinelOne authenticates with a static API token against a
customer-specified management URL.  Alerts come from
`/web/api/v2.1/threats`.  Actions include agent disconnect
(isolate) and hash indicator create (block).

Owner-locked acceptance gate: this file is the ONLY thing added.
No protected file above the adapter boundary mentions SentinelOne.
"""
from __future__ import annotations

import json as _json
import logging
from typing import Any, Optional

from .xdr_vendor_adapter  import VendorAdapter
from .xdr_vendor_registry import register_vendor

log = logging.getLogger("nivxray.xdr.sentinelone")


@register_vendor
class SentineloneVendor(VendorAdapter):
    vendor_key = "sentinelone"

    @classmethod
    def metadata(cls) -> dict:
        return {
            "vendor_key":     cls.vendor_key,
            "display_name":   "SentinelOne Singularity",
            "lifecycle":      "PRODUCTION",
            "credential_schema": [
                {"key": "mgmt_url",  "label": "Management URL",
                    "kind": "text",   "required": True,
                    "placeholder": "https://usea1-partners.sentinelone.net"},
                {"key": "api_token", "label": "API Token",
                    "kind": "secret", "required": True,
                    "note": "Console → Settings → Users → API Token. Write-only."},
            ],
            "capability_ids": [
                "edr.isolate_endpoint", "edr.block_hash",
                "edr.contain_process",
            ],
            "notes": "SentinelOne via static API token · v2.1 API.",
        }

    def _base(self) -> Optional[str]:
        return (self._credentials.get("mgmt_url") or "").rstrip("/") or None

    async def _call(self, method, path, headers=None, body=None):
        base = self._base()
        if not base:
            return {"ok": False, "reason": "NO_LIVE_TENANT",
                        "detail": "mgmt_url missing"}
        if not self._connector:
            return {"ok": False, "reason": "NO_LIVE_TENANT",
                        "detail": "no HTTP connector wired"}
        token = self._credentials.get("api_token")
        h = dict(headers or {})
        if token:
            h["Authorization"] = f"ApiToken {token}"
        return await self._connector(method, base + path, h, body)

    async def connect(self) -> dict:
        if not self._credentials.get("api_token"):
            return {"ok": False, "reason": "NO_LIVE_TENANT",
                        "detail": "api_token missing"}
        r = await self._call("GET", "/web/api/v2.1/system/info")
        if not r.get("ok"):
            reason = "AUTHENTICATION_FAILED" \
                        if r.get("http_status") in (401, 403) \
                        else (r.get("reason") or "CONNECTION_FAILED")
            return {"ok": False, "reason": reason,
                        "detail": r.get("detail"),
                        "vendor_reference": r.get("vendor_reference")}
        return {"ok": True, "reason": "AVAILABLE",
                    "detail": "SentinelOne /system/info reachable",
                    "vendor_reference": r.get("vendor_reference")}

    async def capabilities(self) -> list[dict]:
        return [
            {"action_id": "ENDPOINT_ISOLATE",
              "capability_id": "edr.isolate_endpoint",
              "state": "AVAILABLE",
              "detail": "POST /agents/actions/disconnect"},
            {"action_id": "BLOCK_HASH",
              "capability_id": "edr.block_hash",
              "state": "AVAILABLE",
              "detail": "POST /restrictions (sha1/sha256 hash block)"},
            {"action_id": "PROCESS_KILL",
              "capability_id": "edr.contain_process",
              "state": "NOT_SUPPORTED",
              "detail": "S1 mitigates at threat scope, not per process"},
        ]

    async def ingest_incidents(self, *, since_cursor: Optional[str]) -> dict:
        c = await self.connect()
        if not c.get("ok"):
            return {"events": [], "next_cursor": since_cursor,
                        "error": c.get("detail")}
        q = f"?createdAt__gt={since_cursor}" if since_cursor else ""
        r = await self._call("GET", f"/web/api/v2.1/threats{q}")
        if not r.get("ok"):
            return {"events": [], "next_cursor": since_cursor,
                        "error": r.get("detail")}
        threats = (r.get("json") or {}).get("data") or []
        events = [self._s1_to_incident(t) for t in threats]
        new_cursor = max((t.get("createdAt") for t in threats
                                 if t.get("createdAt")),
                              default=since_cursor)
        return {"events": events, "next_cursor": new_cursor, "error": None}

    def _s1_to_incident(self, t: dict) -> dict:
        info = t.get("threatInfo") or {}
        agent = t.get("agentRealtimeInfo") or {}
        return {
            "incident_id":       t.get("id"),
            "detection_time":    _iso_ms(info.get("createdAt")),
            "modification_time": _iso_ms(info.get("updatedAt")
                                                 or info.get("createdAt")),
            "severity":          (info.get("confidenceLevel") or "medium").lower(),
            "status":            info.get("incidentStatus") or "new",
            "description":       info.get("threatName")
                                        or info.get("classification"),
            "hosts":             [agent.get("agentComputerName")]
                                        if agent.get("agentComputerName") else [],
            "users":             [agent.get("userName")]
                                        if agent.get("userName") else [],
            "mitre_tactics_ids_and_names": [],
            "alerts": [{
                "alert_id":                t.get("id"),
                "detection_timestamp":     _iso_ms(info.get("createdAt")),
                "event_type":              info.get("classification"),
                "severity":                (info.get("confidenceLevel") or "medium").lower(),
                "description":             info.get("threatName"),
                "host_name":               agent.get("agentComputerName"),
                "user_name":               agent.get("userName"),
                "action_file_sha256":      info.get("sha256"),
                "action_process_image_sha256": info.get("sha256"),
                "action_process_image_command_line": info.get("commandLineArguments"),
                "action_process_image_name": info.get("processName"),
            }],
            "key_artifacts": [{"type": "sha256", "value": info["sha256"]}]
                                    if info.get("sha256") else [],
        }

    async def execute_action(self, action_id: str, params: dict) -> dict:
        c = await self.connect()
        if not c.get("ok"):
            return {"ok": False, "vendor_action_id": None,
                        "detail": c.get("detail"), "http_status": None}
        target = params.get("target") or {}
        if action_id == "ENDPOINT_ISOLATE":
            aid = target.get("id") or target.get("value")
            if not aid:
                return {"ok": False, "vendor_action_id": None,
                            "detail": "no agent id supplied", "http_status": 400}
            body = _json.dumps({"filter": {"ids": [aid]}, "data": {}})
            r = await self._call("POST",
                    "/web/api/v2.1/agents/actions/disconnect",
                    headers={"Content-Type": "application/json"},
                    body=body)
            return _s1_result(r)
        if action_id == "BLOCK_HASH":
            sha256 = target.get("value")
            if not sha256:
                return {"ok": False, "vendor_action_id": None,
                            "detail": "no sha256 supplied", "http_status": 400}
            body = _json.dumps({"data": {
                "type": "black_hash", "value": sha256,
                "source": "NivXRay",
                "description": "NivXRay hash block"}})
            r = await self._call("POST",
                    "/web/api/v2.1/restrictions",
                    headers={"Content-Type": "application/json"}, body=body)
            return _s1_result(r)
        return {"ok": False, "vendor_action_id": None,
                    "detail": f"{action_id} not supported by SentinelOne",
                    "http_status": None}


def _iso_ms(iso: Optional[str]) -> Optional[int]:
    import datetime as _dt
    if not iso: return None
    try:
        return int(_dt.datetime.fromisoformat(
            iso.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def _s1_result(r: dict) -> dict:
    if not r.get("ok"):
        return {"ok": False, "vendor_action_id": None,
                    "detail": r.get("detail"), "http_status": r.get("http_status")}
    payload = (r.get("json") or {}).get("data") or {}
    return {"ok": True,
                "vendor_action_id": payload.get("affected") or payload.get("id"),
                "detail": r.get("detail") or f"HTTP {r.get('http_status')}",
                "http_status": r.get("http_status")}
