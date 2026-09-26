"""
Generic REST poller connector · Phase B.

Config schema (per instance):
{
  "label":       "Panorama syslog API",
  "url":         "https://example.com/api/events",
  "method":      "GET",                       # GET | POST
  "auth": {
     "type":     "bearer" | "basic" | "api_key" | "none",
     "header":   "Authorization",             # for api_key
     "prefix":   "Bearer "                    # optional
  },
  "credentials": {                            # NEVER exposed in API
     "token":    "xoxb-…",
     "username": "…",  "password": "…",
     "api_key":  "…",
  },
  "query":         {"limit": 100},            # merged with cursor param
  "body":          null,                      # for POST bodies
  "headers":       {"Accept": "application/json"},
  "cursor_param":  "after",                   # sent in query on next poll
  "cursor_path":   "meta.next_cursor",        # extracted from response
  "records_path":  "results",                 # list-of-records path
  "event_id_path": "id",                      # dedup key per record
  "timestamp_path":"ts",
  "interval_seconds": 60,                     # scheduler cadence
  "timeout_seconds":  30
}
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import httpx

from framework.base    import Connector, Envelope, Health, Capability
from framework.parsers import get_path, utcnow_iso


class RestPollerConnector(Connector):
    source_type: str = "rest"
    label:       str = "Generic REST Poller"
    capabilities = [Capability.DETECTIONS, Capability.NETWORK_EVENTS]
    credential_requirements = []                # per-config; validated at test-time

    configuration_schema = {
        "type": "object",
        "required": ["url"],
        "properties": {
            "url":              {"type": "string"},
            "method":           {"type": "string", "enum": ["GET", "POST"]},
            "auth":             {"type": "object"},
            "credentials":      {"type": "object"},
            "query":            {"type": "object"},
            "body":             {},
            "headers":          {"type": "object"},
            "cursor_param":     {"type": "string"},
            "cursor_path":      {"type": "string"},
            "records_path":     {"type": "string"},
            "event_id_path":    {"type": "string"},
            "timestamp_path":   {"type": "string"},
            "interval_seconds": {"type": "integer", "minimum": 5},
            "timeout_seconds":  {"type": "integer", "minimum": 1},
        },
    }

    def __init__(self, tenant_id: str, config: Dict[str, Any],
                 identity: Optional[str] = None):
        super().__init__(tenant_id, config)
        if identity:
            self.identity = identity
        self.label = config.get("label") or self.label

    def _build_request(self, cursor: Optional[str]) -> Dict[str, Any]:
        cfg = self.config
        headers = dict(cfg.get("headers") or {})
        params  = dict(cfg.get("query")   or {})
        if cursor and cfg.get("cursor_param"):
            params[cfg["cursor_param"]] = cursor

        auth = (cfg.get("auth") or {}).copy()
        creds = cfg.get("credentials") or {}
        auth_type = (auth.get("type") or "none").lower()
        http_auth = None
        if auth_type == "bearer" and creds.get("token"):
            headers["Authorization"] = f"Bearer {creds['token']}"
        elif auth_type == "basic":
            http_auth = (creds.get("username", ""), creds.get("password", ""))
        elif auth_type == "api_key" and creds.get("api_key"):
            h  = auth.get("header") or "X-API-Key"
            pf = auth.get("prefix") or ""
            headers[h] = f"{pf}{creds['api_key']}"

        return {
            "method":  (cfg.get("method") or "GET").upper(),
            "url":     cfg["url"],
            "headers": headers,
            "params":  params,
            "json":    cfg.get("body") if cfg.get("method", "GET").upper() == "POST" else None,
            "auth":    http_auth,
            "timeout": cfg.get("timeout_seconds", 30),
        }

    async def test_connection(self) -> Dict[str, Any]:
        try:
            req = self._build_request(cursor=None)
            async with httpx.AsyncClient() as client:
                resp = await client.request(**req)
            ok = resp.status_code < 400
            self.health = Health.CONNECTED if ok else Health.AUTHENTICATION_FAILED \
                            if resp.status_code in (401, 403) else Health.ERROR
            return {"ok": ok, "status_code": resp.status_code,
                     "content_type": resp.headers.get("content-type")}
        except Exception as e:                                 # noqa: BLE001
            self.health = Health.DISCONNECTED
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    async def collect(self) -> List[Envelope]:
        cfg = self.config
        self.metrics.last_attempt = utcnow_iso()
        try:
            req = self._build_request(cursor=self.checkpoint.cursor)
            async with httpx.AsyncClient() as client:
                resp = await client.request(**req)
            if resp.status_code == 429:
                self.health = Health.RATE_LIMITED
                self.metrics.last_error = "429 Too Many Requests"
                return []
            resp.raise_for_status()
            data = resp.json() if "application/json" in \
                        (resp.headers.get("content-type") or "") else {"raw": resp.text}
        except Exception as e:                                 # noqa: BLE001
            self.health = Health.ERROR
            self.metrics.last_error = f"{type(e).__name__}: {e}"
            self.metrics.events_failed += 1
            return []

        records_path = cfg.get("records_path") or ""
        records = get_path(data, records_path, default=[]) if records_path \
                    else (data if isinstance(data, list) else [data])
        if not isinstance(records, list):
            records = [records]

        envelopes: List[Envelope] = []
        for rec in records:
            eid = get_path(rec, cfg.get("event_id_path") or "", default=None)
            ts  = get_path(rec, cfg.get("timestamp_path") or "", default=None)
            env = Envelope(
                tenant_id            = self.tenant_id,
                source               = self.label,
                source_event_id      = str(eid) if eid is not None else None,
                connector_id         = self.identity,
                collector_id         = "collector-local",
                collection_method    = "rest-poll",
                parser_version       = "phaseB.rest-poller.1",
                source_timestamp     = str(ts) if ts else None,
                collection_timestamp = utcnow_iso(),
                event_type           = self.source_type,
                raw                  = rec if isinstance(rec, dict) else {"value": rec},
                canonical            = {},
            )
            envelopes.append(env)

        # advance cursor if present
        if cfg.get("cursor_path"):
            nxt = get_path(data, cfg["cursor_path"], default=None)
            if nxt:
                self.checkpoint.cursor = str(nxt)
                self.checkpoint.updated_at = utcnow_iso()

        self.metrics.events_collected += len(envelopes)
        self.metrics.last_success = utcnow_iso()
        self.health = Health.CONNECTED
        return envelopes
