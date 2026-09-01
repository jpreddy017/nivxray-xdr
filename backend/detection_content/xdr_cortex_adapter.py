"""
P0 · Round 24 · Palo Alto Cortex XDR reference adapter
──────────────────────────────────────────────────────

**First BYO-EDR adapter.**  Implements the `EDRAdapter` contract
for the Palo Alto Cortex XDR REST API
(https://docs.paloaltonetworks.com/cortex/cortex-xdr).

## Honest state guarantees

* No configured `base_url` + `api_key_id` + `api_key` →
  connect() returns ok=False, capability_probe() returns
  UNAVAILABLE for every action. NivXRay renders these as
  CAPABILITY_UNAVAILABLE downstream — never inferred APPLICABLE.
* Configured but unreachable / 401 / 403 → capability_probe()
  returns FAILED with the vendor error verbatim.
* Configured + reachable + capability endpoint responds →
  capability_probe() returns AVAILABLE only for actions the
  vendor's advanced-api response actually enables.
* Actions the Cortex product does not expose (e.g. threat-name
  exclusion) return NOT_SUPPORTED.

The adapter NEVER surfaces the raw API key through any method.
Downstream logs receive `api_key_id=…` (which is not the secret)
and a `redacted_api_key='***'` marker only.
"""
from __future__ import annotations
import os, time, hashlib, uuid
from datetime import datetime, timezone
from typing import Any

from .xdr_edr_adapter import (
    EDRAdapter, action_result, capability_entry,
    AVAILABLE, UNAVAILABLE, FAILED, NOT_SUPPORTED,
)


# ── Cortex action mapping ──────────────────────────────────────
# NivXRay canonical action → Cortex Advanced API operation.
# Actions Cortex does not expose are omitted and reported
# NOT_SUPPORTED by capability_probe.
_CORTEX_ACTION_MAP: dict[str, dict[str, str]] = {
    "ENDPOINT_ISOLATE": {
        "op":       "isolate",
        "endpoint": "/public_api/v1/endpoints/isolate",
    },
    "TERMINATE_PROCESS": {
        "op":       "action_terminate_process",
        "endpoint": "/public_api/v1/endpoints/terminate_process",
    },
    "PROCESS_EXCLUSION_ADD": {
        "op":       "add_exclusion",
        "endpoint": "/public_api/v1/incidents/insert_alerts",
    },
    "APPLICATION_ALLOW_LIST_ADD": {
        "op":       "allowlist_hash",
        "endpoint": "/public_api/v1/hash_exceptions/allowlist",
    },
    "BLOCK_OBSERVED_HASH": {
        "op":       "blocklist_hash",
        "endpoint": "/public_api/v1/hash_exceptions/blocklist",
    },
}


# Actions Cortex will always be NOT_SUPPORTED (belong to other
# planes — email, IAM, network firewall, etc.).
_UNSUPPORTED_ACTIONS: tuple[str, ...] = (
    "PATH_EXCLUSION_ADD",
    "THREAT_EXCLUSION_ADD",
    "WILDCARD_EXCLUSION_ADD",
    "REVOKE_CREDENTIAL",
    "IP_BLOCK",
    "IOC_ADD_WATCHLIST",
    "OSINT_ENRICH_IP",
    "OSINT_ENRICH_DOMAIN",
    "OSINT_ENRICH_HASH",
)


class CortexXdrAdapter(EDRAdapter):
    vendor = "palo_alto_cortex_xdr"
    supported_actions = tuple(_CORTEX_ACTION_MAP.keys()) + _UNSUPPORTED_ACTIONS

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config or {})
        creds = self._config.get("credentials") or {}
        self._base_url    = self._config.get("base_url") \
                                 or creds.get("base_url")
        self._api_key_id  = creds.get("api_key_id")
        self._api_key     = creds.get("api_key")
        self._tenant      = self._config.get("tenant") \
                                 or creds.get("tenant")
        # Runtime state (never persisted, never surfaced).
        self._connected   = False
        self._connect_detail: str | None = None

    # ── Redaction helper (never returns the raw key) ─────────
    def _redacted_creds(self) -> dict:
        return {
            "base_url":       self._base_url,
            "api_key_id":     self._api_key_id,
            "api_key":        "***" if self._api_key else None,
            "tenant":         self._tenant,
        }

    def _has_credentials(self) -> bool:
        return bool(self._base_url and self._api_key_id and self._api_key)

    # ── Lifecycle ──────────────────────────────────────────
    async def connect(self) -> dict:
        """Attempt to authenticate. Returns ok=False when
        credentials are missing OR the vendor rejects them.  NEVER
        fabricates a success."""
        if not self._has_credentials():
            self._connected = False
            self._connect_detail = "credentials not configured"
            return {
                "ok":              False,
                "vendor":          self.vendor,
                "detail":          self._connect_detail,
                "credentials":     self._redacted_creds(),
                "vendor_reference": None,
            }
        # Perform a lightweight authenticated call to prove
        # connectivity.  We do NOT ship a live HTTP call inside this
        # unit (that belongs to Round 24 · deployment); instead the
        # adapter uses a configurable connector.  When no connector
        # is supplied, an honest 'connector_not_wired' error is
        # returned — never a fabricated success.
        connector = self._config.get("_connector")
        if connector is None:
            self._connected = False
            self._connect_detail = (
                "credentials present but no HTTP connector wired — "
                "capabilities cannot be probed without a live vendor call")
            return {
                "ok":              False,
                "vendor":          self.vendor,
                "detail":          self._connect_detail,
                "credentials":     self._redacted_creds(),
                "vendor_reference": None,
            }
        try:
            resp = await connector("GET", "/public_api/v1/healthcheck/",
                                              headers=self._auth_headers(),
                                              json=None)
            ok = bool(resp.get("ok"))
            self._connected = ok
            self._connect_detail = resp.get("detail") or (
                "healthcheck succeeded" if ok else "healthcheck rejected")
            return {
                "ok":              ok,
                "vendor":          self.vendor,
                "detail":          self._connect_detail,
                "credentials":     self._redacted_creds(),
                "vendor_reference": resp.get("vendor_reference"),
            }
        except Exception as exc:  # noqa: BLE001
            self._connected = False
            self._connect_detail = f"connect failed: {exc}"
            return {"ok": False, "vendor": self.vendor,
                        "detail": self._connect_detail,
                        "credentials": self._redacted_creds(),
                        "vendor_reference": None}

    def _auth_headers(self) -> dict:
        # Cortex advanced-key auth uses HMAC-SHA256 of nonce +
        # timestamp + key. We compute honestly here so a live
        # deployment can wire the connector without any adapter
        # change; unit tests supply the connector so no live network
        # call is made.
        nonce     = uuid.uuid4().hex
        timestamp = str(int(time.time()) * 1000)
        material  = f"{self._api_key}{nonce}{timestamp}".encode()
        auth_key  = hashlib.sha256(material).hexdigest()
        return {
            "x-xdr-timestamp":  timestamp,
            "x-xdr-nonce":      nonce,
            "x-xdr-auth-id":    str(self._api_key_id or ""),
            "Authorization":    auth_key,
            "Content-Type":     "application/json",
        }

    # ── Capability probe ───────────────────────────────────
    async def capability_probe(self) -> list[dict]:
        """Emit one entry per declared action."""
        # 1. Not connected → every action UNAVAILABLE. HONEST.
        if not self._connected:
            state = UNAVAILABLE
            if self._has_credentials():
                state = FAILED   # config present, connect failed
            entries = []
            for aid in _CORTEX_ACTION_MAP:
                entries.append(capability_entry(
                    state, action_id=aid, vendor=self.vendor,
                    detail=self._connect_detail))
            for aid in _UNSUPPORTED_ACTIONS:
                entries.append(capability_entry(
                    NOT_SUPPORTED, action_id=aid, vendor=self.vendor,
                    detail="Cortex XDR does not expose this action"))
            return entries

        # 2. Connected — probe each mapped action against the vendor.
        connector = self._config.get("_connector")
        entries: list[dict] = []
        for aid, meta in _CORTEX_ACTION_MAP.items():
            try:
                resp = await connector(
                    "OPTIONS", meta["endpoint"],
                    headers=self._auth_headers(), json=None)
                if resp.get("ok"):
                    entries.append(capability_entry(
                        AVAILABLE, action_id=aid,
                        vendor=self.vendor,
                        detail=resp.get("detail")))
                else:
                    entries.append(capability_entry(
                        FAILED, action_id=aid, vendor=self.vendor,
                        detail=resp.get("detail")
                                 or "vendor rejected capability probe"))
            except Exception as exc:  # noqa: BLE001
                entries.append(capability_entry(
                    FAILED, action_id=aid, vendor=self.vendor,
                    detail=f"probe error: {exc}"))
        for aid in _UNSUPPORTED_ACTIONS:
            entries.append(capability_entry(
                NOT_SUPPORTED, action_id=aid, vendor=self.vendor,
                detail="Cortex XDR does not expose this action"))
        return entries

    # ── Execute ────────────────────────────────────────────
    async def execute_action(self, action_id: str,
                                        params: dict) -> dict:
        if not self._connected:
            return action_result(
                ok=False, action_id=action_id, vendor=self.vendor,
                error=self._connect_detail
                            or "adapter not connected")
        meta = _CORTEX_ACTION_MAP.get(action_id)
        if not meta:
            return action_result(
                ok=False, action_id=action_id, vendor=self.vendor,
                error="action not supported by Cortex XDR")
        connector = self._config.get("_connector")
        req_id = f"cxdr-{uuid.uuid4().hex[:16]}"
        try:
            resp = await connector(
                "POST", meta["endpoint"],
                headers={**self._auth_headers(),
                              "x-xdr-request-id": req_id},
                json={"request_data": params or {}})
            return action_result(
                ok=bool(resp.get("ok")),
                action_id=action_id, vendor=self.vendor,
                vendor_request_id=req_id,
                vendor_response_id=resp.get("action_id"),
                detail=resp.get("detail"),
                error=None if resp.get("ok") else resp.get("detail"))
        except Exception as exc:  # noqa: BLE001
            return action_result(
                ok=False, action_id=action_id, vendor=self.vendor,
                vendor_request_id=req_id, error=str(exc))

    # ── Ingest ─────────────────────────────────────────────
    async def ingest_alerts(self, since_cursor: str | None
                                          = None) -> dict:
        if not self._connected:
            return {"events": [], "next_cursor": since_cursor,
                        "fetched_at":
                            datetime.now(timezone.utc).isoformat(),
                        "note": self._connect_detail
                                    or "adapter not connected"}
        connector = self._config.get("_connector")
        try:
            resp = await connector(
                "POST", "/public_api/v1/alerts/get_alerts_multi_events",
                headers=self._auth_headers(),
                json={"request_data": {
                    "filters":       [],
                    "search_from":   0,
                    "search_to":     100,
                    "sort":          {"field": "creation_time",
                                              "keyword": "asc"},
                    "since_cursor":  since_cursor,
                }})
            return {"events":      resp.get("alerts") or [],
                        "next_cursor": resp.get("next_cursor"),
                        "fetched_at":
                            datetime.now(timezone.utc).isoformat()}
        except Exception as exc:  # noqa: BLE001
            return {"events": [], "next_cursor": since_cursor,
                        "fetched_at":
                            datetime.now(timezone.utc).isoformat(),
                        "error": str(exc)}
