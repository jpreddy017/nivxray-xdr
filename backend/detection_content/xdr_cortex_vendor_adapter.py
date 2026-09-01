"""
Round 28 · Cortex XDR adapter (VendorAdapter facade).
=====================================================

Thin translation of the existing `xdr_cortex_adapter` /
`xdr_cortex_executor` / `xdr_cortex_parser` implementation into
the new `VendorAdapter` contract.  Preserves every Round 25b/26/
26.5/27 behaviour — this file is orchestration only.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .xdr_vendor_adapter   import VendorAdapter
from .xdr_vendor_registry  import register_vendor
from .xdr_cortex_adapter   import CortexXdrAdapter as _LegacyCortex
from .xdr_cortex_parser    import parse_batch

log = logging.getLogger("nivxray.xdr.cortex.vendor_facade")


@register_vendor
class CortexVendor(VendorAdapter):
    vendor_key = "cortex"

    @classmethod
    def metadata(cls) -> dict:
        return {
            "vendor_key":     cls.vendor_key,
            "display_name":   "Palo Alto Cortex XDR",
            "lifecycle":      "PRODUCTION",
            "credential_schema": [
                {"key": "base_url",     "label": "Cortex FQDN",
                    "kind": "text",     "required": True,
                    "placeholder": "https://api-yourorg.xdr.us.paloaltonetworks.com"},
                {"key": "api_key_id",   "label": "API Key ID",
                    "kind": "text",     "required": True,
                    "placeholder": "42"},
                {"key": "api_key",      "label": "API Key",
                    "kind": "secret",   "required": True,
                    "note": "Advanced-API secret · write-only · never rendered back."},
                {"key": "tenant",       "label": "Tenant (optional)",
                    "kind": "text",     "required": False},
                {"key": "advanced_api", "label": "Advanced API",
                    "kind": "bool",     "required": False, "default": True},
            ],
            "capability_ids": [
                "edr.isolate_endpoint", "edr.contain_process",
                "edr.block_hash",        "edr.disable_user",
                "edr.revoke_token",
            ],
            "notes": "Reference vendor for the BYO-EDR contract.",
        }

    def _legacy(self) -> _LegacyCortex:
        return _LegacyCortex({
            "base_url":    self._credentials.get("base_url"),
            "tenant":      self._credentials.get("tenant"),
            "credentials": self._credentials,
            "_connector":  self._connector,
        })

    async def connect(self) -> dict:
        r = await self._legacy().connect()
        # The legacy adapter already exposes ok/detail/vendor_reference;
        # infer a normalized `reason` code.
        ok = bool(r.get("ok"))
        detail = (r.get("detail") or "").lower()
        if ok:
            reason = "AVAILABLE"
        elif "reject" in detail or "401" in detail or "403" in detail \
                or "authentication_failed" in detail:
            reason = "AUTHENTICATION_FAILED"
        elif "timed out" in detail or "cannot reach" in detail \
                or "connection_failed" in detail:
            reason = "CONNECTION_FAILED"
        elif "credentials not configured" in detail \
                or "no http connector" in detail:
            reason = "NO_LIVE_TENANT"
        else:
            reason = "VENDOR_ERROR" if not ok else "AVAILABLE"
        return {"ok": ok, "reason": reason,
                    "detail": r.get("detail"),
                    "vendor_reference": r.get("vendor_reference")}

    async def capabilities(self) -> list[dict]:
        rows = await self._legacy().capability_probe()
        # Legacy already returns [{action_id, state, detail}].
        # Attach capability_id via a small local map so the shared
        # xdr_capability_service continues to see identical rows.
        from .xdr_capability_service import _ACTION_TO_CAPABILITY
        return [{
            "action_id":     r["action_id"],
            "capability_id": _ACTION_TO_CAPABILITY.get(r["action_id"]),
            "state":         r["state"],
            "detail":        r.get("detail"),
        } for r in rows]

    async def ingest_incidents(self, *, since_cursor: Optional[str]) -> dict:
        legacy = self._legacy()
        connect = await legacy.connect()
        if not connect.get("ok"):
            return {"events": [], "next_cursor": since_cursor,
                        "error": connect.get("detail")}
        return await legacy.ingest_alerts(since_cursor=since_cursor)

    async def execute_action(self, action_id: str, params: dict) -> dict:
        legacy = self._legacy()
        connect = await legacy.connect()
        if not connect.get("ok"):
            return {"ok": False, "vendor_action_id": None,
                        "detail": connect.get("detail"),
                        "http_status": None}
        return await legacy.execute_action(action_id, params)
