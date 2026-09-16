"""
Round 28 · Stub vendor adapter (INTERNAL_TEST_ONLY).
=====================================================

Framework-proof vendor.  Exists ONLY to exercise the shared
wizard / vault / executor / promotion / response-console paths
without a live tenant.

Guardrails (owner-locked · Round 28):
  · `lifecycle=INTERNAL_TEST_ONLY` — hidden by default from
    `list_production_vendors()`.  Customer-facing catalogue MUST
    NOT include this adapter.
  · `connect()` always returns `NO_LIVE_TENANT` — the stub cannot
    ever look "healthy".
  · `capabilities()` returns every action as `NOT_SUPPORTED` so
    the response console gate deterministically refuses to fire.
  · `execute_action()` returns `{ok: False, detail:
    'stub_never_executes'}` — the stub cannot ever appear as
    ACTIONED evidence.

Purpose: exercise the ORCHESTRATION paths uniformly with Cortex,
so any leak of vendor-specific logic above the adapter boundary
fails a regression test immediately.
"""
from __future__ import annotations

from typing import Optional

from .xdr_vendor_adapter  import VendorAdapter
from .xdr_vendor_registry import register_vendor


@register_vendor
class StubVendor(VendorAdapter):
    vendor_key = "demo_edr"

    @classmethod
    def metadata(cls) -> dict:
        return {
            "vendor_key":     cls.vendor_key,
            "display_name":   "Demo EDR (framework test)",
            "lifecycle":      "INTERNAL_TEST_ONLY",
            "credential_schema": [
                {"key": "base_url",  "label": "Base URL",
                    "kind": "text",  "required": True,
                    "placeholder": "https://demo.local"},
                {"key": "api_key",   "label": "API Key",
                    "kind": "secret","required": True,
                    "note": "Demo secret · never leaves the vault."},
            ],
            "capability_ids": [
                "edr.isolate_endpoint",
                "edr.contain_process",
            ],
            "notes": ("Framework-test vendor · never exposed to "
                          "production catalogues.  Every method returns "
                          "an honest not-configured / not-supported "
                          "envelope so no ACTIONED evidence can ever "
                          "originate from this adapter."),
        }

    async def connect(self) -> dict:
        return {"ok": False, "reason": "NO_LIVE_TENANT",
                    "detail": "demo_edr adapter has no live tenant · "
                                 "framework test only",
                    "vendor_reference": None}

    async def capabilities(self) -> list[dict]:
        return [
            {"action_id": "ENDPOINT_ISOLATE",
              "capability_id": "edr.isolate_endpoint",
              "state": "NOT_SUPPORTED",
              "detail": "stub adapter · framework test only"},
            {"action_id": "PROCESS_KILL",
              "capability_id": "edr.contain_process",
              "state": "NOT_SUPPORTED",
              "detail": "stub adapter · framework test only"},
        ]

    async def ingest_incidents(self, *, since_cursor: Optional[str]) -> dict:
        return {"events": [], "next_cursor": since_cursor,
                    "error": "demo_edr adapter never ingests"}

    async def execute_action(self, action_id: str, params: dict) -> dict:
        return {"ok": False, "vendor_action_id": None,
                    "detail": "stub_never_executes", "http_status": None}
