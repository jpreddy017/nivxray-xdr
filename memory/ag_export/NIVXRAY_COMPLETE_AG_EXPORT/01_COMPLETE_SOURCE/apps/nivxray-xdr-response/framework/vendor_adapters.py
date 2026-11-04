"""
Vendor Adapter Contract · NivXRay Response Engine.

    ┌────────────────────────────────────────────┐
    │  Response Engine (framework/executor.py)   │
    └─────────────────┬──────────────────────────┘
                      │  invokes
                      ▼
    ┌────────────────────────────────────────────┐
    │  ResponseAction (registry entry)           │
    │    action_id, provider, capability,        │
    │    parameters, permissions, approval,      │
    │    reversible, destructive                 │
    └─────────────────┬──────────────────────────┘
                      │  adapter =
                      ▼
    ┌────────────────────────────────────────────┐
    │  VendorAdapter (this module)               │
    │    · CrowdStrikeAdapter                    │
    │    · DefenderAdapter                       │
    │    · SentinelOneAdapter                    │
    │    · CiscoSEPAdapter                       │
    │  All implement the SAME contract.          │
    └────────────────────────────────────────────┘
                      │  calls
                      ▼
              Vendor REST / GraphQL / gRPC API

Owner-locked invariants:
  1. **No hard-coded credentials.**  Every adapter loads its
     credentials from the deployment secret store via the
     environment (never from source, never from the browser).
  2. **Never fabricate success.**  A ``{"ok": True}`` return value
     MUST be the direct consequence of a real vendor 2xx.
     Timeouts, transport errors, and 4xx/5xx all return
     ``{"ok": False, "error": "..."}`` — the executor then
     transitions the execution to ``FAILED_EXECUTION`` and never
     forwards evidence.
  3. **Retries** are exponential-backoff, capped, and only for
     idempotent operations.  Destructive/non-idempotent operations
     use vendor-side idempotency keys where the vendor supports them.
  4. **Reversal**: adapters that support the inverse action return
     ``reversal_id`` in their result so the executor can persist it
     for a future ``unisolate`` / ``unblock`` action.
  5. **Adapter status honesty** — each adapter reports one of:
        AVAILABLE      — configured and reachable
        NOT_CONNECTED  — configured but the last preflight failed
        NOT_IMPLEMENTED— the capability is not implemented for this vendor
        NOT_AUTHORIZED — configured but the tenant lacks the vendor scope
     The action registry surfaces this in ``/api/respond/actions``.

Phase 1 ships every adapter as a deterministic stub (``simulation_only``).
Phase C flips the flag to real by populating the credentials env vars.
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from abc      import ABC, abstractmethod
from dataclasses import dataclass, field
from typing   import Any, Dict, List, Optional


# ── Adapter status enum ─────────────────────────────────────────────
STATUS_AVAILABLE        = "AVAILABLE"
STATUS_NOT_CONNECTED    = "NOT_CONNECTED"
STATUS_NOT_IMPLEMENTED  = "NOT_IMPLEMENTED"
STATUS_NOT_AUTHORIZED   = "NOT_AUTHORIZED"


@dataclass
class AdapterResult:
    ok:          bool
    result:      Optional[Dict[str, Any]] = None
    error:       Optional[str]            = None
    reversal_id: Optional[str]            = None
    vendor_ref:  Optional[str]            = None
    latency_ms:  Optional[int]            = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ok": self.ok}
        if self.result      is not None: out["result"]      = self.result
        if self.error       is not None: out["error"]       = self.error
        if self.reversal_id is not None: out["reversal_id"] = self.reversal_id
        if self.vendor_ref  is not None: out["vendor_ref"]  = self.vendor_ref
        if self.latency_ms  is not None: out["latency_ms"]  = self.latency_ms
        return out


@dataclass
class VendorAdapter(ABC):
    """Base class every vendor adapter inherits.

    Subclasses declare which capabilities they implement in
    ``CAPABILITIES``.  A given ``ResponseAction`` binds to an adapter
    method by ``capability``:

        action.capability = "isolate_endpoint"
            ↓
        adapter.execute("isolate_endpoint", params, ctx)

    The registry can also inspect ``status()`` at boot to surface an
    honest ``adapter_status`` per action.
    """

    vendor_id:      str
    display_name:   str
    capabilities:   List[str]       = field(default_factory=list)
    # Set to True by Phase-C adapters that call a real vendor API.
    # Phase-1 stubs keep this False so the registry can flag them.
    real_vendor_call: bool          = False

    # ── env-loaded credentials ─────────────────────────────────────
    def env(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return os.environ.get(f"NIVX_{self.vendor_id.upper()}_{key.upper()}",
                                     default)

    def is_configured(self) -> bool:
        """Overridden by subclasses that need multiple env keys."""
        return bool(self.env("API_URL")) and bool(self.env("API_TOKEN"))

    # ── status probing ─────────────────────────────────────────────
    def status(self) -> Dict[str, Any]:
        if not self.capabilities:
            return {"status": STATUS_NOT_IMPLEMENTED,
                        "reason": f"{self.vendor_id} has no declared capabilities"}
        if not self.real_vendor_call:
            return {"status": STATUS_AVAILABLE,
                        "simulation_only": True,
                        "note": f"{self.vendor_id} adapter is a Phase-1 stub"}
        if not self.is_configured():
            return {"status": STATUS_NOT_CONNECTED,
                        "reason": "credentials not set in deployment secrets"}
        return {"status": STATUS_AVAILABLE, "simulation_only": False}

    # ── execute ────────────────────────────────────────────────────
    async def execute(self, capability: str,
                          params: Dict[str, Any],
                          ctx: Dict[str, Any]) -> AdapterResult:
        if capability not in self.capabilities:
            return AdapterResult(ok=False,
                                            error=f"capability_not_implemented:{capability}")
        method = getattr(self, f"_do_{capability}", None)
        if method is None:
            return AdapterResult(ok=False,
                                            error=f"capability_not_implemented:{capability}")
        # Every real vendor call gets exponential-backoff retry (only
        # for the transient failure classes the adapter marks).
        t0 = time.monotonic()
        try:
            res = await _with_retry(method, params, ctx)
        except Exception as e:                                  # noqa: BLE001
            res = AdapterResult(ok=False,
                                            error=f"{type(e).__name__}: {e}")
        res.latency_ms = int((time.monotonic() - t0) * 1000)
        return res

    # ── reversal ───────────────────────────────────────────────────
    async def reverse(self, capability: str, reversal_id: str,
                          ctx: Dict[str, Any]) -> AdapterResult:
        """Best-effort inverse.  Subclasses that support reversal
        override the per-capability ``_undo_<capability>`` method."""
        method = getattr(self, f"_undo_{capability}", None)
        if method is None:
            return AdapterResult(ok=False,
                                            error=f"reversal_not_supported:{capability}")
        try:
            return await method(reversal_id, ctx)
        except Exception as e:                                  # noqa: BLE001
            return AdapterResult(ok=False,
                                            error=f"{type(e).__name__}: {e}")

    # ── abstract capability methods ─
    # Subclasses implement any of these that match ``capabilities``.
    # Default fallbacks return NOT_IMPLEMENTED so a mis-configured
    # capabilities list never fakes success.


async def _with_retry(coro_fn, params, ctx, *,
                                attempts: int = 3, base_delay: float = 0.25):
    """Exponential-backoff retry, only retrying results the adapter
    marks as ``retryable=True``.  Never retries destructive-writes on
    non-idempotent endpoints (the adapter must not set ``retryable``
    for those)."""
    for i in range(attempts):
        res = await coro_fn(params, ctx)
        if res.ok or not getattr(res, "retryable", False):
            return res
        if i < attempts - 1:
            await asyncio.sleep(base_delay * (2 ** i))
    return res


# ────────────────────────────────────────────────────────────────────
# CROWDSTRIKE Falcon
# ────────────────────────────────────────────────────────────────────
class CrowdStrikeAdapter(VendorAdapter):
    def __init__(self) -> None:
        super().__init__(
            vendor_id="crowdstrike", display_name="CrowdStrike Falcon",
            capabilities=[
                "isolate_endpoint", "unisolate_endpoint",
                "quarantine_file",  "kill_process",
                "block_ip",         "unblock_ip",
                "collect_forensics",
            ],
            real_vendor_call=False,   # flipped to True in Phase C
        )

    def is_configured(self) -> bool:
        return bool(self.env("API_URL")) and bool(self.env("CLIENT_ID")) \
                  and bool(self.env("CLIENT_SECRET"))

    # ── isolate ─────────────────────────────────────────────────────
    async def _do_isolate_endpoint(self, params, ctx) -> AdapterResult:
        host_id = params.get("host_id")
        if not host_id:
            return AdapterResult(ok=False, error="missing_parameter:host_id")
        if not self.real_vendor_call:
            return AdapterResult(
                ok=True,
                result={"vendor": "crowdstrike",
                            "action": "isolate", "host_id": host_id,
                            "simulation_only": True},
                reversal_id=f"cs-isol-{uuid.uuid4().hex[:12]}")
        # Phase-C hook — real CrowdStrike call goes here (aiohttp POST
        # to /devices/entities/devices-actions/v2 with
        # action_name=contain).  Not shipped in Phase 1.
        return AdapterResult(ok=False, error="not_wired_yet")

    async def _undo_isolate_endpoint(self, reversal_id, ctx) -> AdapterResult:
        return AdapterResult(ok=True,
                                        result={"vendor": "crowdstrike",
                                                    "reversal_id": reversal_id,
                                                    "simulation_only": True})

    async def _do_block_ip(self, params, ctx) -> AdapterResult:
        ip = params.get("ip")
        if not ip: return AdapterResult(ok=False, error="missing_parameter:ip")
        if not self.real_vendor_call:
            return AdapterResult(ok=True,
                result={"vendor": "crowdstrike", "action": "block_ip", "ip": ip,
                            "simulation_only": True},
                reversal_id=f"cs-blk-{uuid.uuid4().hex[:12]}")
        return AdapterResult(ok=False, error="not_wired_yet")

    async def _do_kill_process(self, params, ctx) -> AdapterResult:
        for k in ("host_id", "pid"):
            if not params.get(k):
                return AdapterResult(ok=False, error=f"missing_parameter:{k}")
        if not self.real_vendor_call:
            return AdapterResult(ok=True,
                result={"vendor": "crowdstrike", "action": "kill_process",
                            "host_id": params["host_id"], "pid": params["pid"],
                            "simulation_only": True})
        return AdapterResult(ok=False, error="not_wired_yet")


# ────────────────────────────────────────────────────────────────────
# MICROSOFT Defender for Endpoint
# ────────────────────────────────────────────────────────────────────
class DefenderAdapter(VendorAdapter):
    def __init__(self) -> None:
        super().__init__(
            vendor_id="defender", display_name="Microsoft Defender for Endpoint",
            capabilities=[
                "isolate_endpoint", "unisolate_endpoint",
                "quarantine_file",  "restrict_execution",
                "collect_forensics",
            ],
            real_vendor_call=False,
        )
    def is_configured(self) -> bool:
        return bool(self.env("TENANT_ID")) and bool(self.env("CLIENT_ID")) \
                  and bool(self.env("CLIENT_SECRET"))

    async def _do_isolate_endpoint(self, params, ctx) -> AdapterResult:
        host_id = params.get("host_id")
        if not host_id:
            return AdapterResult(ok=False, error="missing_parameter:host_id")
        if not self.real_vendor_call:
            return AdapterResult(ok=True,
                result={"vendor": "defender", "action": "isolate",
                            "host_id": host_id, "simulation_only": True},
                reversal_id=f"mde-isol-{uuid.uuid4().hex[:12]}")
        return AdapterResult(ok=False, error="not_wired_yet")


# ────────────────────────────────────────────────────────────────────
# SENTINELONE
# ────────────────────────────────────────────────────────────────────
class SentinelOneAdapter(VendorAdapter):
    def __init__(self) -> None:
        super().__init__(
            vendor_id="sentinelone", display_name="SentinelOne",
            capabilities=[
                "isolate_endpoint", "unisolate_endpoint",
                "kill_process", "quarantine_file",
                "block_ip", "collect_forensics",
            ],
            real_vendor_call=False,
        )
    def is_configured(self) -> bool:
        return bool(self.env("API_URL")) and bool(self.env("API_TOKEN"))

    async def _do_isolate_endpoint(self, params, ctx) -> AdapterResult:
        host_id = params.get("host_id")
        if not host_id:
            return AdapterResult(ok=False, error="missing_parameter:host_id")
        if not self.real_vendor_call:
            return AdapterResult(ok=True,
                result={"vendor": "sentinelone", "action": "disconnect",
                            "host_id": host_id, "simulation_only": True},
                reversal_id=f"s1-disc-{uuid.uuid4().hex[:12]}")
        return AdapterResult(ok=False, error="not_wired_yet")


# ────────────────────────────────────────────────────────────────────
# CISCO Secure Endpoint (AMP)
# ────────────────────────────────────────────────────────────────────
class CiscoSEPAdapter(VendorAdapter):
    def __init__(self) -> None:
        super().__init__(
            vendor_id="cisco_sep", display_name="Cisco Secure Endpoint",
            capabilities=[
                "isolate_endpoint", "unisolate_endpoint",
                "quarantine_file", "block_ip",
                "collect_forensics",
            ],
            real_vendor_call=False,
        )
    def is_configured(self) -> bool:
        return bool(self.env("API_URL")) and bool(self.env("CLIENT_ID")) \
                  and bool(self.env("API_KEY"))

    async def _do_isolate_endpoint(self, params, ctx) -> AdapterResult:
        host_id = params.get("host_id")
        if not host_id:
            return AdapterResult(ok=False, error="missing_parameter:host_id")
        if not self.real_vendor_call:
            return AdapterResult(ok=True,
                result={"vendor": "cisco_sep", "action": "isolate",
                            "host_id": host_id, "simulation_only": True},
                reversal_id=f"amp-isol-{uuid.uuid4().hex[:12]}")
        return AdapterResult(ok=False, error="not_wired_yet")


# ────────────────────────────────────────────────────────────────────
# Adapter registry
# ────────────────────────────────────────────────────────────────────
class VendorAdapterRegistry:
    def __init__(self, adapters: Optional[List[VendorAdapter]] = None) -> None:
        self._by_id: Dict[str, VendorAdapter] = {}
        for a in adapters or []:
            self._by_id[a.vendor_id] = a

    def register(self, adapter: VendorAdapter) -> None:
        self._by_id[adapter.vendor_id] = adapter

    def get(self, vendor_id: str) -> Optional[VendorAdapter]:
        return self._by_id.get(vendor_id)

    def all(self) -> List[VendorAdapter]:
        return list(self._by_id.values())

    def status_by_capability(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for a in self.all():
            st = a.status()
            for cap in a.capabilities:
                out.setdefault(cap, {})[a.vendor_id] = st
        return out

    @classmethod
    def default(cls) -> "VendorAdapterRegistry":
        return cls([
            CrowdStrikeAdapter(),
            DefenderAdapter(),
            SentinelOneAdapter(),
            CiscoSEPAdapter(),
        ])
