"""
P0 · Round 24 · EDR Adapter Contract
─────────────────────────────────────

**Vendor-neutral integration protocol.**

The response fabric already declares actions with
`required_capability: edr.*`.  This module defines the abstract
contract every EDR vendor adapter must implement.  A concrete
adapter (e.g. Palo Alto Cortex XDR) plugs in and becomes queryable
at capability-probe time.

## Locked capability enum (PRD § Round 24)

    AVAILABLE     · adapter connected, capability probe succeeded
    UNAVAILABLE   · no integration configured for this capability
    FAILED        · integration configured but probe/API failed
    NOT_SUPPORTED · adapter connected but the vendor product does
                    not expose this capability

## Invariants

* An adapter MUST NEVER report AVAILABLE merely because credentials
  exist.  AVAILABLE is only earned by a real capability probe.
* Every action executed through the adapter returns a stable
  action_result including the vendor's own request/response
  identifiers (for provenance).
* Redacted credentials are the ONLY form the adapter surfaces — the
  raw credential is never returned by any adapter method.
* Adapters are stateless w.r.t. NivXRay: state lives in
  `xdr_integrations` (Round 25 credential vault), never on the
  adapter instance beyond one call's context.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any


# ── Locked capability states ──────────────────────────────────
AVAILABLE     = "AVAILABLE"
UNAVAILABLE   = "UNAVAILABLE"
FAILED        = "FAILED"
NOT_SUPPORTED = "NOT_SUPPORTED"
CAPABILITY_STATES = (AVAILABLE, UNAVAILABLE, FAILED, NOT_SUPPORTED)


# ── Action result shape ───────────────────────────────────────
def action_result(*, ok: bool, action_id: str, vendor: str,
                          vendor_request_id: str | None = None,
                          vendor_response_id: str | None = None,
                          detail: Any = None,
                          error: str | None = None) -> dict:
    """Deterministic action-result envelope every adapter must
    return.  Preserves vendor request/response ids for provenance."""
    return {
        "ok":                 bool(ok),
        "action_id":          action_id,
        "vendor":             vendor,
        "vendor_request_id":  vendor_request_id,
        "vendor_response_id": vendor_response_id,
        "detail":             detail,
        "error":              error,
    }


def capability_entry(state: str, *, action_id: str, vendor: str,
                              detail: str | None = None) -> dict:
    if state not in CAPABILITY_STATES:
        raise ValueError(f"capability state {state!r} not in {CAPABILITY_STATES}")
    return {
        "action_id": action_id,
        "vendor":    vendor,
        "state":     state,
        "detail":    detail,
    }


class EDRAdapter(ABC):
    """Vendor-neutral EDR adapter contract.

    A concrete adapter is instantiated with a config dict containing
    (at minimum) a decrypted `credentials` block plus any vendor
    tuning knobs (base_url, tenant, region…).  The adapter MUST
    treat the credentials as opaque and MUST NEVER return them
    through any method.
    """
    vendor: str = "unknown"
    supported_actions: tuple[str, ...] = ()

    def __init__(self, config: dict[str, Any]):
        self._config = dict(config or {})

    # ── Lifecycle ──────────────────────────────────────────
    @abstractmethod
    async def connect(self) -> dict:
        """Establish authenticated connectivity with the vendor.
        Return a dict {ok:bool, detail:str, vendor_reference:str|None}.
        MUST NEVER raise on unauthorised — return ok=False instead."""

    @abstractmethod
    async def capability_probe(self) -> list[dict]:
        """Return one `capability_entry` per action_id declared in
        `supported_actions`.  Every probe result MUST come from a
        real vendor call (or a documented deterministic reason for
        NOT_SUPPORTED).  Never infer AVAILABLE from credential
        presence alone."""

    @abstractmethod
    async def execute_action(self, action_id: str,
                                        params: dict) -> dict:
        """Execute one response action against the vendor.  MUST
        return an `action_result` envelope.  MUST preserve the
        vendor's own request/response ids so NivXRay can attribute
        provenance."""

    @abstractmethod
    async def ingest_alerts(self, since_cursor: str | None
                                          = None) -> dict:
        """Pull vendor alerts newer than `since_cursor`.  Return
        {events:list[dict], next_cursor:str|None,
          fetched_at:iso8601}."""

    async def close(self) -> None:
        """Optional teardown (release HTTP client etc.)."""
        return None
