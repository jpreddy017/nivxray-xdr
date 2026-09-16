"""
Round 28 · VendorAdapter contract.
==================================

The umbrella interface every BYO-EDR vendor implementation must
satisfy so the NivXRay orchestration layer stops needing
vendor-specific code above the adapter boundary.

Locked contract (owner · 2026-02-14):

    VendorAdapter
      ├── metadata()              → identity + credential schema
      ├── connect()               → live probe against the tenant
      ├── capabilities()          → per-action state matrix
      ├── ingest_incidents(cursor)→ pull path returning raw events
      └── execute_action(action_id, params)  → response action

Normalized envelopes (never vendor-specific enums leaking upward):

    ConnectEnvelope     = {ok, reason, detail, vendor_reference?}
    CapabilityEnvelope  = {action_id, capability_id, state, detail?}
    IngestEnvelope      = {events, next_cursor, error?}
    ExecutionEnvelope   = {ok, vendor_action_id?, detail, http_status?}

Vendor-specific implementations own ONLY the translation from
these envelopes into the vendor's REST / GraphQL / whatever
transport.  The wizard, vault, executor, promotion, response
console, and evidence model above them are shared.

Lifecycle classification (owner-locked · Round 28 guardrail):

    PRODUCTION       → shown in the customer-facing vendor catalogue
    INTERNAL_TEST_ONLY → NEVER shown in production UI; framework
                          proof / regression harness only
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


# ── Normalized envelope keys (documentation only) ────────────
CONNECT_REASONS = {
    "AVAILABLE", "NO_LIVE_TENANT",
    "AUTHENTICATION_FAILED", "CONNECTION_FAILED",
    "VENDOR_ERROR", "UNEXPECTED_STATUS",
}

CAPABILITY_STATES = {"AVAILABLE", "UNAVAILABLE", "FAILED", "NOT_SUPPORTED"}

LIFECYCLES = {"PRODUCTION", "INTERNAL_TEST_ONLY"}


class VendorAdapter(ABC):
    """Base class for a NivXRay vendor adapter.  Constructed with
    the operator-supplied credential blob; the adapter itself is
    stateless beyond that.  The `run_id` argument is threaded
    through for the audit trail."""

    #: Stable vendor identifier used in URLs and DB rows.  Owner:
    #: keep short, snake_case, lowercase.
    vendor_key: str = ""

    def __init__(self, credentials: dict, *, connector=None) -> None:
        self._credentials = credentials or {}
        self._connector   = connector    # httpx-shaped call; injected

    # ── Metadata (drives the wizard) ───────────────────────
    @classmethod
    @abstractmethod
    def metadata(cls) -> dict:
        """Return {vendor_key, display_name, lifecycle,
        credential_schema, capability_ids, notes}.  MUST NOT touch
        the network."""

    # ── Live probe ────────────────────────────────────────
    @abstractmethod
    async def connect(self) -> dict:
        """Return {ok, reason, detail, vendor_reference?}.
        `reason` MUST come from CONNECT_REASONS."""

    @abstractmethod
    async def capabilities(self) -> list[dict]:
        """Return [{action_id, capability_id, state, detail?}, …]
        where state ∈ CAPABILITY_STATES."""

    @abstractmethod
    async def ingest_incidents(self, *, since_cursor: Optional[str]
                                     ) -> dict:
        """Return {events: [...], next_cursor: str|None, error: str|None}."""

    @abstractmethod
    async def execute_action(self, action_id: str, params: dict) -> dict:
        """Return {ok, vendor_action_id?, detail, http_status?}."""

    # Convenience — safe defaults for the CredentialVault layer.
    def credential_ref(self) -> Optional[str]:
        return self._credentials.get("credential_ref")
