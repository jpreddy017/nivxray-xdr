"""
NivXRay XDR · Telemetry Adapter Framework — Phase 2 foundation.

Owner rules (locked):

  · Every external telemetry source (endpoint, identity, cloud,
    network, email, …) is ingested through this framework — never
    a bespoke pipeline per vendor.
  · Vendor-specific parsing lives strictly BEHIND the adapter
    boundary.  Anything downstream (Canonical Evidence Graph,
    IKG, IUE, Correlation, Verdict, Cognis) sees ONLY the
    canonical evidence shape defined here.
  · Provenance is mandatory on every emitted record — source
    identity, raw-source reference, timestamps, adapter version.
  · No adapter is allowed to change verdict semantics or invent
    ATT&CK evidence.  Attribution to ATT&CK is a separate
    downstream concern.

Contract:

    TelemetryAdapter (Protocol)
        ├── name              — stable slug, e.g. "okta.system-log"
        ├── source_kind       — "identity" | "cloud" | "endpoint" | "network" | …
        ├── vendor            — "okta" | "entra" | "aws-cloudtrail" | …
        ├── version           — adapter code version (semver)
        ├── declares()        — evidence-capability declaration
        └── async normalise(raw_events) -> list[CanonicalEvent]

The adapter registry is `TelemetryAdapterRegistry`.  Registration
is explicit; no auto-discovery so adapters can never be silently
enabled by dropping a file into the tree.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Protocol


class SourceKind(str, Enum):
    ENDPOINT  = "endpoint"
    IDENTITY  = "identity"
    CLOUD     = "cloud"
    NETWORK   = "network"
    EMAIL     = "email"
    APPLICATION = "application"


@dataclass(frozen=True)
class Provenance:
    """Immutable provenance envelope stamped on every canonical
    event.  Every field is mandatory — if the adapter cannot
    supply one, it must FAIL rather than fabricate.
    """
    source_id:         str                      # tenant-scoped source id
    vendor:            str
    adapter_name:      str
    adapter_version:   str
    raw_ref:           str                      # opaque reference to the raw record
    ingested_at:       str                      # ISO-8601 UTC
    source_event_time: str | None = None        # ISO-8601 UTC when known


@dataclass(frozen=True)
class CanonicalEvent:
    """Adapter output — one row per external telemetry record.

    Downstream services (Evidence Graph, IKG, IUE, Correlation,
    Verdict) know only this shape.  Vendor field names never
    leak past the adapter boundary.
    """
    canonical_id:  str
    source_kind:   SourceKind
    action:        str                           # e.g. "user.session.start"
    actor:         dict[str, Any] = field(default_factory=dict)
    target:        dict[str, Any] = field(default_factory=dict)
    context:       dict[str, Any] = field(default_factory=dict)
    outcome:       str | None = None
    severity_hint: str | None = None             # informational only; verdict engine decides
    tags:          tuple[str, ...] = ()
    provenance:    Provenance | None = None


@dataclass(frozen=True)
class EvidenceCapability:
    """What an adapter can and cannot provide.  Read by the
    Coverage service to render honest capability rows.  An
    adapter that says it does NOT provide `session_ip` will
    never be silently blamed for a missing correlation."""
    provides:      tuple[str, ...] = ()
    does_not_provide: tuple[str, ...] = ()
    caveats:       tuple[str, ...] = ()


class TelemetryAdapter(Protocol):
    name:            str
    source_kind:     SourceKind
    vendor:          str
    version:         str

    def declares(self) -> EvidenceCapability: ...
    async def normalise(self, raw_events: Iterable[dict[str, Any]]
                                     ) -> list[CanonicalEvent]: ...


class TelemetryAdapterRegistry:
    """Explicit, code-only registration.  No import-time
    side-effects, no auto-discovery."""
    def __init__(self) -> None:
        self._adapters: dict[str, TelemetryAdapter] = {}

    def register(self, adapter: TelemetryAdapter) -> None:
        if adapter.name in self._adapters:
            raise ValueError(
                f"adapter already registered: {adapter.name}")
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> TelemetryAdapter:
        if name not in self._adapters:
            raise KeyError(f"unknown adapter: {name}")
        return self._adapters[name]

    def list(self) -> list[dict[str, Any]]:
        return [
            {
                "name":         a.name,
                "vendor":       a.vendor,
                "source_kind":  a.source_kind.value,
                "version":      a.version,
                "capability":   {
                    "provides":            list(a.declares().provides),
                    "does_not_provide":    list(a.declares().does_not_provide),
                    "caveats":             list(a.declares().caveats),
                },
            }
            for a in sorted(self._adapters.values(), key=lambda x: x.name)
        ]


_REGISTRY: TelemetryAdapterRegistry | None = None


def get_registry() -> TelemetryAdapterRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = TelemetryAdapterRegistry()
    return _REGISTRY
