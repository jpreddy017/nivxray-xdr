"""Normalized event contract (e3.dt.event.v1) and shared vocabularies."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

EVENT_SCHEMA = "e3.dt.event.v1"

KINDS = ("PROCESS_START", "PROCESS_END", "FILE_CREATE", "FILE_WRITE", "FILE_DELETE", "FILE_MOVE",
         "FILE_EXECUTE", "NETWORK_CONNECT", "DNS_QUERY", "REGISTRY_SET", "DETECTION", "OTHER")

SEVERITY_RANK = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

# causality
PROVEN_CAUSAL = "PROVEN_CAUSAL"
CORRELATED = "CORRELATED"
UNRESOLVED = "UNRESOLVED"

# identity
ID_START_TIME = "PID_START_TIME"
ID_GUID = "SOURCE_PROCESS_GUID"
ID_PID_ONLY = "PID_ONLY_NOT_AUTHORITATIVE"

SYNTHETIC = "SYNTHETIC"
SHAPE_FAITHFUL = "SHAPE-FAITHFUL / NOT PRODUCTION DATA"


class TenantRequired(ValueError):
    """Raised when a query arrives without a tenant: reads fail closed."""


def require_tenant(tenant_id: Optional[str]) -> str:
    t = (tenant_id or "").strip()
    if not t:
        raise TenantRequired("tenant_id is required for every evidence read")
    return t


def parse_instant(v: Any) -> Optional[int]:
    """UTC epoch ms. A zone-less sensor string is UTC, never local time."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, datetime):
        dt = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    s = str(v).strip().replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def iso(ms: Optional[int]) -> Optional[str]:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def event(**kw: Any) -> Dict[str, Any]:
    """Build a normalized event with every contract key present (absent = None, never guessed)."""
    base: Dict[str, Any] = {
        "schema": EVENT_SCHEMA, "event_id": None, "tenant_id": None, "device_id": None,
        "kind": "OTHER", "observed_ms": None, "ingested_ms": None, "severity": "NONE",
        "process": {}, "parent": {}, "creator": {}, "file": {}, "network": {}, "detection": None,
        "boot_id": None, "sources": [], "provenance": {},
    }
    base.update(kw)
    base["observed_at"] = iso(base["observed_ms"])
    base["ingested_at"] = iso(base["ingested_ms"])
    return base
