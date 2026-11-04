"""
ConnectorRegistry · Phase A.

In-memory registry.  Persistent storage arrives in Phase A.2 once
the tenant-scoped credential store is wired up.

Phase A does NOT register any vendor connector.  The registry is
empty by design so the Admin UI renders honest "NEVER CONNECTED"
states — never a synthetic vendor.
"""
from __future__ import annotations

from threading import RLock
from typing    import Dict, List, Optional, Type

from framework.base import Connector


class ConnectorRegistry:
    def __init__(self) -> None:
        self._lock: RLock                       = RLock()
        self._classes: Dict[str, Type[Connector]] = {}
        self._instances: Dict[str, Connector]   = {}

    # ── class-level registration (vendor adapters register on import) ──
    def register_class(self, source_type: str, cls: Type[Connector]) -> None:
        with self._lock:
            self._classes[source_type] = cls

    # ── instance-level registration (a tenant configures a source) ──
    def register_instance(self, conn: Connector) -> None:
        with self._lock:
            self._instances[conn.identity] = conn

    # ── introspection ────────────────────────────────────────────
    def list_ids(self) -> List[str]:
        with self._lock:
            return list(self._instances.keys())

    def get(self, identity: str) -> Optional[Connector]:
        with self._lock:
            return self._instances.get(identity)

    def all(self) -> List[Connector]:
        with self._lock:
            return list(self._instances.values())

    def source_types(self) -> List[str]:
        with self._lock:
            return list(self._classes.keys())
