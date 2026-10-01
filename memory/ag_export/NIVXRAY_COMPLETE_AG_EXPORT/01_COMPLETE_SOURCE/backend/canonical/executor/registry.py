"""Capability plug-in registry (D4-3)."""
from __future__ import annotations

from enum import Enum
from typing import Callable, Dict, Optional

from ..iue.models import Capability
from ..ssot import AuthoritativeSSOT, Provenance


class CapabilityRole(str, Enum):
    HEALTH   = "health"
    ANALYZER = "analyzer"
    ENRICHER = "enricher"   # INV-2: isolated, non-deterministic-allowed


# Plug-in signature:
#   fn(ssot: AuthoritativeSSOT, raw_input: bytes|str, step_ctx: dict) -> None
CapabilityFn = Callable[[AuthoritativeSSOT, object, dict], None]


CAPABILITY_REGISTRY: Dict[Capability, dict] = {}


def register_capability(cap: Capability, role: CapabilityRole,
                        fn: CapabilityFn, version: str = "1.0.0") -> None:
    if not isinstance(cap, Capability):
        raise TypeError("cap must be canonical.iue.Capability")
    if not isinstance(role, CapabilityRole):
        raise TypeError("role must be CapabilityRole")
    CAPABILITY_REGISTRY[cap] = {"role": role, "fn": fn, "version": version}


def get_capability(cap: Capability) -> Optional[dict]:
    return CAPABILITY_REGISTRY.get(cap)


def clear_registry_for_test() -> None:
    """Test-only helper."""
    CAPABILITY_REGISTRY.clear()
