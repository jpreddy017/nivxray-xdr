"""Capability registry — every runtime unit registers here.

The registry is a strict allow-list. Attempting to register a
capability of a rejected kind (DYNAMIC / UI / IRRELEVANT) raises
at registration time — that keeps the runtime path clean.
"""
from __future__ import annotations

from typing import Callable, Optional

from .types import Capability, CapabilityKind


class CapabilityRegistry:
    """Global read-only-after-init capability registry.

    Registration happens at import time in each sub-engine module.
    """
    def __init__(self) -> None:
        self._caps:  dict[str, Capability] = {}
        self._funcs: dict[str, Callable] = {}

    def register(self, cap: Capability, fn: Callable) -> None:
        if cap.name in self._caps:
            raise ValueError(f"Capability '{cap.name}' already registered.")
        # `Capability.__post_init__` already rejects DYNAMIC/UI/IRRELEVANT.
        # Defensive re-check here in case someone extends the enum.
        if cap.kind in (CapabilityKind.DYNAMIC, CapabilityKind.UI,
                        CapabilityKind.IRRELEVANT):
            raise ValueError(
                f"Refusing to register '{cap.name}' — kind {cap.kind} "
                "is not static-safe for the engine.")
        self._caps[cap.name] = cap
        self._funcs[cap.name] = fn

    def get(self, name: str) -> Optional[Capability]:
        return self._caps.get(name)

    def fn(self, name: str) -> Optional[Callable]:
        return self._funcs.get(name)

    def by_language(self, language: str) -> list[Capability]:
        return sorted(
            (c for c in self._caps.values() if c.language == language),
            key=lambda c: c.name,
        )

    def all(self) -> list[Capability]:
        return sorted(self._caps.values(), key=lambda c: c.name)

    def snapshot(self) -> dict:
        return {
            "total":    len(self._caps),
            "by_kind":  {
                k.value: sum(1 for c in self._caps.values()
                              if c.kind == k)
                for k in CapabilityKind
            },
            "by_language": {
                lang: sum(1 for c in self._caps.values()
                          if c.language == lang)
                for lang in ("cmd", "powershell", "bash", "generic")
            },
            "names": [c.name for c in self.all()],
        }


_REGISTRY: Optional[CapabilityRegistry] = None


def get_registry() -> CapabilityRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = CapabilityRegistry()
        # Deferred imports to break the cycle; sub-engines expose an
        # idempotent `register_all(registry)` we invoke here.
        from . import cmd as _cmd
        from . import powershell as _ps
        _cmd.register_all(_REGISTRY)
        _ps.register_all(_REGISTRY)
    return _REGISTRY


__all__ = ["CapabilityRegistry", "get_registry"]
