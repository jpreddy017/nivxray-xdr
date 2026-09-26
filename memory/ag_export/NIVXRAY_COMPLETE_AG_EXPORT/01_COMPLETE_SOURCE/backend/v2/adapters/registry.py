"""Adapter registry with discovery via `@register`.

Adapters register themselves at import time. `discover()` triggers
imports for every seed adapter so the registry is populated
predictably at test time.
"""
from __future__ import annotations

from importlib import import_module
from typing import Callable, Type, TypeVar

from v2.adapters.base import BaseAdapter, InputAdapter

# name → adapter class (not instance — kept stateless)
ADAPTERS: dict[str, Type[BaseAdapter]] = {}


T = TypeVar("T", bound=BaseAdapter)


def register(cls: Type[T]) -> Type[T]:
    """Class decorator that adds an adapter to the registry.

    Idempotent under module reload: if a class with the same name is
    already registered, the new class REPLACES it. This lets tests
    reload adapter modules to pick up env-var-driven behaviour without
    triggering spurious "name collision" errors.
    """
    name = getattr(cls, "name", None)
    if not name or name == "unnamed":
        raise ValueError(f"Adapter {cls!r} must set a non-empty `name` attribute")
    if not isinstance(cls(), InputAdapter):
        raise TypeError(f"Adapter {cls!r} does not satisfy InputAdapter Protocol")
    ADAPTERS[name] = cls
    return cls


# Modules discovered at boot. Adding a new adapter = adding to this list.
# In Phase 1 all entries are STUBS with no runtime logic.
_SEED_MODULES: tuple[str, ...] = (
    "v2.adapters.command_line",
    "v2.adapters.powershell",
    "v2.adapters.cmd",
    "v2.adapters.bash",
    "v2.adapters.json_events",
)


def discover() -> tuple[str, ...]:
    """Import every seed adapter so the registry is populated."""
    for mod in _SEED_MODULES:
        import_module(mod)
    return tuple(sorted(ADAPTERS))


def reset_registry() -> None:
    """Test helper — clears the registry so a re-discover starts clean."""
    ADAPTERS.clear()


def get(name: str) -> Type[BaseAdapter] | None:
    return ADAPTERS.get(name)
