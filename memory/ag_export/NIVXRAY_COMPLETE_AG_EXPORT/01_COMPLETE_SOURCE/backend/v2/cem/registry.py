"""CEM Version Registry.

Adapters declare a CEM version via `SUPPORTED_CEM = "v1"`. This
registry resolves the version string to the concrete schema module.

Adding a new version is done via a governance amendment: register a
new module here, never mutate an existing one.
"""
from __future__ import annotations

from typing import Any

from v2.cem.v1 import schema as _v1_schema

REGISTRY: dict[str, Any] = {
    "v1": _v1_schema,
}

LATEST: str = "v1"


def get(version: str = LATEST) -> Any:
    if version not in REGISTRY:
        raise KeyError(
            f"Unknown CEM version {version!r}. "
            f"Registered: {sorted(REGISTRY)}"
        )
    return REGISTRY[version]


def supported() -> tuple[str, ...]:
    return tuple(sorted(REGISTRY))
