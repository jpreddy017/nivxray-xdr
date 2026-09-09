"""Base contract for every L2 service.

An L2 service is a pure function ``run(bundle) -> ServiceOutput``.
This module defines the ``BaseService`` protocol and a simple registry
so PR-2's L1 read APIs can enumerate services generically.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

from ..schemas import EvidenceBundle, ServiceOutput


@dataclass(frozen=True)
class BaseService:
    """Uniform descriptor for an L2 service."""

    name: str                                           # short id, e.g. "executive_summary"
    version: str                                        # SemVer, e.g. "0.1.0-scaffold"
    run: Callable[[EvidenceBundle], ServiceOutput]      # pure function


_REGISTRY: dict[str, BaseService] = {}


def register_service(service: BaseService) -> BaseService:
    if service.name in _REGISTRY:
        raise ValueError(f"L2 service already registered: {service.name}")
    _REGISTRY[service.name] = service
    return service


def get_service(name: str) -> BaseService:
    return _REGISTRY[name]


def iter_services() -> Iterator[BaseService]:
    """Deterministic ordering (alphabetical by name)."""
    for name in sorted(_REGISTRY):
        yield _REGISTRY[name]


def all_service_names() -> list[str]:
    return sorted(_REGISTRY)


__all__ = [
    "BaseService",
    "register_service",
    "get_service",
    "iter_services",
    "all_service_names",
]
