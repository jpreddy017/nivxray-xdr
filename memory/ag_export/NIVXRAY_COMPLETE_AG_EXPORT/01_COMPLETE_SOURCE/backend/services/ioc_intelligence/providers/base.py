"""
Provider base · lookup protocol (2026-03-02)
─────────────────────────────────────────────
Every provider defines an async `lookup(kind, value, http)` returning
a ProviderResult.  Failures NEVER raise — they degrade to a
`pending` / `error` verdict so the consensus engine can weight them.

Providers may declare which IOC kinds they support via
`SUPPORTED_KINDS`.  Unsupported kinds skip the provider entirely.
"""
from __future__ import annotations
from typing import Iterable, Protocol

import httpx

from ..schema import ProviderResult, ProviderVerdict


class Provider(Protocol):
    name: str
    SUPPORTED_KINDS: Iterable[str]

    async def lookup(self, kind: str, value: str,
                       http: httpx.AsyncClient) -> ProviderResult: ...


def pending_result(provider: str,
                    detail: str = "credentials required") -> ProviderResult:
    return ProviderResult(
        verdict=ProviderVerdict(
            provider=provider, verdict="unknown",
            detail=detail, source="pending",
        ),
    )


def error_result(provider: str, err: str) -> ProviderResult:
    return ProviderResult(
        verdict=ProviderVerdict(
            provider=provider, verdict="unknown",
            detail="lookup failed", source="error", error=err,
        ),
    )


def unknown_result(provider: str,
                    detail: str = "no record") -> ProviderResult:
    return ProviderResult(
        verdict=ProviderVerdict(
            provider=provider, verdict="unknown",
            detail=detail, source="live",
        ),
    )
