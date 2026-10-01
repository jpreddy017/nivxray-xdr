"""B4 · the reputation SERVICE — registry, cache, and honest aggregation.

The service asks every registered provider that supports the observable
type and RETAINS each answer. It does not pick a winner and it does not
average: provider disagreement is a fact an analyst must be able to see.

Aggregation states — deliberately not verdicts:

```
MALICIOUS_ASSERTED     at least one source asserts KNOWN_MALICIOUS
GOOD_ASSERTED          at least one asserts KNOWN_GOOD, none malicious
NO_INTELLIGENCE        every lookup SUCCEEDED and no source knows it
NO_LOOKUP_COMPLETED    no lookup succeeded — we know NOTHING, not "unknown"
NOT_SUPPORTED          no registered provider can judge this type
```

`NO_INTELLIGENCE` is not benign. `NO_LOOKUP_COMPLETED` is not
`NO_INTELLIGENCE`. Both are reported with the providers involved.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence

from .contract import (CACHE_HIT_FRESH, CACHE_HIT_STALE, CACHE_MISS,
                       INTELLIGENCE_VERDICTS, KNOWN_GOOD, KNOWN_MALICIOUS,
                       LOOKUP_FAILED, NOT_SUPPORTED, UNKNOWN, Observable,
                       ReputationProvider, ReputationResult, now_iso)

AGG_MALICIOUS_ASSERTED = "MALICIOUS_ASSERTED"
AGG_GOOD_ASSERTED = "GOOD_ASSERTED"
AGG_NO_INTELLIGENCE = "NO_INTELLIGENCE"
AGG_NO_LOOKUP_COMPLETED = "NO_LOOKUP_COMPLETED"
AGG_NOT_SUPPORTED = "NOT_SUPPORTED"

AGGREGATE_MEANING = {
    AGG_MALICIOUS_ASSERTED: ("at least one intelligence source asserts this "
                             "observable is malicious"),
    AGG_GOOD_ASSERTED: ("at least one source asserts known-good and none "
                        "asserts malicious"),
    AGG_NO_INTELLIGENCE: ("every lookup completed and NO source holds "
                          "reputation for this observable. This is NOT "
                          "benign"),
    AGG_NO_LOOKUP_COMPLETED: ("no lookup completed, so nothing is known "
                              "either way. This is NOT 'no known "
                              "reputation'"),
    AGG_NOT_SUPPORTED: ("no registered provider can judge this observable "
                        "type"),
}

DEFAULT_TTL_SECONDS = 3600


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ReputationService:
    """Provider registry + result cache. Owns no evidence and no verdicts."""

    def __init__(self, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._providers: dict[str, ReputationProvider] = {}
        self._ttl = int(ttl_seconds)
        self._cache: dict[tuple[str, str], ReputationResult] = {}

    # ── registry ────────────────────────────────────────────────────
    def register(self, provider: ReputationProvider) -> None:
        if not getattr(provider, "provider_id", ""):
            raise ValueError("a provider must declare a provider_id")
        self._providers[provider.provider_id] = provider

    @property
    def providers(self) -> list[dict[str, Any]]:
        return [{"provider_id": p.provider_id,
                 "provider_version": getattr(p, "provider_version", ""),
                 "supported_types": list(getattr(p, "supported_types", ())),
                 "offline": bool(getattr(p, "offline", False))}
                for p in self._providers.values()]

    # ── lookup ──────────────────────────────────────────────────────
    async def evaluate(self, observables: Sequence[Observable], *,
                       tenant_id: str,
                       use_cache: bool = True) -> list[dict[str, Any]]:
        """Per-observable reputation, with every provider answer retained."""
        out: list[dict[str, Any]] = []
        for obs in observables:
            results = await self._lookup_one(obs, tenant_id=tenant_id,
                                             use_cache=use_cache)
            out.append(self._aggregate(obs, results))
        return out

    async def _lookup_one(self, obs: Observable, *, tenant_id: str,
                          use_cache: bool) -> list[ReputationResult]:
        results: list[ReputationResult] = []
        for provider in self._providers.values():
            if obs.type not in getattr(provider, "supported_types", ()):
                results.append(ReputationResult(
                    observable=obs.value, observable_type=obs.type,
                    subject=obs.subject, provider_id=provider.provider_id,
                    verdict=NOT_SUPPORTED,
                    failure_reason=(f"{provider.provider_id} does not "
                                    f"support {obs.type}")))
                continue
            cached = self._from_cache(provider.provider_id, obs,
                                      tenant_id=tenant_id) \
                if use_cache else None
            if cached is not None:
                results.append(cached)
                continue
            try:
                answers = await provider.lookup([obs], tenant_id=tenant_id)
            except Exception as e:  # noqa: BLE001
                results.append(ReputationResult(
                    observable=obs.value, observable_type=obs.type,
                    subject=obs.subject, provider_id=provider.provider_id,
                    verdict=LOOKUP_FAILED,
                    failure_reason=f"{type(e).__name__}: {str(e)[:200]}"))
                continue
            for answer in answers:
                self._to_cache(obs, answer, tenant_id=tenant_id)
                results.append(answer)
        return results

    # ── cache ───────────────────────────────────────────────────────
    def _cache_key(self, provider_id: str, obs: Observable, *,
                   tenant_id: str) -> tuple[str, str]:
        # Tenant is part of the key: a tenant-scoped IOC must never answer
        # for another tenant out of a shared cache.
        return (provider_id, f"{tenant_id}|{obs.cache_key}")

    def _from_cache(self, provider_id: str, obs: Observable, *,
                    tenant_id: str) -> Optional[ReputationResult]:
        hit = self._cache.get(self._cache_key(provider_id, obs,
                                              tenant_id=tenant_id))
        if hit is None:
            return None
        # A failed lookup is never cached as an answer, so it can never be
        # served later as intelligence.
        if hit.verdict == LOOKUP_FAILED:
            return None
        queried = _parse(hit.queried_at)
        expires = _parse(hit.expires_at)
        stale = False
        reference = datetime.now(timezone.utc)
        if expires is not None and reference > expires:
            stale = True
        elif queried is not None and \
                reference - queried > timedelta(seconds=self._ttl):
            stale = True
        return replace(hit, cache_state=(CACHE_HIT_STALE if stale
                                         else CACHE_HIT_FRESH),
                       provenance={**hit.provenance,
                                   "cache_queried_at": hit.queried_at,
                                   "cache_read_at": now_iso(),
                                   "cache_ttl_seconds": self._ttl})

    def _to_cache(self, obs: Observable, result: ReputationResult, *,
                  tenant_id: str) -> None:
        if result.verdict == LOOKUP_FAILED:
            return
        self._cache[self._cache_key(result.provider_id, obs,
                                    tenant_id=tenant_id)] = replace(
            result, cache_state=CACHE_MISS)

    def cache_size(self) -> int:
        return len(self._cache)

    # ── aggregation ─────────────────────────────────────────────────
    def _aggregate(self, obs: Observable,
                   results: list[ReputationResult]) -> dict[str, Any]:
        verdicts = {r.verdict for r in results}
        intelligence = [r for r in results
                        if r.verdict in INTELLIGENCE_VERDICTS]
        if KNOWN_MALICIOUS in verdicts:
            state = AGG_MALICIOUS_ASSERTED
        elif KNOWN_GOOD in verdicts:
            state = AGG_GOOD_ASSERTED
        elif UNKNOWN in verdicts:
            state = AGG_NO_INTELLIGENCE
        elif verdicts and verdicts <= {NOT_SUPPORTED}:
            state = AGG_NOT_SUPPORTED
        else:
            state = AGG_NO_LOOKUP_COMPLETED
        disagreement = (KNOWN_MALICIOUS in verdicts
                        and KNOWN_GOOD in verdicts)
        return {
            "observable": obs.value,
            "observable_type": obs.type,
            "subject": obs.subject,
            "source_field": obs.source_field,
            "evidence_refs": list(obs.evidence_refs),
            "tenant_id": obs.tenant_id,
            "endpoint_id": obs.endpoint_id,
            "aggregate_state": state,
            "aggregate_meaning": AGGREGATE_MEANING[state],
            "providers_queried": [r.provider_id for r in results],
            "providers_with_intelligence": [r.provider_id
                                            for r in intelligence],
            "lookup_failures": [{"provider_id": r.provider_id,
                                 "reason": r.failure_reason}
                                for r in results
                                if r.verdict == LOOKUP_FAILED],
            "provider_disagreement": disagreement,
            "results": [r.to_dict() for r in results],
        }
