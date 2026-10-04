"""EvidenceProvider / EnrichmentProvider abstractions (store-agnostic)."""
from __future__ import annotations

import bisect
from datetime import datetime
from typing import (Any, Callable, Dict, Iterable, List, Optional, Protocol,
                    Sequence, Tuple)

from .contracts import Enrichment, EvidenceRecord, utc


class EvidenceProvider(Protocol):
    async def window(self, *, tenant_id: str, endpoint_id: str, start: datetime,
                     end: datetime, kinds: Sequence[str], limit: int) -> List[EvidenceRecord]: ...

    async def page(self, *, tenant_id: str, endpoint_id: str, start: datetime, end: datetime,
                   after: Optional[Tuple[datetime, str]], limit: int) -> List[EvidenceRecord]: ...


class EnrichmentProvider(Protocol):
    async def lookup(self, *, tenant_id: str, observable: str,
                     observable_type: str) -> Optional[Enrichment]: ...


class NullEnrichmentProvider:
    """Default: no TI wired. INTEL stages therefore evaluate to UNKNOWN."""

    async def lookup(self, *, tenant_id: str, observable: str,
                     observable_type: str) -> Optional[Enrichment]:
        return None


class StaticEnrichmentProvider:
    """Deterministic, tenant-keyed enrichment for tests and replay fixtures."""

    def __init__(self, entries: Dict[Tuple[str, str], Enrichment]) -> None:
        self._e = dict(entries)

    def set(self, tenant_id: str, observable: str, e: Enrichment) -> None:
        self._e[(tenant_id, observable.lower())] = e

    async def lookup(self, *, tenant_id: str, observable: str,
                     observable_type: str) -> Optional[Enrichment]:
        return self._e.get((tenant_id, observable.lower()))


class InMemoryEvidenceProvider:
    """Partitioned by (tenant, endpoint); sorted for bisect window lookups."""

    def __init__(self) -> None:
        self._parts: Dict[Tuple[str, str], List[Tuple[Tuple[datetime, str], EvidenceRecord]]] = {}
        self._by_key: Dict[Tuple[str, str], EvidenceRecord] = {}

    def add(self, rec: EvidenceRecord) -> bool:
        """Idempotent on (tenant, stable_key); a newer generation replaces the ref."""
        k = (rec.tenant_id, rec.stable_key)
        prev = self._by_key.get(k)
        part = self._parts.setdefault((rec.tenant_id, rec.endpoint_id), [])
        if prev is not None:
            if (rec.ref.generation or 0) <= (prev.ref.generation or 0):
                return False
            part.remove((prev.sort_key(), prev))
        self._by_key[k] = rec
        bisect.insort(part, (rec.sort_key(), rec), key=lambda x: x[0])
        return prev is None

    async def window(self, *, tenant_id: str, endpoint_id: str, start: datetime,
                     end: datetime, kinds: Sequence[str], limit: int) -> List[EvidenceRecord]:
        part = self._parts.get((tenant_id, endpoint_id), [])
        lo = bisect.bisect_left(part, (start, ""), key=lambda x: x[0])
        out: List[EvidenceRecord] = []
        ks = set(kinds)
        for sk, rec in part[lo:]:
            if sk[0] > end:
                break
            if rec.kind in ks:
                out.append(rec)
                if len(out) >= limit:
                    break
        return out

    async def page(self, *, tenant_id: str, endpoint_id: str, start: datetime, end: datetime,
                   after: Optional[Tuple[datetime, str]], limit: int) -> List[EvidenceRecord]:
        part = self._parts.get((tenant_id, endpoint_id), [])
        lo = (bisect.bisect_right(part, after, key=lambda x: x[0]) if after
              else bisect.bisect_left(part, (start, ""), key=lambda x: x[0]))
        out = []
        for sk, rec in part[lo:]:
            if sk[0] > end or len(out) >= limit:
                break
            out.append(rec)
        return out


class MongoEvidenceProvider:
    """Store-agnostic Mongo reader: field names and the doc->record mapper are injected.

    The canonical authority decision is pending, so no collection name is assumed here.
    Query shape (needs a matching compound index): {tenant, endpoint, time range}, sort time asc.
    """

    def __init__(self, collection: Any, mapper: Callable[[Dict[str, Any]], Optional[EvidenceRecord]], *,
                 tenant_field: str, endpoint_field: str, time_field: str,
                 time_as_iso: bool = True) -> None:
        self._c, self._map = collection, mapper
        self._tf, self._ef, self._time, self._iso = tenant_field, endpoint_field, time_field, time_as_iso

    def _t(self, d: datetime) -> Any:
        return utc(d) if self._iso else d

    def _filter(self, tenant_id: str, endpoint_id: str, start: datetime, end: datetime) -> Dict[str, Any]:
        if not tenant_id or not endpoint_id:
            raise ValueError("tenant_id and endpoint_id are mandatory")
        return {self._tf: tenant_id, self._ef: endpoint_id,
                self._time: {"$gte": self._t(start), "$lte": self._t(end)}}

    async def _run(self, flt: Dict[str, Any], limit: int) -> List[EvidenceRecord]:
        cur = self._c.find(flt).sort([(self._time, 1)]).limit(int(limit))
        out = []
        async for doc in cur:
            rec = self._map(doc)
            if rec is not None:
                out.append(rec)
        return sorted(out, key=lambda r: r.sort_key())

    async def window(self, *, tenant_id: str, endpoint_id: str, start: datetime,
                     end: datetime, kinds: Sequence[str], limit: int) -> List[EvidenceRecord]:
        recs = await self._run(self._filter(tenant_id, endpoint_id, start, end), limit)
        ks = set(kinds)
        return [r for r in recs if r.kind in ks and r.tenant_id == tenant_id]

    async def page(self, *, tenant_id: str, endpoint_id: str, start: datetime, end: datetime,
                   after: Optional[Tuple[datetime, str]], limit: int) -> List[EvidenceRecord]:
        flt = self._filter(tenant_id, endpoint_id, after[0] if after else start, end)
        recs = await self._run(flt, limit + 64)
        if after:
            recs = [r for r in recs if r.sort_key() > after]
        return recs[:limit]


def dedupe(records: Iterable[EvidenceRecord]) -> List[EvidenceRecord]:
    seen: Dict[str, EvidenceRecord] = {}
    for r in records:
        p = seen.get(r.stable_key)
        if p is None or (r.ref.generation or 0) > (p.ref.generation or 0):
            seen[r.stable_key] = r
    return sorted(seen.values(), key=lambda r: r.sort_key())
