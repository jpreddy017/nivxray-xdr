"""`EvidenceProvider` for the E3 sequence engine, backed ONLY by the §d read.

The engine windows its own surrounding evidence (`SequenceEngine._window`), so a
provider is structurally required — but it must not become a second evidence
read path. This one issues no query of its own: every row comes from
`edr_trajectory.production_adapter.page_device_evidence`, the same
tenant-partitioned, endpoint-ref-bound, newest-first bounded read Device
Trajectory uses, and every row is converted by the Step-22 adapter.

What is deliberately NOT here: no Mongo filter, no collection name, no
normalizer, no hostname or device_iid addressing, no ingest-time ordering, no
unbounded read, and no use of `edr_behavior.provider.MongoStoreProvider`.

Order note: §d returns NEWEST-FIRST (its paging authority). The engine wants
ascending evidence, so this provider reverses within the bounded set it has
read. It never re-sorts on a key of its own invention: ordering is always
(stored observation time, stable evidence identity).
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from edr_behavior.contracts import EvidenceRecord
from edr_plane.behavior_evidence_adapter import to_evidence_record
from edr_trajectory.paging import PAGE_DEFAULT, PAGE_MAX
from edr_trajectory.production_adapter import page_device_evidence

#: §d pages consumed per provider call. A bound, not a runner budget: the
#: execution budget is deliberately unset until the provider is measured.
MAX_PAGES = 8

REFUSED_NO_TENANT = "PROVIDER_NO_RESOLVED_TENANT"
REFUSED_NO_ENDPOINT = "PROVIDER_NO_RESOLVED_ENDPOINT"
REFUSED_NO_REFS = "PROVIDER_ENDPOINT_NOT_ADDRESSABLE_NO_VALIDATED_REFS"
REFUSED_UNBOUNDED = "PROVIDER_UNBOUNDED_READ_REFUSED"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class SdEvidenceProvider:
    """Read-only §d-backed evidence provider for ONE customer and ONE endpoint."""

    def __init__(self, db: Any, *, tenant_id: str, endpoint_id: str,
                 refs: Sequence[str], page_size: int = PAGE_DEFAULT,
                 max_pages: int = MAX_PAGES) -> None:
        tenant = str(tenant_id or "").strip()
        if not tenant:
            raise ValueError(REFUSED_NO_TENANT)
        endpoint = str(endpoint_id or "").strip()
        if not endpoint:
            raise ValueError(REFUSED_NO_ENDPOINT)
        validated = [str(r).strip() for r in (refs or []) if str(r or "").strip()]
        if not validated:
            raise ValueError(REFUSED_NO_REFS)
        self._db = db
        self.tenant_id = tenant
        self.endpoint_id = endpoint
        #: the resolver's VALIDATED alias set. Addressing only — never identity.
        self._refs = validated
        self._page_size = max(1, min(int(page_size or PAGE_DEFAULT), PAGE_MAX))
        self._max_pages = max(1, int(max_pages))
        self.counters: Counter = Counter()
        self.refusals: Counter = Counter()

    # ── internals ────────────────────────────────────────────────────────

    async def _read(self, start: datetime, end: datetime, row_budget: int
                    ) -> Tuple[List[EvidenceRecord], bool]:
        """Ascending records inside [start, end], bounded by rows and pages."""
        cursor: Optional[str] = None
        out: List[EvidenceRecord] = []
        more = False
        for _ in range(self._max_pages):
            page = await page_device_evidence(
                self._db, tenant_id=self.tenant_id, refs=list(self._refs),
                page_size=self._page_size, cursor=cursor,
                time_start=_iso(start), time_end=_iso(end))
            self.counters["sd_pages_read"] += 1
            items = page.get("items") or []
            self.counters["sd_rows_read"] += len(items)
            for row in items:
                rec, why = to_evidence_record(
                    row, tenant_id=self.tenant_id,
                    endpoint_id=self.endpoint_id)
                if rec is None:
                    self.refusals[why] += 1
                    self.counters["rows_refused"] += 1
                    continue
                # never trust the upstream filter alone
                if rec.tenant_id != self.tenant_id or \
                        rec.ref.tenant_id != self.tenant_id:
                    self.counters["cross_tenant_rejected"] += 1
                    continue
                if rec.endpoint_id != self.endpoint_id:
                    self.counters["endpoint_mismatch_rejected"] += 1
                    continue
                out.append(rec)
                self.counters["rows_converted"] += 1
            cursor = page.get("next_cursor")
            if not page.get("has_more") or not cursor:
                break
            if len(out) >= row_budget:
                more = True
                break
        else:
            more = True
        if len(out) > row_budget:
            more = True
        out.sort(key=lambda r: r.sort_key())
        if more:
            self.counters["truncated"] += 1
        return out[:row_budget], more

    # ── EvidenceProvider protocol ────────────────────────────────────────

    async def window(self, *, tenant_id: str, endpoint_id: str,
                     start: datetime, end: datetime, kinds: Sequence[str],
                     limit: int) -> List[EvidenceRecord]:
        """Surrounding evidence for one sequence rule. Bounded by time AND count.

        `limit` is the engine's `max_window_events + 1`, so returning a full
        `limit` rows is how the engine learns the window was truncated and
        answers INSUFFICIENT_EVIDENCE instead of NO_MATCH.
        """
        self._assert_scope(tenant_id, endpoint_id)
        if start is None or end is None or end < start:
            raise ValueError(REFUSED_UNBOUNDED)
        bound = max(1, int(limit))
        recs, _ = await self._read(start, end, bound)
        wanted = set(kinds or ())
        return [r for r in recs if (not wanted or r.kind in wanted)][:bound]

    async def page(self, *, tenant_id: str, endpoint_id: str, start: datetime,
                   end: datetime, after: Optional[Tuple[datetime, str]],
                   limit: int) -> List[EvidenceRecord]:
        """Deterministic forward continuation on §d's own ordering identity.

        No second pagination identity is invented: continuation is
        (stored observation time, stable evidence identity) — exactly the key
        `EvidenceRecord.sort_key()` already exposes.
        """
        self._assert_scope(tenant_id, endpoint_id)
        if start is None or end is None or end < start:
            raise ValueError(REFUSED_UNBOUNDED)
        bound = max(1, int(limit))
        lo = after[0] if after else start
        recs, _ = await self._read(lo, end, bound + 1 if after else bound)
        if after:
            recs = [r for r in recs if r.sort_key() > after]
        return recs[:bound]

    def _assert_scope(self, tenant_id: str, endpoint_id: str) -> None:
        if str(tenant_id or "").strip() != self.tenant_id:
            raise ValueError(REFUSED_NO_TENANT)
        if str(endpoint_id or "").strip() != self.endpoint_id:
            raise ValueError(REFUSED_NO_ENDPOINT)

    def snapshot(self) -> Dict[str, Any]:
        """Counters only. Nothing durable is written by this provider."""
        return {"tenant_id": self.tenant_id, "endpoint_id": self.endpoint_id,
                "counters": dict(self.counters),
                "adapter_refusals": dict(self.refusals)}
