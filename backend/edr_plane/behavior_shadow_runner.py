"""The bounded, single-writer Behavior SHADOW runner.

This is the first module in which `SequenceEngine` actually executes. It joins
the authorities built in Steps 21-29 and adds no alternative evidence or
persistence path:

    ShadowRunRecord  ->  initialized ShadowFrontier  ->  SdEvidenceProvider
    ->  §d row adapter  ->  SequenceEngine(mode=MODE_SHADOW)
    ->  ShadowDetectionStore  ->  runner-derived measurements
    ->  ShadowRunRecord  ->  frontier.advance()   <-- ALWAYS LAST

THE ONE INVARIANT: the checkpoint is the final durable operation for an item,
and it only ever acknowledges work that is already durable. Everything before it
is idempotent, so a crash degrades to at-least-once re-evaluation and never to a
silently skipped, unaccounted evidence item.

Deliberate refusals (owner decisions E7/E8): a NO_EVIDENCE frontier is refused
outright, and ANY adapter refusal on a page refuses the whole invocation BEFORE
the engine runs. Neither is papered over.

Two authorities that are NOT the engine's:
* `duplicates_prevented` comes from the shadow store's DUPLICATE_UNCHANGED write
  outcomes, not from engine metrics (G-8: the store rewrites `status`, so the
  engine's own material comparison can no longer recognise a duplicate).
* persistence of a MATCH is proven by a VERIFIED store write plus a read-back —
  never by `OUTCOME_MATCH`, which `SequenceEngine._emit` returns even after its
  retries are exhausted.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from edr_behavior.contracts import (MODE_SHADOW, OUTCOME_BUDGET,
                                    OUTCOME_INSUFFICIENT, OUTCOME_MATCH,
                                    OUTCOME_NO_MATCH, OUTCOME_SUPPRESSED, sha)
from edr_behavior.engine import SequenceEngine
from edr_behavior.metrics import Metrics
from edr_plane import behavior_shadow_frontier as fr
from edr_plane import behavior_shadow_run as rr
from edr_plane.behavior_shadow_detection_store import (
    WRITE_DUPLICATE, ShadowDetectionRefused, ShadowDetectionStore)
from edr_plane.behavior_sd_provider import SdEvidenceProvider


@dataclass(frozen=True)
class ShadowBudgets:
    """Runner-local hermetic ceilings. NOT configuration, NOT environment.

    Sized against the §d read, not against row counts: one `provider.window()`
    call may consume up to `MAX_PAGES` §d pages PER CANDIDATE RULE PER ITEM, and
    `xdr_canonical_evidence` still has no `event_time` index.
    """
    max_trigger_rows: int = 25
    provider_page_size: int = 100
    max_sd_pages: int = 24
    max_window_events: int = 500
    matcher_budget: int = 2000
    max_rules_evaluated: int = 50
    max_observation_span_seconds: int = 6 * 3600
    sd_call_timeout_seconds: float = 8.0
    #: Provisional, to be set from hermetic measurement rather than argued from
    #: any ingress timeout. The soft stop is checked BETWEEN items only, so a
    #: run always ends on a clean item boundary.
    wall_clock_seconds: float = 60.0
    soft_stop_seconds: float = 20.0


REFUSED_NOT_SINGLE_WRITER = "SHADOW_RUNNER_SINGLE_WRITER_NOT_DECLARED"
REFUSED_CONCURRENT = "SHADOW_RUNNER_CONCURRENT_INVOCATION_REFUSED"
REFUSED_OVERLAPPING_RUN = "SHADOW_RUNNER_OVERLAPPING_STARTED_RUN_REFUSED"
REFUSED_NO_EVIDENCE_FRONTIER = "SHADOW_RUNNER_NO_EVIDENCE_FRONTIER_REFUSED"
REFUSED_NO_RULES = "SHADOW_RUNNER_NO_LIVE_RULES"
REFUSED_RULESET_DIGEST = "SHADOW_RUNNER_RULESET_CONTENT_HASH_MISMATCH"
REFUSED_WINDOW = "SHADOW_RUNNER_WINDOW_UNBOUNDED_OR_TOO_WIDE"
REFUSED_WINDOW_TOO_NARROW = "SHADOW_RUNNER_WINDOW_NARROWER_THAN_RULE_WINDOW"
REFUSED_STORE_BINDING = "SHADOW_RUNNER_SHADOW_STORE_BINDING_MISMATCH"
REFUSED_IDENTITY = "SHADOW_RUNNER_IDENTITY_INVALID"

STOP_ADAPTER_REFUSAL = "SHADOW_ADAPTER_REFUSAL_PAGE_REFUSED"
STOP_EVIDENCE_READ = "SHADOW_EVIDENCE_READ_FAILED"
STOP_INSUFFICIENT = "SHADOW_UNRESOLVED_INSUFFICIENT_EVIDENCE"
STOP_BUDGET = "SHADOW_BUDGET_EXCEEDED"
STOP_WINDOW_TRUNCATED = "SHADOW_WINDOW_TRUNCATED"
STOP_ENGINE = "SHADOW_ENGINE_RULE_ERROR"
STOP_DETECTION_PERSIST = "SHADOW_DETECTION_PERSIST_FAILED"
STOP_DETECTION_UNVERIFIED = "SHADOW_DETECTION_WRITE_UNVERIFIED"
STOP_DETECTION_MISSING = "SHADOW_MATCH_WITHOUT_DURABLE_DETECTION"
STOP_REFS_INVALID = "SHADOW_MATCH_WITHOUT_VALID_EVIDENCE_REFS"
STOP_SCOPE = "SHADOW_CROSS_TENANT_OR_ENDPOINT_RECORD"
STOP_MEASUREMENT = "SHADOW_MEASUREMENT_INTEGRITY_DISAGREEMENT"
STOP_RUN_RECORD = "SHADOW_RUN_RECORD_PERSIST_FAILED"
STOP_CHECKPOINT = "SHADOW_CHECKPOINT_PERSIST_FAILED"
STOP_CHECKPOINT_LEASE = "SHADOW_CHECKPOINT_LEASE_LOST"
STOP_RUN_LEASE = "SHADOW_RUN_RECORD_LEASE_LOST"
STOP_WALL_CLOCK = "SHADOW_WALL_CLOCK_BUDGET_REACHED"
STOP_SD_PAGES = "SHADOW_SD_PAGE_BUDGET_REACHED"
STOP_RULES = "SHADOW_RULES_EVALUATED_BUDGET_REACHED"
STOP_ROWS = "SHADOW_TRIGGER_ROW_BUDGET_REACHED"

#: Outcomes that constitute a successfully processed item (Step 28).
ADVANCING_OUTCOMES = (OUTCOME_NO_MATCH, OUTCOME_MATCH, OUTCOME_SUPPRESSED)
#: Outcomes that are explicitly NOT a completed interpretation.
BLOCKING_OUTCOMES = (OUTCOME_INSUFFICIENT, OUTCOME_BUDGET)

_locks: Dict[Tuple[str, str, str], asyncio.Lock] = {}


class ShadowRunnerRefused(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def ruleset_digest(rules: Sequence[Any]) -> str:
    """Content identity of the EVALUATED ruleset. Declaring one hash and
    evaluating a different set of rules is refused, so a shadow stream can never
    contain results from content it does not name."""
    return "rs_" + sha("ruleset.v1", *sorted(
        f"{r.rule_id}@v{r.version}:{r.content_hash}" for r in rules))[:32]


# ── bounded provider wrapper ─────────────────────────────────────────────

class _BoundedProvider:
    """Enforces the per-call timeout and the aggregate §d page ceiling.

    The engine windows its own evidence, so these bounds have to live between
    the engine and `SdEvidenceProvider`. `SdEvidenceProvider` itself is NOT
    modified (E9 hold).
    """

    def __init__(self, inner: SdEvidenceProvider, budgets: ShadowBudgets
                 ) -> None:
        self.inner = inner
        self._b = budgets

    @property
    def pages_read(self) -> int:
        return int(self.inner.counters.get("sd_pages_read", 0))

    def _check_pages(self) -> None:
        if self.pages_read >= self._b.max_sd_pages:
            raise ShadowRunnerRefused(STOP_SD_PAGES)

    async def window(self, **kw):
        self._check_pages()
        return await asyncio.wait_for(self.inner.window(**kw),
                                      self._b.sd_call_timeout_seconds)

    async def page(self, **kw):
        self._check_pages()
        return await asyncio.wait_for(self.inner.page(**kw),
                                      self._b.sd_call_timeout_seconds)


# ── runner-owned measurement state ───────────────────────────────────────

@dataclass
class _Measure:
    """Every value here is observed by the runner. Nothing is caller-supplied."""
    counters: Dict[str, int] = field(default_factory=dict)
    outcomes: Dict[str, int] = field(default_factory=dict)
    refusals: Dict[str, int] = field(default_factory=dict)
    truncated: bool = False
    lag_ms: Optional[int] = None

    def bump(self, name: str, n: int = 1) -> None:
        if n:
            self.counters[name] = self.counters.get(name, 0) + n

    def outcome(self, name: str, n: int = 1) -> None:
        if n:
            self.outcomes[name] = self.outcomes.get(name, 0) + n

    def drain(self) -> Dict[str, Any]:
        out = {"counters": dict(self.counters), "outcomes": dict(self.outcomes),
               "adapter_refusals": dict(self.refusals),
               "window_truncated": True if self.truncated else None,
               "evidence_lag_ms": self.lag_ms}
        self.counters.clear()
        self.outcomes.clear()
        self.refusals.clear()
        self.truncated = False
        self.lag_ms = None
        return out


def _deltas(pre: Dict[str, int], post: Dict[str, int]) -> Dict[str, int]:
    return {k: int(post.get(k, 0)) - int(pre.get(k, 0))
            for k in set(pre) | set(post)}


# ── entry ────────────────────────────────────────────────────────────────

async def run_shadow(*, db: Any, tenant_id: str, endpoint_id: str,
                     refs: Sequence[str], registry: Any,
                     ruleset_id: str, ruleset_version: Any,
                     ruleset_content_hash: str, checkpoint_store: Any,
                     run_store: Any, detection_backend: Any,
                     shadow_run_id: str, invoked_by: str, reason: str,
                     window_start: datetime, window_end: datetime,
                     single_writer: bool = False,
                     budgets: Optional[ShadowBudgets] = None,
                     suppression: Any = None,
                     clock: Any = None) -> Dict[str, Any]:
    """One bounded shadow invocation. Explicit operator call only."""
    b = budgets or ShadowBudgets()
    if single_writer is not True:
        raise ShadowRunnerRefused(REFUSED_NOT_SINGLE_WRITER)
    tenant = str(tenant_id or "").strip()
    endpoint = str(endpoint_id or "").strip()
    if not tenant or not endpoint or not str(shadow_run_id or "").strip():
        raise ShadowRunnerRefused(REFUSED_IDENTITY)
    if window_start is None or window_end is None or window_end <= window_start:
        raise ShadowRunnerRefused(REFUSED_WINDOW)
    span = (window_end - window_start).total_seconds()
    if span > b.max_observation_span_seconds:
        raise ShadowRunnerRefused(REFUSED_WINDOW)

    rules = [r for r in registry.live_rules() if r.lifecycle != "DRAFT"]
    if not rules:
        raise ShadowRunnerRefused(REFUSED_NO_RULES)
    if ruleset_digest(rules) != str(ruleset_content_hash or "").strip():
        raise ShadowRunnerRefused(REFUSED_RULESET_DIGEST)
    if span < 2 * max(r.time_window_seconds for r in rules):
        raise ShadowRunnerRefused(REFUSED_WINDOW_TOO_NARROW)

    # The frontier must already exist. The runner NEVER initializes one.
    cp = await fr.read(checkpoint_store, tenant_id=tenant,
                       endpoint_id=endpoint,
                       ruleset_content_hash=ruleset_content_hash)
    if cp.get("mode") != fr.MODE_FRONTIER:
        raise ShadowRunnerRefused(REFUSED_NO_EVIDENCE_FRONTIER)
    replay_id = fr.stream_id(ruleset_content_hash)

    key = (tenant, endpoint, replay_id)
    lock = _locks.setdefault(key, asyncio.Lock())
    if lock.locked():
        raise ShadowRunnerRefused(REFUSED_CONCURRENT)
    _assert_no_started_run(run_store, tenant, endpoint, replay_id)

    async with lock:
        return await _execute(
            db=db, tenant=tenant, endpoint=endpoint, refs=refs, rules=rules,
            cp=cp, replay_id=replay_id, ruleset_id=ruleset_id,
            ruleset_version=ruleset_version,
            ruleset_content_hash=ruleset_content_hash,
            checkpoint_store=checkpoint_store, run_store=run_store,
            detection_backend=detection_backend,
            shadow_run_id=shadow_run_id, invoked_by=invoked_by, reason=reason,
            window_start=window_start, window_end=window_end, budgets=b,
            suppression=suppression, clock=clock)


def _assert_no_started_run(run_store: Any, tenant: str, endpoint: str,
                           replay_id: str) -> None:
    """Advisory only (G-6): no unique index, no store-layer CAS. The real guard
    against a second writer is the frontier revision lease."""
    listing = getattr(run_store, "all", None)
    if not callable(listing):
        return
    for doc in listing(tenant):
        if doc.get("state") == rr.STATE_STARTED and \
                doc.get("endpoint_id") == endpoint and \
                doc.get("replay_id") == replay_id:
            raise ShadowRunnerRefused(REFUSED_OVERLAPPING_RUN)


# ── execution ────────────────────────────────────────────────────────────

async def _execute(*, db, tenant, endpoint, refs, rules, cp, replay_id,
                   ruleset_id, ruleset_version, ruleset_content_hash,
                   checkpoint_store, run_store, detection_backend,
                   shadow_run_id, invoked_by, reason, window_start, window_end,
                   budgets, suppression, clock) -> Dict[str, Any]:
    now = clock or (lambda: datetime.now(timezone.utc))
    started_at = now()

    inner = SdEvidenceProvider(db, tenant_id=tenant, endpoint_id=endpoint,
                               refs=list(refs),
                               page_size=budgets.provider_page_size)
    provider = _BoundedProvider(inner, budgets)
    store = ShadowDetectionStore(
        detection_backend, tenant_id=tenant, endpoint_id=endpoint,
        shadow_run_id=shadow_run_id, replay_id=replay_id,
        ruleset_id=ruleset_id, ruleset_version=ruleset_version,
        ruleset_content_hash=ruleset_content_hash)
    if store.tenant_id != tenant or store.endpoint_id != endpoint or \
            store.stream["ruleset_content_hash"] != ruleset_content_hash:
        raise ShadowRunnerRefused(REFUSED_STORE_BINDING)

    metrics = Metrics()
    engine = SequenceEngine(registry=_FixedRegistry(rules), provider=provider,
                            store=store, suppression=suppression,
                            metrics=metrics, clock=now,
                            max_window_events=budgets.max_window_events,
                            budget=budgets.matcher_budget)

    # The audit record exists BEFORE the first §d read.
    record = await rr.create(run_store, tenant_id=tenant,
                             shadow_run_id=shadow_run_id,
                             endpoint_id=endpoint, ruleset_id=ruleset_id,
                             ruleset_version=ruleset_version,
                             ruleset_content_hash=ruleset_content_hash,
                             replay_id=replay_id, invoked_by=invoked_by,
                             reason=reason, started_at=started_at)

    ctx = _Ctx(tenant=tenant, endpoint=endpoint, provider=provider,
               inner=inner, store=store, engine=engine, rules=rules,
               checkpoint_store=checkpoint_store, run_store=run_store,
               ruleset_content_hash=ruleset_content_hash,
               shadow_run_id=shadow_run_id, replay_id=replay_id,
               budgets=budgets, window_start=window_start,
               window_end=window_end, started=started_at, now=now,
               cp=cp, run_rev=int(record["revision"]))
    t0 = time.monotonic()
    try:
        await _drain(ctx, t0)
    except ShadowRunnerRefused as e:
        ctx.state, ctx.failure = rr.STATE_TRUNCATED, e.reason
    duration_ms = int((time.monotonic() - t0) * 1000)
    return await _finalize(ctx, duration_ms)


class _FixedRegistry:
    """The engine takes a registry; this one serves exactly the rules whose
    content identity the shadow stream names, and nothing else."""

    def __init__(self, rules: Sequence[Any]) -> None:
        self._rules = list(rules)

    def live_rules(self) -> List[Any]:
        return list(self._rules)

    def get(self, rule_id: str, version: int) -> Any:
        for r in self._rules:
            if r.rule_id == rule_id and r.version == version:
                return r
        raise KeyError((rule_id, version))


@dataclass
class _Ctx:
    tenant: str
    endpoint: str
    provider: Any
    inner: Any
    store: Any
    engine: Any
    rules: Any
    checkpoint_store: Any
    run_store: Any
    ruleset_content_hash: str
    shadow_run_id: str
    replay_id: str
    budgets: ShadowBudgets
    window_start: datetime
    window_end: datetime
    started: datetime
    now: Any
    cp: Dict[str, Any]
    run_rev: int
    state: str = rr.STATE_COMPLETED
    failure: Optional[str] = None
    items: int = 0
    rules_evaluated: int = 0
    newest_processed: Optional[datetime] = None
    m: _Measure = field(default_factory=_Measure)
    finalize_failed: bool = False
    trace: List[str] = field(default_factory=list)


def _after(ctx: _Ctx) -> Tuple[datetime, str]:
    t = ctx.cp.get("after_time")
    return (datetime.fromisoformat(str(t).replace("Z", "+00:00")),
            str(ctx.cp.get("after_key")))


async def _drain(ctx: _Ctx, t0: float) -> None:
    while True:
        if not _budget_ok(ctx, t0):
            return
        page = await _read_page(ctx)
        if page is None or not page:
            return
        for rec in page:
            if not _budget_ok(ctx, t0):
                return
            if not await _item(ctx, rec):
                return


def _budget_ok(ctx: _Ctx, t0: float) -> bool:
    """Checked BETWEEN items only, so an item is never half-processed."""
    b = ctx.budgets
    for limit, reason in ((b.wall_clock_seconds, STOP_WALL_CLOCK),
                          (b.soft_stop_seconds, STOP_WALL_CLOCK)):
        if time.monotonic() - t0 >= limit:
            ctx.state, ctx.failure = rr.STATE_TRUNCATED, reason
            return False
    if ctx.items >= b.max_trigger_rows:
        ctx.state, ctx.failure = rr.STATE_TRUNCATED, STOP_ROWS
        return False
    if ctx.rules_evaluated >= b.max_rules_evaluated:
        ctx.state, ctx.failure = rr.STATE_TRUNCATED, STOP_RULES
        return False
    if ctx.provider.pages_read >= b.max_sd_pages:
        ctx.state, ctx.failure = rr.STATE_TRUNCATED, STOP_SD_PAGES
        return False
    return True


async def _read_page(ctx: _Ctx) -> Optional[List[Any]]:
    """Bounded forward read. ANY adapter refusal refuses the page before the
    engine is given anything (owner decision E8)."""
    pre_ref = dict(ctx.inner.refusals)
    pre_conv = int(ctx.inner.counters.get("rows_converted", 0))
    pre_rows = int(ctx.inner.counters.get("sd_rows_read", 0))
    remaining = max(1, ctx.budgets.max_trigger_rows - ctx.items)
    try:
        page = await ctx.provider.page(
            tenant_id=ctx.tenant, endpoint_id=ctx.endpoint,
            start=ctx.window_start, end=ctx.window_end, after=_after(ctx),
            limit=remaining)
    except ShadowRunnerRefused:
        raise
    except Exception:
        ctx.state, ctx.failure = rr.STATE_TRUNCATED, STOP_EVIDENCE_READ
        return None
    ctx.m.bump("rows_read",
               int(ctx.inner.counters.get("sd_rows_read", 0)) - pre_rows)
    converted = int(ctx.inner.counters.get("rows_converted", 0)) - pre_conv
    ctx.m.bump("skipped_observed_before_frontier",
               max(0, converted - len(page)))
    _scope_counters(ctx)
    for why, n in _deltas(pre_ref, dict(ctx.inner.refusals)).items():
        if n > 0:
            ctx.m.refusals[why] = ctx.m.refusals.get(why, 0) + n
    if ctx.m.refusals:
        ctx.state, ctx.failure = rr.STATE_INTERRUPTED, STOP_ADAPTER_REFUSAL
        await _measure(ctx)
        return None
    return page


def _scope_counters(ctx: _Ctx) -> None:
    c = ctx.inner.counters
    seen = int(c.get("cross_tenant_rejected", 0)) + \
        int(c.get("endpoint_mismatch_rejected", 0))
    already = ctx.m.counters.get("cross_tenant_reference_count", 0)
    if seen > already:
        ctx.m.bump("cross_tenant_reference_count", seen - already)


async def _item(ctx: _Ctx, rec: Any) -> bool:
    """One evidence item. Returns False when the run must stop."""
    if rec.tenant_id != ctx.tenant or rec.ref.tenant_id != ctx.tenant or \
            rec.endpoint_id != ctx.endpoint:
        ctx.m.bump("cross_tenant_reference_count")
        ctx.state, ctx.failure = rr.STATE_FAILED, STOP_SCOPE
        await _measure(ctx)
        return False

    pre_m = dict(ctx.engine.metrics.c)
    pre_writes = len(ctx.store.writes)
    pre_trunc = int(ctx.inner.counters.get("truncated", 0))
    # G-9: the trigger is declared BEFORE the engine can persist anything.
    ctx.store.expect_trigger(rec.stable_key)
    ctx.trace.append(f"expect_trigger:{rec.stable_key}")
    try:
        ctx.trace.append("process")
        results = await ctx.engine.process(rec, mode=MODE_SHADOW,
                                           rules=ctx.rules,
                                           trigger={"shadow_run_id":
                                                    ctx.shadow_run_id,
                                                    "replay_id": ctx.replay_id,
                                                    "shadow": True})
    except ShadowDetectionRefused as e:
        ctx.m.bump("engine_failures")
        ctx.state, ctx.failure = rr.STATE_FAILED, e.reason
        await _measure(ctx)
        return False
    except ShadowRunnerRefused:
        raise
    except Exception:
        ctx.m.bump("engine_failures")
        ctx.state, ctx.failure = rr.STATE_FAILED, STOP_ENGINE
        await _measure(ctx)
        return False

    d = _deltas(pre_m, dict(ctx.engine.metrics.c))
    new_writes = ctx.store.writes[pre_writes:]
    prov_trunc = int(ctx.inner.counters.get("truncated", 0)) - pre_trunc
    stop = await _classify(ctx, rec, results or [], d, new_writes, prov_trunc)
    ctx.items += 1
    ctx.rules_evaluated += max(0, d.get("candidate_rules", 0))
    ctx.newest_processed = rec.event_time if ctx.newest_processed is None \
        else max(ctx.newest_processed, rec.event_time)

    if not await _measure(ctx):
        return False
    if stop:
        return False
    return await _advance(ctx, rec)


async def _classify(ctx: _Ctx, rec: Any, results: List[Any],
                    d: Dict[str, int], new_writes: List[Dict[str, Any]],
                    prov_trunc: int) -> Optional[str]:
    """Record what actually happened. Returns a stop reason, or None."""
    m = ctx.m
    m.bump("events_evaluated")
    m.bump("rules_evaluated", max(0, d.get("candidate_rules", 0)))
    m.bump("matches", max(0, d.get("matches", 0)))
    m.bump("concurrency_retries", max(0, d.get("concurrency_retries", 0)))
    # G-8: duplicate authority is the STORE, never engine metrics.
    m.bump("duplicates_prevented",
           sum(1 for w in new_writes if w["outcome"] == WRITE_DUPLICATE))
    _scope_counters(ctx)
    for r in results:
        m.outcome(r.outcome)

    if d.get("events_evaluated", 0) != 1:
        ctx.state, ctx.failure = rr.STATE_FAILED, STOP_MEASUREMENT
        return STOP_MEASUREMENT
    if d.get("rule_errors", 0) > 0:
        m.bump("engine_failures", d["rule_errors"])
        ctx.state, ctx.failure = rr.STATE_FAILED, STOP_ENGINE
        return STOP_ENGINE
    if len(results) != max(0, d.get("candidate_rules", 0)):
        ctx.state, ctx.failure = rr.STATE_FAILED, STOP_ENGINE
        return STOP_ENGINE
    if d.get("window_truncated", 0) > 0 or prov_trunc > 0:
        m.truncated = True
        ctx.state, ctx.failure = rr.STATE_TRUNCATED, STOP_WINDOW_TRUNCATED
        return STOP_WINDOW_TRUNCATED
    for r in results:
        if r.outcome == OUTCOME_BUDGET:
            m.truncated = True
            ctx.state, ctx.failure = rr.STATE_TRUNCATED, STOP_BUDGET
            return STOP_BUDGET
        if r.outcome == OUTCOME_INSUFFICIENT:
            ctx.state, ctx.failure = rr.STATE_INTERRUPTED, STOP_INSUFFICIENT
            return STOP_INSUFFICIENT

    matched = [r for r in results
               if r.outcome in (OUTCOME_MATCH, OUTCOME_SUPPRESSED)]
    if not matched:
        return None
    if any(not w["verified"] for w in new_writes):
        ctx.state, ctx.failure = rr.STATE_FAILED, STOP_DETECTION_UNVERIFIED
        return STOP_DETECTION_UNVERIFIED
    if not new_writes:
        ctx.state, ctx.failure = rr.STATE_FAILED, STOP_DETECTION_MISSING
        return STOP_DETECTION_MISSING
    for w in new_writes:
        doc = await ctx.store.verify(w["detection_id"])
        if doc is None:
            ctx.state, ctx.failure = rr.STATE_FAILED, STOP_DETECTION_MISSING
            return STOP_DETECTION_MISSING
        if not _refs_valid(doc, ctx.tenant, rec.stable_key):
            m.bump("matches_without_valid_evidence_refs")
            ctx.state, ctx.failure = rr.STATE_FAILED, STOP_REFS_INVALID
            return STOP_REFS_INVALID
    return None


def _refs_valid(doc: Dict[str, Any], tenant: str, trigger_key: str) -> bool:
    refs = doc.get("evidence_refs") or []
    if not refs:
        return False
    for ref in refs:
        if not isinstance(ref, dict) or ref.get("tenant_id") != tenant:
            return False
        if not str(ref.get("raw_id") or "").strip():
            return False
        if not str(ref.get("stable_key") or "").strip():
            return False
    return trigger_key in set(doc.get("evidence_keys") or [])


async def _measure(ctx: _Ctx) -> bool:
    """Durably record the measurements observed so far. Must succeed before any
    checkpoint advance: the run record is the audit authority, and advancing
    without it would destroy the only proof the item needs re-evaluation."""
    payload = ctx.m.drain()
    if ctx.newest_processed is not None:
        payload["evidence_lag_ms"] = max(
            0, int((ctx.started - ctx.newest_processed).total_seconds() * 1000))
    if not any([payload["counters"], payload["outcomes"],
                payload["adapter_refusals"], payload["window_truncated"],
                payload["evidence_lag_ms"]]):
        return True
    try:
        doc = await rr.update(
            ctx.run_store, tenant_id=ctx.tenant,
            shadow_run_id=ctx.shadow_run_id, expected_revision=ctx.run_rev,
            counters=payload["counters"], outcomes=payload["outcomes"],
            adapter_refusals=payload["adapter_refusals"],
            window_truncated=payload["window_truncated"],
            evidence_lag_ms=payload["evidence_lag_ms"])
        ctx.run_rev = int(doc["revision"])
        return True
    except rr.StaleShadowRun:
        ctx.state, ctx.failure = rr.STATE_INTERRUPTED, STOP_RUN_LEASE
        return False
    except Exception:
        ctx.state, ctx.failure = rr.STATE_FAILED, STOP_RUN_RECORD
        return False


async def _advance(ctx: _Ctx, rec: Any) -> bool:
    """The FINAL durable operation for an item. Acknowledgement only."""
    try:
        ctx.trace.append("advance")
        ctx.cp = await fr.advance(
            ctx.checkpoint_store, tenant_id=ctx.tenant,
            endpoint_id=ctx.endpoint,
            ruleset_content_hash=ctx.ruleset_content_hash,
            processed_sort_key=rec.sort_key(),
            expected_revision=int(ctx.cp.get("revision") or 0),
            item_resolved=True)
        return True
    except fr.StaleCheckpoint:
        ctx.state, ctx.failure = rr.STATE_INTERRUPTED, STOP_CHECKPOINT_LEASE
        return False
    except Exception:
        ctx.state, ctx.failure = rr.STATE_FAILED, STOP_CHECKPOINT
        return False


async def _finalize(ctx: _Ctx, duration_ms: int) -> Dict[str, Any]:
    resume: Dict[str, Any] = {}
    if ctx.state != rr.STATE_COMPLETED and ctx.cp.get("after_time"):
        t, k = _after(ctx)
        resume = {"resume_after_time": t, "resume_after_key": k}
    try:
        record = await rr.finalize(
            ctx.run_store, tenant_id=ctx.tenant,
            shadow_run_id=ctx.shadow_run_id, state=ctx.state,
            expected_revision=ctx.run_rev, completed_at=ctx.now(),
            failure_reason=ctx.failure, execution_duration_ms=duration_ms,
            **resume)
    except Exception:
        # A STARTED record with no completed_at is the truthful statement that
        # this run cannot be accounted for. The checkpoint proves nothing was
        # skipped. No auto-finalize, no heuristic completion.
        ctx.finalize_failed = True
        record = None
    return {"shadow_run_id": ctx.shadow_run_id, "state": ctx.state,
            "failure_reason": ctx.failure, "items_processed": ctx.items,
            "record": record, "finalize_failed": ctx.finalize_failed,
            "checkpoint": dict(ctx.cp),
            "execution_duration_ms": duration_ms,
            "detection_writes": [dict(w) for w in ctx.store.writes],
            "engine_metrics": ctx.engine.metrics.snapshot(),
            "provider": ctx.inner.snapshot(), "trace": list(ctx.trace)}
