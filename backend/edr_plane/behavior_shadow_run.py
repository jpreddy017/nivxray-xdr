"""The durable ENGINEERING record of one bounded Behavior shadow invocation.

This module records measurements. It evaluates nothing, reads no endpoint
evidence, constructs no engine, touches no checkpoint and writes no detection.

Three things it deliberately refuses to be:

1. **A detection.** It does not reuse `edr_behavior.store.DetectionStore`:
   detection identity, overlap and merge semantics have no meaning for an audit
   record, and letting them leak in would make a run record look like a finding.
2. **A verdict.** `COMPLETED` means *the bounded invocation finished*. It does
   NOT mean clean, benign, no-threat, or "nothing found" — see
   `COMPLETED_MEANING`. Nothing here may be promoted to a Fabric Finding, an
   analyst detection, an endpoint verdict or a response trigger.
3. **A quality claim.** There is no true/false-positive, precision, recall,
   accuracy or malicious/benign field, and supplying one is a refusal
   (`FORBIDDEN_FIELDS`).

G-3 (unsolved, stated truthfully): optimistic `revision` checking is NOT a
Mongo compare-and-set. `MongoShadowRunStore` gets atomicity from the server
(`replace_one` filtered on `revision`, plus the unique identity index);
`InMemoryShadowRunStore` only emulates it inside one process and advertises
`supports_atomic_cas = False`. A store that offers no conditional update cannot
provide CAS, and this module does not pretend otherwise.

G-4 (unsolved): eligibility of the first evidence after a NO_EVIDENCE frontier
initialization is not addressed here.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Protocol, Tuple

COLLECTION = "e3_behavior_shadow_runs"

# Additive index design only. This module never creates an index, and nothing
# here is applied to production.
INDEXES: List[Tuple[List[Tuple[str, int]], Dict[str, Any]]] = [
    ([("tenant_id", 1), ("shadow_run_id", 1)],
     {"unique": True, "name": "uniq_tenant_shadow_run"}),
]

STATE_STARTED = "STARTED"
STATE_COMPLETED = "COMPLETED"
STATE_TRUNCATED = "TRUNCATED"
STATE_INTERRUPTED = "INTERRUPTED"
STATE_FAILED = "FAILED"

STATES = (STATE_STARTED, STATE_COMPLETED, STATE_TRUNCATED, STATE_INTERRUPTED,
          STATE_FAILED)
TERMINAL_STATES = (STATE_COMPLETED, STATE_TRUNCATED, STATE_INTERRUPTED,
                   STATE_FAILED)
ALLOWED_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    STATE_STARTED: TERMINAL_STATES,
    STATE_COMPLETED: (), STATE_TRUNCATED: (), STATE_INTERRUPTED: (),
    STATE_FAILED: (),
}

# Carried on every record so no reader can infer a security conclusion.
COMPLETED_MEANING = "BOUNDED_SHADOW_INVOCATION_COMPLETED_ONLY"
DETECTION_SOURCE_CLAIM = "NONE"

REASONS = ("SYNTHETIC_VALIDATION", "OPERATOR_REQUESTED", "RULE_ADDED",
           "RULE_CHANGED", "CONTENT_CHANGED", "MANUAL")

OUTCOMES = ("MATCH", "NO_MATCH", "INSUFFICIENT_EVIDENCE", "BUDGET_EXCEEDED",
            "SUPPRESSED")

# Always materialised at zero so "we measured zero" is distinguishable from
# "we never measured".
COUNTERS = ("rows_read", "events_evaluated", "rules_evaluated", "matches",
            "skipped_observed_before_frontier", "duplicates_prevented",
            "concurrency_retries", "cross_tenant_reference_count",
            "matches_without_valid_evidence_refs", "engine_failures")

# Must stay explicitly measurable, and must stay zero for a safe shadow run.
ZERO_TARGET_COUNTERS = ("cross_tenant_reference_count",
                        "matches_without_valid_evidence_refs")

FORBIDDEN_FIELDS = ("true_positives", "false_positives", "true_negatives",
                    "false_negatives", "precision", "recall", "accuracy",
                    "f1", "malicious", "benign", "verdict", "severity",
                    "risk_score", "confidence", "threat_score")

REFUSED_IDENTITY = "SHADOW_RUN_IDENTITY_INVALID"
REFUSED_BINDING = "SHADOW_RUN_BINDING_INCOMPLETE"
REFUSED_REASON = "SHADOW_RUN_REASON_NOT_ALLOWED"
REFUSED_NOT_FOUND = "SHADOW_RUN_NOT_FOUND"
REFUSED_TENANT = "SHADOW_RUN_TENANT_MISMATCH_REFUSED"
REFUSED_DUPLICATE = "SHADOW_RUN_DUPLICATE_IDENTITY_REFUSED"
REFUSED_STATE = "SHADOW_RUN_STATE_UNKNOWN"
REFUSED_TRANSITION = "SHADOW_RUN_TRANSITION_REFUSED"
REFUSED_TERMINAL = "SHADOW_RUN_ALREADY_TERMINAL_REFUSED"
REFUSED_UNKNOWN_METRIC = "SHADOW_RUN_UNKNOWN_METRIC_REFUSED"
REFUSED_NEGATIVE_METRIC = "SHADOW_RUN_NEGATIVE_METRIC_REFUSED"
REFUSED_FORBIDDEN_METRIC = "SHADOW_RUN_QUALITY_CLAIM_REFUSED"
REFUSED_RESUME_REQUIRED = "SHADOW_RUN_RESUME_POSITION_REQUIRED"
REFUSED_RESUME_NOT_ALLOWED = "SHADOW_RUN_RESUME_POSITION_NOT_ALLOWED"
REFUSED_FAILURE_REASON = "SHADOW_RUN_FAILURE_REASON_REQUIRED"
REFUSED_MARKERS = "SHADOW_RUN_SHADOW_MARKERS_TAMPERED_REFUSED"


class ShadowRunRefused(RuntimeError):
    """A refusal with a named reason. Never a silent fallback."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class StaleShadowRun(ShadowRunRefused):
    """Optimistic-concurrency conflict on (tenant_id, shadow_run_id)."""

    def __init__(self) -> None:
        super().__init__("SHADOW_RUN_STALE_REVISION")


# ── store contract ───────────────────────────────────────────────────────

class ShadowRunStore(Protocol):
    supports_atomic_cas: bool

    async def get(self, tenant_id: str,
                  shadow_run_id: str) -> Optional[Dict[str, Any]]: ...

    async def put(self, doc: Dict[str, Any],
                  expected_revision: Optional[int]) -> int: ...


class InMemoryShadowRunStore:
    """Single-process emulation. See G-3: this is not Mongo CAS."""

    supports_atomic_cas = False

    def __init__(self) -> None:
        self._d: Dict[Tuple[str, str], Dict[str, Any]] = {}

    async def get(self, tenant_id, shadow_run_id):
        d = self._d.get((tenant_id, shadow_run_id))
        return copy.deepcopy(d) if d else None

    async def put(self, doc, expected_revision):
        k = (doc["tenant_id"], doc["shadow_run_id"])
        cur = self._d.get(k)
        if (cur["revision"] if cur else None) != expected_revision:
            if cur is not None and expected_revision is None:
                raise ShadowRunRefused(REFUSED_DUPLICATE)
            raise StaleShadowRun()
        new = copy.deepcopy(doc)
        new["revision"] = (expected_revision or 0) + 1
        self._d[k] = new
        return new["revision"]

    def all(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return [copy.deepcopy(d) for (t, _), d in sorted(self._d.items())
                if tenant_id is None or t == tenant_id]


class MongoShadowRunStore:
    """Motor-style collection. Conditional update is server-side; the unique
    identity index (design only, not created here) rejects concurrent inserts.
    """

    supports_atomic_cas = True

    def __init__(self, collection: Any) -> None:
        self._c = collection

    async def get(self, tenant_id, shadow_run_id):
        return await self._c.find_one(
            {"tenant_id": tenant_id, "shadow_run_id": shadow_run_id},
            {"_id": 0})

    async def put(self, doc, expected_revision):
        body = {k: v for k, v in doc.items() if k not in ("_id", "revision")}
        rev = (expected_revision or 0) + 1
        body["revision"] = rev
        if expected_revision is None:
            try:
                await self._c.insert_one(dict(body))
            except Exception as e:
                text = str(e).lower()
                if "duplicate key" in text or "e11000" in text:
                    raise ShadowRunRefused(REFUSED_DUPLICATE) from None
                raise
            return rev
        res = await self._c.replace_one(
            {"tenant_id": doc["tenant_id"],
             "shadow_run_id": doc["shadow_run_id"],
             "revision": expected_revision}, body)
        if getattr(res, "matched_count", 0) != 1:
            raise StaleShadowRun()
        return rev


# ── helpers ──────────────────────────────────────────────────────────────

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any, reason: str) -> str:
    s = str(value or "").strip()
    if not s:
        raise ShadowRunRefused(reason)
    return s


def _markers(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Shadow markers are set by this module, never by a caller."""
    doc["shadow"] = True
    doc["analyst_visible"] = False
    doc["detection_source_claim"] = DETECTION_SOURCE_CLAIM
    doc["completed_meaning"] = COMPLETED_MEANING
    return doc


def _assert_markers(doc: Mapping[str, Any]) -> None:
    if (doc.get("shadow") is not True or doc.get("analyst_visible") is not False
            or doc.get("detection_source_claim") != DETECTION_SOURCE_CLAIM):
        raise ShadowRunRefused(REFUSED_MARKERS)


def _deltas(values: Optional[Mapping[str, Any]], allowed: Tuple[str, ...],
            closed: bool) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for name, n in (values or {}).items():
        key = str(name)
        if key in FORBIDDEN_FIELDS:
            raise ShadowRunRefused(REFUSED_FORBIDDEN_METRIC)
        if closed and key not in allowed:
            raise ShadowRunRefused(REFUSED_UNKNOWN_METRIC)
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise ShadowRunRefused(REFUSED_NEGATIVE_METRIC)
        out[key] = n
    return out


def _measure(doc: Dict[str, Any], counters, outcomes, adapter_refusals,
             execution_duration_ms, evidence_lag_ms, window_truncated) -> None:
    for name, n in _deltas(counters, COUNTERS, True).items():
        doc["counters"][name] = int(doc["counters"][name]) + n
    for name, n in _deltas(outcomes, OUTCOMES, True).items():
        doc["outcome_counts"][name] = int(doc["outcome_counts"][name]) + n
    for name, n in _deltas(adapter_refusals, (), False).items():
        doc["adapter_refusals"][name] = \
            int(doc["adapter_refusals"].get(name, 0)) + n
    for field, value in (("execution_duration_ms", execution_duration_ms),
                         ("evidence_lag_ms", evidence_lag_ms)):
        if value is None:
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ShadowRunRefused(REFUSED_NEGATIVE_METRIC)
        doc[field] = value
    if window_truncated is not None:
        doc["window_truncated"] = bool(window_truncated)


# ── create / read / update / finalize ────────────────────────────────────

async def create(store: Any, *, tenant_id: str, shadow_run_id: str,
                 endpoint_id: str, ruleset_id: str, ruleset_version: Any,
                 ruleset_content_hash: str, replay_id: str, invoked_by: str,
                 reason: str, started_at: Optional[datetime] = None,
                 now: Optional[datetime] = None) -> Dict[str, Any]:
    """One STARTED record. Nothing is evaluated and no evidence is read."""
    tenant = _text(tenant_id, REFUSED_IDENTITY)
    run_id = _text(shadow_run_id, REFUSED_IDENTITY)
    if reason not in REASONS:
        raise ShadowRunRefused(REFUSED_REASON)
    started = _iso(started_at or now or datetime.now(timezone.utc))

    doc: Dict[str, Any] = {
        "tenant_id": tenant,
        "shadow_run_id": run_id,
        "endpoint_id": _text(endpoint_id, REFUSED_BINDING),
        "ruleset_id": _text(ruleset_id, REFUSED_BINDING),
        "ruleset_version": ruleset_version,
        "ruleset_content_hash": _text(ruleset_content_hash, REFUSED_BINDING),
        "replay_id": _text(replay_id, REFUSED_BINDING),
        "invoked_by": _text(invoked_by, REFUSED_BINDING),
        "reason": reason,
        "started_at": started,
        "completed_at": None,
        "state": STATE_STARTED,
        "failure_reason": None,
        "counters": {name: 0 for name in COUNTERS},
        "outcome_counts": {name: 0 for name in OUTCOMES},
        "adapter_refusals": {},
        "window_truncated": False,
        "execution_duration_ms": 0,
        "evidence_lag_ms": None,
        "resume_after_time": None,
        "resume_after_key": None,
        "revision": 0,
    }
    if ruleset_version is None:
        raise ShadowRunRefused(REFUSED_BINDING)
    doc["revision"] = await store.put(_markers(doc), None)
    return doc


async def read(store: Any, *, tenant_id: str,
               shadow_run_id: str) -> Dict[str, Any]:
    """A record, or a refusal. Reads are tenant-keyed AND tenant-verified."""
    doc = await store.get(_text(tenant_id, REFUSED_IDENTITY),
                          _text(shadow_run_id, REFUSED_IDENTITY))
    if not doc:
        raise ShadowRunRefused(REFUSED_NOT_FOUND)
    if doc.get("tenant_id") != tenant_id:
        raise ShadowRunRefused(REFUSED_TENANT)
    _assert_markers(doc)
    return dict(doc)


async def update(store: Any, *, tenant_id: str, shadow_run_id: str,
                 expected_revision: Optional[int] = None,
                 counters: Optional[Mapping[str, int]] = None,
                 outcomes: Optional[Mapping[str, int]] = None,
                 adapter_refusals: Optional[Mapping[str, int]] = None,
                 execution_duration_ms: Optional[int] = None,
                 evidence_lag_ms: Optional[int] = None,
                 window_truncated: Optional[bool] = None) -> Dict[str, Any]:
    """Accumulate measurements on a STARTED run. Terminal runs are immutable."""
    doc = await read(store, tenant_id=tenant_id, shadow_run_id=shadow_run_id)
    if doc["state"] != STATE_STARTED:
        raise ShadowRunRefused(REFUSED_TERMINAL)
    if expected_revision is not None and \
            int(doc.get("revision") or 0) != int(expected_revision):
        raise StaleShadowRun()
    _measure(doc, counters, outcomes, adapter_refusals, execution_duration_ms,
             evidence_lag_ms, window_truncated)
    doc["revision"] = await store.put(_markers(doc), int(doc["revision"]))
    return doc


async def finalize(store: Any, *, tenant_id: str, shadow_run_id: str,
                   state: str, expected_revision: Optional[int] = None,
                   completed_at: Optional[datetime] = None,
                   failure_reason: Optional[str] = None,
                   resume_after_time: Optional[datetime] = None,
                   resume_after_key: Optional[str] = None,
                   counters: Optional[Mapping[str, int]] = None,
                   outcomes: Optional[Mapping[str, int]] = None,
                   adapter_refusals: Optional[Mapping[str, int]] = None,
                   execution_duration_ms: Optional[int] = None,
                   evidence_lag_ms: Optional[int] = None,
                   now: Optional[datetime] = None) -> Dict[str, Any]:
    """Close the run in exactly one terminal state.

    `COMPLETED` asserts only that the bounded invocation finished; it carries
    no clean/benign/no-threat meaning, and a run with zero matches is still
    just a run with zero matches.
    """
    if state not in STATES:
        raise ShadowRunRefused(REFUSED_STATE)
    doc = await read(store, tenant_id=tenant_id, shadow_run_id=shadow_run_id)
    if state not in ALLOWED_TRANSITIONS.get(doc["state"], ()):
        raise ShadowRunRefused(
            REFUSED_TERMINAL if doc["state"] in TERMINAL_STATES
            else REFUSED_TRANSITION)
    if expected_revision is not None and \
            int(doc.get("revision") or 0) != int(expected_revision):
        raise StaleShadowRun()
    if state == STATE_FAILED and not str(failure_reason or "").strip():
        raise ShadowRunRefused(REFUSED_FAILURE_REASON)

    has_resume = resume_after_time is not None and \
        bool(str(resume_after_key or "").strip())
    if state == STATE_TRUNCATED and not has_resume:
        raise ShadowRunRefused(REFUSED_RESUME_REQUIRED)
    if state == STATE_COMPLETED and (resume_after_time is not None
                                     or resume_after_key is not None):
        raise ShadowRunRefused(REFUSED_RESUME_NOT_ALLOWED)

    _measure(doc, counters, outcomes, adapter_refusals, execution_duration_ms,
             evidence_lag_ms, state == STATE_TRUNCATED or None)
    doc["state"] = state
    doc["completed_at"] = _iso(completed_at or now or
                               datetime.now(timezone.utc))
    doc["failure_reason"] = str(failure_reason).strip() if failure_reason \
        else None
    if has_resume:
        doc["resume_after_time"] = _iso(resume_after_time)
        doc["resume_after_key"] = str(resume_after_key).strip()
    doc["revision"] = await store.put(_markers(doc), int(doc["revision"]))
    return doc


def zero_targets_held(doc: Mapping[str, Any]) -> bool:
    """The two counters that must be zero for a run to be considered safe."""
    counters = doc.get("counters") or {}
    return all(int(counters.get(name, -1)) == 0
               for name in ZERO_TARGET_COUNTERS)
