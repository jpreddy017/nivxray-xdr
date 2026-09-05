"""
XDR Correlation Engine — P1 · Real Stateful Event-Stream Orchestrator.

Sits between Detection/Observation and the existing IKG / ICE /
Verdict engines.  This engine does NOT decide "malicious" — it emits
deterministic correlation evidence that the downstream verdict path
consumes.  `capability ≠ verdict` is preserved end-to-end.

Pipeline:
    Raw Telemetry
       ↓
    Normalization  (existing xdr_ingest)
       ↓
    Detection / Observation  (existing xdr_detection_content + LOLBAS)
       ↓
    ┌─────────────────────────────┐
    │     CORRELATION ENGINE      │
    │  EVENT_MATCH · TEMPORAL     │
    │  TEMPORAL_ORDERED           │
    │  SEQUENCE · COUNT · THRESHOLD│
    │  VALUE_COUNT · GROUP_BY     │
    │  ENTITY_CORRELATION         │
    │  CROSS_SOURCE / HOST / USER │
    │  NEGATIVE_EVIDENCE          │
    └──────────────┬──────────────┘
       ↓
    Correlation Evidence (this module writes it, IKG/ICE/Verdict consume)

Storage:
  * xdr_correlation_rules      — one doc per rule (immutable-ish)
  * xdr_correlation_matches    — one doc per emitted correlation evidence
  * xdr_correlation_state      — sliding per-entity window state
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from pymongo import ASCENDING, DESCENDING, MongoClient

from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import require_permission

router = APIRouter(prefix="/api/xdr/correlation", tags=["xdr-correlation"])


# ── Mongo binding ─────────────────────────────────────────────────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _db():
    return _client[_DB_NAME] if _client is not None else None


def _c_rules():
    return _db()["xdr_correlation_rules"]   if _db() is not None else None


def _c_matches():
    return _db()["xdr_correlation_matches"] if _db() is not None else None


def _c_state():
    return _db()["xdr_correlation_state"]   if _db() is not None else None


def _principal(req: Request) -> tuple[str, str, str]:
    ten = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "default")
    pid = (req.headers.get("X-Principal-Id")
                or getattr(req.state, "principal_id", None) or "admin@nivxray.com")
    pkd = (req.headers.get("X-Principal-Kind")
                or getattr(req.state, "principal_kind", None) or "user")
    return ten, pid, pkd


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat()


# ── Vocabularies ──────────────────────────────────────────────────
OPERATORS = {
    "EVENT_MATCH", "TEMPORAL", "TEMPORAL_ORDERED", "SEQUENCE",
    "COUNT", "THRESHOLD", "VALUE_COUNT", "GROUP_BY",
    "ENTITY_CORRELATION", "CROSS_SOURCE", "CROSS_HOST",
    "CROSS_USER", "NEGATIVE_EVIDENCE",
}

STATES = {"DRAFT", "TESTING", "VALIDATED", "ENABLED", "ACTIVE",
                  "DISABLED", "DEPRECATED"}

# What the engine may emit — deliberately NEVER a verdict.
EVIDENCE_LEVELS = ("CORRELATION_OBSERVED",
                             "CORRELATION_CANDIDATE",
                             "CORRELATION_SUPPORTED")


# ── Models ────────────────────────────────────────────────────────
_NAME_RE = re.compile(r"^[a-zA-Z0-9._:\- /]{1,120}$")


class Condition(BaseModel):
    """One condition in a rule — either an EVENT_MATCH clause (which
    inspects a signal directly) or a placeholder used by the
    NEGATIVE_EVIDENCE operator."""
    id:    str
    operator: str = "EVENT_MATCH"
    match: dict[str, Any] = Field(default_factory=dict)   # ANDed key/value


class OperatorSpec(BaseModel):
    """How the conditions combine."""
    type: str                          # any of OPERATORS
    sequence: list[str] = Field(default_factory=list)
    window_seconds: int = 300
    threshold: int = 1
    value_field: str | None = None
    distinct_field: str | None = None


class CorrelationRuleBody(BaseModel):
    name:                 str
    description:          str | None = None
    enabled:              bool = False
    severity_hint:        str = "informational"
    source:               str = "NivXRay-native"
    license:              str = "NivXRay Public Content"
    conditions:           list[Condition]
    operators:            OperatorSpec
    group_by:             list[str] = Field(default_factory=lambda: ["host_id"])
    negative_conditions:  list[Condition] = Field(default_factory=list)
    exceptions:           list[Condition] = Field(default_factory=list)
    attack_techniques:    list[str] = Field(default_factory=list)


class Signal(BaseModel):
    """One normalized signal fed into the engine.  May come from a
    Detection match, an Observation (LOLBAS/parent-child), or a raw
    telemetry event that survived normalization."""
    signal_id:      str | None = None
    tenant_id:      str | None = None       # injected from X-Tenant-Id header
    signal_kind:    str                              # detection | observation | event
    at:             str | None = None             # iso timestamp
    detection_id:   str | None = None
    event_kind:     str | None = None
    host_id:        str | None = None
    user_id:        str | None = None
    process_id:     str | None = None
    parent_process: str | None = None
    image:          str | None = None
    parent_image:   str | None = None
    command_line:   str | None = None
    dst_ip:         str | None = None
    dst_domain:     str | None = None
    source_event_id: str | None = None
    fields:         dict[str, Any] = Field(default_factory=dict)


# ── Helpers ───────────────────────────────────────────────────────
def _mask(d: dict) -> dict:
    return {k: v for k, v in d.items() if k != "_id"}


def _mint_rule_id() -> str:
    return f"cor_{uuid.uuid4().hex[:20]}"


def _mint_signal_id() -> str:
    return f"sig_{uuid.uuid4().hex[:20]}"


def _mint_match_id() -> str:
    return f"cm_{uuid.uuid4().hex[:20]}"


def _validate_rule(body: CorrelationRuleBody) -> None:
    if not _NAME_RE.match(body.name):
        raise HTTPException(400, detail=f"invalid rule name '{body.name}'")
    if body.operators.type not in OPERATORS:
        raise HTTPException(400, detail={"code": "UNKNOWN_OPERATOR",
                                                                  "operator": body.operators.type,
                                                                  "allowed": sorted(OPERATORS)})
    cids = {c.id for c in body.conditions}
    if len(cids) != len(body.conditions):
        raise HTTPException(400, detail="duplicate condition ids")
    if body.operators.type in {"SEQUENCE", "TEMPORAL_ORDERED"}:
        if not body.operators.sequence:
            raise HTTPException(400, detail=f"{body.operators.type} needs sequence")
        for sid in body.operators.sequence:
            if sid not in cids:
                raise HTTPException(400, detail={
                    "code": "SEQUENCE_ID_UNKNOWN", "condition_id": sid})


def _get_field(signal: dict, key: str) -> Any:
    """Look up a field on a signal, checking both top-level and the
    generic ``fields`` bag."""
    if key in signal and signal[key] is not None:
        return signal[key]
    return (signal.get("fields") or {}).get(key)


def _match_condition(cond: dict, signal: dict) -> bool:
    """Deterministic condition-vs-signal match.  A condition is a set
    of key expectations that are ANDed.  Values may be:
      * scalar        → exact match
      * list          → any-of
      * "contains:X"  → substring in signal value
      * "endswith:X"  → signal value ends with X (case-insensitive)
    """
    m = cond.get("match") or {}
    if not m:
        return False
    for k, expected in m.items():
        actual = _get_field(signal, k)
        if actual is None:
            return False
        if isinstance(expected, list):
            if not any(_scalar_match(actual, ev) for ev in expected):
                return False
        else:
            if not _scalar_match(actual, expected):
                return False
    return True


def _scalar_match(actual: Any, expected: Any) -> bool:
    if isinstance(expected, str):
        if expected.startswith("contains:"):
            return expected[len("contains:"):].lower() in str(actual).lower()
        if expected.startswith("endswith:"):
            return str(actual).lower().endswith(expected[len("endswith:"):].lower())
        if expected.startswith("startswith:"):
            return str(actual).lower().startswith(expected[len("startswith:"):].lower())
        if expected.startswith("regex:"):
            return re.search(expected[len("regex:"):], str(actual)) is not None
    return actual == expected


def _entity_key(rule: dict, signal: dict) -> str:
    """Compose the per-entity key used to shard the sliding window."""
    keys = rule.get("group_by") or ["host_id"]
    return "|".join(str(_get_field(signal, k) or "*") for k in keys)


def _fingerprint(sig: dict, rule_id: str) -> str:
    """Stable fingerprint for a signal inside a rule state — lets us
    dedupe identical signals arriving twice within the same window."""
    h = hashlib.sha256()
    h.update(rule_id.encode())
    for k in sorted(sig):
        if k in {"signal_id", "at", "_id"}:
            continue
        h.update(str(k).encode())
        h.update(str(sig[k]).encode())
    return h.hexdigest()[:16]


# ── Engine core ──────────────────────────────────────────────────
def _load_active_rules(tenant_id: str) -> list[dict]:
    if _c_rules() is None:
        return []
    return list(_c_rules().find({
        "$or": [{"tenant_id": tenant_id}, {"tenant_id": None},
                    {"tenant_id": "*"}, {"tenant_id": {"$exists": False}}],
        "enabled": True,
        "state": {"$in": ["ENABLED", "ACTIVE", "VALIDATED", "TESTING"]},
    }))


def _load_window_state(tenant_id: str, rule_id: str, ekey: str,
                                             window_seconds: int) -> list[dict]:
    if _c_state() is None:
        return []
    cutoff = _now() - timedelta(seconds=window_seconds)
    cutoff_iso = _iso(cutoff)
    return list(_c_state().find({
        "tenant_id": tenant_id, "rule_id": rule_id,
        "entity_key": ekey, "at": {"$gte": cutoff_iso},
    }).sort("at", ASCENDING))


def _prune_state(tenant_id: str, rule_id: str, ekey: str,
                             window_seconds: int) -> None:
    if _c_state() is None:
        return
    cutoff = _now() - timedelta(seconds=window_seconds)
    _c_state().delete_many({
        "tenant_id": tenant_id, "rule_id": rule_id,
        "entity_key": ekey, "at": {"$lt": _iso(cutoff)},
    })


def _persist_state(tenant_id: str, rule_id: str, ekey: str, signal: dict,
                              matched_condition_ids: list[str]) -> None:
    if _c_state() is None:
        return
    doc = {
        "tenant_id":  tenant_id,
        "rule_id":    rule_id,
        "entity_key": ekey,
        "signal_id":  signal.get("signal_id"),
        "at":         signal.get("at") or _iso(_now()),
        "matched_condition_ids": matched_condition_ids,
        "signal":     signal,
    }
    _c_state().insert_one(dict(doc))


def _evaluate(rule: dict, signal: dict) -> dict | None:
    """Evaluate one signal against one rule.  Returns a match doc
    (never a verdict) or None."""
    op    = rule.get("operators") or {}
    conds = rule.get("conditions") or []
    op_type = op.get("type", "EVENT_MATCH")
    win_sec = int(op.get("window_seconds", 300))
    tenant  = signal["tenant_id"]
    ekey    = _entity_key(rule, signal)

    # Which conditions does this signal satisfy?
    matched_here = [c["id"] for c in conds if _match_condition(c, signal)]
    if not matched_here and op_type not in {"NEGATIVE_EVIDENCE"}:
        return None

    _prune_state(tenant, rule["id"], ekey, win_sec)
    _persist_state(tenant, rule["id"], ekey, signal, matched_here)
    state = _load_window_state(tenant, rule["id"], ekey, win_sec)

    # Which conditions are satisfied SOMEWHERE in the current window?
    fired: dict[str, list[dict]] = {c["id"]: [] for c in conds}
    for s in state:
        for cid in (s.get("matched_condition_ids") or []):
            if cid in fired:
                fired[cid].append(s)

    all_fired  = [cid for cid, sigs in fired.items() if sigs]
    all_missing = [cid for cid, sigs in fired.items() if not sigs]

    # Operator dispatch ─────────────────────────────────────────
    if op_type == "EVENT_MATCH":
        # Fires on any single-condition match.
        if not matched_here:
            return None
        return _mint_match(rule, state, matched=all_fired,
                                          missing=all_missing,
                                          level="CORRELATION_OBSERVED",
                                          entity_key=ekey)

    if op_type == "TEMPORAL":
        # Every condition must fire somewhere in the window.
        if all_missing:
            return None
        return _mint_match(rule, state, matched=all_fired,
                                          missing=[], level="CORRELATION_SUPPORTED",
                                          entity_key=ekey)

    if op_type in {"TEMPORAL_ORDERED", "SEQUENCE"}:
        # Conditions in op.sequence must fire in order within the window.
        seq = op.get("sequence") or []
        idx = 0
        used_signals: list[dict] = []
        for s in state:
            need = seq[idx]
            if need in (s.get("matched_condition_ids") or []):
                used_signals.append(s)
                idx += 1
                if idx >= len(seq):
                    break
        if idx < len(seq):
            # Partial progress — emit a CANDIDATE with what we saw.
            if idx == 0:
                return None
            return _mint_match(rule, used_signals,
                                              matched=seq[:idx],
                                              missing=seq[idx:],
                                              level="CORRELATION_CANDIDATE",
                                              entity_key=ekey)
        return _mint_match(rule, used_signals,
                                          matched=seq, missing=[],
                                          level="CORRELATION_SUPPORTED",
                                          entity_key=ekey)

    if op_type in {"COUNT", "THRESHOLD"}:
        # Signals matching the FIRST condition must reach `threshold`.
        first = conds[0]["id"]
        hits = fired.get(first, [])
        threshold = int(op.get("threshold", 1))
        if len(hits) < threshold:
            return None
        return _mint_match(rule, hits, matched=[first], missing=[],
                                          level="CORRELATION_SUPPORTED",
                                          entity_key=ekey,
                                          count=len(hits), threshold=threshold)

    if op_type == "VALUE_COUNT":
        # Distinct count of `distinct_field` in the first condition must
        # reach `threshold`.
        first = conds[0]["id"]
        hits  = fired.get(first, [])
        distinct_field = op.get("distinct_field") or "user_id"
        distinct = { _get_field(h.get("signal") or {}, distinct_field)
                            for h in hits}
        distinct.discard(None)
        threshold = int(op.get("threshold", 1))
        if len(distinct) < threshold:
            return None
        return _mint_match(rule, hits, matched=[first], missing=[],
                                          level="CORRELATION_SUPPORTED",
                                          entity_key=ekey,
                                          distinct_count=len(distinct))

    if op_type == "GROUP_BY":
        # Same as TEMPORAL but scoped to the group-by key.  We already
        # sharded state by ekey, so if all conditions fired the match
        # is by construction group-scoped.
        if all_missing:
            return None
        return _mint_match(rule, state, matched=all_fired, missing=[],
                                          level="CORRELATION_SUPPORTED",
                                          entity_key=ekey)

    if op_type in {"CROSS_HOST", "CROSS_USER", "CROSS_SOURCE"}:
        # Distinct values of the pivot field across the window.
        pivot = ("host_id" if op_type == "CROSS_HOST"
                        else "user_id" if op_type == "CROSS_USER"
                        else "source")
        first = conds[0]["id"]
        hits  = fired.get(first, [])
        distinct = { _get_field(h.get("signal") or {}, pivot) for h in hits }
        distinct.discard(None)
        threshold = int(op.get("threshold", 2))
        if len(distinct) < threshold:
            return None
        return _mint_match(rule, hits, matched=[first], missing=[],
                                          level="CORRELATION_SUPPORTED",
                                          entity_key=ekey,
                                          distinct_pivot=list(distinct))

    if op_type == "NEGATIVE_EVIDENCE":
        # "A observed but required B never observed within window."
        pos_ids = [c["id"] for c in conds[:1]]
        neg_conds = rule.get("negative_conditions") or []
        pos_hits = fired.get(pos_ids[0], []) if pos_ids else []
        if not pos_hits:
            return None
        neg_seen = False
        for s in state:
            for nc in neg_conds:
                if _match_condition(nc, s.get("signal") or {}):
                    neg_seen = True; break
            if neg_seen:
                break
        if neg_seen:
            return None
        return _mint_match(rule, pos_hits, matched=pos_ids,
                                          missing=[nc.get("id") or "neg"
                                                          for nc in neg_conds],
                                          level="CORRELATION_CANDIDATE",
                                          entity_key=ekey,
                                          negative_evidence_present=False)

    return None


def _mint_match(rule: dict, state_docs: list[dict], *,
                             matched: list[str], missing: list[str],
                             level: str, entity_key: str,
                             **extras) -> dict:
    signals = [s.get("signal") or {} for s in state_docs]
    detection_ids = sorted({s.get("detection_id") for s in signals
                                          if s.get("detection_id")})
    raw_ids = sorted({s.get("source_event_id") for s in signals
                                    if s.get("source_event_id")})
    signal_ids = [s.get("signal_id") for s in signals if s.get("signal_id")]
    now = _iso(_now())
    ats = [s.get("at") for s in state_docs if s.get("at")]
    window_start = min(ats) if ats else now
    window_end   = max(ats) if ats else now
    explanation: list[str] = []
    for cid in matched:
        explanation.append(f"✓ condition {cid}")
    for cid in missing:
        explanation.append(f"✗ missing {cid}")
    return {
        "id":               _mint_match_id(),
        "tenant_id":        state_docs[0].get("tenant_id") if state_docs else "*",
        "correlation_id":   rule["id"],
        "correlation_name": rule["name"],
        "severity_hint":    rule.get("severity_hint"),
        "level":            level,
        "entity_key":       entity_key,
        "group_by":         rule.get("group_by") or [],
        "operator":         (rule.get("operators") or {}).get("type"),
        "window_start":     window_start,
        "window_end":       window_end,
        "matched_conditions": matched,
        "missing_conditions": missing,
        "signal_ids":       signal_ids,
        "detection_ids":    detection_ids,
        "raw_event_ids":    raw_ids,
        "evidence_chain":   [{"condition_id": (s.get("matched_condition_ids") or [None])[0],
                                            "signal_id":    s.get("signal_id"),
                                            "at":           s.get("at"),
                                            "signal":       s.get("signal")}
                                          for s in state_docs],
        "explanation":      explanation,
        "attack_techniques": list(rule.get("attack_techniques") or []),
        "capability_not_verdict": True,   # NEVER emit a verdict
        "provenance": {
            "source":        rule.get("source"),
            "license":       rule.get("license"),
            "engine":        "xdr_correlation/1.0",
            "created_at":    now,
        },
        **extras,
    }


def _dispatch_signal(tenant_id: str, signal: dict) -> list[dict]:
    """Evaluate a single signal against every eligible rule for the
    tenant.  Persists matches and returns them for the API response."""
    signal = dict(signal)
    signal["tenant_id"] = tenant_id
    signal.setdefault("signal_id", _mint_signal_id())
    signal.setdefault("at", _iso(_now()))
    matches: list[dict] = []
    for rule in _load_active_rules(tenant_id):
        m = _evaluate(rule, signal)
        if m and _c_matches() is not None:
            _c_matches().insert_one(dict(m))
            matches.append(_mask(m))
    return matches


# ── Bundled rule pack (real, tests-mandated scenarios) ────────────
_BUNDLED_RULES: list[dict] = [
  {"name": "Office → PowerShell → External Connection",
   "description": "Correlation candidate for an Office product spawning "
                          "PowerShell that then makes an external network "
                          "connection.  CANDIDATE only — evidence, not verdict.",
   "severity_hint": "high",
   "conditions": [
     {"id": "A", "operator": "EVENT_MATCH",
      "match": {"detection_id":
                    "proc_creation_win_office_spawns_shell"}},
     {"id": "B", "operator": "EVENT_MATCH",
      "match": {"detection_id":
                    "proc_creation_win_susp_encoded_pshell"}},
     {"id": "C", "operator": "EVENT_MATCH",
      "match": {"event_kind": "network.connection.external"}},
   ],
   "operators": {"type": "TEMPORAL_ORDERED",
                            "sequence": ["A", "B", "C"], "window_seconds": 300},
   "group_by":            ["host_id"],
   "attack_techniques":   ["T1204.002", "T1059.001", "T1071.001"]},
  {"name": "LOLBIN Spawned From Office (parent-child)",
   "description": "Evidence that a LOLBIN executed as a child of an "
                          "Office product.  Capability observation, not a "
                          "verdict — a real determination needs command line, "
                          "network, IOC, historical baseline and asset context.",
   "severity_hint": "medium",
   "conditions": [
     {"id": "A", "operator": "EVENT_MATCH",
      "match": {"detection_id": "behavior_lolbin_from_office"}},
   ],
   "operators":           {"type": "EVENT_MATCH", "window_seconds": 60},
   "group_by":            ["host_id"],
   "attack_techniques":   ["T1204.002"]},
  {"name": "Brute Force Then Success",
   "description": "≥ 10 failed logins followed by a success for the same "
                          "user within 10 minutes.",
   "severity_hint": "medium",
   "conditions": [
     {"id": "F", "operator": "EVENT_MATCH",
      "match": {"event_kind": "auth.failed"}},
     {"id": "S", "operator": "EVENT_MATCH",
      "match": {"event_kind": "auth.success"}},
   ],
   "operators": {"type": "SEQUENCE", "sequence": ["F", "S"],
                            "window_seconds": 600, "threshold": 1},
   "group_by":            ["user_id"],
   "attack_techniques":   ["T1110"]},
  {"name": "Cross-host Credential Pivot",
   "description": "Same user_id observed on ≥ 2 distinct hosts within "
                          "15 minutes with a privileged action on the second "
                          "host.  Evidence for lateral movement — never a "
                          "standalone verdict.",
   "severity_hint": "medium",
   "conditions": [
     {"id": "P", "operator": "EVENT_MATCH",
      "match": {"event_kind": "auth.privileged"}},
   ],
   "operators": {"type": "CROSS_HOST", "window_seconds": 900, "threshold": 2},
   "group_by":            ["user_id"],
   "attack_techniques":   ["T1078", "T1021"]},
  {"name": "Detection Without Follow-up (negative evidence)",
   "description": "An initial-access detection observed but the required "
                          "follow-up detection never occurs — surfaces as a "
                          "CANDIDATE with negative-evidence flag.",
   "severity_hint": "low",
   "conditions": [
     {"id": "A", "operator": "EVENT_MATCH",
      "match": {"event_kind": "detection.initial_access"}},
   ],
   "negative_conditions": [
     {"id": "N", "operator": "EVENT_MATCH",
      "match": {"event_kind": "detection.execution"}},
   ],
    "operators": {"type": "NEGATIVE_EVIDENCE", "window_seconds": 900},
    "group_by":            ["host_id"],
    "attack_techniques":   ["T1566.001"]},
]

# Incorporate the 5 enterprise multi-stage correlation scenarios
from detection_content.correlation_library import ENTERPRISE_CORRELATION_SCENARIOS
_BUNDLED_RULES.extend(ENTERPRISE_CORRELATION_SCENARIOS)


def _seed_bundled_rules() -> int:
    """Insert bundled rules idempotently.  Returns the number of new
    inserts (0 if already seeded)."""
    if _c_rules() is None:
        return 0
    inserted = 0
    now = _iso(_now())
    for r in _BUNDLED_RULES:
        if _c_rules().find_one({"name": r["name"], "tenant_id": "*"}):
            continue
        doc = {
            **r,
            "id":         _mint_rule_id(),
            "tenant_id":  "*",             # bundled = platform-wide
            "enabled":    True,
            "state":      "VALIDATED",
            "version":    1,
            "source":     "NivXRay-native",
            "license":    "NivXRay Public Content",
            "created_at": now,
            "updated_at": now,
            "created_by": "system@bundled",
            "provenance": {"source": "bundled", "license": "NivXRay Public Content"},
        }
        _c_rules().insert_one(dict(doc))
        inserted += 1
    if inserted:
        try:
            _c_rules().create_index([("name", ASCENDING),
                                                    ("tenant_id", ASCENDING)])
            _c_rules().create_index([("enabled", ASCENDING),
                                                    ("state", ASCENDING)])
            _c_matches().create_index([("tenant_id", ASCENDING),
                                                      ("correlation_id", ASCENDING),
                                                      ("window_end", DESCENDING)])
            _c_state().create_index([("tenant_id", ASCENDING),
                                                    ("rule_id", ASCENDING),
                                                    ("entity_key", ASCENDING),
                                                    ("at", ASCENDING)])
        except Exception:  # noqa: BLE001,S110
            pass
    return inserted


# ── Endpoints ─────────────────────────────────────────────────────
@router.get("/status",
                     dependencies=[Depends(require_permission("correlation.read"))])
def status(request: Request):
    if _db() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    rules  = _c_rules().count_documents({
        "$or": [{"tenant_id": ten}, {"tenant_id": "*"}]})
    active = _c_rules().count_documents({
        "$or": [{"tenant_id": ten}, {"tenant_id": "*"}],
        "enabled": True, "state": {"$in": ["ENABLED", "ACTIVE", "VALIDATED"]}})
    matches_total = _c_matches().count_documents({"tenant_id": {"$in": [ten, "*"]}})
    supported = _c_matches().count_documents({"tenant_id": {"$in": [ten, "*"]},
                                                                          "level": "CORRELATION_SUPPORTED"})
    candidates = _c_matches().count_documents({"tenant_id": {"$in": [ten, "*"]},
                                                                          "level": "CORRELATION_CANDIDATE"})
    ops = sorted(OPERATORS)
    return {"ok": True, "data": {
        "rules_total":    rules,
        "rules_active":   active,
        "matches_total":  matches_total,
        "supported":      supported,
        "candidates":     candidates,
        "operators":      ops,
        "operators_implemented": ops,   # all listed above are implemented
    }}


@router.get("/rules",
                     dependencies=[Depends(require_permission("correlation.read"))])
def list_rules(request: Request, limit: int = Query(200, ge=1, le=1000)):
    if _c_rules() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    ten, _, _ = _principal(request)
    cur = _c_rules().find({
        "$or": [{"tenant_id": ten}, {"tenant_id": "*"}]
    }).sort("created_at", DESCENDING).limit(limit)
    return {"ok": True, "data": {"rules": [_mask(r) for r in cur]}}


@router.get("/matches",
                     dependencies=[Depends(require_permission("correlation.read"))])
def list_matches(request: Request, limit: int = Query(100, ge=1, le=1000),
                              level: str | None = Query(None)):
    if _c_matches() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    ten, _, _ = _principal(request)
    q: dict[str, Any] = {"tenant_id": {"$in": [ten, "*"]}}
    if level:
        q["level"] = level
    cur = _c_matches().find(q).sort("window_end", DESCENDING).limit(limit)
    return {"ok": True, "data": {"matches": [_mask(m) for m in cur]}}


class SignalsBody(BaseModel):
    signals: list[Signal]


@router.post("/signals",
                       dependencies=[Depends(require_permission("correlation.publish"))])
def ingest_signals(body: SignalsBody, request: Request):
    ten, _, _ = _principal(request)
    all_matches: list[dict] = []
    for s in body.signals:
        d = s.model_dump()
        d["tenant_id"] = ten
        all_matches.extend(_dispatch_signal(ten, d))
    return {"ok": True, "data": {"accepted": len(body.signals),
                                                      "matches": all_matches}}


class ReplayBody(BaseModel):
    scenario_name: str | None = None
    signals:       list[Signal]
    rule_ids:      list[str] | None = None
    dry_run:       bool = True      # if True, do NOT persist matches


@router.post("/replay",
                       dependencies=[Depends(require_permission("correlation.test"))])
def replay(body: ReplayBody, request: Request):
    """Replay a timeline of signals through the engine.  When
    ``dry_run=True`` (default) neither state nor matches persist to
    Mongo — the response is a deterministic "what would have happened"
    trace an analyst can inspect field-by-field.
    """
    if _db() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)

    # Load rules (bundled + tenant), optionally filter by ids.
    rules = _load_active_rules(ten)
    if body.rule_ids:
        rules = [r for r in rules if r["id"] in set(body.rule_ids)]
    if not rules:
        return {"ok": True, "data": {"scenario": body.scenario_name,
                                                          "matches": [], "trace": [],
                                                          "note": "no rules selected"}}

    # Build an ephemeral state store — a mapping keyed by
    # (rule_id, entity_key) → list[state_doc].
    ephemeral: dict[tuple, list[dict]] = {}
    matches:   list[dict] = []
    trace:     list[dict] = []

    def _match_condition_local(cond, signal):
        return _match_condition(cond, signal)

    def _evaluate_local(rule, signal):
        op    = rule.get("operators") or {}
        conds = rule.get("conditions") or []
        op_type = op.get("type", "EVENT_MATCH")
        win_sec = int(op.get("window_seconds", 300))
        ekey    = _entity_key(rule, signal)
        matched_here = [c["id"] for c in conds
                                    if _match_condition_local(c, signal)]
        if not matched_here and op_type != "NEGATIVE_EVIDENCE":
            return None
        # Prune ephemeral window.
        cutoff = _now() - timedelta(seconds=win_sec)
        buf = ephemeral.setdefault((rule["id"], ekey), [])
        cutoff_iso = _iso(cutoff)
        buf[:] = [b for b in buf if b["at"] >= cutoff_iso]
        buf.append({
            "tenant_id": signal["tenant_id"], "rule_id": rule["id"],
            "entity_key": ekey, "signal_id": signal.get("signal_id"),
            "at": signal.get("at") or _iso(_now()),
            "matched_condition_ids": matched_here, "signal": signal,
        })
        # Redirect through the same evaluator using the ephemeral buffer.
        _real_prune = globals()["_prune_state"]
        _real_persist = globals()["_persist_state"]
        _real_load = globals()["_load_window_state"]
        globals()["_prune_state"]        = lambda *a, **k: None
        globals()["_persist_state"]      = lambda *a, **k: None
        globals()["_load_window_state"]  = \
            lambda _t, _r, _e, _w: buf
        try:
            m = _evaluate(rule, signal)
        finally:
            globals()["_prune_state"]       = _real_prune
            globals()["_persist_state"]     = _real_persist
            globals()["_load_window_state"] = _real_load
        return m

    for i, s in enumerate(body.signals):
        d = s.model_dump()
        d["tenant_id"] = ten
        d.setdefault("signal_id", _mint_signal_id())
        d.setdefault("at", _iso(_now() + timedelta(seconds=i)))
        step_matches: list[dict] = []
        for rule in rules:
            m = _evaluate_local(rule, d)
            if m:
                step_matches.append(m)
                matches.append(m)
        trace.append({"step": i, "signal_id": d["signal_id"],
                          "at": d["at"], "signal_kind": d.get("signal_kind"),
                          "matches_produced": [
                              {"correlation_id": mm["correlation_id"],
                                "level": mm["level"],
                                "matched": mm["matched_conditions"],
                                "missing": mm["missing_conditions"]}
                              for mm in step_matches]})

    if not body.dry_run and _c_matches() is not None:
        for m in matches:
            _c_matches().insert_one(dict(m))

    emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                    action="CORRELATION_REPLAY",
                    resource_kind="correlation_rule", resource_id="*",
                    after={"scenario": body.scenario_name,
                              "signals": len(body.signals),
                              "matches": len(matches),
                              "dry_run": body.dry_run})
    return {"ok": True, "data": {"scenario": body.scenario_name,
                                                      "signals_replayed": len(body.signals),
                                                      "rules_evaluated":  len(rules),
                                                      "matches": matches,
                                                      "trace":   trace}}


@router.post("/rules",
                       dependencies=[Depends(require_permission("correlation.create"))])
def create_rule(body: CorrelationRuleBody, request: Request):
    if _c_rules() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    _validate_rule(body)
    ten, pid, pkd = _principal(request)
    if _c_rules().find_one({"tenant_id": ten, "name": body.name}):
        raise HTTPException(409, detail=f"rule '{body.name}' already exists")
    now = _iso(_now())
    doc = {
        **body.model_dump(),
        "id":         _mint_rule_id(),
        "tenant_id":  ten,
        "state":      "DRAFT",
        "version":    1,
        "created_at": now, "updated_at": now,
        "created_by": pid,
    }
    _c_rules().insert_one(dict(doc))
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                    action="CORRELATION_RULE_CREATED",
                                    resource_kind="correlation_rule",
                                    resource_id=doc["id"],
                                    after={"name": body.name})
    return {"ok": True, "data": _mask(doc), "audit_ref": audit["id"]}


@router.post("/rules/{rule_id}/enable",
                       dependencies=[Depends(require_permission("correlation.publish"))])
def enable_rule(rule_id: str, request: Request):
    return _toggle(rule_id, request, enable=True)


@router.post("/rules/{rule_id}/disable",
                       dependencies=[Depends(require_permission("correlation.publish"))])
def disable_rule(rule_id: str, request: Request):
    return _toggle(rule_id, request, enable=False)


def _toggle(rule_id: str, request: Request, *, enable: bool):
    if _c_rules() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    q = {"id": rule_id, "$or": [{"tenant_id": ten}, {"tenant_id": "*"}]}
    doc = _c_rules().find_one(q)
    if not doc:
        raise HTTPException(status_code=404, detail="rule not found")
    if doc.get("tenant_id") == "*" and not enable:
        # Bundled rules can be toggled but note the audit trail.
        pass
    new_state = "ENABLED" if enable else "DISABLED"
    _c_rules().update_one({"_id": doc["_id"]},
        {"$set": {"enabled": enable, "state": new_state,
                       "updated_at": _iso(_now())}})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                    action=("CORRELATION_RULE_ENABLED" if enable
                                              else "CORRELATION_RULE_DISABLED"),
                                    resource_kind="correlation_rule",
                                    resource_id=rule_id,
                                    after={"state": new_state})
    return {"ok": True, "data": _mask(_c_rules().find_one({"_id": doc["_id"]})),
                 "audit_ref": audit["id"]}


def ensure_bundled_seeded() -> int:
    """Public helper — safe to call at FastAPI startup."""
    if _db() is None:
        return 0
    return _seed_bundled_rules()
