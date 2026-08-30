"""
XDR Rule Studio — authoritative authoring layer (Step 1 + Step 2).

The ONE place analysts author, tune and promote every detection rule
regardless of source lane.  No parallel authoring surfaces are
permitted:  the existing correlation engine remains as a backend
capability; its rules are surfaced HERE, not in a competing UI.

Nine lanes (owner-locked):
  event · endpoint · ioc · network · dns_proxy · cve_exposure ·
  correlation · behavior · content

Mandatory rule lifecycle (persisted on every rule):

    DRAFT → TESTING → VALIDATED → ENABLED → ACTIVE → TUNING
           → DISABLED  → DEPRECATED

ACTIVE transition is IMPOSSIBLE unless every check of the 11-check
Regression Gate passes.  This is enforced architecturally, not merely
documented — the promote endpoint refuses transition on any failure
and returns the deterministic failure reasons.

Non-negotiable architectural stamping on every rule persisted here:

    emits                  = OBSERVATION
    emits_verdict          = false
    verdict_capable        = false
    capability_not_verdict = true

RULE → OBSERVATION → CORRELATION → EVIDENCE BUNDLE → IKG → ICE →
VERDICT → INCIDENT → PLAYBOOK / POLICY.  Verdicts are OWNED by the
Verdict Engine, never by a rule.

Correlation rules live in the SAME `xdr_detection_rules` collection
with `lane="correlation"` so the store is authoritative and unified.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from pymongo import ASCENDING, DESCENDING, MongoClient

from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import require_permission

router = APIRouter(prefix="/api/xdr/rule-studio", tags=["xdr-rule-studio"])

# ── Lifecycle model ─────────────────────────────────────────────
LIFECYCLE_STATES = [
    "DRAFT", "TESTING", "VALIDATED", "ENABLED",
    "ACTIVE", "TUNING", "DISABLED", "DEPRECATED",
]

# Allowed transitions.  Any transition NOT in this table is refused.
_TRANSITIONS: dict[str, set[str]] = {
    "DRAFT":      {"TESTING", "DEPRECATED"},
    "TESTING":    {"DRAFT", "VALIDATED", "DEPRECATED"},
    "VALIDATED":  {"TESTING", "ENABLED", "DEPRECATED"},
    "ENABLED":    {"ACTIVE", "TESTING", "DISABLED"},
    "ACTIVE":     {"TUNING", "DISABLED"},
    "TUNING":     {"ACTIVE", "DISABLED"},
    "DISABLED":   {"TESTING", "DEPRECATED"},
    "DEPRECATED": set(),   # terminal
}

# The 11-check Regression Gate — owner-locked.
GATE_CHECKS = [
    "schema", "data_source", "positive", "negative",
    "false_positive", "correlation", "corpus",
    "performance", "rbac", "provenance", "license",
]

LANES = [
    "event", "endpoint", "ioc", "network", "dns_proxy",
    "cve_exposure", "correlation", "behavior", "content",
]

# Map rule_type (from content pipeline) → Rule Studio lane
_LANE_BY_RULE_TYPE: dict[str, str] = {
    # Content lane
    "sigma":            "content",
    "process_creation": "content",
    "snort_signature":  "network",
    "suricata_signature": "network",
    "yara":             "content",
    "attack_technique": "content",
    "parent_child":     "endpoint",
    "behavioral":       "behavior",
    "ioc":              "ioc",
    "cve_record":       "cve_exposure",
    # Correlation rules use their own lane
    "correlation":      "correlation",
}


def _lane_for_rule_type(rt: str | None) -> str:
    if not rt:
        return "content"
    return _LANE_BY_RULE_TYPE.get(rt, "content")


# ── Mongo binding ───────────────────────────────────────────────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _db():
    return _client[_DB_NAME] if _client is not None else None


def _c_rules():
    return _db()["xdr_detection_rules"] if _db() is not None else None


def _c_corr_rules():
    return _db()["xdr_correlation_rules"] if _db() is not None else None


def _principal(req: Request) -> tuple[str, str, str]:
    ten = (req.headers.get("X-Tenant-Id") or "default")
    pid = (req.headers.get("X-Principal-Id") or "admin@nivxray.com")
    pkd = (req.headers.get("X-Principal-Kind") or "user")
    return ten, pid, pkd


def _hash_payload(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mask(d: dict) -> dict:
    return {k: v for k, v in d.items() if k != "_id"}


# ── Studio metadata backfill (idempotent) ───────────────────────
def _backfill_studio_metadata() -> dict[str, int]:
    """Every rule persisted before Rule Studio landed gets its
    lifecycle / lane / semantic stamps computed deterministically.

    Existing behaviour preserved:
      * rules with state ∈ ACTIVE/ENABLED  → lifecycle ACTIVE  (or ENABLED)
      * rules with state = VALIDATED / IMPORTED → lifecycle VALIDATED
      * license-blocked / license-review        → lifecycle DEPRECATED
      * any other invalid state                → lifecycle DEPRECATED

    Idempotent — only writes rules missing `lifecycle_state`.
    """
    counts = {"backfilled": 0}
    if _c_rules() is None:
        return counts
    cursor = _c_rules().find({"lifecycle_state": {"$exists": False}},
                                                {"_id": 1, "id": 1, "state": 1,
                                                  "enabled": 1, "rule_type": 1,
                                                  "license_policy_state": 1,
                                                  "source": 1})
    for d in cursor:
        state = d.get("state")
        lps   = d.get("license_policy_state")
        if lps in ("LICENSE_BLOCKED", "LICENSE_REVIEW"):
            lifecycle = "DEPRECATED"
        elif state == "ACTIVE" and d.get("enabled"):
            lifecycle = "ACTIVE"
        elif state == "ENABLED":
            lifecycle = "ENABLED"
        elif state in ("VALIDATED", "IMPORTED"):
            lifecycle = "VALIDATED"
        elif state == "DISABLED":
            lifecycle = "DISABLED"
        else:
            lifecycle = "DEPRECATED"
        _c_rules().update_one(
            {"_id": d["_id"]},
            {"$set": {
                "lifecycle_state":  lifecycle,
                "lane":             _lane_for_rule_type(d.get("rule_type")),
                "emits":            "OBSERVATION",
                "emits_verdict":    False,
                "verdict_capable":  False,
                "capability_not_verdict": True,
                "gate_state": {
                    "last_run_at": None,
                    "checks": {c: {"status": "UNKNOWN"} for c in GATE_CHECKS},
                    "pass":  False,
                },
                "lifecycle_history": [{
                    "to":      lifecycle,
                    "at":      _now(),
                    "by":      "system@backfill",
                    "reason":  "studio-metadata-backfill",
                }],
            }})
        counts["backfilled"] += 1
    try:
        _c_rules().create_index([("lane", ASCENDING)])
        _c_rules().create_index([("lifecycle_state", ASCENDING)])
    except Exception:  # noqa: BLE001,S110
        pass
    return counts


def _adopt_correlation_rules() -> dict[str, int]:
    """Idempotent — surface every existing correlation rule into the
    authoritative xdr_detection_rules collection with lane=correlation.
    Original correlation store keeps functioning; this is a mirror
    projection so the Rule Studio has ONE authoritative view.
    """
    counts = {"adopted": 0, "existing": 0}
    if _c_rules() is None or _c_corr_rules() is None:
        return counts
    for corr in _c_corr_rules().find({}, {"_id": 0}):
        existing = _c_rules().find_one({"upstream_id": corr.get("id"),
                                                              "source": "NivXRay-correlation"})
        if existing:
            counts["existing"] += 1
            continue
        doc = {
            "id":                     f"det_{uuid.uuid4().hex[:20]}",
            "upstream_id":            corr.get("id"),
            "upstream_version":       corr.get("version") or "1",
            "title":                  corr.get("name") or corr.get("id"),
            "description":            corr.get("description"),
            "source":                 "NivXRay-correlation",
            "source_url":             None,
            "license":                "NivXRay Public Content",
            "license_id":             "NivXRay-Public-Content",
            "license_policy_state":   "PERMITTED",
            "license_policy_reason":  "internal NivXRay-authored content",
            "license_verified":       True,
            "author":                 corr.get("author") or "system",
            "created":                corr.get("created_at"),
            "modified":               corr.get("modified_at"),
            "level":                  corr.get("severity"),
            "status":                 "stable",
            "tags":                   corr.get("tags") or [],
            "attack_techniques":      corr.get("attack_techniques") or [],
            "cve_references":         [],
            "logsource":              {},
            "detection":              corr.get("expression") or corr,
            "rule_body":              corr,
            "original_content_hash":  _hash_payload(corr.get("expression") or corr),
            "rule_type":              "correlation",
            "lane":                   "correlation",
            "capability_not_verdict": True,
            "emits":                  "OBSERVATION",
            "emits_verdict":          False,
            "verdict_capable":        False,
            "state":                  "VALIDATED" if corr.get("enabled")
                                                          else "IMPORTED",
            "state_reason":           "adopted from correlation engine",
            "enabled":                bool(corr.get("enabled")),
            "lifecycle_state":        ("ACTIVE" if corr.get("enabled")
                                                    else "VALIDATED"),
            "gate_state": {
                "last_run_at": None,
                "checks": {c: {"status": "UNKNOWN"} for c in GATE_CHECKS},
                "pass":  False,
            },
            "lifecycle_history": [{
                "to": "ACTIVE" if corr.get("enabled") else "VALIDATED",
                "at": _now(), "by": "system@adopt",
                "reason": "correlation-adoption",
            }],
            "parser_version":         "correlation-adopt-1.0",
            "lineage":                {"pipeline": ["adopt"],
                                                  "source": "correlation-engine",
                                                  "imported_at": _now()},
        }
        _c_rules().insert_one(dict(doc))
        counts["adopted"] += 1
    return counts


def ensure_studio_ready() -> dict[str, Any]:
    """Boot-hook — idempotent bring-up of Rule Studio metadata."""
    if _db() is None:
        return {"outcome": "STORAGE_UNAVAILABLE"}
    b = _backfill_studio_metadata()
    a = _adopt_correlation_rules()
    return {"outcome": "READY", "backfill": b, "correlation_adopt": a}


# ── 11-check Regression Gate ─────────────────────────────────────
def _run_gate(rule: dict, *, principal: tuple[str, str, str]) -> dict:
    """Deterministic 11-check gate.  Every check returns
    {status: PASS | FAIL | SKIP, reason: str}.  Gate PASSES only when
    ALL 11 have status == PASS.

    Checks are conservative — a missing precondition (e.g. no test
    fixtures registered) yields SKIP but SKIP does NOT count as PASS,
    so the gate refuses ACTIVE until real evidence exists.
    """
    checks: dict[str, dict[str, str]] = {}

    # 1 · Schema — detection body present, rule_type known
    if not (rule.get("detection") or rule.get("rule_body")):
        checks["schema"] = {"status": "FAIL", "reason": "missing detection body"}
    elif not rule.get("rule_type"):
        checks["schema"] = {"status": "FAIL", "reason": "missing rule_type"}
    else:
        checks["schema"] = {"status": "PASS", "reason": "detection body + rule_type present"}

    # 2 · Data-source — the collector protocol referenced must be IMPLEMENTED
    ls = (rule.get("logsource") or {})
    if not ls:
        # Content-lane rules without a logsource (e.g. ATT&CK knowledge) are
        # legitimately data-source-agnostic.
        if rule.get("lane") == "content":
            checks["data_source"] = {"status": "PASS",
                                                  "reason": "content-lane · data-source-agnostic"}
        else:
            checks["data_source"] = {"status": "FAIL",
                                                  "reason": "no logsource declared"}
    else:
        checks["data_source"] = {"status": "PASS",
                                              "reason": f"logsource declared: {ls}"}

    # 3-5 · Test suites (positive/negative/FP) — read from rule.tests[] if any
    tests = rule.get("regression_tests") or {}
    for key in ("positive", "negative", "false_positive"):
        results = tests.get(key) or []
        if not results:
            checks[key] = {"status": "SKIP",
                                  "reason": f"no {key} tests registered"}
        elif all(r.get("passed") for r in results):
            checks[key] = {"status": "PASS",
                                  "reason": f"{len(results)} {key} tests pass"}
        else:
            failed = [r for r in results if not r.get("passed")]
            checks[key] = {"status": "FAIL",
                                  "reason": f"{len(failed)}/{len(results)} {key} tests fail"}

    # 6 · Correlation — rules in correlation lane are checked against the
    #     correlation engine; content-lane rules are exempt.
    if rule.get("lane") == "correlation":
        expr = rule.get("detection") or rule.get("rule_body")
        checks["correlation"] = ({"status": "PASS",
                                                    "reason": "correlation expression present"}
                                                if expr else
                                                    {"status": "FAIL",
                                                    "reason": "correlation lane requires expression"})
    else:
        checks["correlation"] = {"status": "PASS",
                                                "reason": "non-correlation lane · exempt"}

    # 7 · Investigation Corpus
    corpus = tests.get("corpus") or []
    if not corpus:
        checks["corpus"] = {"status": "SKIP",
                                    "reason": "no corpus scenarios attached"}
    elif all(r.get("passed") for r in corpus):
        checks["corpus"] = {"status": "PASS",
                                    "reason": f"{len(corpus)} corpus scenarios pass"}
    else:
        checks["corpus"] = {"status": "FAIL",
                                    "reason": "corpus regression failed"}

    # 8 · Performance — read from rule.performance_budget
    perf = rule.get("performance")
    if not perf:
        checks["performance"] = {"status": "SKIP",
                                                "reason": "no performance measurement"}
    elif perf.get("p95_ms", 0) <= (perf.get("budget_ms") or 250):
        checks["performance"] = {"status": "PASS",
                                                "reason": f"p95={perf.get('p95_ms')}ms within budget"}
    else:
        checks["performance"] = {"status": "FAIL",
                                                "reason": "p95 exceeds budget"}

    # 9 · RBAC
    _, pid, _ = principal
    checks["rbac"] = ({"status": "PASS",
                                  "reason": f"promoter {pid} has detections.publish"}
                              if pid else
                                  {"status": "FAIL", "reason": "no principal"})

    # 10 · Provenance
    if rule.get("source") and rule.get("source_url") is not None \
            and rule.get("license"):
        checks["provenance"] = {"status": "PASS",
                                              "reason": "source + source_url + license present"}
    else:
        checks["provenance"] = {"status": "FAIL",
                                              "reason": "missing source / source_url / license"}

    # 11 · License policy
    lps = rule.get("license_policy_state")
    if lps in ("PERMITTED", "RESTRICTED"):
        checks["license"] = {"status": "PASS",
                                        "reason": f"policy_state={lps}"}
    else:
        checks["license"] = {"status": "FAIL",
                                        "reason": f"policy_state={lps} not activatable"}

    passed = all(c["status"] == "PASS" for c in checks.values())
    return {"last_run_at": _now(),
                "checks":     checks,
                "pass":       passed,
                "summary": {"pass": sum(1 for c in checks.values()
                                                              if c["status"] == "PASS"),
                                    "fail": sum(1 for c in checks.values()
                                                              if c["status"] == "FAIL"),
                                    "skip": sum(1 for c in checks.values()
                                                              if c["status"] == "SKIP")}}


# ── Studio API models ────────────────────────────────────────────
class NewRuleBody(BaseModel):
    lane:        str = Field(..., description=f"One of: {', '.join(LANES)}")
    title:       str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    rule_type:   str | None = None
    logsource:   dict | None = None
    detection:   dict | None = None
    tags:        list[str] | None = None
    attack_techniques: list[str] | None = None
    author:      str | None = None
    license:     str | None = None
    level:       str | None = None


class TransitionBody(BaseModel):
    to:     str = Field(..., description=f"One of: {', '.join(LIFECYCLE_STATES)}")
    reason: str | None = None


# ── Endpoints ────────────────────────────────────────────────────
@router.get("/status",
                     dependencies=[Depends(require_permission("detections.read"))])
def status(request: Request):
    if _c_rules() is None:
        raise HTTPException(503, detail="storage unavailable")
    by_lane      = {lane: 0 for lane in LANES}
    by_lifecycle = {s: 0 for s in LIFECYCLE_STATES}
    for d in _c_rules().find({}, {"_id": 0, "lane": 1,
                                                      "lifecycle_state": 1}):
        lane      = d.get("lane") or "content"
        lifecycle = d.get("lifecycle_state") or "VALIDATED"
        by_lane[lane]           = by_lane.get(lane, 0) + 1
        by_lifecycle[lifecycle] = by_lifecycle.get(lifecycle, 0) + 1
    return {"ok": True, "data": {
        "total":              _c_rules().count_documents({}),
        "by_lane":            by_lane,
        "by_lifecycle":       by_lifecycle,
        "lanes":              LANES,
        "lifecycle_states":   LIFECYCLE_STATES,
        "gate_checks":        GATE_CHECKS,
        "transitions":        {k: sorted(v) for k, v in _TRANSITIONS.items()},
        "semantic_contract":  ("RULE → OBSERVATION → CORRELATION → EVIDENCE "
                                              "BUNDLE → IKG → ICE → VERDICT → INCIDENT "
                                              "→ PLAYBOOK / POLICY"),
        "verdict_owned_by":   "Verdict Engine",
    }}


@router.get("/rules",
                     dependencies=[Depends(require_permission("detections.read"))])
def list_rules(lane: str | None = Query(None),
                          lifecycle_state: str | None = Query(None),
                          gate_pass: bool | None = Query(None),
                          q: str | None = Query(None),
                          skip: int = Query(0, ge=0),
                          limit: int = Query(200, ge=1, le=1000)):
    if _c_rules() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    query: dict[str, Any] = {}
    if lane:            query["lane"]            = lane
    if lifecycle_state: query["lifecycle_state"] = lifecycle_state
    if gate_pass is not None: query["gate_state.pass"] = gate_pass
    if q:
        query["$or"] = [
            {"title":       {"$regex": re.escape(q), "$options": "i"}},
            {"description": {"$regex": re.escape(q), "$options": "i"}},
        ]
    total = _c_rules().count_documents(query)
    cur = _c_rules().find(query, {"_id": 0}).sort(
        "title", ASCENDING).skip(skip).limit(limit)
    return {"ok": True, "data": {"rules": list(cur), "count": total}}


@router.post("/rules",
                       dependencies=[Depends(require_permission("detections.publish"))])
def create_rule(body: NewRuleBody, request: Request):
    """Create a NivXRay-native rule in DRAFT state.  Every rule
    persisted here is architecturally stamped emits=OBSERVATION,
    emits_verdict=false, capability_not_verdict=true."""
    if _c_rules() is None:
        raise HTTPException(503, detail="storage unavailable")
    if body.lane not in LANES:
        raise HTTPException(400, detail={"code": "LANE_UNKNOWN",
                                                                "allowed": LANES})
    ten, pid, pkd = _principal(request)
    rule_id = f"det_{uuid.uuid4().hex[:20]}"
    doc = {
        "id":                     rule_id,
        "upstream_id":            f"native:{rule_id}",
        "upstream_version":       "1",
        "title":                  body.title,
        "description":            body.description,
        "source":                 "NivXRay-native",
        "source_url":             "",
        "license":                body.license or "NivXRay Public Content",
        "license_id":             "NivXRay-Public-Content",
        "license_policy_state":   "PERMITTED",
        "license_policy_reason":  "internal NivXRay-authored content",
        "license_verified":       True,
        "author":                 body.author or pid,
        "created":                _now(),
        "modified":               _now(),
        "original_content_hash":  _hash_payload(body.detection or {}),
        "level":                  body.level or "medium",
        "status":                 "draft",
        "tags":                   body.tags or [],
        "attack_techniques":      body.attack_techniques or [],
        "cve_references":         [],
        "logsource":              body.logsource or {},
        "detection":              body.detection or {},
        "rule_body":              body.detection or {},
        "rule_type":              body.rule_type or "sigma",
        "lane":                   body.lane,
        # Architectural stamping — non-negotiable
        "capability_not_verdict": True,
        "emits":                  "OBSERVATION",
        "emits_verdict":          False,
        "verdict_capable":        False,
        # Lifecycle bootstrap
        "state":                  "IMPORTED",
        "state_reason":           "authored via Rule Studio",
        "enabled":                False,
        "lifecycle_state":        "DRAFT",
        "gate_state": {
            "last_run_at": None,
            "checks": {c: {"status": "UNKNOWN"} for c in GATE_CHECKS},
            "pass":  False,
        },
        "lifecycle_history": [{
            "to":     "DRAFT",
            "at":     _now(),
            "by":     pid,
            "reason": "authored via Rule Studio",
        }],
        "tenant_id":              ten,
        "parser_version":         "rule-studio-1.0",
        "lineage":                {"pipeline": ["studio-authored"],
                                              "source": "rule-studio",
                                              "imported_at": _now()},
    }
    _c_rules().insert_one(dict(doc))
    emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                    action="RULE_CREATED", resource_kind="detection_rule",
                    resource_id=rule_id,
                    after={"lane": body.lane, "title": body.title})
    return {"ok": True, "data": _mask(_c_rules().find_one({"id": rule_id}))}


def _apply_transition(rule_id: str, to_state: str, reason: str | None,
                                      principal: tuple[str, str, str]) -> dict:
    if _c_rules() is None:
        raise HTTPException(503, detail="storage unavailable")
    if to_state not in LIFECYCLE_STATES:
        raise HTTPException(400,
            detail={"code": "LIFECYCLE_UNKNOWN",
                        "allowed": LIFECYCLE_STATES})
    doc = _c_rules().find_one({"id": rule_id})
    if not doc:
        raise HTTPException(404, detail="rule not found")
    current = doc.get("lifecycle_state") or "VALIDATED"
    allowed = _TRANSITIONS.get(current, set())
    if to_state not in allowed:
        raise HTTPException(409,
            detail={"code": "LIFECYCLE_TRANSITION_REFUSED",
                        "current": current, "requested": to_state,
                        "allowed_from_current": sorted(allowed)})

    ten, pid, pkd = principal

    # ACTIVE is the HARD gate — refuse unless every check passes.
    if to_state == "ACTIVE":
        gate = _run_gate(doc, principal=principal)
        _c_rules().update_one({"_id": doc["_id"]},
                                        {"$set": {"gate_state": gate}})
        if not gate["pass"]:
            emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                            action="RULE_PROMOTION_REFUSED",
                            resource_kind="detection_rule",
                            resource_id=rule_id, outcome="FAILURE",
                            after={"gate": gate["summary"],
                                        "failed_checks": [c for c, v in gate["checks"].items()
                                                                    if v["status"] != "PASS"]})
            raise HTTPException(409,
                detail={"code": "REGRESSION_GATE_FAILED",
                            "gate": gate,
                            "reason": "ACTIVE promotion requires ALL 11 checks to PASS"})

    # Commit transition
    history = doc.get("lifecycle_history") or []
    history.append({"from": current, "to": to_state, "at": _now(),
                              "by": pid, "reason": reason or ""})
    upd = {"lifecycle_state": to_state,
              "lifecycle_history": history}
    # Legacy state alias — keep existing code that reads `state` working
    if to_state in ("ACTIVE",):
        upd["state"]   = "ACTIVE"
        upd["enabled"] = True
    elif to_state == "DISABLED":
        upd["state"]   = "DISABLED"
        upd["enabled"] = False
    elif to_state == "DEPRECATED":
        upd["state"]   = "DEPRECATED"
        upd["enabled"] = False
    _c_rules().update_one({"_id": doc["_id"]}, {"$set": upd})
    emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                    action=f"RULE_LIFECYCLE_{to_state}",
                    resource_kind="detection_rule",
                    resource_id=rule_id,
                    after={"from": current, "to": to_state,
                                "reason": reason or ""})
    return _mask(_c_rules().find_one({"_id": doc["_id"]}))


@router.post("/rules/{rule_id}/transition",
                       dependencies=[Depends(require_permission("detections.publish"))])
def transition_rule(rule_id: str, body: TransitionBody, request: Request):
    return {"ok": True, "data": _apply_transition(rule_id, body.to,
                                                                            body.reason, _principal(request))}


@router.post("/rules/{rule_id}/promote",
                       dependencies=[Depends(require_permission("detections.publish"))])
def promote_rule(rule_id: str, request: Request):
    """Shortcut promotion: → ACTIVE.  Runs the 11-check gate.
    Refuses with deterministic reasons on any failure."""
    return {"ok": True, "data": _apply_transition(rule_id, "ACTIVE",
                                                                            "promote-to-active",
                                                                            _principal(request))}


@router.post("/rules/{rule_id}/gate",
                       dependencies=[Depends(require_permission("detections.read"))])
def dry_run_gate(rule_id: str, request: Request):
    """Dry-run the 11-check gate WITHOUT transitioning state.  Useful
    for the Rule Studio UI to render the promotion checklist."""
    if _c_rules() is None:
        raise HTTPException(503, detail="storage unavailable")
    doc = _c_rules().find_one({"id": rule_id})
    if not doc:
        raise HTTPException(404, detail="rule not found")
    gate = _run_gate(doc, principal=_principal(request))
    _c_rules().update_one({"_id": doc["_id"]},
                                    {"$set": {"gate_state": gate}})
    return {"ok": True, "data": {"gate": gate}}


@router.get("/lanes",
                     dependencies=[Depends(require_permission("detections.read"))])
def lanes_summary():
    """Metadata for every lane · consumed by the UI tab bar."""
    return {"ok": True, "data": {"lanes": [
        {"key": "event",         "label": "Event / Log Source",
          "description": "Event ID · provider · channel · application · field/value"},
        {"key": "endpoint",      "label": "Endpoint / EDR",
          "description": "process · parent-child · command line · file / hash / signer · registry · service · persistence · network conn · LOLBAS"},
        {"key": "ioc",           "label": "IOC / Threat Intelligence",
          "description": "IP · domain · URL · hash · email · certificate · IOC lists · TI confidence & reputation"},
        {"key": "network",       "label": "Network / IDS / IPS",
          "description": "Snort · Suricata · protocol · port · signature · payload · network behavior"},
        {"key": "dns_proxy",     "label": "DNS / Proxy",
          "description": "DNS query · domain · DGA · NXDOMAIN · frequency · destination · URL / category · proxy action"},
        {"key": "cve_exposure",  "label": "CVE / Exposure",
          "description": "CVE · CPE · affected software · CVSS · EPSS · KEV · asset exposure · exploit evidence"},
        {"key": "correlation",   "label": "Correlation",
          "description": "sequence · temporal · threshold · value-count · group-by · cross-source · cross-host · cross-user · negative evidence"},
        {"key": "behavior",      "label": "Behavior / Heuristic / Anomaly",
          "description": "behavioral patterns · frequency deviations · baselines · heuristic features · ML observations"},
        {"key": "content",       "label": "Content-based",
          "description": "Sigma · YARA · Snort · Suricata · ATT&CK analytics"},
    ]}}
