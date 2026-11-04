"""
XDR Detection Content Registry — P1 · Multi-Source Foundation.

REAL, populated, executable detection-content registry backed by the
unified `lib.content_pipeline` framework.  Every source (Sigma · Snort
· Suricata · YARA · MITRE ATT&CK) flows through the SAME deterministic
10-stage pipeline:

    DISCOVERED  →  DOWNLOADED  →  PARSED  →  LICENSE_EVALUATED
                →  SCHEMA_VALIDATED  →  NORMALIZED  →  DEDUPLICATED
                →  ATT&CK_MAPPED  →  REGISTERED  →  COMPLETE

Rules NEVER become ACTIVE merely because they were downloaded.
Invalid / LICENSE_BLOCKED / LICENSE_REVIEW content remains in explicit
failure states (retained for audit, never enters ACTIVE).

Storage:
  * xdr_detection_rules      — one doc per registered rule (any source)
  * xdr_detection_versions   — one doc per completed sync (per source)

Bundled snapshots ship alongside the router at
`/app/backend/fixtures/detection/*.json` so a cold-boot pod is NEVER
empty even when the upstream repositories are unreachable.  When
upstream is reachable the same pipeline scales to the full corpus.

Detection ≠ Verdict:  every rule firing is EVIDENCE for the correlation
engine, NEVER an automatic verdict.  The `capability_not_verdict`
principle is preserved end-to-end.
"""
from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pymongo import ASCENDING, DESCENDING, MongoClient

from lib.content_pipeline import (
    ContentSource,
    is_activatable,
    json_list_parser,
    run_pipeline,
)
from lib.content_policy import policy_matrix
from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import require_permission

router = APIRouter(prefix="/api/xdr/detection", tags=["xdr-detection-content"])

# ── Bundled snapshots ────────────────────────────────────────────
_FIX = Path(__file__).resolve().parents[1] / "fixtures" / "detection"


def _bundled(name: str) -> str | None:
    p = _FIX / name
    return f"file://{p}" if p.exists() else None


# ── Source registry ──────────────────────────────────────────────
def _make_sources() -> list[ContentSource]:
    """Deterministic list of every content source NivXRay ingests.

    Each ContentSource carries its own live URL (env-overridable), an
    optional intermediate fallback URL, and finally the bundled offline
    snapshot as the guaranteed last-resort fallback.
    """
    return [
        ContentSource(
            name="SigmaHQ",
            display_name="SigmaHQ (Sigma detection rules)",
            homepage="https://github.com/SigmaHQ/sigma",
            upstream_url=os.environ.get("SIGMA_UPSTREAM_URL"),
            bundled_url=_bundled("sigma_snapshot.json"),
            parser=json_list_parser,
            default_license="DRL 1.1",
            default_rule_type="process_creation",
        ),
        ContentSource(
            name="Snort",
            display_name="Snort / Emerging Threats Open",
            homepage="https://www.snort.org/",
            upstream_url=os.environ.get("SNORT_UPSTREAM_URL"),
            bundled_url=_bundled("snort_snapshot.json"),
            parser=json_list_parser,
            default_license="BSD-3-Clause",
            default_rule_type="snort_signature",
        ),
        ContentSource(
            name="Suricata",
            display_name="Suricata / ET Open",
            homepage="https://suricata.io/",
            upstream_url=os.environ.get("SURICATA_UPSTREAM_URL"),
            bundled_url=_bundled("suricata_snapshot.json"),
            parser=json_list_parser,
            default_license="BSD-3-Clause",
            default_rule_type="suricata_signature",
        ),
        ContentSource(
            name="YARA-Rules",
            display_name="YARA-Rules / Signature Base",
            homepage="https://github.com/Yara-Rules/rules",
            upstream_url=os.environ.get("YARA_UPSTREAM_URL"),
            bundled_url=_bundled("yara_snapshot.json"),
            parser=json_list_parser,
            default_license="GPL-2.0",
            default_rule_type="yara",
        ),
        ContentSource(
            name="MITRE ATT&CK",
            display_name="MITRE ATT&CK (technique knowledge)",
            homepage="https://attack.mitre.org/",
            upstream_url=os.environ.get("ATTACK_UPSTREAM_URL"),
            bundled_url=_bundled("attack_snapshot.json"),
            parser=json_list_parser,
            default_license="MITRE ATT&CK",
            default_rule_type="attack_technique",
        ),
    ]


SOURCES: list[ContentSource] = _make_sources()
SOURCE_BY_NAME: dict[str, ContentSource] = {s.name: s for s in SOURCES}
BUNDLED_URL = _bundled("sigma_snapshot.json")   # kept for legacy tests

_RULE_STATES_VALID   = {"IMPORTED", "VALIDATED", "COMPILED", "TESTED",
                                    "ENABLED", "ACTIVE"}
_RULE_STATES_INVALID = {"INVALID", "PARSE_FAILED", "LICENSE_BLOCKED",
                                    "LICENSE_REVIEW", "UNSUPPORTED",
                                    "REGRESSION_FAILED", "DISABLED"}


# ── Mongo binding (sync) ─────────────────────────────────────────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _db():
    return _client[_DB_NAME] if _client is not None else None


def _c_rules():
    return _db()["xdr_detection_rules"] if _db() is not None else None


def _c_versions():
    return _db()["xdr_detection_versions"] if _db() is not None else None


def _principal(req: Request) -> tuple[str, str, str]:
    ten = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "default")
    pid = (req.headers.get("X-Principal-Id")
                or getattr(req.state, "principal_id", None) or "admin@nivxray.com")
    pkd = (req.headers.get("X-Principal-Kind")
                or getattr(req.state, "principal_kind", None) or "user")
    return ten, pid, pkd


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mask(d: dict) -> dict:
    return {k: v for k, v in d.items() if k != "_id"}


# ── Registrar (stage 9) — writes into Mongo, deterministic ───────
def _register(rules: list[dict]) -> dict[str, int]:
    counts = {"registered": 0, "updated": 0, "existing_unchanged": 0,
                    "retained_non_activatable": 0}
    if _c_rules() is None or not rules:
        return counts
    existing = {d["upstream_id"]: d for d in _c_rules().find(
        {"upstream_id": {"$in": [r["upstream_id"] for r in rules]}},
        {"_id": 0, "upstream_id": 1, "original_content_hash": 1, "id": 1})}
    for n in rules:
        # Rules that fail license policy are RETAINED for audit but
        # never counted as "registered" (activatable content).
        activatable = is_activatable(n["license_policy_state"])
        target_state = ("VALIDATED" if activatable
                                else "LICENSE_BLOCKED"
                                if n["license_policy_state"] == "LICENSE_BLOCKED"
                                else "LICENSE_REVIEW")
        n_final = {**n, "state": target_state}
        prev = existing.get(n["upstream_id"])
        if prev and prev["original_content_hash"] == n["original_content_hash"]:
            counts["existing_unchanged"] += 1
            continue
        if prev:
            n_final["id"] = prev["id"]
            _c_rules().update_one({"upstream_id": n["upstream_id"]},
                                              {"$set": n_final})
            if activatable:
                counts["updated"] += 1
            else:
                counts["retained_non_activatable"] += 1
        else:
            _c_rules().insert_one(dict(n_final))
            if activatable:
                counts["registered"] += 1
            else:
                counts["retained_non_activatable"] += 1
    try:
        _c_rules().create_index([("upstream_id", ASCENDING)], unique=True)
        _c_rules().create_index([("source", ASCENDING)])
        _c_rules().create_index([("rule_type", ASCENDING)])
        _c_rules().create_index([("attack_techniques", ASCENDING)])
    except Exception:  # noqa: BLE001,S110
        pass
    return counts


def _persist_version(source_name: str, version: dict,
                                 principal: tuple[str, str, str]) -> dict:
    ten, pid, _ = principal
    doc = {
        "id":               f"det_v_{uuid.uuid4().hex[:16]}",
        "source":           source_name,
        "outcome":          version["outcome"],
        "stages":           version["stages"],
        "counts":           version["counts"],
        "upstream_sha256":  version.get("upstream_sha256", ""),
        "upstream_url":     version.get("upstream_url", ""),
        "fallback_used":    version.get("fallback_used", False),
        "acquisition_state": version.get("acquisition_state",
                                                          "UNAVAILABLE"),
        "synced_at":        _now(),
        "synced_by":        pid,
        "active":           version["outcome"] == "COMPLETE",
    }
    if _c_versions() is not None:
        if doc["active"]:
            _c_versions().update_many(
                {"source": source_name, "active": True},
                {"$set": {"active": False}})
        _c_versions().insert_one(dict(doc))
    doc.pop("_id", None)
    try:
        emit_audit(tenant_id=ten, principal_id=pid, principal_kind="user",
                        action="DETECTION_SYNCED", resource_kind="detection_pack",
                        resource_id=doc["id"],
                        outcome=("SUCCESS" if doc["active"] else "PARTIAL"),
                        after={"source": source_name, "counts": doc["counts"]})
    except Exception:  # noqa: BLE001,S110
        pass
    return doc


def _sync_source(source: ContentSource,
                            principal: tuple[str, str, str],
                            *, idempotent: bool = False) -> dict:
    """Run the unified pipeline for a single source, register the
    resulting rules, and persist the version doc.

    Returns a legacy-compatible payload merging pipeline stages/counts
    with registrar counts, plus source metadata.
    """
    if _db() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")

    def _hash_check(upstream_sha: str) -> dict | None:
        if not idempotent or _c_versions() is None:
            return None
        active = _c_versions().find_one(
            {"source": source.name, "active": True}, {"_id": 0})
        if active and active.get("upstream_sha256") == upstream_sha \
                and active.get("outcome") == "COMPLETE":
            return active
        return None

    version = run_pipeline(source, idempotent_hash_check=_hash_check)
    reg_counts = _register(version.get("rules", []))
    version["counts"].update(reg_counts)
    # Legacy compat aliases (older tests read these keys):
    version["counts"]["license_valid"]   = (
        version["counts"]["license_permitted"]
        + version["counts"]["license_restricted"])
    version["counts"]["license_blocked_or_review"] = (
        version["counts"]["license_blocked"]
        + version["counts"]["license_review"])
    # `license_blocked` was previously overloaded to also count review
    # in the single-source model; keep the raw blocked count and add
    # the alias above.
    # `registered` legacy name → new registrar output.
    version["counts"]["registered"] = reg_counts["registered"]
    version["stages"]["REGISTERED"] = {
        "status": "OK",
        "registered": reg_counts["registered"],
        "updated": reg_counts["updated"],
        "existing_unchanged": reg_counts["existing_unchanged"],
        "retained_non_activatable": reg_counts["retained_non_activatable"],
    }
    persisted = _persist_version(source.name, version, principal)
    # Return without the (potentially large) `rules[]` payload
    out = {k: v for k, v in version.items() if k != "rules"}
    out["persisted_version_id"] = persisted["id"]
    return out


# ── Legacy single-URL sync (still used by tests that hand in a
#   synthetic file:// path).  Detects the SigmaHQ source or, if the
#   provided URL doesn't match any registered source's bundle, treats
#   the payload as a Sigma-shaped JSON list for backwards compat.
# ─────────────────────────────────────────────────────────────────
def _sync_pipeline_legacy(url: str, principal: tuple[str, str, str],
                                            *, fallback_urls: list[str] | None = None,
                                            idempotent: bool = False) -> dict:
    """Backwards-compat wrapper: run the unified pipeline for a single
    ad-hoc URL treated as SigmaHQ content."""
    source = ContentSource(
        name="SigmaHQ",
        display_name="SigmaHQ (adhoc)",
        homepage="https://github.com/SigmaHQ/sigma",
        upstream_url=url,
        bundled_url=None,
        fallback_urls=[u for u in (fallback_urls or []) if u and u != url],
        parser=json_list_parser,
        default_license="DRL 1.1",
    )
    return _sync_source(source, principal, idempotent=idempotent)


def ensure_synced(principal: tuple[str, str, str] | None = None) -> dict:
    """Boot / on-demand: run every configured source (with idempotent
    hash guards).  Returns aggregated results."""
    principal = principal or ("default", "system@boot", "system")
    if _db() is None:
        return {"outcome": "STORAGE_UNAVAILABLE"}
    per_source: dict[str, dict] = {}
    already = 0
    ran = 0
    for src in SOURCES:
        try:
            r = _sync_source(src, principal, idempotent=True)
            per_source[src.name] = r
            if r.get("idempotent_skip"):
                already += 1
            else:
                ran += 1
        except Exception as exc:  # noqa: BLE001
            per_source[src.name] = {"outcome": "ERROR", "error": str(exc)}
    total = _c_rules().count_documents({}) if _c_rules() is not None else 0
    return {
        "outcome":       ("COMPLETE" if ran + already == len(SOURCES) else "PARTIAL"),
        "sources_run":   ran,
        "sources_skipped": already,
        "per_source":    per_source,
        "total_rules":   total,
        "already_synced": ran == 0 and already > 0,
    }


# Backwards-compat alias — some external callers imported `_sync_pipeline`.
_sync_pipeline = _sync_pipeline_legacy


# ── Endpoints ─────────────────────────────────────────────────────
@router.post("/sync",
                       dependencies=[Depends(require_permission("detections.publish"))])
def sync_now(request: Request,
                     url: str | None = Query(None),
                     use_bundled_fallback: bool = Query(True),
                     source: str | None = Query(None,
                             description="Registered source name (SigmaHQ, Snort, Suricata, YARA-Rules, MITRE ATT&CK). "
                                                 "When omitted the request runs an ad-hoc URL as SigmaHQ.")):
    principal = _principal(request)
    if source and source in SOURCE_BY_NAME:
        return {"ok": True, "data": _sync_source(SOURCE_BY_NAME[source],
                                                                            principal, idempotent=False)}
    primary = url or (SOURCE_BY_NAME["SigmaHQ"].upstream_url) or BUNDLED_URL or ""
    fallbacks = [BUNDLED_URL] if (use_bundled_fallback and BUNDLED_URL) else []
    return {"ok": True, "data": _sync_pipeline_legacy(primary, principal,
                                                                                fallback_urls=fallbacks)}


@router.post("/ensure-synced",
                       dependencies=[Depends(require_permission("detections.publish"))])
def ensure_synced_endpoint(request: Request):
    return {"ok": True, "data": ensure_synced(_principal(request))}


@router.get("/sources/catalog",
                     dependencies=[Depends(require_permission("detections.read"))])
def sources_catalog(request: Request):
    """List every content source NivXRay knows about with honest
    acquisition status (LIVE / BUNDLED_FALLBACK / UNAVAILABLE) and
    latest sync outcome."""
    versions_by_source: dict[str, dict] = {}
    if _c_versions() is not None:
        for v in _c_versions().find({"active": True}, {"_id": 0}):
            versions_by_source[v.get("source")] = v
    counts_by_source: dict[str, int] = {}
    active_by_source: dict[str, int] = {}
    if _c_rules() is not None:
        for d in _c_rules().find({}, {"_id": 0, "source": 1,
                                                              "enabled": 1, "state": 1}):
            src = d.get("source") or "unknown"
            counts_by_source[src] = counts_by_source.get(src, 0) + 1
            if d.get("enabled") and d.get("state") == "ACTIVE":
                active_by_source[src] = active_by_source.get(src, 0) + 1
    catalog = []
    for s in SOURCES:
        v = versions_by_source.get(s.name)
        catalog.append({
            "name":              s.name,
            "display_name":      s.display_name or s.name,
            "homepage":          s.homepage,
            "upstream_url":      s.upstream_url,
            "bundled_available": bool(s.bundled_url),
            "default_license":   s.default_license,
            "default_rule_type": s.default_rule_type,
            "rules_total":       counts_by_source.get(s.name, 0),
            "rules_active":      active_by_source.get(s.name, 0),
            "latest_sync":       v,
            "acquisition_state": (v.get("acquisition_state")
                                                if v else "UNAVAILABLE"),
        })
    return {"ok": True, "data": {"sources": catalog,
                                                        "policy": policy_matrix()}}


@router.get("/status",
                     dependencies=[Depends(require_permission("detections.read"))])
def status(request: Request):
    if _db() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    total = _c_rules().count_documents({}) if _c_rules() is not None else 0
    valid = _c_rules().count_documents({"state": {"$in":
        list(_RULE_STATES_VALID)}}) if _c_rules() is not None else 0
    active_rules = _c_rules().count_documents({
        "$and": [
            {"enabled": True},
            {"state": {"$in": ["VALIDATED", "ACTIVE"]}},
        ]
    }) if _c_rules() is not None else 0
    # Latest version doc — legacy tests read a single "active_version"
    active_version = None
    if _c_versions() is not None:
        active_version = _c_versions().find_one({"active": True},
                                                                          {"_id": 0},
                                                                          sort=[("synced_at", DESCENDING)])

    # ATT&CK coverage across the whole registry
    attack_set: set[str] = set()
    rule_types: dict[str, int] = {}
    sources:    dict[str, int] = {}
    license_state_counts: dict[str, int] = {}
    if _c_rules() is not None:
        for d in _c_rules().find({}, {"_id": 0, "attack_techniques": 1,
                                                              "rule_type": 1, "source": 1,
                                                              "license_policy_state": 1}):
            for t in (d.get("attack_techniques") or []):
                attack_set.add(t)
            rule_types[d.get("rule_type") or "unknown"] = \
                rule_types.get(d.get("rule_type") or "unknown", 0) + 1
            sources[d.get("source") or "unknown"] = \
                sources.get(d.get("source") or "unknown", 0) + 1
            lps = d.get("license_policy_state") or "UNKNOWN"
            license_state_counts[lps] = license_state_counts.get(lps, 0) + 1

    return {"ok": True, "data": {
        "active_version":            active_version,
        "total_rules":               total,
        "valid_rules":               valid,
        "active_rules":              active_rules,
        "attack_techniques":         sorted(attack_set),
        "attack_technique_count":    len(attack_set),
        "rule_types":                rule_types,
        "sources":                   sources,
        "license_state_counts":      license_state_counts,
        "bundled_fallback_available": bool(BUNDLED_URL),
        "sync_state": ("SYNCED"      if (active_version and total > 0)
                              else "NEVER_SYNCED"),
    }}


@router.get("/rules",
                     dependencies=[Depends(require_permission("detections.read"))])
def list_rules(request: Request,
                       source: str | None = Query(None),
                       rule_type: str | None = Query(None),
                       attack: str | None = Query(None),
                       state: str | None = Query(None),
                       license_state: str | None = Query(None),
                       enabled: bool | None = Query(None),
                       q: str | None = Query(None),
                       skip: int = Query(0, ge=0),
                       limit: int = Query(200, ge=1, le=1000)):
    if _c_rules() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    query: dict[str, Any] = {}
    if source:        query["source"]              = source
    if rule_type:     query["rule_type"]           = rule_type
    if attack:        query["attack_techniques"]   = attack.upper()
    if state:         query["state"]               = state
    if license_state: query["license_policy_state"] = license_state
    if enabled is not None: query["enabled"]       = enabled
    if q:
        query["$or"] = [
            {"title":       {"$regex": re.escape(q), "$options": "i"}},
            {"description": {"$regex": re.escape(q), "$options": "i"}},
        ]
    total = _c_rules().count_documents(query)
    cur = _c_rules().find(query, {"_id": 0}).sort("title",
                                                                                            ASCENDING).skip(skip).limit(limit)
    return {"ok": True, "data": {"rules": list(cur), "count": total}}


@router.get("/rules/{rule_id}",
                     dependencies=[Depends(require_permission("detections.read"))])
def get_rule(rule_id: str):
    if _c_rules() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    doc = _c_rules().find_one({"id": rule_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="rule not found")
    return {"ok": True, "data": doc}


def _toggle_rule(rule_id: str, request: Request, *, enable: bool):
    if _c_rules() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _c_rules().find_one({"id": rule_id})
    if not doc:
        raise HTTPException(status_code=404, detail="rule not found")
    if doc.get("state") in _RULE_STATES_INVALID and enable:
        raise HTTPException(409, detail={
            "code": "RULE_IN_INVALID_STATE",
            "state": doc.get("state"),
            "reason": "invalid/non-activatable rules cannot be enabled"})
    # Additionally block enabling if license policy denies it.
    if enable and not is_activatable(doc.get("license_policy_state") or ""):
        raise HTTPException(409, detail={
            "code": "RULE_IN_INVALID_STATE",
            "state": doc.get("license_policy_state"),
            "reason": "license policy does not permit activation"})
    new_state = "ACTIVE" if enable else "DISABLED"
    _c_rules().update_one({"_id": doc["_id"]},
        {"$set": {"enabled": enable, "state": new_state,
                       "state_reason": ("enabled by admin" if enable
                                                else "disabled by admin")}})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action=("DETECTION_RULE_ENABLED" if enable
                    else "DETECTION_RULE_DISABLED"),
        resource_kind="detection_rule", resource_id=rule_id,
        after={"state": new_state})
    return {"ok": True, "data": _mask(_c_rules().find_one({"_id": doc["_id"]})),
                 "audit_ref": audit["id"]}


@router.post("/rules/{rule_id}/enable",
                       dependencies=[Depends(require_permission("detections.publish"))])
def enable_rule(rule_id: str, request: Request):
    return _toggle_rule(rule_id, request, enable=True)


@router.post("/rules/{rule_id}/disable",
                       dependencies=[Depends(require_permission("detections.publish"))])
def disable_rule(rule_id: str, request: Request):
    return _toggle_rule(rule_id, request, enable=False)


@router.get("/versions",
                     dependencies=[Depends(require_permission("detections.read"))])
def list_versions(source: str | None = Query(None),
                            limit: int = Query(20, ge=1, le=200)):
    if _c_versions() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    q: dict[str, Any] = {}
    if source: q["source"] = source
    cur = _c_versions().find(q, {"_id": 0}).sort("synced_at",
                                                                                          DESCENDING).limit(limit)
    return {"ok": True, "data": {"versions": list(cur)}}


@router.get("/policy",
                     dependencies=[Depends(require_permission("detections.read"))])
def get_license_policy():
    """Deterministic snapshot of the license policy matrix — read by
    the UI to render the license badges + policy legend."""
    return {"ok": True, "data": policy_matrix()}
