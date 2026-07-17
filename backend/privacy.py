"""Tenant Privacy & Data-Sovereignty controls — Feb 2026.

Central place where multi-tenant privacy guards are enforced. Every LLM
call, every TI lookup, every persistence write should route decisions
through this module so a single tenant setting change instantly changes
runtime behaviour (no restart, no code deploy).

Settings live in the `tenant_privacy_settings` MongoDB collection as a
single document (`_id: "tenant"`). Missing document = default safe mode.

The four toggles:
  · local_only_mode          — disable ALL outbound LLM calls
  · ti_default_enabled       — send IOCs to external TI providers by default
  · ti_hash_only_mode        — hash IPs/domains before TI lookup (max privacy)
  · investigation_ttl_days   — auto-purge investigations older than N days
                               (0 = never purge)

Per-investigation override:
  · body.is_sensitive — analyst can mark a single investigation as
    sensitive → forces local-only + no TI regardless of tenant settings.

Additionally maintains an append-only `privacy_audit` collection so any
setting change is traceable (compliance requirement).
"""
from __future__ import annotations
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
import hashlib
from pymongo import MongoClient


_client = MongoClient(os.environ.get("MONGO_URL"))
_db     = _client[os.environ.get("DB_NAME")]

_col_settings = _db.tenant_privacy_settings
_col_audit    = _db.privacy_audit
_col_invest   = _db.investigations
_col_cases    = _db.workspace_cases


DEFAULT_SETTINGS: Dict[str, Any] = {
    "_id":                      "tenant",
    "local_only_mode":          False,   # If true, NO LLM calls happen
    "ti_default_enabled":       False,   # SAFE DEFAULT — TI opt-in per case
    "ti_hash_only_mode":        False,   # Max privacy: only hashed IOCs to TI
    "investigation_ttl_days":   30,      # Auto-purge after N days (0=never)
    "workspace_case_ttl_days":  0,       # Golden vault cases: never by default
    "enforce_https_only":       True,
    "created_at":               None,
    "updated_at":               None,
}


def get_settings() -> Dict[str, Any]:
    """Fetch current privacy settings (creates default doc if missing)."""
    doc = _col_settings.find_one({"_id": "tenant"})
    if not doc:
        doc = dict(DEFAULT_SETTINGS)
        doc["created_at"] = datetime.now(timezone.utc).isoformat()
        _col_settings.insert_one(doc)
    return doc


def update_settings(patch: Dict[str, Any], actor: Optional[str] = None) -> Dict[str, Any]:
    """Update settings with audit trail. Only known keys are honoured."""
    allowed = set(DEFAULT_SETTINGS) - {"_id", "created_at"}
    clean = {k: v for k, v in patch.items() if k in allowed}
    clean["updated_at"] = datetime.now(timezone.utc).isoformat()
    _col_settings.update_one({"_id": "tenant"}, {"$set": clean}, upsert=True)
    _col_audit.insert_one({
        "ts":     datetime.now(timezone.utc).isoformat(),
        "actor":  actor or "system",
        "patch":  clean,
    })
    return get_settings()


# ─── enforcement helpers (call these from LLM/TI/persistence paths) ──────

def llm_allowed(is_sensitive: bool = False) -> bool:
    """Return False if the caller MUST skip the LLM step."""
    if is_sensitive:
        return False  # per-case sensitive flag hard-blocks LLM
    s = get_settings()
    return not s.get("local_only_mode", False)


def ti_allowed(is_sensitive: bool = False, per_request_enabled: Optional[bool] = None) -> bool:
    """Return False if the caller MUST skip TI enrichment."""
    if is_sensitive:
        return False
    s = get_settings()
    if per_request_enabled is not None:
        return bool(per_request_enabled)
    return bool(s.get("ti_default_enabled", False))


def ti_hash_only() -> bool:
    return bool(get_settings().get("ti_hash_only_mode", False))


def hash_ioc(value: str) -> str:
    """Deterministic sha256 truncated to 16 chars for privacy-preserving TI lookups."""
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:16]


# ─── TTL enforcement (called on backend startup) ─────────────────────────

def ensure_ttl_indexes() -> Dict[str, Any]:
    """Materialise MongoDB TTL indexes based on current settings.

    Note: TTL indexes require a BSON date field. We use `created_at_dt`
    (indexed date) alongside the existing ISO-string `created_at`.
    """
    s = get_settings()
    results: Dict[str, Any] = {}
    inv_days = int(s.get("investigation_ttl_days") or 0)
    wc_days  = int(s.get("workspace_case_ttl_days") or 0)

    # ---- investigations
    try:
        # drop any existing TTL index (there can only be one per field)
        for idx in _col_invest.list_indexes():
            if "expireAfterSeconds" in idx.get("expireAfterSeconds", {}) or idx["name"].startswith("ttl_"):
                _col_invest.drop_index(idx["name"])
    except Exception:
        pass
    if inv_days > 0:
        try:
            _col_invest.create_index(
                "created_at_dt",
                name="ttl_investigations",
                expireAfterSeconds=inv_days * 86400,
                background=True,
            )
            results["investigations"] = f"TTL {inv_days}d"
        except Exception as e:
            results["investigations"] = f"error: {e}"
    else:
        results["investigations"] = "never"

    # ---- workspace_cases
    try:
        for idx in _col_cases.list_indexes():
            if idx["name"].startswith("ttl_"):
                _col_cases.drop_index(idx["name"])
    except Exception:
        pass
    if wc_days > 0:
        try:
            _col_cases.create_index(
                "created_at_dt",
                name="ttl_workspace_cases",
                expireAfterSeconds=wc_days * 86400,
                background=True,
            )
            results["workspace_cases"] = f"TTL {wc_days}d"
        except Exception as e:
            results["workspace_cases"] = f"error: {e}"
    else:
        results["workspace_cases"] = "never"

    return results


def stamp_ttl(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Attach BSON `created_at_dt` for TTL enforcement. Call before insert."""
    doc.setdefault("created_at_dt", datetime.now(timezone.utc))
    return doc
