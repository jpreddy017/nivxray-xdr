"""NivXRay TAXII 2.1 Push (Feb-2026 roadmap — P1).

Publishes NivXRay-extracted IOCs and indicators as STIX 2.1 objects to a
configurable TAXII 2.1 server (Discovery → API Root → Collections → objects
add-endpoint).

Design rules:
    * Configurable at runtime (server URL, collection ID, auth token).
    * All configuration stored in MongoDB `taxii_config` collection —
      single-document config keyed by `_id = "singleton"`.
    * Auth tokens: Basic (username:password), Bearer (token), or Header
      (raw HTTP header key/value pair).
    * OFFLINE-safe. Every push is wrapped in try/except; failures are
      recorded in `taxii_push_log` and never crash the caller.
    * STIX 2.1 spec: https://docs.oasis-open.org/cti/stix/v2.1/
    * TAXII 2.1 spec: https://docs.oasis-open.org/cti/taxii/v2.1/

Endpoint surface (see routers/taxii.py):
    GET  /api/admin/taxii/config
    POST /api/admin/taxii/config
    POST /api/admin/taxii/test        — HEAD /discovery to verify connectivity
    POST /api/admin/taxii/push        — publish IOCs/indicators from an investigation
    GET  /api/admin/taxii/history?limit=50
"""
from __future__ import annotations

import base64
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx


COLLECTION_CONFIG = "taxii_config"
COLLECTION_LOG = "taxii_push_log"
CONFIG_ID = "singleton"

STIX_VERSION = "2.1"
DEFAULT_TIMEOUT = 20.0


# ------------------------------------------------------------------
# Config storage
# ------------------------------------------------------------------
def _redact(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy with sensitive fields redacted for UI display."""
    if not cfg:
        return {}
    safe = dict(cfg)
    for k in ("password", "token", "auth_header_value"):
        if safe.get(k):
            v = safe[k]
            safe[k] = f"{'*' * max(0, len(v) - 4)}{v[-4:]}" if len(v) > 4 else "****"
    return safe


async def get_config(db) -> Dict[str, Any]:
    doc = await db[COLLECTION_CONFIG].find_one({"_id": CONFIG_ID}) or {}
    doc.pop("_id", None)
    return doc


async def get_config_redacted(db) -> Dict[str, Any]:
    return _redact(await get_config(db))


async def save_config(db, config: Dict[str, Any]) -> Dict[str, Any]:
    """Upsert the singleton config document."""
    # Whitelist keys we accept
    allowed = {
        "server_url", "collection_id", "api_root", "auth_type",
        "username", "password", "token",
        "auth_header_key", "auth_header_value",
        "verify_tls", "identity_name",
    }
    to_write = {k: config[k] for k in config if k in allowed}
    # Defaults
    to_write.setdefault("verify_tls", True)
    to_write.setdefault("auth_type", "none")
    to_write.setdefault("identity_name", "NivXRay")
    to_write["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db[COLLECTION_CONFIG].update_one(
        {"_id": CONFIG_ID},
        {"$set": to_write},
        upsert=True,
    )
    return _redact(await get_config(db))


# ------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------
def _auth_headers(cfg: Dict[str, Any]) -> Dict[str, str]:
    at = (cfg.get("auth_type") or "none").lower()
    if at == "basic":
        user = cfg.get("username") or ""
        pwd = cfg.get("password") or ""
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        return {"Authorization": f"Basic {token}"}
    if at == "bearer":
        token = cfg.get("token") or ""
        return {"Authorization": f"Bearer {token}"}
    if at == "header":
        key = cfg.get("auth_header_key") or "Authorization"
        val = cfg.get("auth_header_value") or ""
        return {key: val}
    return {}


def _taxii_headers(cfg: Dict[str, Any], *, accept: str = "application/taxii+json;version=2.1") -> Dict[str, str]:
    h = {
        "Accept": accept,
        "Content-Type": "application/taxii+json;version=2.1",
    }
    h.update(_auth_headers(cfg))
    return h


# ------------------------------------------------------------------
# STIX 2.1 object builders (minimal — indicator + observed-data)
# ------------------------------------------------------------------
def _stix_id(otype: str) -> str:
    return f"{otype}--{uuid.uuid4()}"


def _now_stix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _identity_object(name: str = "NivXRay") -> Dict[str, Any]:
    now = _now_stix()
    return {
        "type": "identity",
        "spec_version": STIX_VERSION,
        "id": _stix_id("identity"),
        "created": now,
        "modified": now,
        "name": name,
        "identity_class": "system",
    }


def _pattern_for(kind: str, value: str) -> Optional[str]:
    """Return a STIX 2.1 indicator pattern for a NivXRay IOC kind."""
    v = value.replace("'", "\\'")
    if kind == "url":
        return f"[url:value = '{v}']"
    if kind == "ipv4" or kind == "ip":
        return f"[ipv4-addr:value = '{v}']"
    if kind == "ipv6":
        return f"[ipv6-addr:value = '{v}']"
    if kind == "domain":
        return f"[domain-name:value = '{v}']"
    if kind == "email":
        return f"[email-addr:value = '{v}']"
    if kind == "md5":
        return f"[file:hashes.'MD5' = '{v}']"
    if kind == "sha1":
        return f"[file:hashes.'SHA-1' = '{v}']"
    if kind == "sha256":
        return f"[file:hashes.'SHA-256' = '{v}']"
    if kind == "file_path":
        return f"[file:name = '{v}']"
    return None


def _indicator_object(
    kind: str, value: str, identity_ref: str,
    labels: Optional[List[str]] = None, description: str = "",
) -> Optional[Dict[str, Any]]:
    pattern = _pattern_for(kind, value)
    if not pattern:
        return None
    now = _now_stix()
    obj: Dict[str, Any] = {
        "type": "indicator",
        "spec_version": STIX_VERSION,
        "id": _stix_id("indicator"),
        "created": now,
        "modified": now,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "indicator_types": labels or ["malicious-activity"],
        "created_by_ref": identity_ref,
        "name": f"NivXRay {kind} — {value[:80]}",
        "description": description or f"IOC extracted by NivXRay ({kind}).",
    }
    return obj


def build_stix_bundle(iocs: Dict[str, List[str]], *, identity_name: str = "NivXRay",
                       description: str = "") -> Dict[str, Any]:
    """Compose a STIX 2.1 Bundle from a NivXRay IOC dict.

    Args:
        iocs: {"urls":[...], "ips":[...], "domains":[...], "md5":[...], ...}
        identity_name: name of the STIX identity object (created by).
        description: attached to every indicator.

    Returns:
        A dict shaped as {type: "bundle", id: ..., objects: [...]}.
    """
    identity = _identity_object(identity_name)
    identity_id = identity["id"]

    objects: List[Dict[str, Any]] = [identity]

    kind_map = {
        "urls": "url", "url": "url",
        "ips": "ipv4", "ipv4": "ipv4", "ipv6": "ipv6",
        "domains": "domain", "domain": "domain",
        "emails": "email", "email": "email",
        "md5": "md5", "sha1": "sha1", "sha256": "sha256",
        "file_paths": "file_path", "paths": "file_path",
    }
    for key, values in (iocs or {}).items():
        kind = kind_map.get(key)
        if not kind or not values:
            continue
        for value in values:
            ind = _indicator_object(kind, value, identity_id,
                                      description=description)
            if ind:
                objects.append(ind)

    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }


# ------------------------------------------------------------------
# TAXII 2.1 push
# ------------------------------------------------------------------
async def test_connection(db) -> Dict[str, Any]:
    """Hit the TAXII discovery endpoint to verify connectivity + auth."""
    cfg = await get_config(db)
    server = (cfg.get("server_url") or "").rstrip("/")
    if not server:
        return {"ok": False, "error": "server_url not configured"}
    url = f"{server}/taxii2/"
    try:
        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            verify=bool(cfg.get("verify_tls", True)),
        ) as client:
            resp = await client.get(url, headers=_taxii_headers(cfg))
            body_preview = resp.text[:400]
            return {
                "ok": 200 <= resp.status_code < 300,
                "status_code": resp.status_code,
                "server_url": server,
                "response_preview": body_preview,
            }
    except Exception as e:
        return {"ok": False, "error": str(e), "server_url": server}


async def push_stix_bundle(db, bundle: Dict[str, Any]) -> Dict[str, Any]:
    """POST a STIX 2.1 Bundle to the configured TAXII collection's objects endpoint.

    Records the result to `taxii_push_log` regardless of success/failure.
    """
    cfg = await get_config(db)
    server = (cfg.get("server_url") or "").rstrip("/")
    collection_id = cfg.get("collection_id") or ""
    api_root = cfg.get("api_root") or "taxii2"
    if not server or not collection_id:
        result = {
            "ok": False,
            "error": "server_url or collection_id not configured",
            "config": _redact(cfg),
        }
        await _log_push(db, bundle, result)
        return result

    url = f"{server}/{api_root.strip('/')}/collections/{collection_id}/objects/"
    payload = {
        "objects": bundle.get("objects", []),
    }
    try:
        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            verify=bool(cfg.get("verify_tls", True)),
        ) as client:
            resp = await client.post(
                url,
                json=payload,
                headers=_taxii_headers(cfg),
            )
            body_preview = resp.text[:600]
            result = {
                "ok": 200 <= resp.status_code < 300,
                "status_code": resp.status_code,
                "url": url,
                "response_preview": body_preview,
                "objects_sent": len(payload["objects"]),
            }
    except Exception as e:
        result = {"ok": False, "error": str(e), "url": url,
                  "objects_sent": len(payload["objects"])}

    await _log_push(db, bundle, result)
    return result


async def _log_push(db, bundle: Dict[str, Any], result: Dict[str, Any]) -> None:
    entry = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "bundle_id": bundle.get("id"),
        "object_count": len(bundle.get("objects", [])),
        "result": result,
    }
    try:
        await db[COLLECTION_LOG].insert_one(entry)
    except Exception:
        pass


async def list_push_log(db, limit: int = 50) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 50), 200))
    cursor = db[COLLECTION_LOG].find({}).sort("created_at", -1).limit(limit)
    rows: List[Dict[str, Any]] = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        rows.append(doc)
    return rows
