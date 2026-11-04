"""Emergent managed object storage client for the media lane.

Isolated from the GridFS evidence FileStore (``services/files/store.py``).
This lane carries user-facing media/documents only — never EDR evidence.
"""
from __future__ import annotations

import os
import threading

import requests

# `or`, not a default= argument: the platform sets this to "" when it has no value.
STORAGE_BASE = (os.environ.get("INTEGRATION_PROXY_URL") or "").strip() or "https://integrations.emergentagent.com"
STORAGE_URL = STORAGE_BASE.rstrip("/") + "/objstore/api/v1/storage"

APP_NAME = "nivxforge"

_storage_key: str | None = None
_lock = threading.Lock()


class MediaStorageError(Exception):
    def __init__(self, reason: str, status: int = 502, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.detail = detail

    def to_dict(self) -> dict:
        return {"reason": self.reason, "detail": self.detail}


def _emergent_key() -> str:
    key = (os.environ.get("EMERGENT_LLM_KEY") or "").strip()
    if not key:
        raise MediaStorageError("storage_not_configured", 503,
                                "EMERGENT_LLM_KEY is not set")
    return key


def init_storage(force: bool = False) -> str:
    """Mint (or reuse) the session-scoped storage key.

    force=True discards the cached key — the only way to recover from a key
    that went inactive mid-session.
    """
    global _storage_key
    with _lock:
        if _storage_key and not force:
            return _storage_key
        resp = requests.post(f"{STORAGE_URL}/init",
                             json={"emergent_key": _emergent_key()}, timeout=30)
        if resp.status_code != 200:
            raise MediaStorageError("storage_init_failed", 503,
                                    f"HTTP {resp.status_code}: {resp.text[:200]}")
        _storage_key = resp.json()["storage_key"]
        return _storage_key


def _raise_for(resp: requests.Response, op: str) -> None:
    code = resp.status_code
    if code == 402:
        raise MediaStorageError("storage_suspended", 402, "Object storage billing suspended")
    if code == 403:
        raise MediaStorageError("storage_forbidden", 403, "Object storage disabled for this account")
    if code == 439:
        raise MediaStorageError("storage_quota_exceeded", 507, "Storage quota exceeded")
    if code == 404:
        raise MediaStorageError("object_not_found", 404, f"{op}: path or key unknown")
    raise MediaStorageError("storage_error", 502, f"{op}: HTTP {code}: {resp.text[:200]}")


def put_object(path: str, data: bytes, content_type: str) -> dict:
    """Upload bytes. Returns {"path", "size", "etag"}. Retries once on a dead key."""
    for attempt in (0, 1):
        key = init_storage(force=bool(attempt))
        resp = requests.put(f"{STORAGE_URL}/objects/{path}",
                            headers={"X-Storage-Key": key, "Content-Type": content_type},
                            data=data, timeout=180)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404 and attempt == 0:
            continue  # cached key went inactive — re-init once
        _raise_for(resp, "put_object")
    raise MediaStorageError("storage_error", 502, "put_object exhausted retries")


def get_object(path: str) -> tuple[bytes, str]:
    """Download an object. Returns (content_bytes, content_type)."""
    for attempt in (0, 1):
        key = init_storage(force=bool(attempt))
        resp = requests.get(f"{STORAGE_URL}/objects/{path}",
                            headers={"X-Storage-Key": key}, timeout=120)
        if resp.status_code == 200:
            return resp.content, resp.headers.get("Content-Type", "application/octet-stream")
        if resp.status_code == 404 and attempt == 0:
            continue
        _raise_for(resp, "get_object")
    raise MediaStorageError("storage_error", 502, "get_object exhausted retries")


def object_path(tenant_id: str, asset_id: str, ext: str) -> str:
    """nivxforge/media/{tenant}/{uuid}.{ext} — no leading slash."""
    safe_tenant = "".join(c for c in (tenant_id or "default") if c.isalnum() or c in "-_") or "default"
    safe_ext = "".join(c for c in (ext or "bin") if c.isalnum())[:12] or "bin"
    return f"{APP_NAME}/media/{safe_tenant}/{asset_id}.{safe_ext}"


def storage_ready() -> bool:
    try:
        init_storage()
        return True
    except Exception:
        return False
