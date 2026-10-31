"""Machine-principal rate limiting for XDR collector API keys.

P1 gap closed (2026-06): the `X-XDR-API-Key` machine auth path had no
throttle on key id / tenant / source IP, so a leaked production ingest
credential could flood `/api/xdr/ingest/telemetry`.

Design constraints (owner-locked):
  * MongoDB is the ONLY shared store — no Redis, no hosted service.
  * FAIL CLOSED. If the limiter cannot establish its own state the
    protected request is refused (503), never allowed through.
  * Atomic fixed window via a single `find_one_and_update` upsert, so
    concurrent requests can never overshoot the limit.
  * The TTL index is CLEANUP only. Enforcement is the window arithmetic
    below, because TTL deletion is asynchronous (~60s).
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

from pymongo import ASCENDING, MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME = os.environ.get("DB_NAME") or "test_database"
_client: MongoClient | None = None

_COLLECTION = "xdr_machine_rate_buckets"

WINDOW_SECONDS = int(os.environ.get("XDR_MACHINE_RATE_WINDOW_SECONDS") or 60)
LIMITS: dict[str, int] = {
    "ip": int(os.environ.get("XDR_MACHINE_RATE_LIMIT_IP") or 600),
    "key": int(os.environ.get("XDR_MACHINE_RATE_LIMIT_KEY") or 600),
    "tenant": int(os.environ.get("XDR_MACHINE_RATE_LIMIT_TENANT") or 1200),
}

_indexes_ready = False


class RateLimitExceeded(Exception):
    def __init__(self, scope: str, limit: int, retry_after: int,
                 remaining: int = 0):
        self.scope = scope
        self.limit = limit
        self.retry_after = retry_after
        self.remaining = remaining
        super().__init__(f"{scope} rate limit of {limit}/{WINDOW_SECONDS}s exceeded")


class RateLimitUnavailable(Exception):
    """The limiter could not read/write its own state — fail closed."""


def _coll():
    """Bind lazily — the process may load its .env after import time."""
    global _client, _DB_NAME, _indexes_ready
    if _client is None:
        url = os.environ.get("MONGO_URL")
        if not url:
            raise RateLimitUnavailable("rate-limit store unavailable")
        _DB_NAME = os.environ.get("DB_NAME") or _DB_NAME
        _client = MongoClient(url)
    c = _client[_DB_NAME][_COLLECTION]
    if not _indexes_ready:
        try:
            c.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0,
                           name="machine_rate_bucket_ttl")
        except PyMongoError:
            pass  # cleanup index only; enforcement does not depend on it
        _indexes_ready = True
    return c


def _subject_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def consume(scope: str, subject: str) -> dict:
    """Count one request against `scope:subject`.

    Raises `RateLimitExceeded` when the window quota is spent and
    `RateLimitUnavailable` on any store fault.
    """
    limit = LIMITS.get(scope)
    if not limit or limit <= 0:
        raise RateLimitUnavailable(f"no limit configured for scope '{scope}'")
    coll = _coll()
    now = datetime.now(timezone.utc)
    epoch = int(now.timestamp())
    start_epoch = epoch - (epoch % WINDOW_SECONDS)
    start = datetime.fromtimestamp(start_epoch, timezone.utc)
    expires = start + timedelta(seconds=WINDOW_SECONDS)
    reset = max(1, int((expires - now).total_seconds()))
    bucket_id = f"{scope}:{_subject_digest(subject)}:{start_epoch}"

    try:
        doc = coll.find_one_and_update(
            {"_id": bucket_id},
            {"$setOnInsert": {"scope": scope, "limit": limit,
                              "window_seconds": WINDOW_SECONDS,
                              "window_start": start, "expires_at": expires},
             "$inc": {"count": 1}},
            upsert=True, return_document=ReturnDocument.AFTER)
    except DuplicateKeyError:
        try:
            doc = coll.find_one_and_update(
                {"_id": bucket_id}, {"$inc": {"count": 1}},
                return_document=ReturnDocument.AFTER)
        except PyMongoError as ex:
            raise RateLimitUnavailable(str(ex)) from ex
    except PyMongoError as ex:
        raise RateLimitUnavailable(str(ex)) from ex

    if not doc:
        raise RateLimitUnavailable("rate-limit update returned no document")
    count = int(doc.get("count") or 0)
    remaining = max(0, limit - count)
    if count > limit:
        raise RateLimitExceeded(scope, limit, reset)
    return {"scope": scope, "limit": limit, "remaining": remaining,
            "reset": reset, "count": count}


def headers(state: dict) -> dict[str, str]:
    return {
        "RateLimit-Limit": str(state["limit"]),
        "RateLimit-Remaining": str(state["remaining"]),
        "RateLimit-Reset": str(state["reset"]),
        "RateLimit-Policy": f'"{state["scope"]}";q={state["limit"]};w={WINDOW_SECONDS}',
    }
