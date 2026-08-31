"""NivXRay — Shared dependencies: DB client, auth helpers, LLM helpers, settings.

Extracted from server.py during the Feb-2026 modularization refactor.
Every router imports auth / db / LLM helpers from here so there's ONE source
of truth for cross-cutting concerns.

Import-time contract (Feb-21 2026 refactor)
-------------------------------------------
This module MUST NOT perform any side effects at import time:
  * NO required `os.environ["X"]` lookups (only safe `.get(..., default)`)
  * NO Mongo client construction (no `AsyncIOMotorClient(...)`)
  * NO network I/O, DB I/O, or LLM SDK imports

Runtime configuration & DB initialization live in two explicit hooks:
  * `validate_config()`  — raises RuntimeError if required env vars missing
  * `init_database()`    — constructs the Motor client & binds the `client`
                           and `db` proxies

Both are called from `server.py`'s `@app.on_event("startup")` handler so
uvicorn/production still fail-fast when misconfigured, while pytest can
freely import `deps` (and every module that transitively imports it)
without a live Mongo, without secrets, and without a `.env` file.
"""
from __future__ import annotations
import json
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient

# NOTE: `emergentintegrations` is a private-CDN wheel that the RC4.x CI
# strips from `requirements-ci.txt`. Kept out of module scope so pytest
# collection works without the wheel — real routes lazy-import inside
# `new_chat()` / `llm_json()` / `llm_text()`.
if TYPE_CHECKING:  # pragma: no cover — type hints only
    from emergentintegrations.llm.chat import LlmChat  # noqa: F401
    from motor.motor_asyncio import AsyncIOMotorDatabase  # noqa: F401


ROOT_DIR = Path(__file__).parent
# `load_dotenv` is idempotent, has no external side effects when the
# file is absent (which is the case in CI), and only mutates os.environ.
# Left at module scope so tests can still pick up a developer's local .env.
load_dotenv(ROOT_DIR / ".env")

# --- Configuration ------------------------------------------------------ #
# All required config is read via safe `.get(..., "")` so importing this
# module never raises. Validation happens in `validate_config()` below.
_REQUIRED_ENV = (
    "MONGO_URL", "DB_NAME", "JWT_SECRET",
    "ADMIN_EMAIL", "ADMIN_PASSWORD", "EMERGENT_LLM_KEY",
)

MONGO_URL = os.environ.get("MONGO_URL", "")
DB_NAME = os.environ.get("DB_NAME", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY", "")

JWT_ALG = "HS256"
# Configurable via env — defaults to 24 h. Post-Feb-2026 security audit
# (SEC-002) shortened this from 7 days → 24 h.
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))
# When true, the seeded admin user is created with must_change_password=True
# so the first-boot password (or any rotation) must be replaced before the
# admin can call any authenticated route other than /api/auth/change-password.
_ADMIN_FORCE_PW_CHANGE = os.environ.get("ADMIN_FORCE_PASSWORD_CHANGE", "false").lower() in ("1", "true", "yes")


def validate_config() -> None:
    """Fail-fast validator — raises if any required env var is missing.

    Invoked from `server.py`'s FastAPI startup event so uvicorn refuses
    to serve a mis-configured pod. NOT called at import time so pytest
    can collect without a full `.env`.
    """
    missing = [k for k in _REQUIRED_ENV if not os.environ.get(k)]
    if missing:
        raise RuntimeError(
            f"NivXRay config error — missing required env var(s): {missing}. "
            "Populate backend/.env before starting the server."
        )


# ---------------------------------------------------------------------------
# RC5 · Feature flag reader — § 14 of RC5_SEMANTIC_ENGINE_SPEC.md
# ---------------------------------------------------------------------------
def semantic_engine_v2_enabled() -> bool:
    """Return True when `SEMANTIC_ENGINE_V2` env var is truthy.

    Default is False so Phase 1 lands with zero production impact. Flipped
    to True on Prod only at Phase 10 cutover after the 30-day shadow-run
    gate passes.
    """
    return os.environ.get("SEMANTIC_ENGINE_V2", "false").lower() in ("1", "true", "yes", "on")


# --- DB proxy singletons ------------------------------------------------ #
# `client` and `db` are exposed as proxy objects so every existing
# `from deps import db` import site keeps working (there are 30+ of
# them across routers). The proxies contain no Motor client at import
# time — `init_database()` binds a real client at FastAPI startup.
class _MotorProxy:
    """Proxy that forwards attribute + item access to a Motor client/db.

    Raises RuntimeError if used before `init_database()` runs — so a
    test that accidentally hits DB code without proper setup fails
    loudly instead of silently talking to a placeholder.
    """
    __slots__ = ("_real", "_name")

    def __init__(self, name: str) -> None:
        object.__setattr__(self, "_real", None)
        object.__setattr__(self, "_name", name)

    def _bind(self, real: Any) -> None:
        object.__setattr__(self, "_real", real)

    def _require(self) -> Any:
        real = object.__getattribute__(self, "_real")
        if real is None:
            name = object.__getattribute__(self, "_name")
            raise RuntimeError(
                f"deps.{name} accessed before init_database(). "
                "Call validate_config() + init_database() at FastAPI "
                "startup, or install a test fixture that binds it."
            )
        return real

    def __getattr__(self, key: str) -> Any:
        return getattr(self._require(), key)

    def __getitem__(self, key: str) -> Any:
        return self._require()[key]

    def __repr__(self) -> str:
        bound = object.__getattribute__(self, "_real") is not None
        name = object.__getattribute__(self, "_name")
        return f"<_MotorProxy name={name!r} bound={bound}>"


client: Any = _MotorProxy("client")
db: Any = _MotorProxy("db")
security = HTTPBearer()


def init_database() -> None:
    """Construct the real Motor client & bind the `client` / `db` proxies.

    Idempotent — safe to call multiple times. If the previously bound
    client has been closed (e.g. by a FastAPI TestClient teardown in
    a prior pytest module), we transparently rebind a fresh Motor
    client so subsequent DB access does not raise
    ``InvalidOperation: Cannot use MongoClient after close``.

    Called from `server.py`'s FastAPI startup handler AFTER
    `validate_config()` succeeds.
    """
    # Refuse to bind without validated config — belt-and-suspenders.
    validate_config()
    real = object.__getattribute__(client, "_real")
    # Detect a stale/closed client (Motor wraps pymongo; a closed
    # pymongo client exposes ``.topology_description.readable_servers``
    # emptiness — but the cleanest signal is the underlying `_topology`
    # `_opened_events` count, which we access via the guarded shim
    # below).
    stale = False
    if real is not None:
        try:
            inner = real.delegate  # pymongo.MongoClient
            # Motor exposes `.delegate`; if not, treat as healthy.
            topo = getattr(inner, "_topology", None)
            if topo is not None and getattr(topo, "_closed", False):
                stale = True
        except Exception:  # noqa: BLE001
            pass
    if real is None or stale:
        real_client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        real_db = real_client[os.environ["DB_NAME"]]
        client._bind(real_client)
        db._bind(real_db)


# --- Sync pymongo access for legacy read-heavy paths ------------------- #
# A handful of routers (cases, learner, lab, batch_test, public_feeds)
# use the *synchronous* pymongo driver for read-heavy paths. Instead of
# each creating its own module-scope `MongoClient(os.environ.get(...))`
# — which is an import-time side effect and duplicates state — they now
# import `sync_collection("<name>")` from here. The returned proxy resolves
# the underlying `pymongo.Collection` on first use (via `get_sync_db()`),
# after `validate_config()` has succeeded.
_sync_client: Any = None


def _get_sync_client() -> Any:
    """Return (and memoize) the process-wide sync pymongo client.

    Fails fast via `validate_config()` if required env vars are missing.
    """
    global _sync_client
    if _sync_client is None:
        validate_config()
        from pymongo import MongoClient
        _sync_client = MongoClient(os.environ["MONGO_URL"])
    return _sync_client


def get_sync_db() -> Any:
    """Return the sync pymongo Database. Lazily initialised on first call."""
    return _get_sync_client()[os.environ["DB_NAME"]]


class _SyncCollectionProxy:
    """Lazy proxy for a sync pymongo Collection.

    Resolves the real collection on first attribute access — so a router
    can do `_col = sync_collection("workspace_cases")` at import time
    without touching the DB, and `_col.find(...)` inside a route handler
    still works exactly as before.
    """
    __slots__ = ("_col_name", "_real")

    def __init__(self, collection_name: str) -> None:
        object.__setattr__(self, "_col_name", collection_name)
        object.__setattr__(self, "_real", None)

    def _resolve(self) -> Any:
        real = object.__getattribute__(self, "_real")
        if real is None:
            name = object.__getattribute__(self, "_col_name")
            real = get_sync_db()[name]
            object.__setattr__(self, "_real", real)
        return real

    def __getattr__(self, key: str) -> Any:
        return getattr(self._resolve(), key)

    def __getitem__(self, key: Any) -> Any:
        return self._resolve()[key]

    def __repr__(self) -> str:
        name = object.__getattribute__(self, "_col_name")
        bound = object.__getattribute__(self, "_real") is not None
        return f"<_SyncCollectionProxy name={name!r} bound={bound}>"


def sync_collection(name: str) -> _SyncCollectionProxy:
    """Factory for a lazy sync pymongo collection proxy."""
    return _SyncCollectionProxy(name)


# --- Password / JWT ----------------------------------------------------- #
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = await db.users.find_one({"email": email}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # Force password change gate — 428 signals the client to redirect to
    # the change-password modal before making any other authenticated
    # request. The change-password endpoint itself uses `get_current_user_raw`
    # (defined below) which bypasses this gate.
    if user.get("must_change_password"):
        raise HTTPException(status_code=428, detail="password_change_required")
    return user


async def get_current_user_raw(creds: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Same as ``get_current_user`` but SKIPS the must_change_password gate.

    Only the change-password endpoint should use this dependency. Every
    other authenticated route MUST use ``get_current_user`` so a stale
    session can't touch data before rotating a compromised password.
    """
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = await db.users.find_one({"email": email}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


_security_optional = HTTPBearer(auto_error=False)


async def get_current_user_optional(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_security_optional),
) -> Optional[Dict[str, Any]]:
    """Return the authenticated user, or ``None`` when no valid bearer
    token was presented.  Used by capabilities (Operations Dashboard,
    scoped incident list) that must serve an honest empty state to
    unauthenticated callers rather than 403.

    Never raises for missing / invalid tokens — the caller decides
    how to degrade.  A ``must_change_password`` flag on the user
    still short-circuits to ``None`` to prevent stale-session leakage.
    """
    if creds is None:
        return None
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        email = payload.get("sub")
    except jwt.PyJWTError:
        return None
    if not email:
        return None
    user = await db.users.find_one({"email": email}, {"_id": 0, "password": 0})
    if not user or user.get("must_change_password"):
        return None
    return user



async def require_admin(user=Depends(get_current_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def seed_admin(logger) -> None:
    """Idempotent admin seed — only creates the admin when missing.

    Feb-2026 (SEC-001): NEVER re-set the password on an existing admin
    account (the previous implementation didn't re-set either — this
    docstring makes the guarantee explicit). If the environment carries
    `ADMIN_FORCE_PASSWORD_CHANGE=true`, the seeded user is marked with
    `must_change_password=True` so the first login is forced through
    `/api/auth/change-password` before any other authenticated route
    can be used.
    """
    existing = await db.users.find_one({"email": ADMIN_EMAIL})
    if existing:
        return
    await db.users.insert_one({
        "email": ADMIN_EMAIL,
        "password": hash_password(ADMIN_PASSWORD),
        "role": "admin",
        "must_change_password": _ADMIN_FORCE_PW_CHANGE,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    logger.info(
        f"Seeded admin user: {ADMIN_EMAIL} "
        f"(must_change_password={_ADMIN_FORCE_PW_CHANGE})"
    )


# --- Settings ----------------------------------------------------------- #
async def load_osint_keys() -> Dict[str, str]:
    doc = await db.settings.find_one({"_id": "osint_keys"}) or {}
    return doc.get("keys", {})


def mask(v: str) -> str:
    if not v: return ""
    if len(v) <= 8: return "•" * len(v)
    return v[:4] + "•" * max(4, len(v) - 8) + v[-4:]


# --- LLM helpers -------------------------------------------------------- #
def new_chat(session_id: str, system: str,
             provider: str = "anthropic", model: str = "claude-sonnet-4-5-20250929") -> "LlmChat":
    # Lazy import — see module-header note about the RC4.x CI wheel filter.
    from emergentintegrations.llm.chat import LlmChat
    return LlmChat(
        api_key=EMERGENT_LLM_KEY,
        session_id=session_id,
        system_message=system,
    ).with_model(provider, model)


async def llm_json(session_id: str, system: str, user: str, retries: int = 2,
                   provider: str = "anthropic", model: str = "claude-sonnet-4-5-20250929") -> Dict[str, Any]:
    """Send a prompt and parse JSON. Retries with exponential backoff on
    empty responses / parse errors — a common Claude edge-case that used
    to bubble up as `Expecting value: line 1 column 1 (char 0)` 502s."""
    import asyncio as _asyncio
    from emergentintegrations.llm.chat import UserMessage  # lazy — see header note
    last_err: Any = None
    for attempt in range(retries + 1):
        chat = new_chat(session_id, system, provider=provider, model=model)
        try:
            resp = await chat.send_message(UserMessage(text=user))
            raw = resp if isinstance(resp, str) else str(resp)
            cleaned = raw.strip()
            if not cleaned:
                # Empty upstream response — retry with linear backoff before
                # 502-ing so a transient rate-limit / content-filter miss
                # doesn't kill the whole request.
                last_err = "empty response from LLM"
                if attempt < retries:
                    await _asyncio.sleep(0.6 * (attempt + 1))
                continue
            m = re.search(r"```(?:json)?\s*(.*?)\s*```", cleaned, re.DOTALL)
            if m: cleaned = m.group(1)
            if not cleaned.lstrip().startswith("{"):
                m2 = re.search(r"\{.*\}", cleaned, re.DOTALL)
                if m2: cleaned = m2.group(0)
            return json.loads(cleaned)
        except Exception as e:
            last_err = e
            if attempt < retries:
                await _asyncio.sleep(0.4 * (attempt + 1))
    raise HTTPException(status_code=502, detail=f"LLM JSON parse failed: {last_err}")


async def llm_text(session_id: str, system: str, user: str) -> str:
    from emergentintegrations.llm.chat import UserMessage  # lazy — see header note
    chat = new_chat(session_id, system)
    try:
        r = await chat.send_message(UserMessage(text=user))
        return r if isinstance(r, str) else str(r)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM error: {e}")
