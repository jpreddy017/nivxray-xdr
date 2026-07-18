"""NivXRay — Shared dependencies: DB client, auth helpers, LLM helpers, settings.

Extracted from server.py during the Feb-2026 modularization refactor.
Every router imports auth / db / LLM helpers from here so there's ONE source
of truth for cross-cutting concerns.
"""
from __future__ import annotations
import json
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient

from emergentintegrations.llm.chat import LlmChat, UserMessage


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# --- Config ------------------------------------------------------------- #
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ["JWT_SECRET"]
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
EMERGENT_LLM_KEY = os.environ["EMERGENT_LLM_KEY"]

JWT_ALG = "HS256"
# Configurable via env — defaults to 24 h. Post-Feb-2026 security audit
# (SEC-002) shortened this from 7 days → 24 h.
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))
# When true, the seeded admin user is created with must_change_password=True
# so the first-boot password (or any rotation) must be replaced before the
# admin can call any authenticated route other than /api/auth/change-password.
_ADMIN_FORCE_PW_CHANGE = os.environ.get("ADMIN_FORCE_PASSWORD_CHANGE", "false").lower() in ("1", "true", "yes")

# --- Global singletons -------------------------------------------------- #
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]
security = HTTPBearer()


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
             provider: str = "anthropic", model: str = "claude-sonnet-4-5-20250929") -> LlmChat:
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
    chat = new_chat(session_id, system)
    try:
        r = await chat.send_message(UserMessage(text=user))
        return r if isinstance(r, str) else str(r)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM error: {e}")
