"""Tenant Privacy admin router — Feb 2026.

Endpoints:
  GET  /api/admin/privacy/settings    → current tenant privacy config
  PUT  /api/admin/privacy/settings    → update settings (admin only)
  GET  /api/admin/privacy/audit       → last N audit-log entries
  POST /api/admin/privacy/purge-now   → force TTL re-application (admin only)
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from deps import get_current_user
import privacy


router = APIRouter()


def _email(user: Any) -> Optional[str]:
    return getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)


def _role(user: Any) -> Optional[str]:
    return getattr(user, "role", None) or (user.get("role") if isinstance(user, dict) else None)


def _admin(user: Any):
    if _role(user) != "admin":
        raise HTTPException(status_code=403, detail="admin role required")


class SettingsPatch(BaseModel):
    local_only_mode:         Optional[bool] = None
    ti_default_enabled:      Optional[bool] = None
    ti_hash_only_mode:       Optional[bool] = None
    investigation_ttl_days:  Optional[int]  = None
    workspace_case_ttl_days: Optional[int]  = None
    enforce_https_only:      Optional[bool] = None


@router.get("/admin/privacy/settings")
async def get_settings(user=Depends(get_current_user)):
    s = privacy.get_settings()
    s.pop("_id", None)
    return s


@router.put("/admin/privacy/settings")
async def update_settings(body: SettingsPatch, user=Depends(get_current_user)):
    _admin(user)
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    if not patch:
        raise HTTPException(status_code=400, detail="no settings to update")
    s = privacy.update_settings(patch, actor=_email(user))
    ttl_result = privacy.ensure_ttl_indexes()
    s.pop("_id", None)
    return {"settings": s, "ttl_indexes": ttl_result}


@router.get("/admin/privacy/audit")
async def get_audit(limit: int = 50, user=Depends(get_current_user)):
    _admin(user)
    cur = privacy._col_audit.find(
        {}, {"_id": 0}
    ).sort("ts", -1).limit(min(int(limit), 500))
    return {"rows": list(cur)}


@router.post("/admin/privacy/purge-now")
async def purge_now(user=Depends(get_current_user)):
    _admin(user)
    return {"ttl_indexes": privacy.ensure_ttl_indexes()}
