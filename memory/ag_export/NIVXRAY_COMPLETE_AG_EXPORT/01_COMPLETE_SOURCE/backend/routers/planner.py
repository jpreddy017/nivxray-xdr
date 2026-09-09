"""Layer validator + predictive planner API endpoints."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from deps import get_current_user
from layer_validator import validate_base64, validate_hex, validate_url_encoded, \
    validate_hex_family, plan_next, full_trace

router = APIRouter()


class AdvisorIn(BaseModel):
    input: str


class TraceIn(BaseModel):
    steps: List[Dict[str, Any]]  # [{"op": "...", "output": "..."}]


@router.post("/planner/advise")
async def advise(body: AdvisorIn, user=Depends(get_current_user)):
    """Return real-time hints about what the input looks like + which
    decoder button the analyst should click next."""
    text = body.input or ""
    hints = plan_next(text)
    # Also run quick structural checks so the UI can show a health chip
    checks = {
        "base64":     validate_base64(text) if len(text) >= 20 else {"valid": False, "reason": "too short", "salvage": None},
        "hex":        validate_hex(text) if len(text) >= 20 else {"valid": False, "reason": "too short", "salvage": None},
        "url":        validate_url_encoded(text) if "%" in text else {"valid": False, "reason": "no %-escapes", "salvage": None},
        "hex_family": validate_hex_family(text),
    }
    return {"hints": hints, "structural_checks": checks, "input_length": len(text)}


@router.post("/planner/trace")
async def trace(body: TraceIn, user=Depends(get_current_user)):
    """Given a full decoded chain of steps, return per-layer health with
    exact rule violations + salvage suggestions."""
    return full_trace(body.steps)
