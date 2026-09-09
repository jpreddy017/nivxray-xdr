"""Behavior Registry API · read-only catalog of the semantic vocabulary."""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from services.ida.behavior_registry import (
    REGISTRY_SCHEMA_VERSION, build_registry,
)


router = APIRouter(tags=["behavior-registry"])


@router.get("/behaviors/registry")
def list_registry() -> Dict[str, Any]:
    reg = build_registry()
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "count":          len(reg),
        "behaviors":      [spec.to_dict() for spec in reg.values()],
    }


@router.get("/behaviors/registry/{behavior_type}")
def get_registry_entry(behavior_type: str) -> Dict[str, Any]:
    reg = build_registry()
    spec = reg.get(behavior_type)
    if spec is None:
        raise HTTPException(status_code=404,
                                detail=f"unknown behavior_type: {behavior_type}")
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "behavior":       spec.to_dict(),
    }


__all__ = ["router"]
