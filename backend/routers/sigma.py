"""Sigma rule emit router — Feb 2026.

POST /api/emit/sigma → analyst clicks a button in Workspace and gets a
paste-ready Sigma detection rule based on the current investigation.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from deps import get_current_user
import sigma_generator

router = APIRouter()


class SigmaIn(BaseModel):
    input:    str = ""
    output:   str = ""
    mitre:    List[Any]      = Field(default_factory=list)
    lolbas:   List[Any]      = Field(default_factory=list)
    iocs:     Dict[str, Any] = Field(default_factory=dict)
    verdict:  Optional[Dict[str, Any]] = None
    title:    Optional[str] = None


@router.post("/emit/sigma")
async def emit_sigma_endpoint(body: SigmaIn, user=Depends(get_current_user)):
    yaml_text = sigma_generator.emit_sigma(
        payload=body.input,
        output=body.output,
        mitre=body.mitre,
        lolbas=body.lolbas,
        iocs=body.iocs or {},
        verdict=body.verdict,
        title=body.title,
    )
    return {"sigma_yaml": yaml_text, "bytes": len(yaml_text)}
