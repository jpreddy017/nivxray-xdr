"""Static analyzer routes mounted under the existing EDR Forensics router."""
import json
import os
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from deps import get_current_user
from edr_decode.forensics_runner import ForensicsRunner
from edr_decode.reputation import ReputationService
from edr_decode.reputation_transport import ReputationTransport
from edr_decode.runner import DecodeUnavailable
from routers.edr_tenancy import edr_scope, edr_tenant

router = APIRouter()
runner = ForensicsRunner()


async def provider_key(tenant_id: str, name: str):
    # Only explicit EDR-owned, tenant-scoped provider keys are eligible.
    try:
        config = json.loads(os.environ.get("EDR_FORENSICS_PROVIDER_KEYS", "{}"))
        tenant = config.get(tenant_id, {})
        key = tenant.get(name)
    except (ValueError, AttributeError):
        return None
    if isinstance(key, str) and key and not any(ord(char) < 32 for char in key):
        return key
    return None


reputation = ReputationService(ReputationTransport(secret_resolver=provider_key))


class CommandInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["command"]
    command_line: str = Field(min_length=1, max_length=65536)


class IndicatorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["ip", "domain", "url", "hash"]
    value: str = Field(min_length=1, max_length=2048)


@router.post("/command-analysis")
async def command_analysis(
    body: CommandInput,
    response: Response,
    user: dict = Depends(get_current_user),
    tenant_id: str = Depends(edr_tenant),
):
    edr_scope(tenant_id, user)
    response.headers["Cache-Control"] = "no-store"
    submission = body.model_dump()
    try:
        report = await runner.analyze(submission)
    except ValueError:
        raise HTTPException(422, "Command must be non-empty UTF-8 text up to 64 KiB") from None
    except DecodeUnavailable:
        raise HTTPException(503, "Static command analysis is temporarily unavailable") from None
    return {
        "artifact_id": report["input_sha256"],
        "submission": submission,
        "report": report,
    }


@router.post("/ioc-reputation")
async def ioc_reputation(
    body: IndicatorInput,
    response: Response,
    user: dict = Depends(get_current_user),
    tenant_id: str = Depends(edr_tenant),
):
    edr_scope(tenant_id, user)
    response.headers["Cache-Control"] = "no-store"
    try:
        return await reputation.lookup(tenant_id=tenant_id, kind=body.kind, value=body.value)
    except ValueError:
        raise HTTPException(422, "Indicator is invalid or ineligible for external lookup") from None
