"""NivXForge Connector · Management → Downloads, productized.

The Cisco Secure Endpoint administrator workflow, reproduced:

    Management -> Downloads -> Windows Connector -> Version -> Group
    -> applicable Policy -> Download / deployment URL -> Install
    -> Register -> Computer appears -> Policy delivered -> ACK -> Telemetry

Mapped onto NivXForge's stronger invariants:

  * the connector is a RELEASE. Its artifact is produced once and is
    redistributable to every device; nothing is rebuilt per endpoint,
    per group or per tenant.
  * choosing a Group (and therefore a Policy) produces DEPLOYMENT
    CONTEXT around that released artifact — an install invocation plus a
    bounded, tenant-bound enrolment credential. The artifact SHA-256 is
    identical across every deployment, and the response says so.
  * a release with no legitimate artifact reports
    `ARTIFACT_NOT_PUBLISHED`. No download is fabricated.
"""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from deps import db as _db, get_current_user
from edr_plane.connector import catalog
from edr_plane.enrollment import store as enrollment_store
from edr_plane.enrollment.security import digest
from edr_plane.policy import store as policy_store
from routers.edr_tenancy import edr_scope, edr_tenant

releases = APIRouter(prefix="/edr/connector",
                     tags=["nivxforge-edr-connector"])

DEPLOYMENTS = "edr_connector_deployments"


def _who(user: dict) -> str:
    return (user or {}).get("email") or "unknown"


def _scoped(tenant_id: str, user: dict) -> str:
    edr_scope(tenant_id, user)
    return tenant_id


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


ADMIN_WORKFLOW = [
    "choose the connector RELEASE (product, version, architecture, channel)",
    "choose the GROUP the computer should join",
    "the group's assigned POLICY is resolved and shown — it is not chosen "
    "separately, so a computer cannot land in a group and a contradicting "
    "policy",
    "create the deployment: a bounded enrolment credential is minted around "
    "the ALREADY-RELEASED artifact; the connector is not rebuilt",
    "download the released artifact once and redistribute the same bytes",
    "install with the deployment invocation on each computer",
    "the computer registers and appears under Computers",
    "the connector fetches its policy — that is DELIVERED",
    "the connector acknowledges the exact version and config digest — only "
    "then is it APPLIED",
    "authenticated telemetry arrives and the computer becomes CONNECTED",
]


@releases.get("/releases")
async def list_releases(user: dict = Depends(get_current_user)
                        ) -> Dict[str, Any]:
    """The connector release catalog with real on-disk artifact truth."""
    rows = catalog.catalog()
    return {
        "releases": rows,
        "count": len(rows),
        "published": sum(1 for r in rows
                         if r["artifact_state"] == catalog.ARTIFACT_PUBLISHED),
        "channels": sorted({r["channel"] for r in rows}),
        "distribution_contract": catalog.DISTRIBUTION_CONTRACT,
        "admin_workflow": ADMIN_WORKFLOW,
    }


@releases.get("/releases/{release_id}")
async def get_release(release_id: str,
                      user: dict = Depends(get_current_user)
                      ) -> Dict[str, Any]:
    row = catalog.get(release_id)
    if row is None:
        raise HTTPException(404, detail={"code": "RELEASE_NOT_FOUND"})
    return {"release": row,
            "distribution_contract": catalog.DISTRIBUTION_CONTRACT}


@releases.get("/releases/{release_id}/artifact/{name}",
              response_class=PlainTextResponse)
async def download_release_artifact(release_id: str, name: str,
                                    user: dict = Depends(get_current_user)
                                    ) -> PlainTextResponse:
    """The released artifact. The SAME bytes for every tenant and device."""
    row = catalog.get(release_id)
    if row is None:
        raise HTTPException(404, detail={"code": "RELEASE_NOT_FOUND"})
    if row["artifact_state"] != catalog.ARTIFACT_PUBLISHED:
        raise HTTPException(409, detail={
            "code": row["artifact_state"],
            "reason": row["artifact_state_reason"]})
    path = catalog.artifact_path(release_id, name)
    if not path:
        raise HTTPException(404, detail={"code": "ARTIFACT_NOT_IN_RELEASE"})
    try:
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
    except OSError:
        raise HTTPException(404, detail={"code": "ARTIFACT_MISSING"}) from None
    sha = next((f["sha256"] for f in row["artifact_files"]
                if f["name"] == name), "")
    return PlainTextResponse(body, headers={
        "Content-Disposition": f'attachment; filename="{name}"',
        "X-NivXForge-Release": release_id,
        "X-NivXForge-Sha256": sha,
        "X-NivXForge-Redistributable": "true"})


# ── deployment context (never a rebuild) ─────────────────────────────
class CreateDeploymentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    release_id: str
    group_id: str
    label: Optional[str] = Field(default=None, max_length=200)
    ttl_seconds: int = Field(default=86400, ge=300, le=86400)


@releases.post("/deployments")
async def create_deployment(body: CreateDeploymentBody, request: Request,
                            user: dict = Depends(get_current_user),
                            tenant_id: str = Depends(edr_tenant)
                            ) -> Dict[str, Any]:
    """Generate deployment context AROUND a released artifact.

    The enrolment credential's plaintext exists in THIS response and
    nowhere else. The connector artifact is untouched: its SHA-256 is
    returned so the operator can verify that the same bytes are being
    deployed everywhere.
    """
    tenant = _scoped(tenant_id, user)
    release = catalog.get(body.release_id)
    if release is None:
        raise HTTPException(404, detail={"code": "RELEASE_NOT_FOUND"})
    if release["artifact_state"] != catalog.ARTIFACT_PUBLISHED:
        raise HTTPException(409, detail={
            "code": release["artifact_state"],
            "reason": release["artifact_state_reason"],
            "note": ("deployment context is only generated around a "
                     "published artifact; nothing is fabricated")})
    group = await _db[policy_store.GROUPS].find_one(
        {"tenant_id": tenant, "id": body.group_id}, {"_id": 0})
    if group is None:
        raise HTTPException(404, detail={
            "code": "GROUP_NOT_FOUND",
            "reason": "the group must exist before a computer can be "
                      "deployed into it"})

    policy = None
    policy_version = None
    if group.get("policy_id"):
        policy = await _db[policy_store.POLICIES].find_one(
            {"tenant_id": tenant, "id": group["policy_id"]}, {"_id": 0})
        if policy:
            policy_version = await _db[policy_store.VERSIONS].find_one(
                {"tenant_id": tenant, "policy_id": policy["id"],
                 "version": policy.get("current_version")}, {"_id": 0})

    deployment_id = "dep_" + secrets.token_hex(8)
    minted = await enrollment_store.mint_enrollment_token(
        _db, tenant_id=tenant, issued_by=_who(user),
        label=(body.label or f"deployment into {group.get('name')}"),
        ttl_seconds=body.ttl_seconds)
    token = minted.get("enrollment_token")
    # The GROUP is carried by the enrolment credential, server-side —
    # this is how "choose a Group when you obtain the connector" is
    # reproduced without putting a group into the artifact. The installer
    # takes no group argument and the artifact is unchanged.
    await _db[enrollment_store.TOKENS].update_one(
        {"tenant_id": tenant, "token_hash": digest(token)},
        {"$set": {"group_id": body.group_id,
                  "deployment_id": deployment_id,
                  "release_id": body.release_id}})

    backend = str(request.base_url).rstrip("/") if request else ""
    entry = release.get("entrypoint") or "install"
    invocation = (
        f"powershell -ExecutionPolicy Bypass -File .\\{entry} "
        f"-BackendUrl {backend} -TenantId {tenant} "
        f"-EnrollmentToken <ENROLLMENT_TOKEN>"
        if str(release.get("os")) == "WINDOWS" else
        f"sudo ./{entry} --backend {backend} --tenant {tenant} "
        f"--enrollment-token <ENROLLMENT_TOKEN>")
    doc = {
        "deployment_id": deployment_id, "tenant_id": tenant,
        "release_id": body.release_id,
        "connector_version": release.get("connector_version"),
        "artifact_identity": release.get("artifact_identity"),
        "group_id": body.group_id, "group_name": group.get("name"),
        "policy_id": (policy or {}).get("id"),
        "policy_name": (policy or {}).get("name"),
        "policy_version": (policy_version or {}).get("version"),
        "label": body.label or None, "created_at": _now(),
        "created_by": _who(user),
        "enrollment_token_expires_at": minted.get("expires_at"),
        "rebuilt_connector": False,
    }
    await _db[DEPLOYMENTS].insert_one(dict(doc))
    doc.pop("_id", None)
    return {
        "deployment": doc,
        "enrollment_token": token,
        "install_invocation": invocation.replace("<ENROLLMENT_TOKEN>",
                                                 str(token or "")),
        "install_invocation_redacted": invocation,
        "artifact": {"release_id": body.release_id,
                     "artifact_identity": release.get("artifact_identity"),
                     "files": [{"name": f["name"], "sha256": f["sha256"]}
                               for f in release.get("artifact_files") or []],
                     "redistributable": True,
                     "rebuild_required_per_endpoint": False},
        "policy_preview": ({"policy_id": policy["id"],
                            "policy_name": policy["name"],
                            "version": (policy_version or {}).get("version"),
                            "config_digest": (policy_version or {}).get(
                                "config_digest"),
                            "state": "ASSIGNED_TO_GROUP"} if policy else
                           {"state": "POLICY_UNASSIGNED",
                            "reason": "this group has no policy assigned; "
                                      "computers joining it will honestly "
                                      "report POLICY_UNASSIGNED"}),
        "credential_contract": (
            "the enrolment credential is bounded, tenant-bound and appears "
            "in THIS response only. It is never embedded into the released "
            "artifact, which is why one artifact serves every device. The "
            "chosen Group travels with the credential server-side, so the "
            "installer needs no group argument."),
        "next_steps": ADMIN_WORKFLOW[4:],
    }


@releases.get("/deployments")
async def list_deployments(user: dict = Depends(get_current_user),
                           tenant_id: str = Depends(edr_tenant)
                           ) -> Dict[str, Any]:
    """Deployment context records. No secret is ever returned again."""
    tenant = _scoped(tenant_id, user)
    rows = [d async for d in _db[DEPLOYMENTS].find(
        {"tenant_id": tenant}, {"_id": 0}).sort("created_at", -1).limit(200)]
    return {"tenant_id": tenant, "deployments": rows, "count": len(rows),
            "note": ("the enrolment credential minted for a deployment is "
                     "not stored and is never re-disclosed; create a new "
                     "deployment if it was lost")}
