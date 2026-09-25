"""NivXForge EDR · Windows Device Onboarding V1 · Management surfaces.

Three admin surfaces that make the onboarding workflow real, all backed by
facts that already exist:

    GET  /api/edr/onboarding/packages              what can actually be installed
    GET  /api/edr/onboarding/packages/{id}/file/{name}   the reusable artifact
    GET  /api/edr/onboarding/computers             the Computers grid truth

Nothing here invents state. A package is listed only if its artifact exists on
disk (version, size and SHA-256 are read from the file). A computer's status
comes from the enrolment record the agent plane already writes, and CONNECTED
requires AUTHENTICATED TELEMETRY — enrolment alone is never enough.

Credential-free installer contract: the reusable artifact is scanned for any
embedded secret shape before it is offered, so one build can be handed to
every computer without carrying a tenant credential.
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse

from deps import db as _db, get_current_user
from edr_plane.enrollment import store
from routers.edr_enrollment import _tenant

router = APIRouter(prefix="/edr/onboarding", tags=["nivxforge-edr-onboarding"])

AGENTS_ROOT = os.environ.get("NIVXFORGE_AGENTS_ROOT", "/app/agents")

GROUPS = "edr_groups"
POLICIES = "edr_policies"

DEFAULT_GROUP = {"id": "grp_default_windows", "name": "Default (Windows)"}
DEFAULT_POLICY = {"id": "pol_default_detect_only",
                  "name": "Default Windows Policy",
                  "mode": "DETECT_ONLY",
                  "prevention_enabled": False,
                  "declared_capabilities": ["WINDOWS_EVENT_LOG_COLLECTION"],
                  "not_enforced": ["ransomware_prevention",
                                   "exploit_prevention", "device_control"]}

#: Anything that looks like a credential must NOT be in a reusable build.
_SECRET_SHAPES = (
    re.compile(r"nvx_[0-9a-f]{48}"),
    re.compile(r"nvxenr_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"nvxses_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"nvxcrd_[A-Za-z0-9_\-]{16,}"),
)

PACKAGES = {
    "windows-x64": {
        "id": "windows-x64",
        "os": "WINDOWS",
        "architecture": "x64",
        "display_name": "NivXForge Sensor · Windows x64",
        "directory": "nivxforge-windows",
        "files": ["Install-NivXForgeSensor.ps1", "nivxforge_sensor.py"],
        "entrypoint": "Install-NivXForgeSensor.ps1",
        "release_status": "PREVIEW",
        "signing_status": "UNSIGNED",
        "supported_windows": ["Windows 10 21H2+", "Windows 11",
                              "Windows Server 2019", "Windows Server 2022"],
        "requires": ["Python 3.11+ on the endpoint",
                     "elevated PowerShell for installation"],
        "silent_install": (
            "powershell -ExecutionPolicy Bypass -File "
            ".\\Install-NivXForgeSensor.ps1 -BackendUrl <backend> "
            "-TenantId <tenant> -EnrollmentToken <token>"),
    },
    "windows-arm64": {
        "id": "windows-arm64", "os": "WINDOWS", "architecture": "arm64",
        "display_name": "NivXForge Sensor · Windows ARM64",
        "directory": "nivxforge-windows-arm64", "files": [],
        "entrypoint": None, "release_status": "NOT_BUILT",
        "signing_status": "UNSIGNED", "supported_windows": [],
        "requires": [], "silent_install": None,
    },
    "windows-x86": {
        "id": "windows-x86", "os": "WINDOWS", "architecture": "x86",
        "display_name": "NivXForge Sensor · Windows 32-bit",
        "directory": "nivxforge-windows-x86", "files": [],
        "entrypoint": None, "release_status": "NOT_BUILT",
        "signing_status": "UNSIGNED", "supported_windows": [],
        "requires": [], "silent_install": None,
    },
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _artifact_path(package: dict, name: str) -> str:
    if name not in (package.get("files") or []):
        raise HTTPException(404, detail={"code": "ARTIFACT_NOT_IN_PACKAGE"})
    return os.path.join(AGENTS_ROOT, package["directory"], name)


def _sensor_version(directory: str) -> str | None:
    path = os.path.join(AGENTS_ROOT, directory, "nivxforge_sensor.py")
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("SENSOR_VERSION"):
                    return line.split("=", 1)[1].strip().strip('"\' ')
    except OSError:
        return None
    return None


def _describe(package: dict) -> dict[str, Any]:
    """A package as it actually exists on disk. Absent means absent."""
    files, missing, credential_free = [], [], True
    for name in package.get("files") or []:
        path = os.path.join(AGENTS_ROOT, package["directory"], name)
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            missing.append(name)
            continue
        text = blob.decode("utf-8", "replace")
        embedded = [shape.pattern for shape in _SECRET_SHAPES
                    if shape.search(text)]
        if embedded:
            credential_free = False
        files.append({
            "name": name,
            "size_bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "modified_at": datetime.fromtimestamp(
                os.path.getmtime(path), tz=timezone.utc).isoformat(),
            "embedded_credential_shapes": embedded,
        })
    available = bool(files) and not missing and credential_free
    return {
        **{k: v for k, v in package.items() if k != "directory"},
        "sensor_version": _sensor_version(package["directory"]),
        "files": files,
        "missing_files": missing,
        "credential_free": credential_free,
        "available": available,
        "state": ("AVAILABLE" if available
                  else "NOT_BUILT" if not files and not missing
                  else "INCOMPLETE" if missing
                  else "REFUSED_EMBEDDED_CREDENTIAL"),
        "state_reason": (
            "the reusable build exists on disk and carries no credential"
            if available else
            "no artifact has been built for this architecture yet"
            if not files and not missing else
            f"artifacts missing from the build: {missing}" if missing else
            "an artifact contains something shaped like a credential; a "
            "reusable build must never carry one"),
        "download_available": available,
    }


@router.get("/packages")
async def list_packages(user: dict = Depends(get_current_user),
                        request: Request = None) -> dict[str, Any]:
    """What can ACTUALLY be installed right now, per architecture."""
    packages = [_describe(p) for p in PACKAGES.values()]
    return {
        "packages": packages,
        "available": sum(1 for p in packages if p["available"]),
        "onboarding_workflow": [
            "download the reusable installer",
            "mint an enrollment token (POST /api/edr/enrollment/tokens)",
            "run the installer elevated with -BackendUrl -TenantId "
            "-EnrollmentToken",
            "the platform mints the endpoint identity and a per-device "
            "credential",
            "the computer appears under Computers and becomes CONNECTED only "
            "after authenticated telemetry arrives",
        ],
        "installer_contract": (
            "ONE build for every computer: the installer carries no tenant "
            "credential, and each installation receives its own device "
            "credential"),
    }


@router.get("/packages/{package_id}/file/{name}",
            response_class=PlainTextResponse)
async def download_artifact(package_id: str, name: str,
                            user: dict = Depends(get_current_user)
                            ) -> PlainTextResponse:
    package = PACKAGES.get(package_id)
    if package is None:
        raise HTTPException(404, detail={"code": "PACKAGE_NOT_FOUND"})
    described = _describe(package)
    if not described["available"]:
        raise HTTPException(409, detail={
            "code": "PACKAGE_NOT_AVAILABLE",
            "state": described["state"], "reason": described["state_reason"]})
    path = _artifact_path(package, name)
    try:
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
    except OSError:
        raise HTTPException(404, detail={"code": "ARTIFACT_MISSING"}) from None
    return PlainTextResponse(body, headers={
        "Content-Disposition": f'attachment; filename="{name}"',
        "X-NivXForge-Sha256": hashlib.sha256(body.encode()).hexdigest(),
        "X-NivXForge-Credential-Free": "true"})


# ── default placement (group + policy) ────────────────────────────
async def ensure_default_placement(tenant_id: str) -> dict[str, str]:
    """The default group and policy every newly enrolled computer lands in."""
    await _db[GROUPS].update_one(
        {"tenant_id": tenant_id, "id": DEFAULT_GROUP["id"]},
        {"$setOnInsert": {**DEFAULT_GROUP, "tenant_id": tenant_id,
                          "is_default": True,
                          "created_at": _now().isoformat()}}, upsert=True)
    await _db[POLICIES].update_one(
        {"tenant_id": tenant_id, "id": DEFAULT_POLICY["id"]},
        {"$setOnInsert": {**DEFAULT_POLICY, "tenant_id": tenant_id,
                          "is_default": True,
                          "created_at": _now().isoformat()}}, upsert=True)
    return {"group_id": DEFAULT_GROUP["id"], "policy_id": DEFAULT_POLICY["id"]}


async def assign_default_placement(tenant_id: str, endpoint_id: str) -> dict:
    """Assigned at enrolment, and only if the endpoint has no placement yet."""
    placement = await ensure_default_placement(tenant_id)
    await _db[store.ENDPOINTS].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
         "$or": [{"group_id": None}, {"group_id": {"$exists": False}}]},
        {"$set": {**placement,
                  "placement_basis": "DEFAULT_AT_ENROLMENT",
                  "placement_at": _now().isoformat()}})
    return placement


# ── Computers ─────────────────────────────────────────────────────
def _staleness_limit(record: dict) -> float:
    interval = record.get("report_interval_seconds")
    return float(interval) * 3 if interval else 900.0


def _age_seconds(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        return (_now() - datetime.fromisoformat(
            iso.replace("Z", "+00:00"))).total_seconds()
    except ValueError:
        return None


def _status(record: dict) -> dict[str, Any]:
    """CONNECTED requires authenticated telemetry. Nothing is assumed."""
    if record.get("credential_state") == "REVOKED":
        return {"status": "REVOKED",
                "basis": "the device credential was revoked"}
    telemetry_age = _age_seconds(record.get("last_telemetry_at"))
    limit = _staleness_limit(record)
    if telemetry_age is None:
        if record.get("enrollment_state") in (None, "NEVER_ENROLLED"):
            return {"status": "NOT_ENROLLED",
                    "basis": "no enrolment record for this computer"}
        return {"status": "ENROLLED_NO_TELEMETRY",
                "basis": ("enrolled, but no authenticated telemetry has been "
                          "received; enrolment alone is never CONNECTED")}
    if telemetry_age <= limit:
        return {"status": "CONNECTED",
                "basis": ("authenticated telemetry received "
                          f"{int(telemetry_age)}s ago, within the sensor's own "
                          f"declared cadence ({int(limit)}s)")}
    heartbeat_age = _age_seconds(record.get("last_heartbeat_at"))
    if heartbeat_age is not None and heartbeat_age <= limit:
        return {"status": "ALIVE_NO_RECENT_TELEMETRY",
                "basis": ("the sensor is heartbeating but its last telemetry "
                          f"is {int(telemetry_age)}s old"
                          + (f"; {record['outbox_queue_depth']} events are "
                             "queued at the sensor"
                             if record.get("outbox_queue_depth") else ""))}
    return {"status": "SILENT",
            "basis": (f"last authenticated telemetry {int(telemetry_age)}s "
                      f"ago, beyond {int(limit)}s, and no recent heartbeat")}


def _protection(policy: dict | None, record: dict) -> dict[str, Any]:
    if policy is None:
        return {"state": "UNAVAILABLE",
                "basis": "no policy is assigned to this computer"}
    return {
        "state": ("DETECT_ONLY" if policy.get("mode") == "DETECT_ONLY"
                  else str(policy.get("mode") or "UNAVAILABLE")),
        "prevention_enabled": bool(policy.get("prevention_enabled")),
        "not_enforced": list(policy.get("not_enforced") or []),
        "policy_lifecycle": {
            "configured": True,
            "assigned": bool(record.get("policy_id")),
            "received_by_sensor": record.get("policy_received_at") is not None,
            "enforced": False,
            "verified": False,
        },
        "basis": ("the assigned policy declares this mode; the Windows V1 "
                  "sensor collects and reports and enforces nothing, so "
                  "enforcement is reported as not enforced rather than as "
                  "protection"),
    }


@router.get("/computers")
async def computers(user: dict = Depends(get_current_user),
                    request: Request = None) -> dict[str, Any]:
    """The Computers grid, entirely from recorded endpoint truth."""
    tenant = _tenant(user, request)
    records = await store.list_endpoints(_db, tenant_id=tenant)
    policies = {doc["id"]: doc async for doc in
                _db[POLICIES].find({"tenant_id": tenant})}
    groups = {doc["id"]: doc async for doc in
              _db[GROUPS].find({"tenant_id": tenant})}
    rows = []
    for record in records:
        policy = policies.get(record.get("policy_id"))
        group = groups.get(record.get("group_id"))
        state = _status(record)
        rows.append({
            "endpoint_id": record.get("endpoint_id"),
            "hostname": record.get("hostname"),
            "os": record.get("platform"),
            "os_version": record.get("os_version"),
            "architecture": record.get("architecture"),
            "group": (group or {}).get("name"),
            "group_id": record.get("group_id"),
            "policy": (policy or {}).get("name"),
            "policy_id": record.get("policy_id"),
            "sensor_version": record.get("sensor_version"),
            "protection": _protection(policy, record),
            "telemetry": {
                "last_telemetry_at": record.get("last_telemetry_at"),
                "last_heartbeat_at": record.get("last_heartbeat_at"),
                "event_count": record.get("event_count") or 0,
                "queue_depth_at_sensor": record.get("outbox_queue_depth"),
                "report_interval_seconds": record.get(
                    "report_interval_seconds"),
            },
            "last_seen": record.get("last_seen"),
            "enrollment_state": record.get("enrollment_state"),
            "credential_state": record.get("credential_state"),
            "sensor_state": record.get("sensor_state"),
            "status": state["status"],
            "status_basis": state["basis"],
            #: Detections are owned by the detection plane; this surface does
            #: not invent a count it has not read.
            "detections": None,
            "detections_basis": "NOT_WIRED_IN_THIS_WAVE",
            "unavailable_fields": [
                name for name, value in (
                    ("os_version", record.get("os_version")),
                    ("architecture", record.get("architecture")),
                    ("sensor_version", record.get("sensor_version")),
                    ("group", (group or {}).get("name")),
                    ("policy", (policy or {}).get("name")),
                ) if not value],
        })
    return {
        "tenant_id": tenant,
        "count": len(rows),
        "computers": rows,
        "status_contract": (
            "CONNECTED requires authenticated endpoint telemetry inside the "
            "sensor's own declared cadence. Enrolment, a heartbeat or an "
            "accepted install are never sufficient."),
    }
