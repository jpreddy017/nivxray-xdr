"""NivXForge Connector · the RELEASE catalog.

A connector is a released PRODUCT ARTIFACT, not something built per
endpoint, per group or per tenant. This module is the catalog of
legitimate releases; the artifact for a release is produced ONCE and the
same bytes are installed on every device.

Deployment context (which group, which policy, which enrolment
credential) is generated AROUND a released artifact at install time. It
never recompiles the connector, and the artifact identity (SHA-256) is
identical across every deployment — which is what the Downloads surface
discloses.

Artifact truth is read from disk. If no legitimate artifact exists for a
release, the release reports `ARTIFACT_NOT_PUBLISHED`. Nothing is
fabricated into a download.
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

AGENTS_ROOT = os.environ.get("NIVXFORGE_AGENTS_ROOT", "/app/agents")

#: A reusable artifact must never carry a credential.
_SECRET_SHAPES = (
    re.compile(r"nvx_[0-9a-f]{48}"),
    re.compile(r"nvxenr_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"nvxses_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"nvxcrd_[A-Za-z0-9_\-]{16,}"),
)

ARTIFACT_PUBLISHED = "PUBLISHED"
ARTIFACT_NOT_PUBLISHED = "ARTIFACT_NOT_PUBLISHED"
ARTIFACT_INCOMPLETE = "ARTIFACT_INCOMPLETE"
ARTIFACT_REFUSED = "ARTIFACT_REFUSED_EMBEDDED_CREDENTIAL"

#: What a connector release DECLARES it can do. The policy authority and
#: the exclusion plane both read this, so neither can claim enforcement
#: the released artifact does not perform.
_V1_CAPABILITIES: Dict[str, bool] = {
    "process_event_collection": True,
    "authenticated_telemetry": True,
    "heartbeat": True,
    "policy_fetch_and_ack": True,
    "endpoint_prevention": False,
    "file_event_collection": False,
    "network_event_collection": False,
    "registry_event_collection": False,
    "endpoint_exclusions": False,
    "offline_local_inference": False,
}

RELEASES: List[Dict[str, Any]] = [
    {
        "release_id": "nvf-connector-windows-0.6.2-x64",
        "product": "NivXForge Windows Connector",
        "connector_version": "0.6.2",
        "os": "WINDOWS", "architecture": "x64", "channel": "PREVIEW",
        "support_status": "INTERNAL_VALIDATION",
        "release_date": "2026-11-16", "end_of_support": None,
        "signing_status": "UNSIGNED_INTERNAL_VALIDATION_BUILD",
        "supported_os": ["Windows 11 x64 (validation)", "Windows Server 2025 x64 (CI validated)"],
        "requires": ["Administrator PowerShell", "Fresh tenant enrollment token", "Outbound HTTPS to nivxray.nivxforge.com"],
        "release_notes": [
            "Fixes fresh-install forensic collection: one worker survives telemetry cycles and transient telemetry errors; its SQLite connection closes on shutdown.",
            "Includes separate PowerShell history source budgets and registry binary capture up to 1 MiB per value with original size and SHA-256.",
            "Windows CI verifies collector providers, in-flight collection, missing-enrollment recovery, frozen journal, real SCM start/stop, and rollback. Build commit 28260d4ccded92684e838140fe79becdaeed9988.",
            "For a new computer choose Deploy this version, then run install with its tenant and enrollment token. Existing M1 installations use m1-upgrade with their existing config.",
            "Unsigned internal-validation build. Collection limits remain explicit; no memory or disk imaging, prevention engine, or automatic compromise capture."
        ],
        "declared_capabilities": {**_V1_CAPABILITIES, "endpoint_exclusions": True, "forensic_snapshot": True},
        "artifact": {"directory": "nivxforge-windows/releases/0.6.2",
                     "files": ["NivXForgeEDRSetup.exe"], "entrypoint": "NivXForgeEDRSetup.exe",
                     "expected_sha256": {"NivXForgeEDRSetup.exe": "34cc1fc8ce7fb39db4a2a669ade08522e31e79665195bc192092b8119aa0fe11"}},
    },

    {
        "release_id": "nvf-connector-windows-0.5.1-x64",
        "product": "NivXForge Windows Connector",
        "connector_version": "0.5.1",
        "os": "WINDOWS", "architecture": "x64", "channel": "PREVIEW",
        "support_status": "INTERNAL_VALIDATION",
        "release_date": "2026-11-16", "end_of_support": None,
        "signing_status": "UNSIGNED_INTERNAL_VALIDATION_BUILD",
        "supported_os": ["Windows 10 21H2+", "Windows 11", "Windows Server 2019", "Windows Server 2022"],
        "requires": ["elevated prompt for installation"],
        "release_notes": [
            "41 Windows forensic categories; up to 10,000 rows per category, 2 MiB per category and 12 MiB total evidence, with explicit partial status.",
            "Adds PowerShell script-block events, structured logged-in users and byte-limited partial evidence retention. Windows CI verifies real collection, event parsing, service lifecycle and rollback.",
            "Unsigned internal-validation build. No automatic compromise capture, memory image or disk image. Sensitive histories require the full profile.",
        ],
        "declared_capabilities": {**_V1_CAPABILITIES, "endpoint_exclusions": True, "forensic_snapshot": True},
        "artifact": {"directory": "nivxforge-windows/releases/0.5.1",
                     "files": ["NivXForgeEDRSetup.exe"], "entrypoint": "NivXForgeEDRSetup.exe",
                     "expected_sha256": {"NivXForgeEDRSetup.exe": "9fd07ce6b7b02bfeeecbb13e95ea63e5d989eb63b1715b985ddb182709e3f717"}},
    },
    {
        "release_id": "nvf-connector-windows-0.5.0-x64",
        "product": "NivXForge Windows Connector",
        "connector_version": "0.5.0",
        "os": "WINDOWS", "architecture": "x64", "channel": "PREVIEW",
        "support_status": "INTERNAL_VALIDATION",
        "release_date": "2026-11-16", "end_of_support": None,
        "signing_status": "UNSIGNED_INTERNAL_VALIDATION_BUILD",
        "supported_os": ["Windows 10 21H2+", "Windows 11", "Windows Server 2019", "Windows Server 2022"],
        "requires": ["elevated prompt for installation"],
        "release_notes": [
            "41 Windows forensic categories; up to 10,000 rows per category, 2 MiB per category and 12 MiB total evidence, with explicit partial status.",
            "Adds process owners and compacts acknowledged evidence into replay receipts. Windows CI verifies collectors, service lifecycle and rollback.",
            "Unsigned internal-validation build. No automatic compromise capture, memory image or disk image. Sensitive histories require the full profile.",
        ],
        "declared_capabilities": {**_V1_CAPABILITIES, "endpoint_exclusions": True, "forensic_snapshot": True},
        "artifact": {"directory": "nivxforge-windows/releases/0.5.0",
                     "files": ["NivXForgeEDRSetup.exe"], "entrypoint": "NivXForgeEDRSetup.exe",
                     "expected_sha256": {"NivXForgeEDRSetup.exe": "ba894b852f3b414055b34be62b4b8a5bf966ea50636228385b76543c0cfe0880"}},
    },
    {
        "release_id": "nvf-connector-windows-0.4.0-x64",
        "product": "NivXForge Windows Connector",
        "connector_version": "0.4.0",
        "os": "WINDOWS", "architecture": "x64", "channel": "PREVIEW",
        "support_status": "INTERNAL_VALIDATION",
        "release_date": "2026-11-16", "end_of_support": None,
        "signing_status": "UNSIGNED_INTERNAL_VALIDATION_BUILD",
        "supported_os": ["Windows 10 21H2+", "Windows 11", "Windows Server 2019", "Windows Server 2022"],
        "requires": ["elevated prompt for installation"],
        "release_notes": [
            "On-demand forensic collection across 41 Windows artifact categories, with independent category status and bounded collection.",
            "Includes durable command recovery and a native Windows service. Windows CI verifies providers, installer, service lifecycle and recovery.",
            "Unsigned internal-validation build. No automatic compromise capture, memory image or disk image. Sensitive histories require the full profile.",
        ],
        "declared_capabilities": {**_V1_CAPABILITIES, "endpoint_exclusions": True, "forensic_snapshot": True},
        "artifact": {"directory": "nivxforge-windows/releases/0.4.0",
                     "files": ["NivXForgeEDRSetup.exe"], "entrypoint": "NivXForgeEDRSetup.exe",
                     "expected_sha256": {"NivXForgeEDRSetup.exe": "5e393dbceb83d9033ab58767749a0d3855f22e1321df5b3eb3e5d9336b2bc941"}},
    },
    {
        "release_id": "nvf-connector-windows-0.2.0-x64",
        "product": "NivXForge Windows Connector",
        "connector_version": "0.2.0",
        "os": "WINDOWS",
        "architecture": "x64",
        "channel": "PREVIEW",
        "support_status": "PREVIEW_NOT_FOR_PRODUCTION",
        "release_date": "2026-09-26",
        "end_of_support": None,
        "signing_status": "UNSIGNED",
        "supported_os": ["Windows 10 21H2+", "Windows 11",
                         "Windows Server 2019", "Windows Server 2022"],
        "requires": ["Python 3.11+ on the endpoint",
                     "elevated PowerShell for installation"],
        "release_notes": [
            "Adds ENDPOINT-SIDE EXCLUSION ENFORCEMENT: exclusions carried "
            "by the applied policy version are evaluated locally. A "
            "COLLECTION-scoped exclusion means the matching event is never "
            "delivered; a DETECTION-scoped exclusion (the default) delivers "
            "the evidence and lets the server suppress only the verdict.",
            "Adds policy fetch + acknowledgement of the exact config "
            "digest, and reporting of what the local engine actually "
            "enforced (counts and value digests only — never the excluded "
            "content).",
            "An exclusion this connector cannot honour is REFUSED and "
            "reported as refused, rather than silently skipped.",
            "Still no prevention engine, and no file/network/registry "
            "observation on Windows.",
        ],
        "declared_capabilities": {**_V1_CAPABILITIES,
                                  "endpoint_exclusions": True},
        "artifact": {"directory": "nivxforge-windows",
                     "files": ["Install-NivXForgeSensor.ps1",
                               "nivxforge_sensor.py",
                               "nivxforge_exclusions.py"],
                     "entrypoint": "Install-NivXForgeSensor.ps1"},
    },
    {
        "release_id": "nvf-connector-linux-0.2.0-x64",
        "product": "NivXForge Linux Connector",
        "connector_version": "0.2.0",
        "os": "LINUX",
        "architecture": "x64",
        "channel": "PREVIEW",
        "support_status": "PREVIEW_NOT_FOR_PRODUCTION",
        "release_date": "2026-09-26",
        "end_of_support": None,
        "signing_status": "UNSIGNED",
        "supported_os": ["Linux with /proc (process + network + watched "
                         "path observation)"],
        "requires": ["Python 3.11+", "root for installation",
                     "NET_ADMIN for the containment engine"],
        "release_notes": [
            "Adds ENDPOINT-SIDE EXCLUSION ENFORCEMENT with the same "
            "canonical evaluator as the Windows release, including "
            "COLLECTION vs DETECTION enforcement scope.",
            "Process, network and watched-path observation.",
            "Kernel-level containment with read-back proof. No "
            "file-content prevention engine.",
        ],
        "declared_capabilities": {**_V1_CAPABILITIES,
                                  "endpoint_exclusions": True,
                                  "network_event_collection": True,
                                  "file_event_collection": True},
        "artifact": {"directory": "nivxforge-linux",
                     "files": ["nivxforge_sensor.py",
                               "nivxforge_exclusions.py"],
                     "entrypoint": "nivxforge_sensor.py"},
    },
    {
        "release_id": "nvf-connector-windows-0.1.0-x64",
        "product": "NivXForge Windows Connector",
        "connector_version": "0.1.0",
        "os": "WINDOWS",
        "architecture": "x64",
        "channel": "PREVIEW",
        "support_status": "SUPERSEDED",
        "release_date": "2026-09-06",
        "end_of_support": "2026-09-26",
        "signing_status": "UNSIGNED",
        "supported_os": ["Windows 10 21H2+", "Windows 11",
                         "Windows Server 2019", "Windows Server 2022"],
        "requires": ["Python 3.11+ on the endpoint"],
        "release_notes": [
            "Superseded by 0.2.0. Collection, telemetry, heartbeat and "
            "policy ACK only — no endpoint-side exclusion enforcement.",
        ],
        "declared_capabilities": dict(_V1_CAPABILITIES),
        #: The 0.1.0 bytes are no longer published. Endpoints still
        #: RUNNING 0.1.0 continue to read its declared capability, which
        #: is why the entry is retained rather than deleted.
        "artifact": {"directory": "nivxforge-windows-0.1.0", "files": [],
                     "entrypoint": None},
    },
    {
        "release_id": "nvf-connector-windows-arm64",
        "product": "NivXForge Windows Connector",
        "connector_version": None,
        "os": "WINDOWS",
        "architecture": "arm64",
        "channel": "PREVIEW",
        "support_status": "NOT_RELEASED",
        "release_date": None,
        "end_of_support": None,
        "signing_status": "UNSIGNED",
        "supported_os": [],
        "requires": [],
        "release_notes": [],
        "declared_capabilities": {},
        "artifact": {"directory": "nivxforge-windows-arm64", "files": [],
                     "entrypoint": None},
    },
]

_BY_ID = {r["release_id"]: r for r in RELEASES}


def _scan(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return None
    text = blob.decode("utf-8", "replace")
    return {
        "name": os.path.basename(path),
        "size_bytes": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "modified_at": datetime.fromtimestamp(
            os.path.getmtime(path), tz=timezone.utc).isoformat(),
        "embedded_credential_shapes": [s.pattern for s in _SECRET_SHAPES
                                       if s.search(text)],
    }


def _discovered_files(directory: str) -> List[str]:
    """Any artifact the release DECLARES but did not enumerate."""
    try:
        return sorted(f for f in os.listdir(os.path.join(AGENTS_ROOT,
                                                         directory))
                      if not f.startswith("."))
    except OSError:
        return []


def describe(release: Dict[str, Any]) -> Dict[str, Any]:
    """A release with its ACTUAL artifact truth from disk."""
    art = release.get("artifact") or {}
    declared = list(art.get("files") or [])
    files, missing = [], []
    for name in declared:
        info = _scan(os.path.join(AGENTS_ROOT, art.get("directory") or "",
                                  name))
        (files.append(info) if info else missing.append(name))
    embedded = [f["name"] for f in files if f["embedded_credential_shapes"]]
    if not declared:
        state, reason = ARTIFACT_NOT_PUBLISHED, (
            "no artifact has been produced for this release; the console "
            "shows no download rather than fabricating one")
    elif missing:
        state, reason = ARTIFACT_INCOMPLETE, (
            f"the release declares artifacts that are not on disk: {missing}")
    elif embedded:
        state, reason = ARTIFACT_REFUSED, (
            f"an artifact contains something shaped like a credential "
            f"({embedded}); a redistributable connector must never carry one")
    elif any(f["sha256"] != art.get("expected_sha256", {}).get(f["name"], f["sha256"]) for f in files):
        state, reason = "ARTIFACT_HASH_MISMATCH", "Artifact bytes do not match the verified release; download is refused."
    else:
        state, reason = ARTIFACT_PUBLISHED, (
            "the released artifact exists, its identity is recorded, and it "
            "carries no credential — the same bytes install on every device")
    identity = (hashlib.sha256(
        "|".join(sorted(f"{f['name']}:{f['sha256']}" for f in files))
        .encode()).hexdigest() if files else None)
    return {
        **{k: v for k, v in release.items() if k != "artifact"},
        "artifact_state": state,
        "artifact_state_reason": reason,
        "artifact_identity": identity,
        "artifact_files": files,
        "artifact_missing": missing,
        "artifact_directory_contents": _discovered_files(
            art.get("directory") or ""),
        "entrypoint": art.get("entrypoint"),
        "download_available": state == ARTIFACT_PUBLISHED,
        "redistributable": state == ARTIFACT_PUBLISHED,
        "rebuild_required_per_endpoint": False,
    }


def catalog() -> List[Dict[str, Any]]:
    return [describe(r) for r in RELEASES]


def get(release_id: str) -> Optional[Dict[str, Any]]:
    r = _BY_ID.get(release_id)
    return describe(r) if r else None


def artifact_path(release_id: str, name: str) -> Optional[str]:
    r = _BY_ID.get(release_id)
    if not r:
        return None
    art = r.get("artifact") or {}
    if name not in (art.get("files") or []):
        return None
    return os.path.join(AGENTS_ROOT, art.get("directory") or "", name)


def capabilities(release_id: Optional[str]) -> Dict[str, bool]:
    """Declared capability of a release. Unknown release -> nothing is
    claimed, which is the safe direction."""
    r = _BY_ID.get(release_id or "")
    return dict((r or {}).get("declared_capabilities") or {})


def capabilities_for_connector_version(version: Optional[str],
                                       os_family: Optional[str] = None
                                       ) -> Dict[str, bool]:
    """Capabilities of whichever release matches a reported connector
    version string (the sensor reports e.g. `0.2.0-windows`).

    `os_family` matters: two releases can share a version number and
    declare different capabilities, so a Linux endpoint must never
    inherit the Windows release's declaration.
    """
    if not version:
        return {}
    want = str(os_family or "").upper() or None
    candidates = []
    for r in RELEASES:
        cv = r.get("connector_version")
        if cv and str(version).startswith(cv):
            candidates.append(r)
    if want:
        exact = [r for r in candidates if str(r.get("os")) == want]
        if exact:
            candidates = exact
    return dict((candidates[0] if candidates else {}).get(
        "declared_capabilities") or {})


DISTRIBUTION_CONTRACT = (
    "A connector release is built ONCE. The same artifact is "
    "redistributable to every device: selecting a Group or a Policy "
    "generates DEPLOYMENT CONTEXT around the released artifact and never "
    "recompiles it. The artifact SHA-256 is identical across every "
    "deployment, which is what makes it verifiable.")
