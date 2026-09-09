"""
NivXRay XDR — Telemetry Ingestion & Normalization Module.

P0-2 note (2026-09-05): DSM classes are re-exported LAZILY via PEP-562
`__getattr__`.  Eager top-level imports would defeat the per-DSM load-failure
visibility in `registry.py` — one broken DSM module would make importing the
whole telemetry package fail, which is precisely the silent-failure class this
work removes.  The public import surface is unchanged:

    from detection_content.telemetry import WindowsSecurityDSM   # still works
"""
from __future__ import annotations

from .models import (
    CanonicalTelemetryEvent,
    HostEntity,
    IdentityEntity,
    ProcessEntity,
    NetworkEntity,
    FileEntity,
    AuthEntity,
    CloudContext,
    ProvenanceEnvelope,
)
from .registry import TelemetryDSMRegistry, TELEMETRY_DSM_REGISTRY

_LAZY: dict[str, str] = {
    "WindowsSecurityDSM":        ".windows_security_dsm",
    "WindowsSecurityParser":     ".windows_security_dsm",
    "WindowsSecurityNormalizer": ".windows_security_dsm",
    "LinuxAuditdDSM":            ".linux_auditd_dsm",
    "LinuxAuditdParser":         ".linux_auditd_dsm",
    "LinuxAuditdNormalizer":     ".linux_auditd_dsm",
    "AWSCloudTrailDSM":          ".aws_cloudtrail_dsm",
    "AWSCloudTrailParser":       ".aws_cloudtrail_dsm",
    "AWSCloudTrailNormalizer":   ".aws_cloudtrail_dsm",
    "SysmonDSM":                 ".sysmon_dsm",
    "SysmonParser":              ".sysmon_dsm",
    "SysmonNormalizer":          ".sysmon_dsm",
}


def __getattr__(name: str):
    module_path = _LAZY.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module
    module = import_module(module_path, __name__)
    value = getattr(module, name)
    globals()[name] = value          # cache; subsequent access is direct
    return value


__all__ = [
    "CanonicalTelemetryEvent",
    "HostEntity",
    "IdentityEntity",
    "ProcessEntity",
    "NetworkEntity",
    "FileEntity",
    "AuthEntity",
    "CloudContext",
    "ProvenanceEnvelope",
    "WindowsSecurityDSM",
    "WindowsSecurityParser",
    "WindowsSecurityNormalizer",
    "LinuxAuditdDSM",
    "LinuxAuditdParser",
    "LinuxAuditdNormalizer",
    "AWSCloudTrailDSM",
    "AWSCloudTrailParser",
    "AWSCloudTrailNormalizer",
    "SysmonDSM",
    "SysmonParser",
    "SysmonNormalizer",
    "TelemetryDSMRegistry",
    "TELEMETRY_DSM_REGISTRY",
]
