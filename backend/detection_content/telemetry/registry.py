"""
NivXRay XDR — Telemetry DSM Registry.
Unified Device Support Module registry supporting network, endpoint, and cloud telemetry.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .windows_security_dsm import WindowsSecurityDSM
from .linux_auditd_dsm import LinuxAuditdDSM
from .aws_cloudtrail_dsm import AWSCloudTrailDSM


class TelemetryDSMRegistry:
    def __init__(self):
        self._dsms: List[Any] = [
            WindowsSecurityDSM(),
            LinuxAuditdDSM(),
            AWSCloudTrailDSM(),
        ]

    def register_dsm(self, dsm: Any):
        # Insert at beginning so specialized DSMs take priority
        self._dsms.insert(0, dsm)

    def resolve(self, ev: Dict[str, Any]) -> Optional[Any]:
        for d in self._dsms:
            try:
                if d.supports(ev):
                    return d
            except Exception:
                continue
        return None

    def list(self) -> List[Dict[str, Any]]:
        return [d.identity() for d in self._dsms]


TELEMETRY_DSM_REGISTRY = TelemetryDSMRegistry()
