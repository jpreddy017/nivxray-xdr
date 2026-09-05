"""
NivXRay XDR — Telemetry DSM Registry (SINGLE AUTHORITATIVE REGISTRY).

P0-2 unification (owner-authorised 2026-09-05).  Before this change there
were two registries: `xdr_pipeline.DSMRegistry` (used in production) and
`TelemetryDSMRegistry` (used only by tests, missing SysmonDSM, with a
`register_dsm()` that was never called).  They are now the same object.

Invariants (owner-mandated):
  * ONE authoritative production registry — `TELEMETRY_DSM_REGISTRY`.
  * NO silent import/registration failure.  Every failure is logged at
    ERROR and recorded in `load_failures()` so an operator can tell
    "DSM never loaded" apart from "no DSM supports this event".
  * `supports()` failures FAIL CLOSED (treated as non-supporting) and are
    recorded in `resolve_failures()` — never silently discarded, never
    propagated into the pipeline.
  * Resolution order is preserved exactly as it was in production:
        snort-eve, windows-security-evd, linux-auditd,
        aws-cloudtrail, microsoft-sysmon
    `snort-eve` is registered first by `xdr_pipeline` (first=True).
  * Registration is idempotent by DSM id.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("nivxray.xdr.telemetry.dsm_registry")


class TelemetryDSMRegistry:
    """Authoritative DSM registry.  Loud on failure, fail-closed on resolve."""

    def __init__(self) -> None:
        self._dsms: List[Any] = []
        self._load_failures: List[Dict[str, Any]] = []
        self._resolve_failures: List[Dict[str, Any]] = []

    # ── registration ────────────────────────────────────────────────
    def register(self, dsm: Any, *, first: bool = False) -> bool:
        """Register a DSM instance.  Idempotent by `dsm.id`."""
        dsm_id = getattr(dsm, "id", None) or dsm.__class__.__name__
        if any((getattr(d, "id", None) or d.__class__.__name__) == dsm_id
               for d in self._dsms):
            return False
        if first:
            self._dsms.insert(0, dsm)
        else:
            self._dsms.append(dsm)
        return True

    # Backwards-compatible alias retained for the pre-P0-2 API surface.
    def register_dsm(self, dsm: Any) -> bool:
        return self.register(dsm, first=True)

    def register_failure(self, dsm_id: str, exc: BaseException,
                         *, phase: str = "import") -> None:
        """Record — loudly — that a DSM could not be loaded."""
        record = {
            "dsm_id": dsm_id,
            "status": "LOAD_FAILED",
            "phase": phase,
            "error_type": type(exc).__name__,
            "error": str(exc)[:400],
        }
        self._load_failures.append(record)
        log.error(
            "DSM LOAD FAILED · dsm_id=%s phase=%s %s: %s",
            dsm_id, phase, type(exc).__name__, str(exc)[:400],
        )

    def try_register(self, dsm_id: str, factory, *, first: bool = False) -> bool:
        """Instantiate + register a DSM, recording any failure observably.

        `factory` is a zero-arg callable that imports and constructs the
        DSM.  Import errors, constructor errors and syntax errors inside
        the DSM module are all captured per-DSM — one broken DSM can no
        longer take its siblings down with it.
        """
        try:
            dsm = factory()
        except BaseException as exc:  # noqa: BLE001 — recorded, then re-surfaced via load_failures()
            self.register_failure(dsm_id, exc, phase="import")
            return False
        try:
            return self.register(dsm, first=first)
        except BaseException as exc:  # noqa: BLE001
            self.register_failure(dsm_id, exc, phase="register")
            return False

    # ── resolution ──────────────────────────────────────────────────
    def resolve(self, ev: Dict[str, Any]) -> Optional[Any]:
        """First DSM whose `supports()` returns True, else None.

        A DSM whose `supports()` raises is treated as NOT supporting
        (fail closed) and the failure is recorded in `resolve_failures()`.
        """
        for d in self._dsms:
            try:
                if d.supports(ev):
                    return d
            except BaseException as exc:  # noqa: BLE001 — fail closed, stay observable
                dsm_id = getattr(d, "id", None) or d.__class__.__name__
                record = {
                    "dsm_id": dsm_id,
                    "status": "SUPPORTS_ERROR",
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:400],
                }
                self._resolve_failures.append(record)
                log.error(
                    "DSM supports() FAILED · dsm_id=%s %s: %s — failing closed",
                    dsm_id, type(exc).__name__, str(exc)[:400],
                )
                continue
        return None

    # ── observability ───────────────────────────────────────────────
    def list(self) -> List[Dict[str, Any]]:
        """Identities of loaded DSMs.  Shape unchanged from pre-P0-2."""
        return [d.identity() for d in self._dsms]

    def load_failures(self) -> List[Dict[str, Any]]:
        return list(self._load_failures)

    def resolve_failures(self) -> List[Dict[str, Any]]:
        return list(self._resolve_failures)

    def health(self) -> Dict[str, Any]:
        """Operator-facing truth: what loaded, what failed, and why."""
        return {
            "registry": "nivxray::xdr::telemetry::dsm_registry",
            "loaded_count": len(self._dsms),
            "loaded": self.list(),
            "load_failure_count": len(self._load_failures),
            "load_failures": self.load_failures(),
            "resolve_failure_count": len(self._resolve_failures),
            "resolve_failures": self.resolve_failures(),
            "honesty_note": (
                "load_failures lists DSMs that exist in the codebase but could "
                "not be imported or constructed. A source whose DSM appears here "
                "will report 'no DSM supports this event' for every event — that "
                "is a CODE failure, not a data mismatch."
            ),
        }


TELEMETRY_DSM_REGISTRY = TelemetryDSMRegistry()


# ── Telemetry-package DSMs · explicit, per-DSM, loud on failure ─────
# Order here is preserved from the pre-P0-2 production registry.
# `snort-eve` is registered by `detection_content.xdr_pipeline` with
# first=True so it keeps position 0.

def _register_builtin_dsms(reg: TelemetryDSMRegistry) -> None:
    def _windows():
        from .windows_security_dsm import WindowsSecurityDSM
        return WindowsSecurityDSM()

    def _linux():
        from .linux_auditd_dsm import LinuxAuditdDSM
        return LinuxAuditdDSM()

    def _cloudtrail():
        from .aws_cloudtrail_dsm import AWSCloudTrailDSM
        return AWSCloudTrailDSM()

    def _sysmon():
        from .sysmon_dsm import SysmonDSM
        return SysmonDSM()

    reg.try_register("windows-security-evd", _windows)
    reg.try_register("linux-auditd", _linux)
    reg.try_register("aws-cloudtrail", _cloudtrail)
    reg.try_register("microsoft-sysmon", _sysmon)


_register_builtin_dsms(TELEMETRY_DSM_REGISTRY)
