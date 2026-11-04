"""
Evidence Forwarder · Phase 1.

The Response Engine NEVER writes SSOT / Verdict / IKG directly.
Every completed execution emits (evidence, audit, timeline) rows to
the authoritative NivXRay backend via the Response→Base contract
defined in RESPONSE_INGEST_CONTRACT.md.

If the base target is unset, the forwarder returns synthetic local
refs and stamps the execution `forwarding_state = "not_wired"`.  The
execution is still recorded on the response engine so the invoker
gets a deterministic outcome.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing   import Any, Dict, Optional

import httpx


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceForwarder:
    def __init__(self) -> None:
        self.forwarded:      int = 0
        self.failed:         int = 0
        self.last_error: Optional[str] = None
        self.last_forwarded_at: Optional[str] = None

    @property
    def url(self) -> Optional[str]:
        return os.environ.get("NIVX_RESPONSE_EVIDENCE_URL") or None
    @property
    def token(self) -> Optional[str]:
        return os.environ.get("NIVX_RESPONSE_EVIDENCE_TOKEN") or None
    @property
    def timeout(self) -> float:
        return float(os.environ.get("NIVX_RESPONSE_EVIDENCE_TIMEOUT", "10"))

    def configured(self) -> bool:
        return bool(self.url)

    def status(self) -> Dict[str, Any]:
        return {
            "configured":         self.configured(),
            "state":              "connected" if self.configured() else "not_wired",
            "forwarded":          self.forwarded,
            "failed":             self.failed,
            "last_error":         self.last_error,
            "last_forwarded_at":  self.last_forwarded_at,
        }

    async def forward(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """POST an evidence envelope to the base.  Returns
        `{evidence_ref, audit_ref, timeline_ref, forwarding_state}`.

        If the forwarder is not configured we still return
        deterministic refs so the invoker gets a complete response —
        the `forwarding_state` field makes the "not-wired" reality
        explicit and honest."""
        if not self.configured():
            refs = _synth_refs()
            return {**refs, "forwarding_state": "not_wired",
                     "reason": "NIVX_RESPONSE_EVIDENCE_URL is not set"}
        try:
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.url, json=envelope, headers=headers)
                resp.raise_for_status()
            body = resp.json() if resp.text else {}
            self.forwarded += 1
            self.last_error = None
            self.last_forwarded_at = _iso()
            return {
                "evidence_ref":  body.get("evidence_ref")  or _synth_refs()["evidence_ref"],
                "audit_ref":     body.get("audit_ref")     or _synth_refs()["audit_ref"],
                "timeline_ref":  body.get("timeline_ref")  or _synth_refs()["timeline_ref"],
                "forwarding_state": "forwarded",
            }
        except Exception as e:                                  # noqa: BLE001
            self.failed += 1
            self.last_error = f"{type(e).__name__}: {e}"
            # Never LIE — mark the execution as failed_forwarding so
            # the caller / operator knows the evidence chain is broken.
            return {**_synth_refs(),
                     "forwarding_state": "failed_forwarding",
                     "reason":           self.last_error}


def _synth_refs() -> Dict[str, str]:
    return {
        "evidence_ref": "local-evidence-" + uuid.uuid4().hex[:12],
        "audit_ref":    "local-audit-"    + uuid.uuid4().hex[:12],
        "timeline_ref": "local-timeline-" + uuid.uuid4().hex[:12],
    }
