"""File disposition from our OWN signature / hash-reputation engines (AMP parity: a known-signature hit IS evidence-backed
MALICIOUS file disposition, with provenance). Behavioral MATCH, ML (TESTING), IOC correlation and MITRE mapping are NOT
disposition evidence and never produce one."""
from __future__ import annotations

from typing import Any

DISPOSITION_KINDS = {"SIGNATURE", "HASH_REPUTATION"}
NOT_DISPOSITION = {"BEHAVIORAL_MATCH", "ML_TESTING", "IOC_CORRELATION", "MITRE_MAPPING"}


def signature_assessment(det: dict[str, Any] | None) -> dict[str, Any] | None:
    if not det or det.get("kind") not in DISPOSITION_KINDS or not det.get("name") or not det.get("at"):
        return None
    engine = det.get("engine") or "signature engine"
    return {"state": "MALICIOUS", "source": engine,
            "evidence": [{"provider": engine, "kind": det["kind"], "basis": f"{engine} signature {det['name']}, {det['at']}",
                          "observation_id": det.get("observation_id")}]}
