"""Adapters connecting Security State Core to existing NivXRay engines."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..contracts import (
    EntityCategory,
    EntityRef,
)
from ..model.security_state import SecurityState
from ..state_engine.engine import SecurityStateEngine


class SSOTAdapter:
    """Reads AuthoritativeSSOT and CEM models to construct SecurityState inputs."""
    VERSION = "1.0.0"

    def __init__(self, state_engine: Optional[SecurityStateEngine] = None) -> None:
        self.state_engine = state_engine or SecurityStateEngine()

    def extract_evidence_from_ssot(self, ssot_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract normalized evidence list from an AuthoritativeSSOT dictionary."""
        evidence_items: List[Dict[str, Any]] = []

        # 1. Raw / Profile input
        if ssot_data.get("input_raw"):
            evidence_items.append({
                "id": "ev-input-raw",
                "type": "input_payload",
                "source": ssot_data.get("source", {}).get("channel", "ssot"),
                "timestamp": ssot_data.get("created_at", "2026-09-04T00:00:00Z"),
                "payload": {
                    "command_line": str(ssot_data.get("input_raw", "")),
                    "profile": ssot_data.get("input_profile", {}),
                },
            })

        # 2. Artifacts
        for art in ssot_data.get("artifacts", []):
            evidence_items.append({
                "id": art.get("id", f"art-{len(evidence_items)}"),
                "type": "extracted_artifact",
                "source": "decoder_pipeline",
                "timestamp": art.get("provenance", {}).get("at", "2026-09-04T00:00:00Z"),
                "payload": art.get("attrs", {}),
            })

        # 3. Graph Nodes
        for node in ssot_data.get("evidence_graph", {}).get("nodes", []):
            evidence_items.append({
                "id": node.get("id", f"node-{len(evidence_items)}"),
                "type": node.get("kind", "graph_node"),
                "source": "evidence_graph",
                "timestamp": node.get("provenance", {}).get("at", "2026-09-04T00:00:00Z"),
                "payload": node.get("attrs", {}),
            })

        return evidence_items

    def extract_from_investigation_result(self, result: Any, case_id: str = "case-01") -> List[Dict[str, Any]]:
        """Extract canonical evidence from a real NivXRay v2 InvestigationResult."""
        evidence_items: List[Dict[str, Any]] = []
        
        # 1. Input / CRE effective command
        cmd = ""
        if hasattr(result, "cre") and result.cre:
            cmd = getattr(result.cre, "effective_payload", "")
        if not cmd and hasattr(result, "report") and result.report:
            cmd = getattr(result.report, "input_summary", "")

        evidence_items.append({
            "id": f"ev-{case_id}-cmd",
            "type": "process",
            "source": "v2_investigation_pipeline",
            "timestamp": "2026-09-04T00:00:00Z",
            "payload": {
                "process_name": "powershell.exe" if "powershell" in cmd.lower() else "cmd.exe",
                "command_line": cmd,
                "iu_type": str(getattr(getattr(result, "iu", None), "primary_type", "")),
            }
        })

        # 2. Intents
        if hasattr(result, "intent") and result.intent:
            intents = getattr(result.intent, "intents", [])
            for idx, item in enumerate(intents):
                evidence_items.append({
                    "id": f"ev-{case_id}-intent-{idx}",
                    "type": "derived_intent",
                    "source": "semantic_intent_engine",
                    "timestamp": "2026-09-04T00:00:00Z",
                    "payload": {
                        "category": str(getattr(item, "category", "")),
                        "reason": str(getattr(item, "reason", "")),
                        "confidence": float(getattr(item, "confidence", 0.8)),
                    }
                })

        # 3. Verdict
        if hasattr(result, "verdict") and result.verdict:
            evidence_items.append({
                "id": f"ev-{case_id}-verdict",
                "type": "verdict_telemetry",
                "source": "v2_verdict_engine",
                "timestamp": "2026-09-04T00:00:00Z",
                "payload": {
                    "score": float(getattr(result.verdict, "score", 0.0)),
                    "label": str(getattr(result.verdict, "label", "")),
                    "reasons": list(getattr(result.verdict, "reasons", [])),
                }
            })

        return evidence_items


class VerdictAdapter:
    """Consumes CanonicalVerdict output from v2 Verdict Engine without altering scoring."""
    VERSION = "1.0.0"

    def correlate_verdict_with_state(
        self,
        verdict_data: Dict[str, Any],
        security_state: SecurityState,
    ) -> Dict[str, Any]:
        """Correlate verdict confidence with security state without mutative side-effects."""
        v_label = verdict_data.get("label", "Undetermined")
        v_conf = verdict_data.get("confidence", 0.0)
        v_reasons = verdict_data.get("reason", "")

        return {
            "entity_id": security_state.entity_ref.entity_id,
            "verdict_label": v_label,
            "verdict_confidence": v_conf,
            "verdict_reason": v_reasons,
            "security_state_classification": security_state.classification.value,
            "epistemic_status": security_state.epistemic_status.value,
            "active_capabilities": security_state.active_capabilities,
        }
