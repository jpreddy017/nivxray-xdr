"""NivXRay Security State — First-Class Provenance & Reasoning DAG."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import EpistemicStatus


@dataclass
class ProvenanceNode:
    """An atomic reasoning step or evidence item in the conclusion DAG."""
    node_id: str
    label: str
    node_type: str  # 'CONCLUSION', 'STATE_TRANSITION', 'ATTACK_STATE', 'CAPABILITY', 'CAUSAL_FACT', 'EVIDENCE', 'ASSUMPTION'
    epistemic_status: str  # One of the 10 EpistemicStatus terms
    description: str
    confidence: float = 1.0
    source_sensor: Optional[str] = None
    timestamp: Optional[str] = None
    parent_ids: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EpistemicDecomposition:
    """Explicit decomposition of uncertainty for an analyst."""
    supporting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    missing_evidence: List[Dict[str, Any]] = field(default_factory=list)
    contradictory_evidence: List[Dict[str, Any]] = field(default_factory=list)
    assumptions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProvenanceGraphBuilder:
    """Builds a deterministic, auditable provenance DAG for Security State conclusions."""

    @staticmethod
    def build_provenance_tree(
        state_record: Dict[str, Any],
        evidence_items: List[Dict[str, Any]],
        ikg: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Constructs an unbroken provenance DAG linking high-level state to evidence."""
        nodes: List[ProvenanceNode] = []
        edges: List[Dict[str, str]] = []

        case_id = state_record.get("case_id", "unknown-case")
        classification = state_record.get("classification", "NOT_EVALUATED")
        attack_state = state_record.get("attack_state", "PRE_ATTACK")
        capabilities = state_record.get("active_capabilities", [])
        version = state_record.get("version", 1)
        state_hash = state_record.get("state_hash", "")

        # 1. Root Conclusion Node
        root_id = f"conclusion::{case_id}::v{version}"
        nodes.append(
            ProvenanceNode(
                node_id=root_id,
                label=f"State: {classification}",
                node_type="CONCLUSION",
                epistemic_status=state_record.get("epistemic_status", EpistemicStatus.DERIVED.value),
                description=f"Consolidated security state classification v{version} (Hash: {state_hash[:12]}...)",
                meta={"version": version, "state_hash": state_hash, "classification": classification},
            )
        )

        # 2. Attack State Machine Node
        as_id = f"attack_state::{case_id}::{attack_state}"
        nodes.append(
            ProvenanceNode(
                node_id=as_id,
                label=f"Attack State: {attack_state}",
                node_type="ATTACK_STATE",
                epistemic_status=EpistemicStatus.DERIVED.value,
                description=f"Current advancement in 18-stage attack lifecycle: {attack_state}",
                parent_ids=[root_id],
            )
        )
        edges.append({"source": root_id, "target": as_id, "relation": "advances_to"})

        # 3. Active Capabilities Nodes
        for cap in capabilities:
            cap_id = f"capability::{case_id}::{cap}"
            nodes.append(
                ProvenanceNode(
                    node_id=cap_id,
                    label=f"Capability: {cap}",
                    node_type="CAPABILITY",
                    epistemic_status=EpistemicStatus.SUPPORTED.value,
                    description=f"Observed or inferred dual-use capability: {cap}",
                    parent_ids=[as_id],
                )
            )
            edges.append({"source": as_id, "target": cap_id, "relation": "exhibits_capability"})

        # 4. Derived Facts / Causal Links
        derived_facts = state_record.get("derived_facts", [])
        for idx, df in enumerate(derived_facts):
            df_id = f"derived_fact::{case_id}::{idx}"
            rule = df.get("rule_or_model", "causal_inference")
            prop = df.get("property_name", "")
            val = df.get("property_value", "")
            nodes.append(
                ProvenanceNode(
                    node_id=df_id,
                    label=f"Causal Fact: {prop}",
                    node_type="CAUSAL_FACT",
                    epistemic_status=EpistemicStatus.DERIVED.value,
                    description=f"Derived by rule '{rule}': {prop} = {val}",
                    confidence=df.get("confidence", 1.0),
                    parent_ids=[as_id],
                )
            )
            edges.append({"source": as_id, "target": df_id, "relation": "supported_by_fact"})

        # 5. Ground-Truth Evidence Nodes (connecting to IKG / CES frames)
        for ev in evidence_items[:20]:  # Bound top 20 for legible UI DAG
            ev_id = ev.get("id") or ev.get("evidence_id") or f"ev-{hash(str(ev)) % 100000}"
            action = ev.get("action") or ev.get("source") or "telemetry"
            ts = ev.get("timestamp") or ev.get("event_timestamp") or ""
            cmd = ""
            if isinstance(ev.get("payload"), dict):
                cmd = ev["payload"].get("command_line") or ev["payload"].get("process_name") or ""
            elif isinstance(ev.get("observation"), str):
                cmd = ev["observation"]

            ev_node_id = f"evidence::{ev_id}"
            nodes.append(
                ProvenanceNode(
                    node_id=ev_node_id,
                    label=f"Evidence: {action}",
                    node_type="EVIDENCE",
                    epistemic_status=EpistemicStatus.OBSERVED.value,
                    description=cmd or f"Ground truth sensor event ({action})",
                    timestamp=ts,
                    source_sensor=ev.get("source") or "endpoint_sensor",
                )
            )
            # Link to capabilities or attack state
            edges.append({"source": as_id, "target": ev_node_id, "relation": "grounded_in_telemetry"})

        # 6. Epistemic Uncertainty Decomposition
        decomposition = EpistemicDecomposition(
            supporting_evidence=evidence_items,
            missing_evidence=state_record.get("missing_evidence", []),
            contradictory_evidence=state_record.get("contradictions", []),
            assumptions=state_record.get("assumptions", []),
        )

        return {
            "case_id": case_id,
            "version": version,
            "root_conclusion_id": root_id,
            "nodes": [n.to_dict() for n in nodes],
            "edges": edges,
            "epistemic_decomposition": decomposition.to_dict(),
        }
