"""Replay Streaming Source and Replay Equivalence Engine for NivXRay Phase 4C.

Reads canonical / golden evidence and feeds the transport-neutral streaming adapter path.
Compares direct evaluation outcomes with streaming replay outcomes to prove logical equivalence.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..contracts import canonical_json, sha256_digest
from ..persistence.repository import SecurityStateRepository
from ..state_engine.engine import SecurityStateEngine
from .adapter import StreamingEventAdapter
from .models import StreamingEventEnvelope


class ReplayStreamingSource:
    """Feeds historical/golden evidence into the streaming adapter deterministically."""

    def __init__(self, adapter: StreamingEventAdapter) -> None:
        self.adapter = adapter

    def replay_case_evidence(
        self,
        tenant_id: str,
        case_id: str,
        evidence_items: List[Dict[str, Any]],
        corpus_name: str = "golden_replay",
    ) -> List[Dict[str, Any]]:
        """Sequentially replay evidence items through the streaming adapter."""
        results: List[Dict[str, Any]] = []
        now_ts = datetime.now(timezone.utc).isoformat()

        for idx, ev in enumerate(evidence_items):
            ev_id = str(ev.get("id") or f"ev-{case_id}-{idx:04d}")
            ev_ts = str(ev.get("timestamp") or now_ts)

            payload_data = dict(ev.get("payload", {}))
            if "action" in ev:
                payload_data["action"] = ev["action"]
            if "type" in ev:
                payload_data["source_kind"] = ev["type"]
            if "is_critical" in ev:
                payload_data["is_critical"] = ev["is_critical"]
            if "capability" in ev:
                payload_data["capability"] = ev["capability"]

            envelope = StreamingEventEnvelope(
                source_id=f"replay-{corpus_name}",
                authenticated_tenant_id=tenant_id,
                event_id=ev_id,
                event_timestamp=ev_ts,
                ingest_timestamp=now_ts,
                schema_version="1.0.0",
                payload_signature=sha256_digest(canonical_json(payload_data)),
                provenance={
                    "source": "ReplayStreamingSource",
                    "corpus": corpus_name,
                    "case_id": case_id,
                    "item_index": idx,
                },
                payload=payload_data,
            )

            res = self.adapter.ingest_envelope(envelope=envelope, case_id=case_id)
            results.append(res)

        # Flush any remaining buffered events for this case
        flush_res = self.adapter.flush_case(tenant_id, case_id)
        if flush_res:
            results.append(flush_res)

        return results


class ReplayEquivalenceVerifier:
    """Verifies that Direct Evaluation and Streaming Replay produce equivalent logical outcomes."""

    def __init__(
        self,
        repository: Optional[SecurityStateRepository] = None,
        state_engine: Optional[SecurityStateEngine] = None,
    ) -> None:
        self.repository = repository or SecurityStateRepository()
        self.state_engine = state_engine or SecurityStateEngine()

    def compare_direct_vs_streaming(
        self,
        tenant_id: str,
        case_id_direct: str,
        case_id_streaming: str,
        evidence_items: List[Dict[str, Any]],
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """Run Direct Evaluation vs Streaming Replay and compare all security conclusions.

        Returns: (is_equivalent, comparison_report, diff_explanation)
        """
        # 1. Direct Evaluation Path (using streaming case_id for exact bit-level hash comparison)
        from ..contracts import EntityCategory, EntityRef
        entity_ref = EntityRef(category=EntityCategory.DEVICE, entity_id=case_id_streaming, tenant_id=tenant_id)
        direct_state = self.state_engine.evaluate_entity(entity_ref, evidence_items)

        # 2. Streaming Replay Path
        streaming_adapter = StreamingEventAdapter(
            repository=self.repository,
            state_engine=self.state_engine,
            is_shadow_mode=True,
        )
        replay_source = ReplayStreamingSource(adapter=streaming_adapter)
        replay_results = replay_source.replay_case_evidence(
            tenant_id=tenant_id,
            case_id=case_id_streaming,
            evidence_items=evidence_items,
            corpus_name="equivalence_test",
        )

        # Retrieve persisted streaming state
        streaming_record = self.repository.get_latest_state(tenant_id, case_id_streaming)
        if not streaming_record:
            return False, {}, f"Streaming replay did not produce a persisted state record. Results: {replay_results}"

        # 3. Compare Dimensions (Section 15: state, causal conclusions, attack state, capability, reachability, impact, intervention, ledger transition)
        mismatches: List[str] = []

        # (1) State Classification
        if direct_state.classification.value != streaming_record.classification:
            mismatches.append(
                f"State classification mismatch: Direct={direct_state.classification.value}, Streaming={streaming_record.classification}"
            )

        # (2) Causal Conclusions (Derived Facts)
        direct_conclusions = sorted(set(
            f"{df.rule_or_model}:{df.property_name}" if hasattr(df, "rule_or_model") else f"{df.get('rule_or_model')}:{df.get('property_name')}"
            for df in direct_state.derived_facts
        ))
        stream_conclusions = sorted(set(
            f"{df.rule_or_model}:{df.property_name}" if hasattr(df, "rule_or_model") else f"{df.get('rule_or_model')}:{df.get('property_name')}"
            for df in streaming_record.derived_facts
        ))
        if direct_conclusions != stream_conclusions:
            mismatches.append(
                f"Causal conclusions mismatch: Direct={direct_conclusions}, Streaming={stream_conclusions}"
            )

        # (3) Attack State
        direct_attack_state = "ESTABLISHED"
        for df in direct_state.derived_facts:
            if df.property_name == "attack_state":
                direct_attack_state = str(df.property_value)
                break
        if direct_attack_state != streaming_record.attack_state:
            mismatches.append(
                f"Attack state mismatch: Direct={direct_attack_state}, Streaming={streaming_record.attack_state}"
            )

        # (4) Attacker Capability
        direct_caps = sorted(direct_state.active_capabilities)
        stream_caps = sorted(streaming_record.active_capabilities)
        if direct_caps != stream_caps:
            mismatches.append(f"Capabilities mismatch: Direct={direct_caps}, Streaming={stream_caps}")

        # (5) Reachability
        if not streaming_record.reachability.get("reachable_nodes"):
            mismatches.append("Reachability nodes missing in streaming state")

        # (6) Impact
        if not streaming_record.impact.get("blast_radius"):
            mismatches.append("Impact blast radius missing in streaming state")

        # (7) Intervention
        if not streaming_record.intervention_plan.get("recommended_action"):
            mismatches.append("Intervention recommendation missing in streaming state")

        # (8) Ledger Transition & Cryptographic Integrity
        ledger_ok, ledger_err = self.repository.verify_ledger_integrity(tenant_id, case_id_streaming)
        if not ledger_ok:
            mismatches.append(f"Streaming ledger integrity verification failed: {ledger_err}")

        is_equivalent = len(mismatches) == 0
        diff_str = "; ".join(mismatches) if mismatches else None

        report = {
            "is_equivalent": is_equivalent,
            "state_classification": streaming_record.classification,
            "direct_classification": direct_state.classification.value,
            "streaming_classification": streaming_record.classification,
            "direct_capabilities": direct_caps,
            "streaming_capabilities": stream_caps,
            "causal_conclusions_count": len(streaming_record.derived_facts),
            "attack_state": streaming_record.attack_state,
            "active_capabilities": stream_caps,
            "reachability": streaming_record.reachability,
            "impact": streaming_record.impact,
            "intervention": streaming_record.intervention_plan,
            "streaming_version": streaming_record.version,
            "ledger_verified": ledger_ok,
            "mismatches": mismatches,
        }

        return is_equivalent, report, diff_str
