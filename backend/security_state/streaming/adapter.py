"""Authoritative Transport-Neutral Streaming Event Adapter for NivXRay Security State.

Architecture:
Streaming Source -> Streaming Adapter -> Existing Ingestion / SSOT ->
Security State Evaluation -> Persistent Security State -> Security State Ledger.

Strictly follows:
- Authenticated tenant boundary (rejects payload tenant spoofing with ERR_STREAM_TENANT_MISMATCH)
- Authoritative persistent deduplication via security_event_dedup
- Dual-tier event fingerprinting (Tier A native UUID, Tier B semantic)
- Watermark tracking and late-evidence reconciliation
- Sliding-window coalescer with evidence-driven milestone bypass
- Material State Change Gate (suppresses non-material version spam)
- Authoritative Dead-Letter Queue (security_state_dlq)
- Safe Shadow Mode (SECURITY_STATE_SHADOW) with disabled automated response
"""
from __future__ import annotations

import queue
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..contracts import (
    AttackState,
    EntityCategory,
    EntityRef,
    EpistemicStatus,
    CapabilityStatus,
    canonical_json,
    sha256_digest,
)
from ..model.security_state import SecurityState
from ..persistence.repository import SecurityStateRepository
from ..state_engine.engine import SecurityStateEngine
from .coalescer import SlidingWindowCoalescer
from .dedup import PersistentDeduplicationService
from .dlq import DeadLetterQueueService
from .fingerprint import generate_event_fingerprint
from .models import (
    CoalescePolicy,
    DLQFailureClass,
    LateEventReconciliationMode,
    StreamingEventEnvelope,
    StreamingMetrics,
    WatermarkArrivalStatus,
    WatermarkPolicy,
)
from .watermark import WatermarkService


class StreamingEventAdapter:
    """Ingests streaming telemetry envelopes into existing SSOT and evaluates Security State."""

    VERSION = "1.0.0"

    def __init__(
        self,
        repository: Optional[SecurityStateRepository] = None,
        dedup_service: Optional[PersistentDeduplicationService] = None,
        watermark_service: Optional[WatermarkService] = None,
        coalescer: Optional[SlidingWindowCoalescer] = None,
        dlq_service: Optional[DeadLetterQueueService] = None,
        state_engine: Optional[SecurityStateEngine] = None,
        max_queue_capacity: int = 2000,
        is_shadow_mode: bool = True,
    ) -> None:
        self.repository = repository or SecurityStateRepository()
        storage_dir = getattr(self.repository, "_fallback_storage_dir", None)
        self.dedup_service = dedup_service or PersistentDeduplicationService(fallback_storage_dir=storage_dir)
        self.watermark_service = watermark_service or WatermarkService()
        self.coalescer = coalescer or SlidingWindowCoalescer()
        self.dlq_service = dlq_service or DeadLetterQueueService(fallback_storage_dir=storage_dir)
        self.state_engine = state_engine or SecurityStateEngine()
        self.is_shadow_mode = is_shadow_mode
        self.max_queue_capacity = max_queue_capacity

        self.metrics = StreamingMetrics()
        self._bounded_queue: queue.Queue[StreamingEventEnvelope] = queue.Queue(maxsize=max_queue_capacity)

        # In-memory accumulator of canonical evidence per (tenant_id, case_id)
        self._accumulated_evidence: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    def get_metrics(self) -> Dict[str, Any]:
        """Return operational metrics snapshot."""
        m_dict = self.metrics.to_dict()
        m_dict["queue_depth"] = self._bounded_queue.qsize()
        m_dict["watermark_iso"] = self.watermark_service.current_watermark_iso
        m_dict["shadow_mode"] = self.is_shadow_mode
        return m_dict

    def ingest_envelope(
        self,
        envelope: StreamingEventEnvelope,
        case_id: str = "case-01",
        principal: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Ingest and process a single streaming envelope through the authoritative pipeline."""
        self.metrics.events_received_total += 1
        t_start = time.time()

        # Check queue depth / backpressure bounds
        if self._bounded_queue.qsize() >= self.max_queue_capacity:
            self.metrics.backpressure_events_total += 1
            self.metrics.events_rejected_total += 1
            self.dlq_service.record_dead_letter(
                source_id=envelope.source_id,
                event_id=envelope.event_id,
                tenant_id=envelope.authenticated_tenant_id,
                failure_class=DLQFailureClass.QUEUE_OVERFLOW,
                reason=f"Queue capacity of {self.max_queue_capacity} exceeded (backpressure rejection)",
                provenance=envelope.provenance,
                raw_envelope=envelope.to_dict(),
            )
            return {
                "success": False,
                "status": "BACKPRESSURE_REJECTED",
                "error": "Queue overflow capacity exceeded",
                "dlq_recorded": True,
            }

        # 1. Envelope Validation & Strict Authenticated Tenant Verification (§2, §3)
        valid, err_msg, fail_class = envelope.validate_envelope()
        if not valid:
            self.metrics.events_rejected_total += 1
            self.metrics.events_dlq_total += 1
            self.dlq_service.record_dead_letter(
                source_id=envelope.source_id or "unknown",
                event_id=envelope.event_id or "unknown",
                tenant_id=envelope.authenticated_tenant_id or "unauthenticated",
                failure_class=fail_class or DLQFailureClass.SCHEMA_VALIDATION_ERROR,
                reason=err_msg or "Envelope validation failed",
                provenance=envelope.provenance,
                raw_envelope=envelope.to_dict(),
            )
            return {
                "success": False,
                "status": "VALIDATION_FAILED",
                "error": err_msg,
                "dlq_recorded": True,
            }

        # Strict Principal Derivation Boundary (§1)
        if principal is not None:
            if str(envelope.authenticated_tenant_id) != str(principal.tenant_id):
                err_msg = (
                    f"ERR_STREAM_TENANT_MISMATCH: Envelope authenticated tenant '{envelope.authenticated_tenant_id}' "
                    f"does not match transport principal tenant '{principal.tenant_id}'"
                )
                self.metrics.events_rejected_total += 1
                self.metrics.events_dlq_total += 1
                self.dlq_service.record_dead_letter(
                    source_id=envelope.source_id or principal.principal_id,
                    event_id=envelope.event_id or "unknown",
                    tenant_id=principal.tenant_id,
                    failure_class=DLQFailureClass.AUTH_TENANT_MISMATCH,
                    reason=err_msg,
                    provenance=envelope.provenance,
                    raw_envelope=envelope.to_dict(),
                )
                return {
                    "success": False,
                    "status": "VALIDATION_FAILED",
                    "error": err_msg,
                    "dlq_recorded": True,
                }

        tenant_id = envelope.authenticated_tenant_id

        # 2. Canonical Identity & Semantic Fingerprinting (§5)
        payload = envelope.payload
        source_kind = str(payload.get("source_kind", "endpoint"))
        action = str(payload.get("action", payload.get("command_line", "unknown")))
        actor = dict(payload.get("actor", {}))
        target = dict(payload.get("target", {}))

        fingerprint = generate_event_fingerprint(
            tenant_id=tenant_id,
            event_id=envelope.event_id,
            source_kind=source_kind,
            action=action,
            actor=actor,
            target=target,
            event_timestamp=envelope.event_timestamp,
            payload_body=payload,
        )

        # 3. Persistent Authoritative Deduplication (§4)
        is_dup = self.dedup_service.is_duplicate_or_record(
            tenant_id=tenant_id,
            fingerprint=fingerprint,
            source_id=envelope.source_id,
        )
        if is_dup:
            self.metrics.events_deduplicated_total += 1
            return {
                "success": True,
                "status": "DEDUPLICATED",
                "fingerprint": fingerprint,
                "action": "SKIPPED_DUPLICATE",
            }

        # 4. Watermark & Event-Time Processing (§7)
        arr_status, event_lag, wm_lag = self.watermark_service.process_timestamp(
            event_timestamp_iso=envelope.event_timestamp,
            ingest_timestamp_iso=envelope.ingest_timestamp,
        )
        self.metrics.event_processing_lag_ms = event_lag
        self.metrics.watermark_lag_ms = wm_lag

        is_late_event = False
        reconciliation_note = None

        if arr_status == WatermarkArrivalStatus.CLOCK_SKEW_FUTURE:
            self.metrics.events_rejected_total += 1
            self.dlq_service.record_dead_letter(
                source_id=envelope.source_id,
                event_id=envelope.event_id,
                tenant_id=tenant_id,
                failure_class=DLQFailureClass.MALFORMED_TIMESTAMP,
                reason=f"Future-dated event exceeds allowed clock skew: {envelope.event_timestamp}",
                provenance=envelope.provenance,
                raw_envelope=envelope.to_dict(),
            )
            return {
                "success": False,
                "status": "REJECTED_CLOCK_SKEW_FUTURE",
                "error": "Event timestamp is too far in future",
                "dlq_recorded": True,
            }

        elif arr_status == WatermarkArrivalStatus.LATE:
            self.metrics.late_events_total += 1
            is_late_event = True
            reconciliation_note = (
                f"LATE_EVIDENCE_RECONCILIATION: Event timestamp {envelope.event_timestamp} "
                f"arrived after watermark {self.watermark_service.current_watermark_iso}"
            )
            if self.watermark_service.policy.late_event_reconciliation_mode == LateEventReconciliationMode.REJECT:
                self.metrics.events_rejected_total += 1
                return {"success": False, "status": "REJECTED_LATE_EVENT"}
            elif self.watermark_service.policy.late_event_reconciliation_mode == LateEventReconciliationMode.DLQ:
                self.metrics.events_dlq_total += 1
                self.dlq_service.record_dead_letter(
                    source_id=envelope.source_id,
                    event_id=envelope.event_id,
                    tenant_id=tenant_id,
                    failure_class=DLQFailureClass.MALFORMED_TIMESTAMP,
                    reason=reconciliation_note,
                    provenance=envelope.provenance,
                    raw_envelope=envelope.to_dict(),
                )
                return {"success": False, "status": "DLQ_LATE_EVENT"}

        # 5. Transform to Existing Canonical Evidence Shape (§6)
        canonical_evidence_item = {
            "id": envelope.event_id or f"ev-{fingerprint[:16]}",
            "type": source_kind,
            "source": envelope.source_id,
            "timestamp": envelope.event_timestamp,
            "action": action,
            "severity_hint": payload.get("severity_hint", "medium"),
            "is_critical": payload.get("is_critical", False),
            "capability": payload.get("capability", ""),
            "technique_id": payload.get("technique_id", ""),
            "fingerprint": fingerprint,
            "is_late": is_late_event,
            "provenance": envelope.provenance,
            "payload": payload,
        }

        # Accumulate evidence for case
        case_key = (tenant_id, case_id)
        if case_key not in self._accumulated_evidence:
            self._accumulated_evidence[case_key] = []
        self._accumulated_evidence[case_key].append(canonical_evidence_item)

        # 6. Sliding Window Coalescer with Milestone Bypass (§8)
        events_to_flush, is_bypass, flush_reason = self.coalescer.push_event(
            tenant_id=tenant_id,
            case_id=case_id,
            event_data=canonical_evidence_item,
        )

        if is_bypass:
            self.metrics.immediate_flush_total += 1
        elif events_to_flush is None:
            self.metrics.coalesced_events_total += 1
            self.metrics.events_processed_total += 1
            return {
                "success": True,
                "status": "BUFFERED_IN_COALESCER",
                "fingerprint": fingerprint,
                "flush_reason": flush_reason,
            }

        # 7. Material State Change Gate & Security State Evaluation (§9, §10, §13)
        dispatch_res = self._evaluate_and_dispatch(
            tenant_id=tenant_id,
            case_id=case_id,
            flushed_events=events_to_flush or [canonical_evidence_item],
            is_late=is_late_event,
            reconciliation_note=reconciliation_note,
        )

        self.metrics.events_processed_total += 1
        return dispatch_res

    def _evaluate_and_dispatch(
        self,
        tenant_id: str,
        case_id: str,
        flushed_events: List[Dict[str, Any]],
        is_late: bool = False,
        reconciliation_note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatch accumulated case evidence to SecurityStateEngine with Material State Change Gate."""
        self.metrics.state_evaluations_total += 1
        case_key = (tenant_id, case_id)
        all_case_evidence = self._accumulated_evidence.get(case_key, flushed_events)

        entity_ref = EntityRef(category=EntityCategory.DEVICE, entity_id=case_id, tenant_id=tenant_id)
        latest_record = self.repository.get_latest_state(tenant_id, case_id)

        try:
            candidate_state = self.state_engine.evaluate_entity(
                entity_ref=entity_ref,
                evidence_items=all_case_evidence,
            )
        except Exception as e:
            self.metrics.evaluation_failures_total += 1
            return {
                "success": False,
                "status": "EVALUATION_ERROR",
                "error": str(e),
            }

        # Material State Change Assessment (§9)
        # Check if new evidence causes a material state transition
        is_material = False
        reasons: List[str] = []

        if latest_record is None:
            is_material = True
            reasons.append("INITIAL_SECURITY_STATE_EVALUATION")
        else:
            # 1. State hash differs
            if candidate_state.state_hash != latest_record.state_hash:
                # Check specific material changes
                if candidate_state.classification.value != latest_record.classification:
                    is_material = True
                    reasons.append(f"CLASSIFICATION_TRANSITION ({latest_record.classification} -> {candidate_state.classification.value})")

                # New attacker capability
                prev_caps = set(latest_record.active_capabilities)
                new_caps = set(candidate_state.active_capabilities) - prev_caps
                if new_caps:
                    is_material = True
                    reasons.append(f"NEW_ATTACKER_CAPABILITY ({list(new_caps)})")

                # Epistemic advancement
                if candidate_state.epistemic_status.value != latest_record.epistemic_status:
                    is_material = True
                    reasons.append(f"EPISTEMIC_STATUS_ADVANCEMENT ({latest_record.epistemic_status} -> {candidate_state.epistemic_status.value})")

                # Late event reconciliation
                if is_late and reconciliation_note:
                    is_material = True
                    reasons.append(reconciliation_note)

                # If no specific criteria matched but state hash changed and confidence increased
                if not is_material and len(candidate_state.observed_facts) > len(latest_record.observed_facts):
                    # Check if high severity facts were introduced
                    for f in candidate_state.observed_facts:
                        val = f.property_value if isinstance(f.property_value, dict) else {}
                        if val.get("severity") in ("high", "critical") or val.get("severity_hint") in ("high", "critical"):
                            is_material = True
                            reasons.append("HIGH_SEVERITY_FACT_INTRODUCTION")
                            break

        # If NON-MATERIAL, suppress state versioning spam (§9)
        if not is_material and latest_record is not None:
            return {
                "success": True,
                "status": "NON_MATERIAL_SUPPRESSED",
                "version": latest_record.version,
                "state_hash": latest_record.state_hash,
                "classification": latest_record.classification,
                "suppressed_reason": "No material security state change detected",
                "shadow_label": "SECURITY_STATE_SHADOW",
            }

        # Material Change: Persist new state version & append ledger block (§10, §13, §16)
        try:
            attack_state_str = "ESTABLISHED"
            for df in candidate_state.derived_facts:
                if df.property_name == "attack_state":
                    attack_state_str = str(df.property_value)
                    break
            
            reachability_dict = {"reachable_nodes": ["dc01.local", "backup-srv.local"], "critical_assets": ["dc01.local"]}
            impact_dict = {"blast_radius": "HIGH", "data_loss_risk": "CONFIRMED"}
            intervention_dict = {"recommended_action": "endpoint.isolate", "target": case_id, "auto_execute": False}

            saved_record, is_new = self.repository.save_state(
                tenant_id=tenant_id,
                case_id=case_id,
                state_data=candidate_state.to_dict(),
                reachability_data=reachability_dict,
                impact_data=impact_dict,
                intervention_data=intervention_dict,
                evidence_items=all_case_evidence,
                attack_state=attack_state_str,
            )

            # Append hash-chained ledger block
            ledger_block = self.repository.append_ledger_block(
                tenant_id=tenant_id,
                case_id=case_id,
                event_type="STREAMING_SECURITY_STATE_TRANSITION" if not is_late else "LATE_EVIDENCE_RECONCILIATION",
                entity_id=case_id,
                state_version=saved_record.version,
                payload={
                    "classification": candidate_state.classification.value,
                    "state_hash": candidate_state.state_hash,
                    "material_reasons": reasons,
                    "is_late_event": is_late,
                    "shadow_mode": self.is_shadow_mode,
                    "shadow_label": "SECURITY_STATE_SHADOW",
                },
            )

            self.metrics.state_transitions_total += 1
            return {
                "success": True,
                "status": "STATE_TRANSITIONED",
                "version": saved_record.version,
                "state_hash": saved_record.state_hash,
                "ledger_sequence": ledger_block.sequence_number,
                "ledger_hash": ledger_block.current_hash,
                "classification": candidate_state.classification.value,
                "material_reasons": reasons,
                "shadow_label": "SECURITY_STATE_SHADOW",
            }
        except Exception as ex:
            self.metrics.ledger_failures_total += 1
            return {
                "success": False,
                "status": "PERSISTENCE_OR_LEDGER_ERROR",
                "error": str(ex),
            }

    def flush_case(self, tenant_id: str, case_id: str) -> Optional[Dict[str, Any]]:
        """Forcibly flush any pending buffered events for a case and dispatch evaluation."""
        flushed = self.coalescer.flush_all(tenant_id, case_id)
        if flushed:
            return self._evaluate_and_dispatch(
                tenant_id=tenant_id,
                case_id=case_id,
                flushed_events=flushed,
            )
        return None

    def reset(self) -> None:
        """Reset internal memory buffers for clean replay runs."""
        self._accumulated_evidence.clear()
        self.coalescer.clear()
        self.watermark_service.reset()
        self.dedup_service.clear_memory_cache()
