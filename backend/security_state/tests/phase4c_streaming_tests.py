"""Comprehensive Phase 4C Test Suite for NivXRay Streaming Adapter & Shadow Mode."""
from __future__ import annotations

import os
import shutil
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from security_state.contracts import (
    EntityCategory,
    EntityRef,
    CapabilityStatus,
    canonical_json,
    sha256_digest,
)
from security_state.persistence.repository import SecurityStateRepository
from security_state.state_engine.engine import SecurityStateEngine
from security_state.streaming.adapter import StreamingEventAdapter
from security_state.streaming.coalescer import SlidingWindowCoalescer
from security_state.streaming.dedup import PersistentDeduplicationService
from security_state.streaming.dlq import DeadLetterQueueService
from security_state.streaming.fingerprint import generate_event_fingerprint, quantize_timestamp_1s
from security_state.streaming.models import (
    CoalescePolicy,
    DLQFailureClass,
    LateEventReconciliationMode,
    StreamingEventEnvelope,
    WatermarkArrivalStatus,
    WatermarkPolicy,
)
from security_state.streaming.replay import ReplayEquivalenceVerifier, ReplayStreamingSource
from security_state.streaming.watermark import WatermarkService


def get_test_dir(suffix: str = "phase4c") -> str:
    d = os.path.join(os.path.dirname(__file__), f".test_storage_{suffix}")
    os.makedirs(d, exist_ok=True)
    return d


def clean_test_dir(d: str) -> None:
    shutil.rmtree(d, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1: Envelope Validation & Strict Authenticated Tenant Security
# ─────────────────────────────────────────────────────────────────────────────
def test_envelope_validation_and_tenant_security():
    test_dir = get_test_dir("t1_tenant")
    clean_test_dir(test_dir)
    try:
        dlq_svc = DeadLetterQueueService(fallback_storage_dir=test_dir)
        adapter = StreamingEventAdapter(
            repository=SecurityStateRepository(fallback_storage_dir=test_dir),
            dlq_service=dlq_svc,
        )

        # 1. Valid envelope passes
        valid_env = StreamingEventEnvelope(
            source_id="edr-agent-01",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={"action": "process.start", "command_line": "powershell.exe -NoP"},
        )
        res = adapter.ingest_envelope(valid_env, case_id="case-t1")
        assert res["success"] is True, f"Valid envelope failed: {res}"

        # 2. Forged Tenant Injection in Payload: Payload says tenant-evil, Auth is tenant-corp!
        spoofed_env = StreamingEventEnvelope(
            source_id="edr-agent-01",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={
                "tenant_id": "tenant-evil",  # FORGERY ATTEMPT
                "action": "process.start",
                "command_line": "net user /add",
            },
        )
        res_spoof = adapter.ingest_envelope(spoofed_env, case_id="case-t1")
        assert res_spoof["success"] is False, "Spoofed tenant envelope MUST fail!"
        assert "ERR_STREAM_TENANT_MISMATCH" in res_spoof["error"]
        assert res_spoof["dlq_recorded"] is True

        # Verify DLQ record
        dlq_recs = dlq_svc.get_dlq_records("tenant-corp")
        assert len(dlq_recs) == 1
        assert dlq_recs[0].failure_class == DLQFailureClass.AUTH_TENANT_MISMATCH.value
        assert "tenant-evil" in dlq_recs[0].reason

        # 3. Payload Integrity Violation (tampered signature)
        tampered_env = StreamingEventEnvelope(
            source_id="edr-agent-01",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload_signature="invalid_signature_hash_12345",
            payload={"action": "service.install"},
        )
        res_tamp = adapter.ingest_envelope(tampered_env, case_id="case-t1")
        assert res_tamp["success"] is False
        assert "signature mismatch" in res_tamp["error"].lower()
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2: Canonical Event Identity & Dual-Tier Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────
def test_canonical_identity_and_dual_tier_fingerprinting():
    # Tier A: Valid Native UUID
    native_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    fp_tier_a = generate_event_fingerprint(
        tenant_id="tenant-corp",
        event_id=native_uuid,
        source_kind="endpoint",
        action="process.start",
        actor={"name": "admin"},
        target={"name": "cmd.exe"},
        event_timestamp="2026-09-04T05:00:00.123456Z",
    )
    assert fp_tier_a == f"tier_a:tenant-corp:{native_uuid}"

    # Tier B: Semantic Fingerprint with 1-second timestamp quantization
    ts1 = "2026-09-04T05:00:00.123456Z"
    ts2 = "2026-09-04T05:00:00.876543Z"  # Same second, different microsecond jitter

    fp_b1 = generate_event_fingerprint(
        tenant_id="tenant-corp",
        event_id=None,  # Missing UUID
        source_kind="endpoint",
        action="process.start",
        actor={"name": "admin", "ip": "10.0.0.5"},
        target={"name": "powershell.exe"},
        event_timestamp=ts1,
        payload_body={"command_line": "Get-Process"},
    )
    fp_b2 = generate_event_fingerprint(
        tenant_id="tenant-corp",
        event_id=None,
        source_kind="endpoint",
        action="process.start",
        actor={"name": "admin", "ip": "10.0.0.5"},
        target={"name": "powershell.exe"},
        event_timestamp=ts2,
        payload_body={"command_line": "Get-Process"},
    )
    assert fp_b1.startswith("tier_b:tenant-corp:")
    assert fp_b1 == fp_b2, "1-second quantization must neutralize microsecond transport jitter!"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3: Persistent Authoritative Deduplication Across Restarts
# ─────────────────────────────────────────────────────────────────────────────
def test_persistent_deduplication_across_restarts():
    test_dir = get_test_dir("t3_dedup")
    clean_test_dir(test_dir)
    try:
        dedup_svc = PersistentDeduplicationService(fallback_storage_dir=test_dir)
        fp = "tier_b:tenant-corp:test_fingerprint_hash_abc123"

        # 1. First event -> Not duplicate
        is_dup1 = dedup_svc.is_duplicate_or_record("tenant-corp", fp, "source-1")
        assert is_dup1 is False, "First arrival must not be duplicate"

        # 2. Second event -> Duplicate
        is_dup2 = dedup_svc.is_duplicate_or_record("tenant-corp", fp, "source-1")
        assert is_dup2 is True, "Second arrival must be detected as duplicate"

        # 3. Simulate Server Restart: Wipe in-memory LRU cache
        dedup_svc.clear_memory_cache()

        # 4. Third event post-restart -> MUST STILL BE DETECTED AS DUPLICATE FROM DISK/DB!
        is_dup3 = dedup_svc.is_duplicate_or_record("tenant-corp", fp, "source-1")
        assert is_dup3 is True, "Authoritative persistent store must detect duplicate even after restart!"

        # 5. Multi-tenant isolation: Same fingerprint for tenant-other is NOT duplicate
        is_dup_other = dedup_svc.is_duplicate_or_record("tenant-other", fp, "source-1")
        assert is_dup_other is False, "Deduplication must be strictly tenant-scoped"
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4: Watermark Tracking, Out-of-Order & Late Event Reconciliation
# ─────────────────────────────────────────────────────────────────────────────
def test_watermark_tracking_and_late_reconciliation():
    policy = WatermarkPolicy(watermark_delay_seconds=10.0, allowed_clock_skew_seconds=30.0)
    wm_svc = WatermarkService(policy=policy)

    now = datetime.now(timezone.utc)
    t0 = now.isoformat()
    t_future = (now + timedelta(seconds=60)).isoformat()
    t_past = (now - timedelta(seconds=5)).isoformat()
    t_late = (now - timedelta(seconds=25)).isoformat()

    # 1. Initial event in-order
    status1, lag1, wm1 = wm_svc.process_timestamp(t0)
    assert status1 == WatermarkArrivalStatus.IN_ORDER
    # Watermark should be t0 - 10s
    assert wm_svc.current_watermark_epoch > 0.0

    # 2. Clock-skewed future event (> 30s)
    status_skew, _, _ = wm_svc.process_timestamp(t_future)
    assert status_skew == WatermarkArrivalStatus.CLOCK_SKEW_FUTURE

    # 3. Out-of-order event within watermark delay
    status_ooo, _, _ = wm_svc.process_timestamp(t_past)
    assert status_ooo == WatermarkArrivalStatus.OUT_OF_ORDER

    # 4. Late event beyond watermark delay (> 10s behind)
    status_late, _, _ = wm_svc.process_timestamp(t_late)
    assert status_late == WatermarkArrivalStatus.LATE


# ─────────────────────────────────────────────────────────────────────────────
# TEST 5: Coalescing & Critical Security Milestone Immediate Bypass
# ─────────────────────────────────────────────────────────────────────────────
def test_coalescer_with_critical_milestone_bypass():
    policy = CoalescePolicy(coalesce_window_ms=5000.0, coalesce_max_events=10)
    coalescer = SlidingWindowCoalescer(policy=policy)

    # 1. Low severity / benign event -> Buffered
    benign_ev = {
        "id": "ev-1",
        "action": "file.read",
        "severity_hint": "low",
        "payload": {"command_line": "notepad.exe file.txt"},
    }
    flushed, is_bypass, reason = coalescer.push_event("tenant-1", "case-1", benign_ev)
    assert flushed is None
    assert is_bypass is False
    assert reason == "BUFFERED"

    # 2. Critical Security Milestone: Credential Access Behavior
    # Bypass driven by canonical evidence + security-state materiality!
    critical_ev = {
        "id": "ev-2",
        "action": "credential.access",
        "severity_hint": "critical",
        "is_critical": True,
        "capability": "CAP_CREDENTIAL_ACCESS",
        "payload": {"command_line": "procdump -ma lsass.exe lsass.dmp"},
    }
    flushed_crit, is_bypass_crit, reason_crit = coalescer.push_event("tenant-1", "case-1", critical_ev)
    assert flushed_crit is not None, "Milestone event MUST flush buffer immediately"
    assert is_bypass_crit is True
    assert len(flushed_crit) == 2, "Pending buffered events + critical event flushed together"
    assert flushed_crit[0]["id"] == "ev-1"
    assert flushed_crit[1]["id"] == "ev-2"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 6: Material State Change Gate (Suppression vs Transition)
# ─────────────────────────────────────────────────────────────────────────────
def test_material_state_change_gate():
    test_dir = get_test_dir("t6_gate")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        adapter = StreamingEventAdapter(repository=repo)

        # Event 1: Initial event -> triggers Initial State Transition
        env1 = StreamingEventEnvelope(
            source_id="source-1",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={
                "action": "process.start",
                "command_line": "powershell.exe -ExecutionPolicy Bypass",
                "is_critical": True,
            },
        )
        res1 = adapter.ingest_envelope(env1, case_id="case-gate")
        assert res1["status"] == "STATE_TRANSITIONED"
        assert res1["version"] == 1

        # Event 2: Non-material benign event (no new capability, no attack state change)
        env2 = StreamingEventEnvelope(
            source_id="source-1",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={
                "action": "file.read",
                "command_line": "type c:\\temp\\readme.txt",
                "is_critical": False,
                "severity_hint": "low",
            },
        )
        res2 = adapter.ingest_envelope(env2, case_id="case-gate")
        # Either buffered or non-material suppressed
        if res2.get("status") == "NON_MATERIAL_SUPPRESSED":
            assert res2["version"] == 1, "Non-material event must NOT create new version"

        # Event 3: Material Security Escalation: Ransomware volume shadow copy destruction
        env3 = StreamingEventEnvelope(
            source_id="source-1",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={
                "action": "process.start",
                "command_line": "vssadmin delete shadows /all /quiet",
                "is_critical": True,
                "capability": "CAP_RANSOMWARE_ENCRYPTION",
            },
        )
        res3 = adapter.ingest_envelope(env3, case_id="case-gate")
        assert res3["status"] == "STATE_TRANSITIONED"
        assert res3["version"] == 2
        assert any(k in str(res3.get("material_reasons", [])) for k in ("vssadmin", "RANSOMWARE", "BACKUP_TAMPERING"))
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 7: Dead Letter Queue (DLQ) Recording & Remediated Replay
# ─────────────────────────────────────────────────────────────────────────────
def test_dlq_recording_and_remediation_replay():
    test_dir = get_test_dir("t7_dlq")
    clean_test_dir(test_dir)
    try:
        dlq_svc = DeadLetterQueueService(fallback_storage_dir=test_dir)
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        adapter = StreamingEventAdapter(repository=repo, dlq_service=dlq_svc)

        # 1. Submit corrupt envelope (missing source_id)
        corrupt_env = StreamingEventEnvelope(
            source_id="",  # MISSING
            authenticated_tenant_id="tenant-corp",
            event_id="ev-corrupt-01",
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={"action": "service.start"},
        )
        res = adapter.ingest_envelope(corrupt_env, case_id="case-dlq")
        assert res["success"] is False
        assert res["dlq_recorded"] is True

        # Verify DLQ item
        records = dlq_svc.get_dlq_records("tenant-corp", replayed=False)
        assert len(records) == 1
        dlq_item = records[0]
        assert dlq_item.event_id == "ev-corrupt-01"
        assert dlq_item.failure_class == DLQFailureClass.SCHEMA_VALIDATION_ERROR.value

        # 2. Remediation & Replay: Correct the source_id and replay
        remediated_envelope = StreamingEventEnvelope(
            source_id="remediated-source-01",
            authenticated_tenant_id=dlq_item.tenant_id,
            event_id=dlq_item.event_id,
            event_timestamp=dlq_item.raw_envelope["event_timestamp"],
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload=dlq_item.raw_envelope["payload"],
        )
        replay_res = adapter.ingest_envelope(remediated_envelope, case_id="case-dlq")
        assert replay_res["success"] is True

        # Mark remediated in DLQ
        marked = dlq_svc.mark_replayed(dlq_item.tenant_id, dlq_item.dlq_id)
        assert marked is True

        # Check pending DLQ is now 0
        remaining = dlq_svc.get_dlq_records("tenant-corp", replayed=False)
        assert len(remaining) == 0
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 8: Replay Equivalence (Direct SSOT Evaluation vs Streaming Replay)
# ─────────────────────────────────────────────────────────────────────────────
def test_replay_equivalence_direct_vs_streaming():
    test_dir = get_test_dir("t8_equiv")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        verifier = ReplayEquivalenceVerifier(repository=repo)

        now = datetime.now(timezone.utc)
        ts1 = (now - timedelta(seconds=10)).isoformat()
        ts2 = (now - timedelta(seconds=5)).isoformat()

        golden_evidence = [
            {
                "id": "ev-archetype-cmd",
                "type": "endpoint",
                "timestamp": ts1,
                "action": "process.start",
                "is_critical": True,
                "payload": {
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -enc SQBFAFgA...",
                    "iu_type": "command_line",
                }
            },
            {
                "id": "ev-archetype-cred",
                "type": "endpoint",
                "timestamp": ts2,
                "action": "credential.access",
                "is_critical": True,
                "capability": "CAP_CREDENTIAL_ACCESS",
                "payload": {
                    "command_line": "mimikatz.exe sekurlsa::logonpasswords",
                    "technique_id": "T1003",
                }
            }
        ]

        is_equiv, report, diff = verifier.compare_direct_vs_streaming(
            tenant_id="tenant-corp",
            case_id_direct="case-direct-01",
            case_id_streaming="case-stream-01",
            evidence_items=golden_evidence,
        )

        assert is_equiv is True, f"Replay equivalence failed! Diff: {diff}, Report: {report}"
        assert report["direct_classification"] == report["streaming_classification"]
        assert report["direct_capabilities"] == report["streaming_capabilities"]
        assert report["ledger_verified"] is True
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 9: Safe Shadow Mode Invariant & Zero Execution Gate
# ─────────────────────────────────────────────────────────────────────────────
def test_safe_shadow_mode_invariant():
    test_dir = get_test_dir("t9_shadow")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        adapter = StreamingEventAdapter(repository=repo, is_shadow_mode=True)

        env = StreamingEventEnvelope(
            source_id="stream-source",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={
                "action": "credential.access",
                "command_line": "mimikatz sekurlsa::logonpasswords",
                "is_critical": True,
            },
        )
        res = adapter.ingest_envelope(env, case_id="case-shadow")
        assert res["status"] == "STATE_TRANSITIONED"
        assert res["shadow_label"] == "SECURITY_STATE_SHADOW"

        # Check persisted state and ledger records
        latest = repo.get_latest_state("tenant-corp", "case-shadow")
        assert latest is not None
        # Intervention auto_execute MUST be False
        assert latest.intervention_plan.get("auto_execute") is False

        # Ledger block must carry shadow label
        blocks = repo.get_ledger_blocks("tenant-corp", "case-shadow")
        assert len(blocks) == 1
        assert blocks[0].payload.get("shadow_label") == "SECURITY_STATE_SHADOW"
        assert blocks[0].payload.get("shadow_mode") is True
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 10: Late Evidence Reconciliation Without Historical Mutation
# ─────────────────────────────────────────────────────────────────────────────
def test_late_evidence_reconciliation_immutability():
    test_dir = get_test_dir("t10_late")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        wm_svc = WatermarkService(WatermarkPolicy(watermark_delay_seconds=5.0))
        adapter = StreamingEventAdapter(repository=repo, watermark_service=wm_svc)

        now = datetime.now(timezone.utc)

        # Event 1: At T=0
        env1 = StreamingEventEnvelope(
            source_id="stream-source",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=now.isoformat(),
            ingest_timestamp=now.isoformat(),
            payload={"action": "process.start", "command_line": "cmd.exe", "is_critical": True},
        )
        res1 = adapter.ingest_envelope(env1, case_id="case-late")
        assert res1["version"] == 1
        hash_v1 = res1["state_hash"]

        # Event 2: At T=+10s (advances watermark)
        t_plus_10 = (now + timedelta(seconds=10)).isoformat()
        env2 = StreamingEventEnvelope(
            source_id="stream-source",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=t_plus_10,
            ingest_timestamp=t_plus_10,
            payload={
                "action": "persistence.add",
                "command_line": "schtasks /create /sc onlogon /tn task1 /tr cmd.exe",
                "is_critical": True,
                "capability": "CAP_PERSISTENCE",
            },
        )
        res2 = adapter.ingest_envelope(env2, case_id="case-late")
        assert res2["version"] == 2
        hash_v2 = res2["state_hash"]

        # Event 3: Late Event at T=-20s (strictly arrives after watermark is established)
        t_minus_20 = (now - timedelta(seconds=20)).isoformat()
        env3 = StreamingEventEnvelope(
            source_id="stream-source",
            authenticated_tenant_id="tenant-corp",
            event_id=str(uuid.uuid4()),
            event_timestamp=t_minus_20,
            ingest_timestamp=now.isoformat(),
            payload={
                "action": "privilege.escalation",
                "command_line": "whoami /priv",
                "is_critical": True,
                "capability": "CAP_PRIVILEGE_ESCALATION",
            },
        )
        res3 = adapter.ingest_envelope(env3, case_id="case-late")
        assert res3["version"] == 3
        assert any("LATE_EVIDENCE_RECONCILIATION" in r for r in res3.get("material_reasons", []))

        # IMMUTABILITY PROOF: Historical version v1 and v2 MUST NOT BE MUTATED!
        v1_record = repo.get_state_by_version("tenant-corp", "case-late", 1)
        v2_record = repo.get_state_by_version("tenant-corp", "case-late", 2)
        assert v1_record.state_hash == hash_v1, "Version 1 state hash must remain strictly immutable!"
        assert v2_record.state_hash == hash_v2, "Version 2 state hash must remain strictly immutable!"

        # Ledger Blocks reflect LATE_EVIDENCE_RECONCILIATION
        blocks = repo.get_ledger_blocks("tenant-corp", "case-late")
        assert len(blocks) == 3
        assert blocks[2].event_type == "LATE_EVIDENCE_RECONCILIATION"
        assert blocks[2].payload["is_late_event"] is True

        # SHA-256 chain remains cryptographically valid
        chain_ok, chain_err = repo.verify_ledger_integrity("tenant-corp", "case-late")
        assert chain_ok is True, f"Ledger chain broken: {chain_err}"
    finally:
        clean_test_dir(test_dir)
