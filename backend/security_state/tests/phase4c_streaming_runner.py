"""Deterministic Test Runner for NivXRay Phase 4C Streaming Adapter & Shadow Replay."""
from __future__ import annotations

import os
import sys
import time
from typing import List

from security_state.tests.phase4c_streaming_tests import (
    test_envelope_validation_and_tenant_security,
    test_canonical_identity_and_dual_tier_fingerprinting,
    test_persistent_deduplication_across_restarts,
    test_watermark_tracking_and_late_reconciliation,
    test_coalescer_with_critical_milestone_bypass,
    test_material_state_change_gate,
    test_dlq_recording_and_remediation_replay,
    test_replay_equivalence_direct_vs_streaming,
    test_safe_shadow_mode_invariant,
    test_late_evidence_reconciliation_immutability,
)


def run_phase_4c_performance_benchmarks():
    """Benchmark p50, p95, p99 latencies across all streaming pipeline stages."""
    import uuid
    from datetime import datetime, timezone
    from security_state.persistence.repository import SecurityStateRepository
    from security_state.streaming.adapter import StreamingEventAdapter
    from security_state.streaming.dedup import PersistentDeduplicationService
    from security_state.streaming.fingerprint import generate_event_fingerprint
    from security_state.streaming.models import StreamingEventEnvelope
    from security_state.streaming.watermark import WatermarkService
    from security_state.streaming.coalescer import SlidingWindowCoalescer
    from security_state.state_engine.engine import SecurityStateEngine
    from security_state.contracts import EntityRef, EntityCategory

    storage_dir = os.path.join(os.path.dirname(__file__), ".bench_storage_phase4c")
    os.makedirs(storage_dir, exist_ok=True)

    try:
        repo = SecurityStateRepository(fallback_storage_dir=storage_dir)
        dedup = PersistentDeduplicationService(fallback_storage_dir=storage_dir)
        wm = WatermarkService()
        coalescer = SlidingWindowCoalescer()
        engine = SecurityStateEngine()
        adapter = StreamingEventAdapter(
            repository=repo,
            dedup_service=dedup,
            watermark_service=wm,
            coalescer=coalescer,
            state_engine=engine,
        )

        n_samples = 200
        latencies: dict[str, List[float]] = {
            "fingerprint": [],
            "dedup": [],
            "watermark": [],
            "coalescer": [],
            "evaluation": [],
            "persistence": [],
            "complete_replay": [],
        }

        ref = EntityRef(category=EntityCategory.DEVICE, entity_id="bench-case", tenant_id="bench-tenant")
        ev_item = {
            "id": "ev-bench",
            "type": "endpoint",
            "source": "bench",
            "timestamp": "2026-09-04T00:00:00Z",
            "payload": {"command_line": "powershell.exe -enc ...", "process_name": "powershell.exe"}
        }

        for i in range(n_samples):
            ev_id = str(uuid.uuid4())
            ts = datetime.now(timezone.utc).isoformat()
            
            # 1. Fingerprint
            t0 = time.perf_counter()
            fp = generate_event_fingerprint("bench-tenant", ev_id, "endpoint", "process.start", {}, {}, ts)
            latencies["fingerprint"].append((time.perf_counter() - t0) * 1000.0)

            # 2. Dedup
            t0 = time.perf_counter()
            dedup.is_duplicate_or_record("bench-tenant", fp, "source-bench")
            latencies["dedup"].append((time.perf_counter() - t0) * 1000.0)

            # 3. Watermark
            t0 = time.perf_counter()
            wm.process_timestamp(ts)
            latencies["watermark"].append((time.perf_counter() - t0) * 1000.0)

            # 4. Coalescer
            t0 = time.perf_counter()
            coalescer.push_event("bench-tenant", "bench-case", ev_item)
            latencies["coalescer"].append((time.perf_counter() - t0) * 1000.0)

            # 5. Security State Evaluation
            t0 = time.perf_counter()
            st = engine.evaluate_entity(ref, [ev_item])
            latencies["evaluation"].append((time.perf_counter() - t0) * 1000.0)

            # 6. Persistence & Ledger
            t0 = time.perf_counter()
            repo.save_state("bench-tenant", f"bench-case-{i}", st.to_dict(), {}, {}, {}, [ev_item])
            repo.append_ledger_block("bench-tenant", f"bench-case-{i}", "BENCH", "bench-case", 1, {"test": True})
            latencies["persistence"].append((time.perf_counter() - t0) * 1000.0)

            # 7. Complete Replay Pipeline
            env = StreamingEventEnvelope(
                source_id="bench",
                authenticated_tenant_id="bench-tenant",
                event_id=str(uuid.uuid4()),
                event_timestamp=ts,
                ingest_timestamp=ts,
                payload={"action": "process.start", "command_line": "powershell.exe", "is_critical": True},
            )
            t0 = time.perf_counter()
            adapter.ingest_envelope(env, case_id=f"replay-bench-{i}")
            latencies["complete_replay"].append((time.perf_counter() - t0) * 1000.0)

        print("\n" + "=" * 90)
        print("NIVXRAY PHASE 4C STREAMING PERFORMANCE BENCHMARK (200 Iterations)")
        print("=" * 90)
        print(f"{'Pipeline Stage':<35} | {'p50 (ms)':<12} | {'p95 (ms)':<12} | {'p99 (ms)':<12}")
        print("-" * 90)

        for stage, vals in latencies.items():
            if not vals:
                continue
            s_vals = sorted(vals)
            p50 = s_vals[int(len(s_vals) * 0.50)]
            p95 = s_vals[int(len(s_vals) * 0.95)]
            p99 = s_vals[int(len(s_vals) * 0.99)]
            print(f"{stage:<35} | {p50:<12.3f} | {p95:<12.3f} | {p99:<12.3f}")

        print("=" * 90 + "\n")
    finally:
        import shutil
        shutil.rmtree(storage_dir, ignore_errors=True)


def run_phase_4c_streaming_suite():
    tests = [
        ("Envelope Validation & Strict Authenticated Tenant Context", test_envelope_validation_and_tenant_security),
        ("Dual-Tier Canonical Identity & Fingerprinting", test_canonical_identity_and_dual_tier_fingerprinting),
        ("Persistent Deduplication (security_event_dedup & Restart Safety)", test_persistent_deduplication_across_restarts),
        ("Watermark Tracking & Clock-Skew Bounds", test_watermark_tracking_and_late_reconciliation),
        ("Coalescing & Critical Security Milestone Immediate Bypass", test_coalescer_with_critical_milestone_bypass),
        ("Material State Change Gate (Suppression vs Escalation)", test_material_state_change_gate),
        ("Dead-Letter Queue (DLQ) Recording & Remediated Replay", test_dlq_recording_and_remediation_replay),
        ("Replay Equivalence (Direct SSOT vs Streaming Replay)", test_replay_equivalence_direct_vs_streaming),
        ("Safe Shadow Mode Invariant (SECURITY_STATE_SHADOW & Zero Execution)", test_safe_shadow_mode_invariant),
        ("Late Evidence Reconciliation & Historical State Immutability", test_late_evidence_reconciliation_immutability),
    ]

    print("\n" + "=" * 90)
    print("NIVXRAY PHASE 4C: STREAMING ADAPTER & SHADOW REPLAY VERIFICATION SUITE")
    print("=" * 90)

    passed = 0
    t_start = time.time()

    for name, test_fn in tests:
        t0 = time.time()
        try:
            test_fn()
            dt = (time.time() - t0) * 1000.0
            print(f"  [PASS] {name:<65} ({dt:6.2f} ms)")
            passed += 1
        except Exception as e:
            dt = (time.time() - t0) * 1000.0
            print(f"  [FAIL] {name:<65} ({dt:6.2f} ms)")
            print(f"         Error: {e}")
            import traceback
            traceback.print_exc()

    total_dt = time.time() - t_start
    print("=" * 90)
    print(f"Phase 4C Results: {passed}/{len(tests)} tests passed in {total_dt:.3f}s")
    print("=" * 90)

    if passed == len(tests):
        # Run benchmarks
        run_phase_4c_performance_benchmarks()
    else:
        raise RuntimeError(f"Phase 4C Suite Failed: {len(tests) - passed} failures")


if __name__ == "__main__":
    run_phase_4c_streaming_suite()
