"""Performance profiler measuring p50, p95, p99, throughput, and memory for Security State engines."""
import gc
import os
import sys
import time
import tracemalloc

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from security_state.contracts import EntityCategory, EntityRef, AttackState
from security_state.state_engine.engine import SecurityStateEngine
from security_state.transitions.engine import TransitionEngine
from security_state.causal.engine import CausalSecurityEngine
from security_state.capability.engine import CapabilityContext, TrustedCapabilityAbuseEngine
from security_state.reachability.engine import EnterpriseReachabilityEngine
from security_state.counterfactual.engine import CounterfactualEngine
from security_state.impact.engine import ImpactEngine
from security_state.intervention.optimizer import InterventionOptimizer
from security_state.ledger.ledger import SecurityStateLedger


def benchmark_engine(name, func, iterations=500):
    latencies = []
    tracemalloc.start()
    gc.collect()

    t_start = time.time()
    for _ in range(iterations):
        t0 = time.perf_counter()
        func()
        latencies.append((time.perf_counter() - t0) * 1000.0)
    total_time = time.time() - t_start
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    latencies.sort()
    p50 = latencies[int(iterations * 0.50)]
    p95 = latencies[int(iterations * 0.95)]
    p99 = latencies[int(iterations * 0.99)]
    throughput = iterations / total_time

    print(f"{name:<35} | p50: {p50:6.3f} ms | p95: {p95:6.3f} ms | p99: {p99:6.3f} ms | {throughput:8.1f} ops/s | Peak Mem: {peak_mem / 1024:6.1f} KB")
    return {
        "engine": name,
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "throughput_ops_sec": throughput,
        "peak_mem_kb": peak_mem / 1024,
    }


def run_all_benchmarks():
    print("=" * 105)
    print("NivXRay Security State Core — Comprehensive Benchmark & Latency Profiler")
    print("=" * 105)
    print(f"{'Engine Component':<35} | {'p50 Latency':<14} | {'p95 Latency':<14} | {'p99 Latency':<14} | {'Throughput':<16} | {'Peak Memory'}")
    print("-" * 105)

    tenant = "tenant-bench"
    entity = EntityRef(category=EntityCategory.DEVICE, entity_id="host-01", tenant_id=tenant)
    ev_sample = [
        {"id": "ev-1", "type": "process", "payload": {"process_name": "powershell.exe", "command_line": "downloadstring"}},
        {"id": "ev-2", "type": "process", "payload": {"process_name": "schtasks.exe", "command_line": "schtasks /create /tn test"}}
    ]

    se = SecurityStateEngine()
    s0 = se.evaluate_entity_state(tenant, entity, [])
    benchmark_engine("State Construction", lambda: se.evaluate_entity_state(tenant, entity, ev_sample))

    te = TransitionEngine()
    benchmark_engine("State Transition Evaluation", lambda: te.compute_transition(s0, s0, ["ev-1"], "causal-proof", "capabilities"))

    ce = CausalSecurityEngine()
    causal_events = [
        {"id": "e1", "pid": 100, "process_name": "cmd.exe"},
        {"id": "e2", "pid": 200, "ppid": 100, "process_name": "powershell.exe"}
    ]
    benchmark_engine("Causal Security Inference", lambda: ce.evaluate_causality(tenant, "case-1", causal_events))

    cap_engine = TrustedCapabilityAbuseEngine()
    ctx = CapabilityContext(
        capability_name="powershell.exe", identity_ref=entity, is_authorized_admin=False,
        source_ip_or_subnet="10.0.0.1", destination_ip_or_domain="xyz.com", timestamp="2026-09-04T00:00:00Z",
        is_within_business_hours=False, command_line="powershell -enc ...", parent_process="word.exe",
        process_privilege_level="USER"
    )
    benchmark_engine("Capability Abuse Evaluation", lambda: cap_engine.evaluate_capability(tenant, ctx, ["e1"]))

    re = EnterpriseReachabilityEngine()
    benchmark_engine("Reachability Graph Computation", lambda: re.compute_reachability(tenant, "case-1", [entity], ["admin"], ["CAP_CREDENTIAL_DUMPING"]))
    reach = re.compute_reachability(tenant, "case-1", [entity], ["admin"], ["CAP_CREDENTIAL_DUMPING"])

    cfe = CounterfactualEngine()
    benchmark_engine("Counterfactual World Projection", lambda: cfe.evaluate_counterfactuals(tenant, "case-1", s0, reach, AttackState.CREDENTIAL_ACCESS))
    cf = cfe.evaluate_counterfactuals(tenant, "case-1", s0, reach, AttackState.CREDENTIAL_ACCESS)

    ie = ImpactEngine()
    benchmark_engine("Impact & Blast Radius Scoring", lambda: ie.evaluate_impact(tenant, "case-1", reach, [entity]))
    imp = ie.evaluate_impact(tenant, "case-1", reach, [entity])

    opt = InterventionOptimizer()
    benchmark_engine("Intervention Plan Optimization", lambda: opt.optimize_intervention(tenant, "case-1", reach, imp, cf, [entity]))

    ledger = SecurityStateLedger(tenant, "case-1")
    benchmark_engine("Security State Ledger Chaining", lambda: ledger.append("TEST_EVENT", "host-01", {"key": "value"}))

    print("=" * 105)
    print("ALL 9 ENGINE BENCHMARKS COMPLETED SUCCESSFULLY.")


if __name__ == '__main__':
    run_all_benchmarks()
