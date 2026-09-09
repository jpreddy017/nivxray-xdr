# NivXRay Security State: Benchmark & Performance Report

> **Document Type:** Benchmark & Latency Profiling Report  
> **Status:** Empirically Measured  
> **Profiler:** `backend/security_state/benchmarks/benchmark.py`  
> **Iterations:** 500 per engine component  

---

## 1. Engine Latency & Throughput Profile

All benchmarks were captured with memory tracing (`tracemalloc`) and strict garbage collection isolation:

| Subsystem Component | p50 Latency | p95 Latency | p99 Latency | Throughput | Peak Memory |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **State Construction** | **0.507 ms** | 0.595 ms | 0.761 ms | **1,922.8 ops/s** | 32.0 KB |
| **State Transition Evaluation** | **0.099 ms** | 0.105 ms | 0.114 ms | **9,916.6 ops/s** | 26.2 KB |
| **Causal Security Inference** | **0.219 ms** | 0.242 ms | 0.401 ms | **4,410.5 ops/s** | 27.5 KB |
| **Capability Abuse Evaluation** | **0.168 ms** | 0.184 ms | 0.281 ms | **5,762.6 ops/s** | 23.2 KB |
| **Reachability Graph Computation**| **0.451 ms** | 0.516 ms | 0.626 ms | **2,170.0 ops/s** | 32.7 KB |
| **Counterfactual World Projection**| **0.304 ms** | 0.359 ms | 0.497 ms | **3,191.4 ops/s** | 27.3 KB |
| **Impact & Blast Radius Scoring** | **0.214 ms** | 0.368 ms | 0.462 ms | **4,343.9 ops/s** | 23.8 KB |
| **Intervention Plan Optimization** | **0.116 ms** | 0.236 ms | 1.209 ms | **6,859.1 ops/s** | 21.9 KB |
| **Security State Ledger Chaining** | **0.059 ms** | 0.066 ms | 0.075 ms | **16,288.7 ops/s**| 280.6 KB |

---

## 2. Architectural Analysis

1. **Sub-Millisecond Execution**:
   Every single security state engine component completes its computation in under 0.6ms (p50) and under 1.3ms (p99).
2. **Minimal Footprint**:
   Peak resident memory overhead per evaluation cycle is under 35KB for core graph and state operations, and 280KB for full ledger cryptographic block assembly.
3. **Investigation Velocity**:
   End-to-end full evaluation (Evidence &rarr; State &rarr; Causality &rarr; Capability &rarr; Reachability &rarr; Counterfactual &rarr; Impact &rarr; Intervention &rarr; Ledger) takes less than **2.2 milliseconds**, enabling real-time inline evaluation without streaming ingestion delays.
