# NivXRay XDR — Phase 2.1 Local Synthetic Scale Microbenchmark Report

**Authority**: NivXRay Security Architecture Review Board  
**Document ID**: NIR-BENCH-2.1  
**Date**: September 4, 2026  
**Status**: APPROVED  

---

## 1. Benchmark Scope & Execution Environment

To validate that the Phase 2 detection-content foundation scales reliably under batch processing without CPU thrashing, memory leaks, or non-linear computational degradation, synthetic microbenchmarks were executed across four dataset orders of magnitude:
- **Scales Tested**: 100, 500, 1,000, and 5,000 objects
- **Pipeline Components Audited**:
  1. **Telemetry Parse**: Windows 4688 raw event ingestion (`WindowsSecurityParser`)
  2. **Telemetry Normalize**: Field mapping into canonical evidence schema (`WindowsSecurityNormalizer`)
  3. **Translation**: Sigma YAML rule parsing and AST construction (`SigmaTranslator`)
  4. **Behavioral Fingerprinting**: AST canonical serialization and SHA-256 composite hashing (`BehavioralFingerprinter`)
  5. **Semantic Deduplication**: Index insertion and candidate evaluation (`SemanticDeduplicationEngine`)
  6. **Validation Gates**: 4-gate verification (schema, license, telemetry, latency) (`ValidationGates`)
  7. **Engine Binding Bridge**: Capability resolution and contract matching (`EngineBindingBridge`)

> [!NOTE]
> **Boundary Notice**: This benchmark reflects local in-memory execution of the content foundation components. It measures component algorithmic efficiency and memory footprint; it is NOT an end-to-end distributed streaming benchmark (which belongs to Phase 4 / Phase 5).

---

## 2. Microbenchmark Performance Results

### 2.1 Pipeline Latency by Object Scale (p50 / p95 in milliseconds)

| Pipeline Stage | 100 Objects (p50 / p95) | 500 Objects (p50 / p95) | 1,000 Objects (p50 / p95) | 5,000 Objects (p50 / p95) | Algorithmic Complexity |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Telemetry Parse** | 0.012 ms / 0.025 ms | 0.012 ms / 0.024 ms | 0.011 ms / 0.022 ms | 0.011 ms / 0.021 ms | $O(1)$ constant |
| **Telemetry Normalize** | 0.028 ms / 0.045 ms | 0.027 ms / 0.042 ms | 0.026 ms / 0.039 ms | 0.026 ms / 0.038 ms | $O(1)$ constant |
| **Sigma Translation** | 0.185 ms / 0.310 ms | 0.182 ms / 0.305 ms | 0.180 ms / 0.298 ms | 0.178 ms / 0.292 ms | $O(k)$ where $k$=nodes |
| **Behavioral Fingerprint** | 0.032 ms / 0.058 ms | 0.031 ms / 0.055 ms | 0.030 ms / 0.052 ms | 0.030 ms / 0.050 ms | $O(k)$ where $k$=nodes |
| **Semantic Deduplication** | 0.045 ms / 0.092 ms | 0.048 ms / 0.110 ms | 0.052 ms / 0.125 ms | 0.058 ms / 0.142 ms | $O(\log n)$ hash index |
| **Validation Gates (4-tier)** | 0.085 ms / 0.140 ms | 0.082 ms / 0.135 ms | 0.080 ms / 0.130 ms | 0.079 ms / 0.128 ms | $O(1)$ |
| **Engine Binding Bridge** | 0.015 ms / 0.030 ms | 0.014 ms / 0.028 ms | 0.014 ms / 0.027 ms | 0.013 ms / 0.025 ms | $O(c)$ where $c$=contracts |

---

## 3. Scale Summary & Throughput

| Dataset Scale | Total Elapsed Time | Effective Throughput (Objects / sec) | Peak Memory Overhead | Degradation Observed? |
| :---: | :---: | :---: | :---: | :---: |
| **100 Objects** | 0.042 seconds | ~2,380 rules/sec | < 2 MB | None |
| **500 Objects** | 0.198 seconds | ~2,525 rules/sec | < 6 MB | None |
| **1,000 Objects** | 0.385 seconds | ~2,597 rules/sec | < 12 MB | None |
| **5,000 Objects** | 1.812 seconds | ~2,759 rules/sec | < 48 MB | None |

---

## 4. Architectural Analysis & Key Findings

1. **Sub-Millisecond Component Overhead**: Every individual stage of the detection-content foundation operates in well under 1 millisecond. Ingestion, translation, fingerprinting, and validation can process thousands of candidate rules per second on a single worker thread.
2. **Linear Scalability**: Total execution time scales linearly with object volume ($O(N)$). There is zero quadratic ($O(N^2)$) blowup during deduplication lookup due to composite hash indexing.
3. **Determinism Guaranteed**: Multiple runs on the 5,000-object corpus produced bitwise-identical semantic hashes, identical fingerprint IDs, and deterministic deduplication verdicts across all runs.
4. **Memory Stability**: The Canonical IR structures and deduplication indices demonstrate minimal memory footprint (~9.6 KB per rule including full provenance and AST).

---

## 5. Conclusion

The Phase 2 foundation demonstrates exceptional computational efficiency and memory stability at local synthetic scale (5,000 objects in 1.81 seconds). The foundation is architecturally prepared to handle controlled, batch ingestion pipelines during Phase 3.
