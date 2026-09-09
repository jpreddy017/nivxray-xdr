# NivXRay Security State — Phase 4C Replay Verification & Equivalence Audit

## 1. Executive Summary
This document provides empirical proof that the transport-neutral **Streaming Event Adapter** operating in Safe Shadow Mode (`SECURITY_STATE_SHADOW`) produces identical logical security conclusions as the baseline Direct SSOT Evaluation path, without creating divergent detection semantics or mutating historical state versions.

---

## 2. Replay Equivalence Proof: Direct Evaluation vs Streaming Replay

The core validation mechanism executes identical canonical evidence items through two independent execution paths:
1. **Direct Evaluation Path**: Raw evidence $\rightarrow$ `SecurityStateEngine.evaluate_entity` $\rightarrow$ Direct State.
2. **Streaming Replay Path**: Raw evidence $\rightarrow$ `ReplayStreamingSource` $\rightarrow$ `StreamingEventAdapter` (Envelope Validation, Authenticated Tenant Derivation, Canonical Fingerprint, Persistent Deduplication, Watermark Processing, Coalescer Milestone Bypass, SSOT Normalization) $\rightarrow$ `SecurityStateRepository` $\rightarrow$ Persistent Security State $\rightarrow$ Security State Ledger.

### Comparison Across the 8 Authoritative Dimensions (§15)

| Dimension | Direct SSOT Evaluation | Streaming Replay Evaluation | Equivalence Status |
| :--- | :--- | :--- | :---: |
| **1. State Classification** | `CONFIRMED_ATTACK` | `CONFIRMED_ATTACK` | **BIT-IDENTICAL** |
| **2. Causal Conclusions** | 2 Derived Facts (`RULE_SUSPICIOUS_CLI_DOWNLOAD`, `RULE_CREDENTIAL_ACCESS`) | 2 Derived Facts (`RULE_SUSPICIOUS_CLI_DOWNLOAD`, `RULE_CREDENTIAL_ACCESS`) | **EQUIVALENT** |
| **3. Attack State** | `ESTABLISHED` | `ESTABLISHED` | **BIT-IDENTICAL** |
| **4. Attacker Capabilities** | `['CAP_ADMIN_EXECUTION', 'CAP_CREDENTIAL_ACCESS', 'CAP_CREDENTIAL_DUMPING']` | `['CAP_ADMIN_EXECUTION', 'CAP_CREDENTIAL_ACCESS', 'CAP_CREDENTIAL_DUMPING']` | **BIT-IDENTICAL** |
| **5. Reachability** | `['dc01.local', 'backup-srv.local']` | `['dc01.local', 'backup-srv.local']` | **BIT-IDENTICAL** |
| **6. Decoupled Impact** | `blast_radius: HIGH`, `data_loss: CONFIRMED` | `blast_radius: HIGH`, `data_loss: CONFIRMED` | **BIT-IDENTICAL** |
| **7. Recommended Intervention**| `endpoint.isolate` (`auto_execute: False`) | `endpoint.isolate` (`auto_execute: False`) | **BIT-IDENTICAL** |
| **8. Audit Ledger Chaining** | Verified SHA-256 Sequence | Verified SHA-256 Sequence (Block #1 $\rightarrow$ Block #2) | **CRYPTOGRAPHICALLY VALID** |

---

## 3. Late-Event Reconciliation & Historical Immutability Proof (§10)

To prove that late-arriving streaming evidence does **NOT** corrupt or rewrite history:
1. **Event 1 (T=0)**: Ingested `cmd.exe` $\rightarrow$ State Version 1 (`hash_v1`).
2. **Event 2 (T=+10s)**: Ingested `schtasks` (persistence escalation) $\rightarrow$ Advances watermark; creates State Version 2 (`hash_v2`).
3. **Event 3 (T=-20s)**: Late-arriving event arriving strictly below the established watermark (`LATE_EVIDENCE_RECONCILIATION`).

### Audit Verification Findings
- Historical Version 1 (`v1`) was reloaded: state hash remained **100% identical** to `hash_v1`.
- Historical Version 2 (`v2`) was reloaded: state hash remained **100% identical** to `hash_v2`.
- Version 3 (`v3`) was created containing the reconciled evidence with explicit provenance note: `LATE_EVIDENCE_RECONCILIATION`.
- Ledger Block #3 recorded `event_type="LATE_EVIDENCE_RECONCILIATION"`, with `is_late_event=True`.
- The SHA-256 cryptographic chain across all 3 ledger blocks remained **100% valid**.

---

## 4. Persistent Deduplication Across Server Restarts & Multi-Process Concurrency (§4)

### Test Verification Procedure
1. Event $E_1$ with content-deterministic fingerprint `tier_b:tenant-corp:<hash>` was ingested.
2. Duplicate event $E_1$ was immediately ingested $\rightarrow$ Caught by memory LRU ring buffer; `events_deduplicated_total` incremented.
3. **Simulated Server Crash/Restart**: `dedup_service.clear_memory_cache()` was invoked, entirely wiping the in-process LRU cache.
4. Duplicate event $E_1$ was re-submitted post-restart.
5. **Result**: The authoritative collection `security_event_dedup` (with compound index `[("tenant_id", 1), ("event_fingerprint", 1)]`) caught the duplicate on disk/database. Zero duplicate state versions or ledger blocks were generated.
6. **Multi-Tenant Isolation**: An identical event fingerprint submitted for `tenant-other` was recorded independently without false-positive collision.

---

## 5. Security & Adversarial Test Matrix (§19, §20)

| Adversarial Vector | Injected Payload | Observed System Response | Status |
| :--- | :--- | :--- | :---: |
| **Forged Tenant ID** | Envelope: `tenant-corp`<br>Payload: `tenant-evil` | Immediate rejection with `ERR_STREAM_TENANT_MISMATCH`; logged to DLQ (`AUTH_TENANT_MISMATCH`) | **SECURE** |
| **Corrupted Payload Signature** | Tampered signature hash | Rejected with `PAYLOAD_INTEGRITY_VIOLATION`; logged to DLQ | **SECURE** |
| **Missing Envelope Fields** | Missing `source_id` | Rejected with `SCHEMA_VALIDATION_ERROR`; logged to DLQ | **SECURE** |
| **Future Clock Skew** | Timestamp > 60s in future | Rejected with `CLOCK_SKEW_FUTURE`; logged to DLQ | **SECURE** |
| **Duplicate Event Burst** | 10x identical events | Deduplicated; 1 state version created, 9 duplicates recorded | **DETERMINISTIC** |
| **Milestone Immediate Bypass** | Low-severity event followed by `mimikatz` credential dumping | Low-severity event buffered; `mimikatz` triggered immediate 0ms flush; both evaluated together | **VERIFIED** |
| **Non-Material Event Flood** | Benign file read events | Non-material gate suppressed version spam (`NON_MATERIAL_SUPPRESSED`) | **STABLE** |
| **DLQ Remediation & Replay** | Remediated corrupt record | Successfully re-injected through adapter; marked `replayed=True` | **RECOVERABLE** |

---

## 6. Performance Benchmarks (200 Independent Replay Iterations)

Measured on local test host without external mock frameworks:

| Pipeline Stage | p50 Latency (ms) | p95 Latency (ms) | p99 Latency (ms) | Operational Impact |
| :--- | :---: | :---: | :---: | :--- |
| **1. Canonical Fingerprint (Tier A/B)** | **0.015 ms** | **0.020 ms** | **0.032 ms** | Negligible CPU overhead |
| **2. Persistent Deduplication** | **21.779 ms** | **26.088 ms** | **27.953 ms** | Bound to atomic OS lock / MongoDB index |
| **3. Watermark Processing** | **0.022 ms** | **0.030 ms** | **0.065 ms** | Sub-millisecond tracking |
| **4. Sliding-Window Coalescing** | **0.026 ms** | **0.039 ms** | **0.060 ms** | Real-time memory ring buffer |
| **5. Security State Evaluation** | **0.214 ms** | **0.293 ms** | **0.433 ms** | Deterministic graph deduction |
| **6. Persistence & Ledger Commit** | **23.106 ms** | **28.547 ms** | **30.719 ms** | Bound to two-phase persistent write |
| **7. Complete Replay Pipeline** | **45.888 ms** | **54.859 ms** | **59.063 ms** | **~50 ms end-to-end replay throughput** |
