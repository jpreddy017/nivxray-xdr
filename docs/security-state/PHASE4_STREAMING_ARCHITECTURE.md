# NivXRay Phase 4A: Live Evidence Streaming Architecture Blueprint

> **Document Type:** Live Evidence Streaming Architecture Specification  
> **Status:** Final & Authoritative Architecture Contract (Pre-Implementation)  
> **Phase:** 4A (Specification & Integration Contracts Only)  
> **Feature Flag Gate:** `NIVX_FLAG_SECURITY_STATE=disabled` (Safe Baseline Lock)  

---

## 1. System Context & Target Architecture

The goal of Phase 4 is to stream live multi-vendor telemetry (EDR, CloudTrail, Okta, Sysmon, Network Bro/Zeek) into the NivXRay platform and evaluate Security State dynamically without creating a competing ingestion pipeline.

The Security State subsystem sits **downstream of existing NivXRay ingestion and canonical evidence layers**:

```text
       ┌─────────────────────────────────────────────────────────────────────────────┐
       │                          LIVE TELEMETRY SOURCES                             │
       │    [EDR / Windows Events]     [CloudTrail / Okta]     [Network / Bro]       │
       └──────────────────────────────────────┬──────────────────────────────────────┘
                                              │ Raw Telemetry Stream
                                              ▼
       ┌─────────────────────────────────────────────────────────────────────────────┐
       │                   EXISTING NIVXRAY TELEMETRY ADAPTERS                       │
       │      backend/services/telemetry_adapters/framework.py (TelemetryAdapter)    │
       │        · Vendor-specific parser boundary (Okta, Entra, AWS, Endpoint)       │
       │        · Normalization into homogeneous CanonicalEvent                      │
       │        · Mandatory Provenance envelope stamped at ingestion                 │
       └──────────────────────────────────────┬──────────────────────────────────────┘
                                              │ CanonicalEvent Stream
                                              ▼
       ┌─────────────────────────────────────────────────────────────────────────────┐
       │                   EXISTING CANONICAL SSOT & EVIDENCE GRAPH                  │
       │         backend/canonical/ssot/models.py & backend/v2/investigation/         │
       │        · Authoritative Canonical Evidence Storage (workspace_cases)         │
       │        · Input Understanding (IU) & Command Reconstruction Engine (CRE)     │
       │        · Semantic Intent Engine & Stage-2 Verdict Correlation               │
       └──────────────────────────────────────┬──────────────────────────────────────┘
                                              │ Evidence Notification Bus
                                              ▼
 ╔═════════════════════════════════════════════════════════════════════════════════════╗
 ║                NEW: SECURITY STATE STREAM ADAPTER & COALESCER (PHASE 4)             ║
 ║                                                                                     ║
 ║   1. Tenant-Scoped Ingestion Queue                                                  ║
 ║   2. Watermark Ordering & Clock-Skew Buffer (Out-of-Order Handling)                 ║
 ║   3. Sliding Window Coalescer (2-sec / 50-event debounce to avoid storm)            ║
 ║   4. Material State Change Filter (Suppresses redundant low-value evaluations)      ║
 ╚═════════════════════════════════════════════════════════════════════════════════════╝
                                              │ Coalesced Evaluation Trigger
                                              ▼
 ╔═════════════════════════════════════════════════════════════════════════════════════╗
 ║                 SECURITY STATE REASONING CORE (PHASES 1 - 3B)                       ║
 ║                                                                                     ║
 ║   · SecurityStateEngine (Epistemic Status, Active Capabilities)                     ║
 ║   · CausalIntelligenceEngine (Telemetry-Corroborated Ancestry)                      ║
 ║   · AttackStateMachine (Progression: PERSISTENCE -> PRIV_ESC -> IMPACT)             ║
 ║   · Reachability & Impact Decomposition (Decoupled Blast Radius)                    ║
 ║   · Counterfactuals & Minimal Effective Interventions (Graph Cuts)                  ║
 ╚═════════════════════════════════════════════════════════════════════════════════════╝
                                              │ Atomically Committed State & Ledger
                                              ▼
 ╔═════════════════════════════════════════════════════════════════════════════════════╗
 ║                  DISTRIBUTED PERSISTENCE LAYER (PHASE 3B)                           ║
 ║                                                                                     ║
 ║   · MongoDB: `security_states` (Deterministic State Versioning v1 -> v2)            ║
 ║   · MongoDB: `security_state_ledgers` (Immutable SHA-256 Block Chaining)            ║
 ║   · Two-Phase Consistency & Crash-Window Reconciliation                             ║
 ║   · Cache-Aside Pattern (MongoDB as Single Source of Truth)                         ║
 ╚═════════════════════════════════════════════════════════════════════════════════════╝
                                              │ Closed-Loop Feedback
                                              ▼
       ┌─────────────────────────────────────────────────────────────────────────────┐
       │                RESPONSE SAFETY GATE & CLOSED-LOOP VERIFICATION              │
       │        · Safety Gate validates containment actions prior to execution       │
       │        · Post-Action telemetry streamed to re-observe entity state          │
       │        · Confirms containment efficacy in new state version                 │
       └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Source of Truth (SSOT) Boundaries

To prevent architectural duplication, exact system ownership is established:

| Domain | Authoritative Existing NivXRay Subsystem | Security State Role | Invariant |
| :--- | :--- | :--- | :--- |
| **Raw Telemetry** | `services.telemetry_adapters` raw queue | **NEVER STORES RAW TELEMETRY**. | Security State stores zero raw syslog/EDR payloads. |
| **Canonical Events** | `services.telemetry_adapters.framework.CanonicalEvent` | Ingests canonical event references. | No vendor-specific parsing in Security State. |
| **Canonical Evidence** | `backend/v2/investigation/evidence.py` | Consumes `Evidence` primitives emitted by IU/CRE. | Evidence objects are immutable once emitted. |
| **Evidence Graph (IKG)** | `backend/canonical/ssot/models.py:EvidenceGraph` | Consumes nodes/edges as facts. | Security State does not render raw graphs. |
| **Incident Entity State** | *(New)* **`backend/security_state/`** | **Sole Authority for Entity Security State**. | Computes formal states, versions, and ledgers. |
| **Incident Verdict** | `services.verdict_stage2` | Consumes verdict hints as input facts. | Does not overwrite 0-100 verdict scores. |

---

## 3. Telemetry Event Identity & Idempotency

### Deterministic Event Fingerprinting:
Every incoming telemetry event received by the streaming adapter is assigned a deterministic **Event Fingerprint** ($H_{\text{event}}$):

$$H_{\text{event}} = \text{SHA256}(\text{tenant\_id} \parallel \text{source\_id} \parallel \text{event\_id} \parallel \text{source\_event\_time})$$

### Event Ingestion Lifecycle Matrix:
1. **Duplicate Event**: If $H_{\text{event}}$ already exists in the sliding deduplication ring buffer (10-minute window), it is discarded immediately at the ingest boundary.
2. **Replayed Event**: Replayed historical events are identified by matching against historical evidence references in `security_states.evidence_references`. Zero duplicate state versions are created.
3. **Late-Arriving Event**: Processed via the Watermark Ordering Model (see Section 4).
4. **Contradictory Event**: Emits a `CONTRADICTION` fact into the entity's `contradictions[]` array, triggering state re-evaluation into epistemic status `CONTRADICTED`.

---

## 4. Ordering Model & Clock Skew Resilience

Telemetry stream ordering cannot rely on arrival order due to network jitter, collector buffering, and multi-region clock drift.

### The 3 Timestamps:
1. **`event_time` ($t_{\text{event}}$)**: Wall-clock timestamp from the source sensor (subject to clock skew).
2. **`ingest_time` ($t_{\text{ingest}}$)**: Timestamp when NivXRay's telemetry adapter first received the byte stream.
3. **`processing_time` ($t_{\text{proc}}$)**: Monotonic UTC timestamp when Security State evaluation initiates.

### Watermark Delay Algorithm:
The streaming engine maintains an event-time watermark:

$$W = \max(t_{\text{event}}) - \Delta_{\text{watermark}}$$

Where $\Delta_{\text{watermark}} = 10\text{ seconds}$ (configurable per tenant).

- **In-Order Window**: Events where $t_{\text{event}} \ge W$ are buffered in a prioritized event-time heap.
- **Late-Arriving Telemetry ($t_{\text{event}} < W$)**: Handled without corrupting existing historical ledger blocks. The engine evaluates whether the late evidence alters the current reachability or active capabilities:
  - If state classification changes: Generates a new state version `v(N+1)` with rationale `LATE_EVIDENCE_RECONCILIATION`.
  - If state classification is unchanged: Records evidence reference without bumping version (idempotent no-op).

---

## 5. Stream Processing Semantics: Effectively-Once

NivXRay adopts **Effectively-Once Processing Semantics**:

1. **Transport Layer**: **At-Least-Once Delivery**. Kafka/EDR collectors guarantee that every event is delivered at least once.
2. **Deduplication Layer**: In-memory LRU fingerprint cache (100,000 entries per tenant) eliminates 99.9% of immediate network retries.
3. **Storage & State Layer**: Database-level compound unique index on `(tenant_id, case_id, version)` and `(tenant_id, case_id, sequence_number)` with Optimistic Concurrency Control (OCC) guarantees that duplicate evaluations result in identical state hashes without generating duplicate ledger blocks.

---

## 6. Debouncing, Coalescing & State Change Detection

A live enterprise sensor can emit 10,000 events per second. Running a full reachability matrix calculation and ledger append on every single event would trigger a catastrophic state-version explosion.

### The 3-Tier Coalescing Hierarchy:

```text
Raw Event Stream (10,000 eps)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ TIER 0: Pre-Filter (Telemetry Adapter)                      │
│   · Drops routine benign heartbeats & noise                 │
└──────────────────────────────┬──────────────────────────────┘
                               │ (100 eps)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ TIER 1: Sliding Window Coalescer (Security State Adapter)   │
│   · 2.0 second temporal window OR 50 accumulated events     │
│   · Coalesces events into a single Investigation Batch      │
└──────────────────────────────┬──────────────────────────────┘
                               │ (1 batch / 2 sec)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ TIER 2: Material Security State Change Gate                 │
│   · Evaluates whether batch introduces:                     │
│       a) New attacker capability                            │
│       b) State transition trigger                           │
│       c) Elevation in Intent risk band                      │
│       d) New compromised foothold entity                    │
│   · IF NO MATERIAL CHANGE -> Discards batch without write   │
│   · IF MATERIAL CHANGE   -> Persists State v(N+1) & Ledger  │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Backpressure & Queueing Policy

When inbound telemetry bursts exceed processing throughput:

1. **High Watermark (80% queue capacity)**: Streaming adapter initiates reactive backpressure, signaling upstream collectors to throttle pull intervals.
2. **Overflow Ring Buffer**: Low-severity informational events (`severity_hint: "low"`) are deferred to disk-backed spillover queues.
3. **Zero Evidence Drops**: High-confidence indicators, process executions, credential access events, and network connection events are **never dropped**. If capacity reaches 95%, the system sheds background analytics while keeping the Security State reasoning path alive.
4. **Dead-Letter Queue (DLQ)**: Malformed JSON or unparseable payloads are routed to `security_state_dlq` with full raw byte capture and error diagnostics.

---

## 8. Failure Recovery & High-Availability Scenarios

| Failure Scenario | Recovery Mechanism | State Invariant Maintained |
| :--- | :--- | :--- |
| **Telemetry Collector Crash** | Resumes reading from last committed Kafka/WAL offset. | At-least-once replay; deduplicated by $H_{\text{event}}$. |
| **Worker Process Crash Mid-Evaluation** | State written as `PENDING_LEDGER` is rejected during crash recovery; prior state `vN` preserved. | No uncommitted state is ever served. |
| **MongoDB Partition / Outage** | Adapter enters write-pause mode, buffering up to 5,000 events in local disk spool. | In-flight events are preserved without data loss. |
| **Engine Algorithm Exception** | Event marked `EVALUATION_FAILED`, isolated to DLQ; prior state remains active. | An unhandled exception cannot corrupt active state. |

---

## 9. Observability & Streaming Metrics

The streaming adapter exposes the following Prometheus/OpenTelemetry metrics:

| Metric Name | Type | Description | Target SLA |
| :--- | :---: | :--- | :--- |
| `nivx_stream_ingest_events_total` | Counter | Total raw telemetry events ingested by source. | N/A |
| `nivx_stream_dedup_dropped_total` | Counter | Duplicate events dropped at fingerprint boundary. | N/A |
| `nivx_stream_coalesced_batches_total`| Counter | Total batches emitted by sliding-window coalescer. | N/A |
| `nivx_stream_coalescing_ratio` | Gauge | Ratio of raw events to state evaluation batches. | > 20:1 |
| `nivx_stream_queue_depth` | Gauge | Current depth of tenant evaluation queue. | < 500 events |
| `nivx_stream_consumer_lag_ms` | Gauge | Latency between `ingest_time` and `processing_time`. | < 2,000 ms |
| `nivx_stream_state_transition_total` | Counter | Total state versions committed to MongoDB. | N/A |
| `nivx_stream_ledger_write_latency_ms`| Histogram | Latency of atomic ledger block append. | p95 < 10 ms |
| `nivx_stream_dlq_events_total` | Counter | Total malformed events routed to dead-letter queue. | 0 |

---

## Production Safety Status

Feature flag remains locked in safe baseline mode:
```text
NIVX_FLAG_SECURITY_STATE=disabled
```
No live streaming collectors or sockets are started. Architecture and contracts only.
