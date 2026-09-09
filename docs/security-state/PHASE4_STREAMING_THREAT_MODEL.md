# NivXRay Phase 4A: Streaming Ingestion Boundary Threat Model

> **Document Type:** Threat Modeling & Attack Surface Analysis  
> **Status:** Final & Authoritative  
> **Target Boundary:** Live Telemetry Ingestion -> Telemetry Adapters -> Security State Streaming Core  
> **Framework:** STRIDE-aligned Security Threat Matrix  
> **Feature Flag Gate:** `NIVX_FLAG_SECURITY_STATE=disabled` (Safe Baseline Lock)  

---

## Executive Summary

Exposing the Security State subsystem to live streaming telemetry introduces an expanded attack surface. Because Security State determines attacker capabilities, reachability, and automated containment interventions, an adversary who successfully manipulates or poisons the streaming boundary could induce false-positive service lockouts (denial of service) or suppress containment actions during a real breach.

This threat model identifies **11 threat classes** across the streaming boundary and establishes defensive controls and verification signatures for each.

---

## 1. Threat Classification Matrix (STRIDE)

| Threat ID | Threat Name | STRIDE Class | Severity | Primary Target Layer |
| :--- | :--- | :---: | :---: | :--- |
| **T-01** | Forged Telemetry Injection | Spoofing | **HIGH** | Ingestion Boundary |
| **T-02** | Telemetry Replay Attack | Tampering | **MEDIUM** | Event Coalescer |
| **T-03** | Cross-Tenant State Poisoning | Information Disclosure | **CRITICAL** | Tenant Demux / Database |
| **T-04** | In-Flight Event Tampering | Tampering | **HIGH** | Transport / Kafka Bridge |
| **T-05** | Event Storming / Queue Poisoning | Denial of Service | **HIGH** | Ingestion Queue / Coalescer |
| **T-06** | Timestamp Manipulation & Skew | Tampering | **MEDIUM** | Watermark Buffer |
| **T-07** | Compromised / Rogue Sensor | Spoofing | **CRITICAL** | Telemetry Adapter Registry |
| **T-08** | Decompression / Oversized Bomb | Denial of Service | **HIGH** | JSON Deserializer |
| **T-09** | Parser Abuse / Injection | Elevation of Privilege| **HIGH** | CRE / IU Peeling Engine |
| **T-10** | Causal Ancestry Spoofing (PPID/PID)| Tampering | **HIGH** | Causal Intelligence Core |
| **T-11** | Ledger Sequence Race Attack | Tampering | **CRITICAL** | Distributed Ledger Repo |

---

## 2. In-Depth Threat Scenarios & Mitigations

### Threat T-01: Forged Telemetry Injection
- **Attack Vector**: Adversary crafts synthetic Sysmon or EDR JSON events claiming critical admin tools were executed legitimately to prevent alert firing, or conversely injects fake ransomware indicators to cause automated isolation of core domain controllers.
- **Vulnerability**: Unauthenticated telemetry intake endpoints.
- **Architectural Mitigation**:
  1. Mandatory mutual TLS (mTLS) with client certificate verification for all EDR collectors.
  2. Cryptographic HMAC signing of every `StreamingEventEnvelope` by the collector agent.
  3. Strict schema validation rejecting un-whitelisted properties before parsing.

---

### Threat T-02: Telemetry Replay Attack
- **Attack Vector**: Adversary captures a legitimate telemetry stream and replays it hours later to force the engine into an obsolete state or create a loop of redundant interventions.
- **Vulnerability**: Ingestion endpoints lacking temporal nonce checks.
- **Architectural Mitigation**:
  1. Every event has a mandatory monotonic $H_{\text{event}}$ fingerprint:
     $$H_{\text{event}} = \text{SHA256}(\text{tenant\_id} \parallel \text{source\_id} \parallel \text{event\_id} \parallel \text{source\_event\_time})$$
  2. In-memory LRU fingerprint cache drops duplicates within the active sliding window.
  3. Historical events matching previously committed state versions are ignored (idempotent no-op).

---

### Threat T-03: Cross-Tenant State Poisoning
- **Attack Vector**: An attacker in multi-tenant environment injects telemetry tagged with another tenant's `tenant_id` or probes `case_id` collisions to view cross-tenant reachability matrices or cause state corruption.
- **Vulnerability**: Relying on unverified payload `tenant_id` fields.
- **Architectural Mitigation**:
  1. Tenant ID is **derived solely from the authenticated mTLS certificate or JWT claim**, NEVER from the raw telemetry JSON payload.
  2. If the payload body contains a mismatched `tenant_id`, the event is dropped with `ERR_STREAM_TENANT_MISMATCH (4001)` and logged as a security alert.
  3. Database compound unique indexes `(tenant_id, case_id, version)` strictly prevent cross-tenant key leakage.

---

### Threat T-04: In-Flight Event Tampering
- **Attack Vector**: Man-in-the-middle on intermediate collector nodes alters command lines or strips malicious flags before events reach the engine.
- **Vulnerability**: Unencrypted internal transport between collectors and backend.
- **Architectural Mitigation**:
  1. Mandatory end-to-end TLS 1.3 encryption across all internal message broker queues.
  2. Telemetry Adapters stamp an immutable `Provenance` envelope on every `CanonicalEvent` including raw SHA-256 payload digest.

---

### Threat T-05: Event Storming & Queue Poisoning (DoS)
- **Attack Vector**: Adversary floods the endpoint with 100,000 events/second (e.g. generating millions of benign file creates) to overwhelm the causal reasoning engine and trigger backpressure drops of real malicious signals.
- **Vulnerability**: Unbounded queues and lack of tier-based event prioritization.
- **Architectural Mitigation**:
  1. **Tier 0 Pre-Filtering**: Non-security telemetry (heartbeats, benign file reads) is discarded prior to the evaluation queue.
  2. **Sliding Window Coalescer**: Aggregates bursts into 2.0-second / 50-event batches.
  3. **Priority Ingestion Queues**: High-severity events (process creation, credential dumping, network connections) bypass background queues via dedicated high-priority channels.

---

### Threat T-06: Timestamp Manipulation & Clock Skew Exploit
- **Attack Vector**: Attacker tampers with the local workstation clock, reporting an attack with a timestamp 4 hours in the future or 48 hours in the past to subvert causal ancestry or bypass temporal correlation rules.
- **Vulnerability**: Blind trust in client sensor wall-clock timestamps.
- **Architectural Mitigation**:
  1. The streaming engine tracks three distinct timestamps: `event_time`, `ingest_time`, and `processing_time`.
  2. Telemetry with $|t_{\text{event}} - t_{\text{ingest}}| > 300\text{ seconds}$ is flagged with `CLOCK_SKEW_SUSPECT`.
  3. Causal Intelligence Engine refuses to infer causal parent-child relationships if child timestamp precedes parent timestamp ($\Delta t < 0$).

---

### Threat T-07: Compromised / Rogue Telemetry Source
- **Attack Vector**: An attacker achieves root/SYSTEM privileges on a host, compromises the EDR agent, and sends falsified signals to blind the SOC.
- **Vulnerability**: Treating single-source telemetry as non-repudiable ground truth.
- **Architectural Mitigation**:
  1. Epistemic Status modeling: Telemetry from a single uncorroborated sensor evaluates to status `DERIVED` or `INFERRED`, never `OBSERVED`.
  2. Multi-source cross-validation: Process events on an endpoint must correlate with firewall/network flow logs or identity auth events before reaching `CONFIRMED_ATTACK`.
  3. Causal claims are formally bounded to **`STRONG_CAUSAL_EVIDENCE` (Telemetry-Corroborated Process Ancestry)**, never claiming kernel-level non-repudiation.

---

### Threat T-08: Decompression & Oversized Payload Bombs
- **Attack Vector**: Attacker transmits heavily nested or gzip-compressed payloads that expand to gigabytes in memory, crashing backend worker processes.
- **Vulnerability**: Unrestricted buffer allocation in JSON/deobfuscation parsers.
- **Architectural Mitigation**:
  1. Hard byte limit enforced at reverse proxy: Maximum 2MB per streaming event batch.
  2. Decompression ratio limits: Recursion depth capped at 5 layers; maximum decompressed buffer size capped at 10MB.
  3. Malformed or oversized events routed directly to Dead-Letter Queue (DLQ).

---

### Threat T-09: Parser Abuse & Injection into Deobfuscation Engines
- **Attack Vector**: Attacker sends malformed command-line wrappers designed to cause infinite recursion or regex catastrophic backtracking in CRE or IU parsers.
- **Vulnerability**: Unbounded regex evaluation.
- **Architectural Mitigation**:
  1. All regex evaluation in Input Understanding (IU) and CRE enforces strict timeouts (50ms max per evaluation).
  2. Memory and execution depth limits on recursive peeling (max 8 wrapper layers).

---

### Threat T-10: Causal Ancestry Spoofing (PPID / PID Recycling)
- **Attack Vector**: Attacker spawns processes via unmonitored injection or exploits PID recycling to fool the causal engine into declaring `winword.exe` as the parent of an administrative PowerShell command when it was actually invoked by malware.
- **Vulnerability**: Naive parent-child correlation based solely on numeric Process ID (PID).
- **Architectural Mitigation**:
  1. Causal engine verifies compound process keys: `(host_id, pid, process_create_time, process_guid)`.
  2. Telemetry that reports a child process starting prior to parent start time ($\Delta t < 0$) is flagged as anomalous and causal link is denied.

---

### Threat T-11: Ledger Sequence Race Attack
- **Attack Vector**: Malicious worker attempts to inject a rogue ledger block or race on sequence numbers to cause a fork in the audit trail.
- **Vulnerability**: Single-process sequence assignment without database-level uniqueness.
- **Architectural Mitigation**:
  1. Sequence numbers generated via MongoDB atomic `$inc` counters (`security_state_counters`).
  2. Compound unique index `(tenant_id, case_id, sequence_number)` and `(tenant_id, case_id, current_hash)` rejects forks at the database level.
  3. SHA-256 block hash chaining ensures any altered block fails integrity verification across all replicas.

---

## 3. Threat Modeling Signatures & Diagnostic Rules

The streaming engine implements automated security detection rules that trigger alerts when anomalous streaming telemetry patterns are observed:

```python
STREAMING_SECURITY_RULES = [
    {
        "id": "SEC-STR-01",
        "name": "Excessive Clock Skew Detected",
        "condition": "abs(event.source_event_time - event.ingested_at) > 300",
        "action": "FLAG_CLOCK_SKEW_SUSPECT"
    },
    {
        "id": "SEC-STR-02",
        "name": "Cross-Tenant Identifier Injection",
        "condition": "event.payload.tenant_id != event.envelope.tenant_id",
        "action": "DROP_AND_ALERT_SECURITY_BREACH"
    },
    {
        "id": "SEC-STR-03",
        "name": "Chronologically Inverted Causal Claim",
        "condition": "child_event.timestamp < parent_event.timestamp",
        "action": "REFUSE_CAUSAL_EDGE"
    },
    {
        "id": "SEC-STR-04",
        "name": "Replay Window Violation",
        "condition": "event.fingerprint in historical_ledger_evidence",
        "action": "DISCARD_IDEMPOTENT_REPLAY"
    }
]
```

---

## Production Safety Status

Feature flag remains locked in safe baseline mode:
```text
NIVX_FLAG_SECURITY_STATE=disabled
```
No live telemetry collectors or unverified streaming adapters are activated.
