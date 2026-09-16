# NivXRay Security State — Phase 4C Streaming Implementation Architecture

## 1. Executive Summary & Safety Boundary
Phase 4C implements the transport-neutral Streaming Adapter and Safe Shadow Replay subsystem for the NivXRay Security State and Causal Intelligence platform.

### Core Principle & Mandate
> **"Streaming transports evidence; it does NOT become a new detection engine or a second ingestion architecture."**

Streaming feeds the existing ground-truth NivXRay evidence substrate without bypassing Canonical Evidence, the Telemetry Adapter framework, or Authoritative SSOT.

```
+─────────────────────────────────────────────────────────────────────────────+
|                               STREAMING SOURCE                              |
|              (ReplayStreamingSource / Live Transport Envelope)              |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
|                           STREAMING EVENT ADAPTER                           |
|  - Authenticated Tenant Context Derivation (Rejects payload tenant spoof)   |
|  - Canonical Event Identity: Tier A (Native UUID) / Tier B (Semantic 1s)    |
|  - Authoritative Persistent Deduplication (security_event_dedup)           |
|  - Watermark & Event-Time Tracking (In-Order, OOO, Late, Clock-Skewed)      |
|  - Sliding-Window Coalescer with Evidence-Driven Critical Milestone Bypass   |
|  - Dead-Letter Queue (security_state_dlq) with Remediated Replay            |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
|                       EXISTING NIVXRAY INGESTION PATH                       |
|           (services/telemetry_adapters/framework.py · CanonicalEvent)       |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
|                        CANONICAL EVIDENCE & SSOT SUBSTRATE                  |
|               (v2/investigation/evidence.py · SSOTAdapter)                  |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
|                         MATERIAL STATE CHANGE GATE                          |
|             (Suppresses non-material spam; evaluates escalation)            |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
|                     SECURITY STATE EVALUATION & PERSISTENCE                 |
|       (Persistent Security State Records · Immutable SHA-256 Ledger)        |
+─────────────────────────────────────────────────────────────────────────────+
```

### Safety Boundary (Strict Non-Production / Local)
- Feature Flag: `NIVX_FLAG_SECURITY_STATE=disabled`.
- Zero connections to production Kafka, production EDR, customer telemetry, external SaaS, or real customer tenants.
- Automated response execution remains strictly gated and disabled (`auto_execute=False`).
- Shadow Mode is stamped on all records: `SECURITY_STATE_SHADOW`.

---

## 2. Adapter Interface & Transport Neutrality
The adapter boundary is completely decoupled from underlying messaging brokers. No Kafka, WebSocket, or gRPC dependencies are hardcoded into Security State logic.

### Core Protocol Implementations (`backend/security_state/streaming/`)
| Component | Module | Purpose |
| :--- | :--- | :--- |
| **StreamingEventEnvelope** | [`models.py`](file:///d:/Projects/backend/security_state/streaming/models.py) | Transport-neutral envelope with cryptographic tenant context & HMAC signature |
| **Event Fingerprint** | [`fingerprint.py`](file:///d:/Projects/backend/security_state/streaming/fingerprint.py) | Dual-tier canonical identity generation (UUID vs 1-second quantized semantic) |
| **Persistent Deduplication** | [`dedup.py`](file:///d:/Projects/backend/security_state/streaming/dedup.py) | Authoritative `security_event_dedup` collection with multi-process atomic locks |
| **Watermark Processor** | [`watermark.py`](file:///d:/Projects/backend/security_state/streaming/watermark.py) | Event-time tracking, clock-skew bounding, and late-event reconciliation |
| **Sliding Window Coalescer**| [`coalescer.py`](file:///d:/Projects/backend/security_state/streaming/coalescer.py) | Buffering with Critical Security Milestone Immediate Bypass |
| **Dead-Letter Queue (DLQ)** | [`dlq.py`](file:///d:/Projects/backend/security_state/streaming/dlq.py) | Authoritative `security_state_dlq` collection with remediation replay |
| **Streaming Event Adapter** | [`adapter.py`](file:///d:/Projects/backend/security_state/streaming/adapter.py) | End-to-end integration coordinating ingestion, SSOT, evaluation, and ledger |
| **Replay Source & Verifier**| [`replay.py`](file:///d:/Projects/backend/security_state/streaming/replay.py) | Deterministic replay source and direct vs streaming equivalence verifier |

---

## 3. Event Envelope & Authenticated Tenant Boundary

### Envelope Schema (`StreamingEventEnvelope`)
```python
@dataclass(frozen=True)
class StreamingEventEnvelope:
    source_id: str                      # Identifier of verified sensor or stream
    authenticated_tenant_id: str        # Cryptographically authenticated tenant ID (mTLS/JWT context)
    event_id: str                       # Native event UUID or empty for Tier B
    event_timestamp: str                # ISO-8601 UTC event generation timestamp
    ingest_timestamp: str               # ISO-8601 UTC adapter ingestion timestamp
    schema_version: str = "1.0.0"       # Envelope schema version
    payload_signature: str = ""         # SHA-256 HMAC integrity digest of payload
    provenance: Dict[str, Any]          # Immutable provenance dictionary
    payload: Dict[str, Any]             # Telemetry body (process, file, network, auth)
```

### Strict Authenticated Tenant Derivation
- `tenant_id` is **never** accepted from the untrusted JSON payload body.
- If `payload.get("tenant_id")` is present and does NOT match `authenticated_tenant_id`:
  1. Envelope is immediately rejected.
  2. Error `ERR_STREAM_TENANT_MISMATCH` is raised.
  3. Failure class `AUTH_TENANT_MISMATCH` is logged to `security_state_dlq`.
  4. `events_rejected_total` is incremented.
  5. The payload is never permitted to override the authenticated transport context.

---

## 4. Dual-Tier Canonical Event Identity

To absorb network retries, collector duplicates, and microsecond clock jitter:

### Tier A: Native Source UUID
When `event_id` is a valid RFC 4122 UUID (`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`), identity is:
```
tier_a:{authenticated_tenant_id}:{event_id.lower()}
```

### Tier B: Content-Deterministic Semantic Fingerprint
When native UUID is missing, invalid, or generated by duplicate collectors:
```python
semantic_fields = {
    "tenant_id": authenticated_tenant_id,
    "source_kind": source_kind.lower().strip(),
    "action": action.lower().strip(),
    "actor": {"id": actor_id, "name": actor_name, "ip": actor_ip},
    "target": {"id": target_id, "name": target_name, "hash": target_hash},
    "core": {"command_line": cmd, "process_name": proc, ...},
    "quantized_ts": quantize_timestamp_1s(event_timestamp)
}
fingerprint = "tier_b:" + tenant_id + ":" + sha256(canonical_json(semantic_fields))
```
**Excluded from Identity**: Ephemeral transport metadata (Kafka partition/offset, transport routing hops, collector process PID, ingest timestamps) is strictly excluded, ensuring bit-identical fingerprints across retransmissions.

---

## 5. Authoritative Persistent Deduplication (`security_event_dedup`)

Deduplication correctness does not rely on local in-memory caches.

### Storage & Unique Indexing
- Authoritative Collection: `security_event_dedup`.
- Compound Unique Index: `[("tenant_id", 1), ("event_fingerprint", 1)]` (`unique=True`).
- TTL Index: `[("ttl_expires_at", 1)]` (`expireAfterSeconds=0`, default TTL 86,400s / 24 hours).
- Multi-Process Fallback: Cross-process OS directory locks (`InterProcessCaseLock`) protecting tenant-scoped persistent stores when running offline.

### Memory LRU Performance Optimization
- An in-memory LRU ring buffer (`OrderedDict`, capacity 10,000) avoids repeated database hits for rapid bursts.
- **Cache Invalidation Safety**: If the memory cache is completely wiped (simulating server crash/restart or multi-instance cache miss), the underlying database unique index guarantees that duplicates are detected and skipped without duplicating state versions or ledger entries.

---

## 6. Watermark Tracking & Out-of-Order Processing

Configured via `WatermarkPolicy`:
- `watermark_delay_seconds`: 10.0s (default)
- `allowed_clock_skew_seconds`: 60.0s (default)
- `late_event_reconciliation_mode`: `"RECONCILE_INCREMENTAL"`

### Watermark Computation
$$\text{Watermark}(t) = \max(\text{event\_time}) - \text{watermark\_delay\_seconds}$$

### Arrival Classification
1. **Clock-Skewed (Future)**: `event_time > processing_time + allowed_clock_skew_seconds` $\rightarrow$ Rejected, logged to DLQ (`MALFORMED_TIMESTAMP`).
2. **In-Order**: `event_time >= max_event_time` $\rightarrow$ Advances watermark.
3. **Out-of-Order (Buffered)**: $\text{Watermark} \le \text{event\_time} < \text{max\_event\_time}$ $\rightarrow$ Processed within active window.
4. **Late**: $\text{event\_time} < \text{Watermark}$ $\rightarrow$ Handled via `LATE_EVIDENCE_RECONCILIATION`.

---

## 7. Sliding-Window Coalescer with Critical Milestone Bypass

To avoid evaluation thrashing from noisy telemetry, non-critical events are buffered up to `coalesce_window_ms` (2000 ms) or `coalesce_max_events` (50 events).

### Milestone Bypass: Canonical Evidence + Security-State Materiality
Bypass is **NOT** restricted to a hardcoded list of ATT&CK IDs. Instead, it is driven by evidence materiality:
1. **Critical Evidence Flags**: `is_critical=True` or `severity_hint in ("critical", "high")`.
2. **Attacker Capability Milestones**: Evidence indicating `CAP_CREDENTIAL_ACCESS`, `CAP_PRIVILEGE_ESCALATION`, `CAP_LATERAL_MOVEMENT`, `CAP_RANSOMWARE_ENCRYPTION`, or `CAP_DEFENSE_EVASION`.
3. **Destructive or Sensitive Operations**: Active credential access tools (`mimikatz`, `lsass.dmp`, `procdump`), shadow copy deletion (`vssadmin delete shadows`, `wmic shadowcopy delete`), token impersonation, or hypervisor tampering.
4. **ATT&CK Corroboration**: Techniques matching `T1003`, `T1059`, `T1078`, `T1021`, `T1490`, `T1562`, `T1055` serve as supporting inputs.

**Bypass Action**: Bypasses buffering with **0 ms delay**, immediately flushing any pending buffered events for that case and evaluating Security State.

---

## 8. Material State Change Gate

Events entering evaluation pass through the Material State Change Gate before creating new database records:
- Evaluates candidate state against the latest persisted state record.
- **Suppressed (`NON_MATERIAL_SUPPRESSED`)**: If classification, active capabilities, attack state, and epistemic status are unchanged, and no high-severity facts were introduced, version increment and ledger block appending are suppressed.
- **Transitioned (`STATE_TRANSITIONED`)**: A new version and hash-chained ledger block are created only when genuine material escalation occurs.

---

## 9. Dead-Letter Queue (`security_state_dlq`) & Remediated Replay

Authoritative storage for unroutable or corrupted streaming envelopes:
- Collection: `security_state_dlq`.
- Unique Index: `[("tenant_id", 1), ("dlq_id", 1)]`.
- Preserved Attributes: `dlq_id`, `source_id`, `event_id`, `tenant_id`, `failure_class`, `reason`, `timestamp`, `schema_version`, `provenance`, `raw_envelope`, `replayed`.
- **Replay API**: Remediated events can be re-ingested through the adapter and marked `replayed=True`, ensuring zero silent telemetry loss.
