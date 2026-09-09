# NivXRay Security State — Phase 4C Safe Shadow Mode & Cockpit Telemetry

## 1. Safety Boundary & Invariant Rules

Safe Shadow Mode allows NivXRay analysts and engineers to evaluate live or replayed streaming evidence against the Security State and Causal Intelligence engine without affecting production verdicts or triggering automated response actions.

```
+─────────────────────────────────────────────────────────────────────────────+
|                         SAFE SHADOW MODE INVARIANTS                         |
+─────────────────────────────────────────────────────────────────────────────+
| 1. PRODUCTION VERDICT DECOUPLING:                                           |
|    Security State outputs do NOT alter, override, or replace existing       |
|    v2 Canonical Verdict Engine classifications.                             |
|                                                                             |
| 2. RESPONSE EXECUTION LOCK:                                                 |
|    Automated response execution is hard-locked to FALSE (auto_execute=False).|
|    Zero response actions (containment, isolation, token revocation) can     |
|    be executed by streaming events.                                         |
|                                                                             |
| 3. EXPLICIT SHADOW LABELING:                                                |
|    Every evaluated state record, transition, and ledger block carries:      |
|    shadow_label = "SECURITY_STATE_SHADOW"                                   |
|    shadow_mode = True                                                       |
|                                                                             |
| 4. FEATURE FLAG GATE:                                                       |
|    NIVX_FLAG_SECURITY_STATE=disabled remains enforced in backend/v2/flags.py|
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Operator Cockpit UI Integration (`SecurityStateTab.jsx`)

The analyst investigation cockpit reflects the live streaming and shadow state through truthful telemetry indicators connected directly to the backend router.

### Cockpit Badges & Status Indicators
1. **`SECURITY_STATE_SHADOW` Badge**:
   - Visual: Deep purple background (`bg-purple-950 text-purple-300 border-purple-800`).
   - Purpose: Clearly identifies to the analyst that the state was computed under shadow mode without active response authority.
2. **`STREAM: CONNECTED (SHADOW)` Badge**:
   - Visual: Emerald background when stream adapter is active; zinc when disconnected.
   - Purpose: Real-time confirmation of streaming transport connectivity.
3. **`LEDGER: VERIFIED (SHA-256)` Badge**:
   - Visual: Emerald background confirming immutable cryptographic chain integrity; changes to red (`LEDGER: TAMPER DETECTED`) if sequence or hash breaks.
4. **Streaming Observability Strip**:
   - `TRANSPORT`: Displays active transport adapter (e.g. `REPLAY_ADAPTER_LOCAL`).
   - `EVENT LAG`: Real-time processing lag relative to event timestamps.
   - `EVENTS PROCESSED`: Authoritative count of events processed through the pipeline.
   - `LATE EVENTS`: Real-time count of out-of-order events reconciled after watermark establishment.
   - `DLQ EVENTS`: Count of dead-lettered envelopes requiring administrative review or remediation.
   - `SAFETY GATE`: Explicit notice confirming `AUTOMATED RESPONSE: DISABLED (SAFETY GATE)`.

---

## 3. Security State Ledger Audit Records

Every state transition persisted under Shadow Mode records explicit provenance in the immutable audit ledger (`security_state_ledgers`):

```json
{
  "sequence_number": 2,
  "block_id": "blk-000002",
  "event_type": "STREAMING_SECURITY_STATE_TRANSITION",
  "entity_id": "endpoint-finance-04",
  "state_version": 2,
  "previous_hash": "b3b961d1f35956dd996d505b60d84c6fc89cbcc334a360f7d0b4cf9793a997b2",
  "current_hash": "38af37a7e7a63b90d02e4035824b5a7ab7624e3ef9f6cc1ad73b16fac5ca2ee4",
  "payload": {
    "classification": "CONFIRMED_ATTACK",
    "state_hash": "a18830cdb0418b0c7418b6201766de6cf9fee2af22df85e0912cf87716666bac",
    "material_reasons": [
      "NEW_ATTACKER_CAPABILITY (['CAP_CREDENTIAL_ACCESS'])"
    ],
    "is_late_event": false,
    "shadow_mode": true,
    "shadow_label": "SECURITY_STATE_SHADOW"
  },
  "timestamp": "2026-09-04T05:22:00.000000Z",
  "verified": true
}
```

---

## 4. Operational Gate & Final Classification

### Final Verification Question
> *"Can the same streaming adapter path safely consume live telemetry later without changing the Security State architecture?"*

### Assessment
1. **Transport Neutrality**: The `StreamingEventAdapter` interface is fully decoupled from the transport mechanism. Live Kafka, WebSocket, or EDR webhook ingestors need only construct the approved `StreamingEventEnvelope` with authenticated tenant context.
2. **Architecture Purity**: The streaming path strictly traverses the existing NivXRay Canonical Evidence and SSOT substrate (`TelemetryAdapter` $\rightarrow$ `CanonicalEvent` $\rightarrow$ `Evidence` $\rightarrow$ `SSOT` $\rightarrow$ `SecurityStateEngine`). No duplicate detection engines or shadow schemas were introduced.
3. **Persistent Idempotency**: Multi-replica persistent deduplication (`security_event_dedup`), watermarking, and two-phase ledger commits protect against distributed race conditions, replays, and crash windows.

### Gate Classification: **VERIFIED**

> **PHASE 4C COMPLETE — READY FOR CONTROLLED SHADOW REPLAY**
