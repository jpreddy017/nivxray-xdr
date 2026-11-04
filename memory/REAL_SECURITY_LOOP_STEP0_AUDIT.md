# STEP 0 — REAL SECURITY LOOP · CURRENT-STATE AUDIT (read-only)

Date: 2026-06 (this fork) · **No code was modified. No telemetry was injected.
No credential was minted. Nothing was deployed.**

Method: source inspection + live read-only probes of the preview runtime, the
preview MongoDB, the production API (`/api/health`, `/api/openapi.json`) and the
**deployed production JS bundles** on `xdr.nivxforge.com`.

---

## A · Architecture actually observed

```
REAL LINUX HOST (this preview pod is one)
   │
   ├── NivXForge Linux sensor  agents/nivxforge-linux/nivxforge_sensor.py
   │      (supervisor: nivxforge_sensor · RUNNING · /proc polling, real)
   │      → POST /api/edr/agent/telemetry   (bearer session, credential-bound)
   │      → edr_raw_events                  (71,079 rows · payload_sha256 · dedup_key)
   │      → edr_plane/canonical_bridge.bridge()
   │            parse → canonical → derivation appended to the RAW row
   │      → process_event_through_pipeline()  ← SAME core pipeline
   │
   └── auditd  (NOT present in this pod: no /var/log/audit, no systemd)
          → scripts/nivxray_auditd_forwarder.py   (host shipper, stdlib only)
          → POST /api/xdr/ingest/telemetry        (X-XDR-API-Key + X-Tenant-Id)
          → routers/xdr_ingest.py
                tenant isolation → idempotency claim → xdr_canonical_events (raw row)
          → process_event_through_pipeline()  ← SAME core pipeline

ONE core pipeline (backend/detection_content/xdr_pipeline.py):
  DSM resolve → Parser → Normalizer → xdr_canonical_evidence
  → detection (nivxray_native_sigma + library + authored rule store)
  → IUE (understanding) → ICE (correlation) → VEEE (verdict)
  → spread watchlist (evidence only, re-scored by the SAME VEEE)
  → materialise_incident (GATED) → workspace_cases
  → investigation → response fabric → closed loop → framework mapping
  → autonomous investigator
```

Two ingress doors, **one** reasoning core. No second engine, no second verdict
plane. Confirmed by `grep process_event_through_pipeline`: every producer
(xdr_ingest, edr_plane bridge, v2 ingestion, content supply chain) funnels here.

---

## B · Component classification (evidence for every line)

| # | Component | State | Evidence |
|---|---|---|---|
| 1 | NivXForge EDR telemetry path | **WORKING** | sensor log `collected=18 sent=18`; `edr_raw_events` 71,079; `xdr_canonical_evidence` 65,516 rows `NivXForge/LinuxSensor`, newest `2026-09-14T13:55:52Z` — live right now |
| 2 | auditd telemetry onboarding | **PARTIAL** | exactly **1** auditd canonical event ever (`Linux/Auditd`, 2026-09-10, tenant `start-fix-21002`) — the acceptance proof. No production auditd host enrolled |
| 3 | `nivx-prod-1` tenant | **UNKNOWN** | production reads require an owner credential; not probed. Preview has no `nivx-prod-1` |
| 4 | Collector (record + state machine) | **WORKING** | `xdr_collectors` 117 docs; states observed `ADOPTED / CONNECTED / DEGRADED / DISABLED`; `CONNECTED` only from ingest counters (`xdr_ingest.py:592`) |
| 5 | Collector runtime (`apps/nivxray-xdr-collector`) | **NOT DEPLOYED** | runs in preview under supervisor `xdr_collector`; `XDR_COLLECTOR_RUNTIME_URL` unset for the core; **no vendor connector registered** (`framework/registry.py`: "Phase A does NOT register any vendor connector") |
| 6 | auditd forwarder script | **WORKING (unexercised in prod)** | `scripts/nivxray_auditd_forwarder.py` — offset file, `--preflight/--dry-run/--once`, `source_event_id = auditd:<epoch:serial>` for exactly-once |
| 7 | Ingestion API | **WORKING** | `POST /api/xdr/ingest/telemetry`, scope `collectors.enroll`, tenant proven **before** collector lookup (`xdr_ingest.py:382-426`) |
| 8 | Queue / streaming | **NOT IMPLEMENTED (by design)** | batched POST only; `INGEST_CONTRACT.md §5` non-goals. Collector plane has an outbox (`framework/outbox.py`) but is not deployed |
| 9 | Parsers | **PARTIAL** | DSM order `snort-eve → windows-security-evd → linux-auditd → aws-cloudtrail → microsoft-sysmon → cef-leef → nivxforge-linux-sensor`. auditd parser works; **defects in D2/D3 below** |
| 10 | Normalization | **PARTIAL** | canonical schema populated for sensor + auditd; auditd loses host + identity (D2) |
| 11 | Canonical evidence schema | **WORKING** | `CanonicalTelemetryEvent` (host/identity/process/network/file/auth/cloud + provenance + raw_ref + additional_fields); 65,814 rows |
| 12 | Raw → canonical traceability | **WORKING (sensor) / PARTIAL (auditd)** | 50/50 newest sensor evidence rows resolve to their `edr_raw_events` row via `provenance.trace_id`; auditd evidence embeds raw **by value** (`raw_ref`) with no pointer to its `xdr_canonical_events` row |
| 13 | Enrichment | **WORKING** | `xdr_intelligence_observations` 213, `xdr_osint_cache` 18, framework mappings 3,125 |
| 14 | Deterministic detection | **WORKING** | `evaluate_detection()` — Sigma-strict golden rule + Enterprise library + authored rule store, one evaluator; `xdr_detection_rules` 98. **No AI in the verdict path** |
| 15 | Correlation (ICE) | **PARTIAL** | 10 real correlation rules (parent/child, cross-host pivot, brute-force→success); `xdr_correlation_matches` 86. **Single domain only** — every live match is endpoint evidence |
| 16 | Incident creation | **WORKING + GATED** | `materialise_incident` refuses below gate and the refusal is returned verbatim; real incident from real sensor activity: `inc_e933fc93e30f4579b675` "Execution from a world-writable directory" |
| 17 | Investigation APIs | **WORKING** | `xdr_investigations` 536, findings 3,501, activity 20,245 |
| 18 | Response service | **WORKING, HONEST-FAILING** | `xdr_response_executions` 236; real chain request→approve→dispatch→EDR; latest EDR commands end `CAPABILITY_UNAVAILABLE` with `verification: null` — **no fake success** |
| 19 | Independent verification | **PARTIAL** | `verified_at`/`verification` fields exist and are correctly `None` when unverified; **no successful verified containment exists yet** because the sensor cannot isolate inside this container |
| 20 | Audit trail | **WORKING** | `xdr_audit_log` 9,667; `xdr_vault_audit` 120,048; `edr_rejected_telemetry` 1,045 with `evidence_eligibility: NEVER_EVIDENCE` — unauthorised ingest is itself a recorded signal |
| 21 | Tenant isolation | **WORKING (prod now patched)** | backend: batch must be single-tenant, header must equal collector owner. Frontend: **deployed** `XdrAdminPage` chunk contains `X-Tenant-Id` ×5, `col-tenant-context` ×1, `confirm_tenant_id` ×6 |
| 22 | Authentication | **WORKING** | API-key auth + IP/key/tenant rate limiting, fail-closed 503; sensor uses credential→session exchange (observed `SESSION_EXPIRED` 401 then recovery) |
| 23 | Timing instrumentation | **NOT IMPLEMENTED** | only `event_time` and `ingest_time`; no stage latencies (D1) |
| 24 | Production runtime | **HEALTHY & CURRENT** | `GET /api/health` 200; `CreateKeyBody = [name, confirm_tenant_id, allow_new_tenant, description, scopes, expires_at]` → **the P1 hardening IS live in production** |
| 25 | Production XDR SPA | **CURRENT** | `xdr.nivxforge.com/` → 307 → `/xdr`; admin chunk carries both tenant-context patches |

---

## C · Defects found (read-only, nothing fixed)

- **D1 · Provenance timestamp set is incomplete.** `ProvenanceEnvelope` carries
  only `ingest_time`. There is no `sensor_observed_at`, `collector_received_at`,
  `parsed_at` or `normalized_at`. `edr_raw_events.event_time` is `null` on live
  sensor rows even though the payload contains `observed_at`. Step 3 and Step 12
  cannot pass as written until this is addressed.
- **D2 · auditd normalizer loses host and identity.** On the one real auditd
  event: `host.hostname = ""`, `host.host_id = ""` (the envelope's
  `source: "acceptance-host"` is never read), `identity.username = "uid:"`.
  An EXECVE record has no `uid`/`pid`, and nothing back-fills from the paired
  SYSCALL record. **Entity resolution and correlation are weakened at the root.**
- **D3 · auditd event_type mislabel.** `type=EXECVE` is classified
  `auditd_syscall`, not `process_execution`, because the branch requires
  `syscall` or `exe` — neither appears on an EXECVE record.
- **D4 · No auditd record stitching.** auditd emits SYSCALL + EXECVE + PROCTITLE
  under one `audit(epoch:serial)`. Each is ingested as an independent event, so
  the pieces of one real execution never reassemble.
- **D5 · Two raw stores, one link style.** Sensor path: `edr_raw_events` +
  derivations + `provenance.trace_id` (traceable). XDR ingest path:
  `xdr_canonical_events` minimal row, but the canonical evidence does not carry
  its id — the link is by value, not by reference.
- **D6 · Collector `Start` fix is committed locally (`1b625697`) and its
  production deployment status is UNKNOWN.** Not schema-visible, so it cannot
  be confirmed from `openapi.json`.

---

## D · Is "collector stuck in STARTING" still a real blocker?

**No — and it never blocked ingestion.**

- `xdr_ingest.py:558-609` writes collector state **directly** from the
  received/parsed/normalized counters and does not pass through
  `_ALLOWED_TRANSITIONS`. Any prior state, including `STARTING`, moves straight
  to `CONNECTED` on the first real event.
- Proven once already: the single real auditd event drove
  `collector_state CONNECTED`, reason `telemetry received/parsed/normalized:
  1/1/1`.
- `Start` only matters for a **listening** transport, which the FastAPI core
  cannot bind (no UDP/TCP 514 behind the Kubernetes ingress). That is the
  separate, undeployed collector runtime's job.

**Conclusion: pressing Start is not on the critical path. Do not touch it.**

---

## E · Exact current telemetry path (two doors, one core)

1. **EDR sensor (live today, genuine):** real Linux host → `nivxforge_sensor.py`
   /proc polling → `POST /api/edr/agent/telemetry` (session bearer) →
   `edr_raw_events` (sha256 + dedup_key + trust_state AUTHENTICATED) →
   `canonical_bridge` → `xdr_canonical_evidence` + `v2_shadow_observations`
   (`origin: collector-live`, `case_id: null`) → core pipeline → gated incident.
2. **XDR ingest (built, exercised once, genuine-capable):** real Linux host →
   `auditd` → `nivxray_auditd_forwarder.py` → `POST /api/xdr/ingest/telemetry`
   → tenant guard → idempotency claim → `xdr_canonical_events` → core pipeline.

---

## F · Components to ADOPT, never rebuild

`xdr_ingest.py` · `services/ingest_idempotency.py` ·
`detection_content/xdr_pipeline.py` and every engine it calls (IUE / ICE / VEEE
/ incident gate) · `detection_content/telemetry/*` DSMs ·
`edr_plane/canonical_bridge.py` · `v2/ingestion/telemetry_bridge.py` ·
`apps/nivxray-xdr-response` + `routers/edr_response.py` ·
`services/machine_rate_limit.py` · `routers/xdr_audit_log.py` ·
`scripts/nivxray_auditd_forwarder.py` · `agents/nivxforge-linux/nivxforge_sensor.py`.

---

## G · Smallest next action for ONE genuine event → raw → canonical evidence

Both previously-blocking items are now **clear**: production carries the P1
hardening, and the deployed admin bundle carries both tenant-context patches.

Recommended (no owner host work, provable today):
> **Instrument and prove the loop on the telemetry that is ALREADY genuine and
> already flowing** — the live NivXForge Linux sensor on this real host. Pick N
> real events produced in the last minutes and walk them end to end
> (source activity → raw row → derivation → canonical evidence → detection →
> verdict → incident-or-refusal), recording exactly which provenance timestamps
> exist and which do not. Zero writes beyond what the running sensor already
> does.

Production auditd path (needs the owner, sequenced, one step at a time):
> revoke the exposed key → mint in `nivx-prod-1` (`confirm_tenant_id`,
> `allow_new_tenant`) → create the collector with `TENANT = nivx-prod-1` →
> `apt install auditd` + one execve rule on the host →
> `--preflight` → `--dry-run` → `--once`.

---

## H · Risks of that next action

| Action | Risk |
|---|---|
| Sensor-path proof (preview) | Read-only. Risk ≈ 0. Not production, and it is the EDR/endpoint domain, so it cannot by itself justify a "cross-domain XDR" claim |
| Mint a production ingest key | A live credential exists from that moment. The previously exposed key **must** be revoked first |
| Create the production collector | First write into `nivx-prod-1`. If the tenant selector is wrong it lands in `default` and the forwarder is refused `403 TENANT_ISOLATION_VIOLATION` |
| `apt install auditd` + rules | Adds disk I/O and log volume on the owner's host; over-broad rules can be noisy |
| Run the forwarder | Ships **verbatim command lines** to the platform — real data, potentially sensitive. Start with `--dry-run` |
| Fixing D2/D3/D4 | Touches a shared normalizer; needs regression against the existing auditd + sensor corpus before any deploy |

---

## STOP

Awaiting owner review and approval of the next action. Nothing further will be
changed until then.
