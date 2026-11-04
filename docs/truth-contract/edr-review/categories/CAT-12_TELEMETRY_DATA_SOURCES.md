# CAT-12 · Telemetry / Data Sources / Integrations (the XDR data plane)

> STRICT READ-ONLY deep-dive. **This is the root-cause category for CAT-06, CAT-09, CAT-13, CAT-14 and CAT-15.**

## 1 · PRE-AG baseline (proven)

| Artifact | Evidence at `5d67934e` | Status |
|---|---|---|
| Collector runtime | `backend/detection_content/collector_runtime.py` | IMPLEMENTED |
| Collector routers | `routers/xdr_collectors.py`, `routers/xdr_collector_landing.py` | IMPLEMENTED |
| Telemetry routers | `routers/telemetry.py`, `routers/telemetry_adapters.py` | IMPLEMENTED |
| Telemetry adapter framework | `backend/services/telemetry_adapters/framework.py` (commit `87672882`, pre-AG) | IMPLEMENTED |
| **SnortEveDSM** (network IDS) | `xdr_pipeline.py:29-48` — `id="snort-eve"`, `vendor="Snort"`, `product="Snort / Suricata EVE"`, `source_type="NETWORK_IDS"` | IMPLEMENTED |
| DSM registry (pipeline) | `xdr_pipeline.py:51-74` | IMPLEMENTED |
| Parser + normalizer | `xdr_pipeline.py:88` `SnortEveParser`, `:126` `SnortNormalizer` | IMPLEMENTED |
| Vendor adapters | `xdr_{cortex,falcon,mde,sentinelone,stub}_vendor_adapter.py` + `xdr_vendor_registry.py` | IMPLEMENTED |
| Cortex vendor integration | 9 `/api/xdr/vendor/cortex/*` paths (connections, ingest, poll, rotate, audit, webhooks) | IMPLEMENTED |
| Data-source registry | `/api/xdr/data-sources` + `/kinds` | IMPLEMENTED |
| Ingest surface | `/api/v2/ingest/{csv,evtx,json,ndjson,syslog,webhook}`, `/api/xdr/ingest/telemetry` | IMPLEMENTED |
| Credential vault + secrets | `xdr_credential_vault.py`, `/api/xdr/secrets/*` | IMPLEMENTED |

## 2 · AG delta

| Added | Type |
|---|---|
| `detection_content/telemetry/windows_security_dsm.py` | **DSM — Windows Security** |
| `detection_content/telemetry/linux_auditd_dsm.py` | **DSM — Linux Auditd** |
| `detection_content/telemetry/aws_cloudtrail_dsm.py` | **DSM — AWS CloudTrail** |
| `detection_content/telemetry/{models,registry}.py` | second DSM registry (`TelemetryDSMRegistry`, `:14-39`) |
| `detection_content/telemetry/sysmon_dsm.py` | **POST-AG-EMERGENT** (`869f7336`) — neither PRE-AG nor AG |

**AG tripled DSM coverage (1 → 4). This is AG's second-largest genuine contribution after Security State.**

## 3 · Current state (live) — the hard break in the architecture

### 3.1 · DSM inventory: 5 DSMs

| DSM | Domain | Origin |
|---|---|---|
`snort-eve` | network IDS | **PRE-AG** |
`windows_security` | endpoint/host | **AG** |
`linux_auditd` | endpoint/host | **AG** |
`aws_cloudtrail` | cloud | **AG** |
`sysmon` | endpoint/host | **POST-AG-EMERGENT** |

### 3.2 · Declared source kinds: 16 — configured: 0

`GET /api/xdr/data-sources` (live, authenticated):
```json
{"ok":true,"data":{"data_sources":[],"count":0,
 "kinds":["aws_cloudtrail","azure_activity","cef_syslog","edr_stream","file_ingest",
          "gcp_audit_logs","generic_rest","generic_syslog","generic_webhook","kafka_topic",
          "leef_syslog","ndr_stream","office365_activity","otlp_logs","sysmon_wef",
          "windows_event_fwd"]}}
```
**16 kinds declared. `count: 0` configured.** 11 of the 16 kinds have **no DSM behind them at all**.

### 3.3 · Collector health: nothing has ever connected

`GET /api/xdr/collector/telemetry-health` (live):
```json
{"transports":[
  {"source_type":"rest","health":"never_connected","instances":0,"note":"no connector instance configured"},
  {"source_type":"webhook","health":"never_connected","instances":0,"note":"no connector instance configured"},
  {"source_type":"syslog","health":"never_connected","instances":0,"note":"no connector instance configured"}],
 "ingest":{"configured":false,"url_set":false,"token_set":false,"delivered":0,
           "failed_retryable":0,"failed_fatal":…}}
```

### 3.4 · What *is* flowing

| Store | Docs | Source |
|---|---|---|
`xdr_canonical_evidence` | **222** | golden/synthetic via `/api/v2/ingestion/golden/{id}` |
`xdr_canonical_events` | 280 | |
`xdr_collectors` | 110 | collector **definitions**, 0 running instances |
`xdr_data_sources` | 22 | historical/registry rows; live API reports 0 configured |
`xdr_integrations` | 6 | |
`xdr_cortex_ingest_audit` | 95 | Cortex vendor ingest attempts |
`xdr_cortex_scheduler_audit` | **38,326** | scheduler activity (highest-volume collection in the DB) |

| Dimension | Verdict |
|---|---|
| Implemented | ✅ collectors, adapters, DSMs, parsers, normalizers, vault |
| Registered | ✅ 33 collector paths + 9 Cortex paths + 7 ingest paths |
| Executed | ✅ on golden/synthetic data |
| Runtime-proven | 🔴 **zero live sources; all transports `never_connected`** |
| Production-ready | 🔴 |

## 4 · Industry benchmark

| Vendor | Data plane |
|---|---|
| **Cortex XDR** | **Cortex Native Data Lake** centralising endpoint/network/cloud/identity; ingestion via XDR Collectors (XDRC), Broker VM applets, API collectors, or the unified **Connector** framework (tenants onboarded after 2026-07-26); data-digestion layer performs **log stitching** into a unified session story |
| **Microsoft Defender XDR** | Native first-party telemetry (endpoint/identity/email/cloud apps) + Sentinel workspace connection to expand hunting datasets and enable external disruptions (AWS, Okta); **30 days raw retention** |
| **Trellix** | **1,000+ integrations** via Cloud Connect (SaaS webhooks/APIs) and CommBrokers (on-prem message brokers) |
| **CrowdStrike** | Falcon sensor telemetry + LogScale + third-party via NG-SIEM |
| **SentinelOne** | Singularity Data Lake, OCSF-normalised, native + third-party |
| **Cisco XDR** | Endpoint, network, firewall, email, identity, DNS across integrated products |
| **Splunk** | Universal ingest — the strongest raw-ingest story of the set |

## 5 · Gap — the P0 of the whole audit

| Gap | Severity | Evidence |
|---|---|---|
| **Zero connected telemetry sources** | **P0** | `count: 0`; all transports `never_connected`. The entire 3→12 pipeline runs on synthetic data only |
| **Two DSM registries — and the AG "unified" one is dead in production** | **P0** | **REFINED 2026-09-05** (`../NIVXRAY_XDR_P0_2_DSM_REGISTRY_OWNERSHIP_CONFLICT_MAP.md`). Production uses `DSM_REGISTRY` only (`xdr_pipeline.py:74`, consumed at `:237` and `routers/content_supply_chain.py:907`). `TELEMETRY_DSM_REGISTRY` (`telemetry/registry.py:39`) has **zero production consumers**, **omits `SysmonDSM`** (`registry.py:16-20`), and its `register_dsm()` (`:22-24`) is **never called anywhere**. Load failures are swallowed at `xdr_pipeline.py:57-58` and `:62-63` — and one shared `try` covers all three AG DSMs, so **one broken file disables three DSMs silently**. `resolve()` semantics are **asymmetric**: production (`:66-67`) does not guard `supports()` while the test-path registry (`:28-32`) does — tests are more forgiving than production. Master DEV-2 + **DEV-9** |
| 11 of 16 declared source kinds have no DSM | **P1** | `azure_activity`, `gcp_audit_logs`, `office365_activity`, `edr_stream`, `ndr_stream`, `kafka_topic`, `otlp_logs`, `cef_syslog`, `leef_syslog`, `generic_*` |
| No log stitching / session assembly at ingest | P1 | Cortex's differentiator; NivXRay correlates per-event post-canonical (CAT-06) |
| No retention plane | **P1** | `sdl` tab disabled at `XdrShell.jsx:195`; blocks CAT-09 and CAT-05 backtesting |
| Integration count | P2 | 6 `xdr_integrations` + 5 vendor adapters vs Trellix's 1,000+. **Breadth is a go-to-market problem, not an architectural one** — the adapter framework already exists |

**Recommended P0 action (unchanged from master §I):** unify the DSM registry and **fail loud**, then connect exactly **one** real source end-to-end. That single change converts the pipeline from "synthetic-proven" to "production-proven" and unblocks CAT-06 cross-domain correlation, CAT-09 hunting, CAT-13 EDR and CAT-07 UBAE — none of which can honestly proceed first.

## 6 · Honest positive

Every surface in this category **reports its own emptiness accurately**: `count: 0`, `never_connected`, `no connector instance configured`, `configured: false`, `url_set: false`, `token_set: false`. There is no fabricated health, no simulated throughput. This is the Honest-State contract working exactly as intended on the product's weakest plane.

## 7 · UNKNOWN

- U-12.1 — Why `xdr_data_sources` holds 22 docs while the live API reports 0 configured. Schema/filter mismatch vs stale rows — **not determinable read-only**.
- U-12.2 — Whether the 110 `xdr_collectors` definitions are valid or historical test rows.
- U-12.3 — What is generating 38,326 `xdr_cortex_scheduler_audit` records against 95 ingest audits. Scheduler activity without ingest yield; requires execution to explain.
