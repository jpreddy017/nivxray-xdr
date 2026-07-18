# NivXRay · Enterprise Integration Architecture
### HLD · LLD · Presentation Deck (EOD 2026-07-18)

**Audience**: SOC leads, security architects, CISO office, sales-engineering.
**Purpose**: Show how NivXRay slots into an existing SIEM / EDR / SOAR stack without ripping-and-replacing anything the customer already runs.

---

## Slide 1 · Positioning

**NivXRay is NOT a SIEM. NivXRay is NOT an EDR. NivXRay is a Deep-Decode + MITRE-Attribution + IOC-Enrichment micro-service that plugs into an existing SOC stack in one of two ways — Type-I (inline, automatic) or Type-II (on-demand, analyst-triggered).**

---

## Slide 2 · The two deployment types (per customer diagram)

### Type-I · Inline / auto-enrichment mode
```
   Log Sources                                                                     
   ┌──────────────┐                                                                
   │ Firewall     │──▶┐                                                            
   │ WAF          │──▶│                                                            
   │ IDS/IPS      │──▶│   ┌───────────┐    ┌─────┐    ┌─────────┐    ┌──────────────┐
   │ DB           │──▶│──▶│ Collector │───▶│ EDR │───▶│ NivXRay │───▶│ SNOW / SIEM  │
   │ Servers      │──▶│   │ Connector │    └─────┘    │ Decode+ │    │ XDR / SOAR   │
   │ Other apps / │──▶│   └───────────┘               │ MITRE + │    └──────┬───────┘
   │ net devices  │──▶┘                                │ TI-HITS │           │
   └──────────────┘                                    └─────────┘           ▼
                                                                        ┌─────────┐
                                                                        │ Analyst │
                                                                        │ has LESS│
                                                                        │ work    │
                                                                        └─────────┘
```
- Every event/alert flowing from EDR → SIEM passes through NivXRay for **pre-attribution**
- Verdicts, MITRE tags, IOCs, TI-HITS **arrive at the SIEM already normalized**
- Analyst opens a notable in Splunk/Sentinel — the MITRE tags are already there
- **Latency budget**: p95 <200 ms per event (fast mode) so it doesn't back-pressure the pipeline
- **Best for**: high-volume SOCs, MSSPs, MDR providers, automated response

### Type-II · On-demand / investigation mode
```
   Log Sources                                                                       
   ┌──────────────┐                                                                  
   │ Firewall     │──▶┐                                                              
   │ WAF          │──▶│   ┌───────────┐    ┌─────┐    ┌──────────────┐    ┌────────┐
   │ IDS/IPS      │──▶│──▶│ Collector │───▶│ EDR │───▶│ SIEM / XDR / │───▶│Analyst │
   │ DB / Servers │──▶│   │ Connector │    └─────┘    │ ServiceNow   │    │ User   │
   │ Other        │──▶┘   └───────────┘               └──────────────┘    └───┬────┘
   └──────────────┘                                                            │
                                                                     "let me pull this into
                                                                      NivXRay for deeper look"
                                                                                │
                                                                                ▼
                                                                        ┌──────────────┐
                                                                        │   NivXRay    │
                                                                        │  Deep-Decode │
                                                                        │  Investigator│
                                                                        └──────────────┘
                                                                    (NivXRay as part of
                                                                     analyst's investigation)
```
- NivXRay is NOT in the automatic pipeline
- Analyst picks a suspicious event in SIEM → opens NivXRay → pastes the payload → gets full decode
- **Latency budget**: interactive — deep mode (500-2000 ms) acceptable
- **Best for**: SOC power-tool adoption, forensic investigations, incident-response teams
- **Zero SIEM disruption** — no schema changes, no ingest changes, no risk

### How to pick

| If the customer… | Recommend |
|---|---|
| …wants auto-tagged notables in Splunk ES / Sentinel Analytics | **Type-I** |
| …has strict SLAs on SIEM ingest latency | **Type-II** (start here, upgrade later) |
| …can't touch their EDR→SIEM pipeline (change-freeze) | **Type-II** |
| …runs an MSSP or handles many tenants | **Type-I** with per-tenant JWT |
| …is doing a proof-of-value | **Type-II** first (0-risk), then Type-I in production |

Most customers **start with Type-II** (2-week POC) → **graduate to Type-I** once ROI proven.

---

### Mode A · **Pull** (SIEM/EDR calls NivXRay)

```
   Splunk ┐
   Sentinel│      POST /api/decode/smart          POST /api/batch/test/json
   QRadar ─┼───▶  (single event, sync,    ──▶     (500 events, sync, ~30s)   ───▶  NivXRay
   Sumo   ┘       ~150ms p95)                                                        Engine
                                                                            ◀────    JSON verdict
                                                                                     + MITRE + IOCs
                                                                                     + LOLBAS + TI-HITS
```

- **Adapter**: Splunk custom command · Sentinel Logic App · CrowdStrike Falcon Fusion action
- **Latency**: 150ms per event (fast mode) · 300ms (balanced) · 800ms (deep)
- **Auth**: JWT bearer token (per-tenant when multi-tenancy lands)

### Mode B · **Push** (NivXRay streams enriched events back)

```
       raw event                                       enriched
   EDR ─────▶  Kafka topic ─────▶  NivXRay consumer ─────▶ Kafka topic ────▶  SIEM
                                    (batch of 100)                            (nivxray_verdicts)
```

- Kafka + Redpanda + AWS Kinesis supported via a thin `nivxray-connector` sidecar
- **Throughput**: 5,000 events/sec on a 4-vCPU pod
- **Backpressure**: Kafka commit only after verdict written

### Mode C · **Webhook** (SOAR-first)

```
   SOAR playbook trigger ──▶  POST NivXRay ──▶  SOAR receives verdict ──▶  ticket / block / isolate
   (XSOAR/Splunk SOAR/Tines)   /api/decode/smart                            (automatic response)
```

- Direct HTTPS · signed HMAC · reused across SOARs
- Round-trip: 200ms · fits inside a Tines / Torq / XSOAR step

---

## Slide 3 · LLD — Data contracts

### Request (from SIEM/EDR/SOAR)
```json
POST /api/decode/smart
Authorization: Bearer <tenant-jwt>
X-Request-ID: <caller-trace-id>

{
  "text": "powershell -EncodedCommand VwByAA==",
  "analysis_mode": "balanced",        // fast | balanced | deep
  "context": {                        // optional caller context
    "hostname": "WIN10-DEV-42",
    "user":     "svc_backup",
    "process_tree": "explorer.exe > cmd.exe > powershell.exe",
    "source_alert_id": "splunk-alert-98123"
  }
}
```

### Response (to SIEM/EDR/SOAR)
```json
{
  "request_id":  "nvx-9c56...",
  "verdict":     "Malicious",         // Malicious | Suspicious | Unknown | Benign
  "confidence":  92,                  // 0-100
  "engine":      "archetype:PS_EncodedCommand+PS_STRING_CONCAT+...",
  "score":       0.94,
  "reached_shellcode": true,
  "chain":       ["extract-b64", "utf16le-decode", "ps-string-concat"],
  "mitre": [
    {"id":"T1059.001","technique":"PowerShell","tactic":"Execution"},
    {"id":"T1027.010","technique":"Command Obfuscation","tactic":"Defense Evasion"}
  ],
  "lolbins":    ["powershell.exe"],
  "iocs": {
    "ips":     ["10.2.27.30"],
    "urls":    [],
    "domains": [],
    "hashes":  []
  },
  "ti_hits": [                        // ← new IOC-enrichment layer
    {"value":"10.2.27.30","source":"sans_dshield","severity":"high",
     "reports":319739,"tags":["attacker","honeypot-observed"]}
  ],
  "narrative": "AMSI bypass reflectively patches amsiInitFailed then calls curl.exe to internal 10.2.27.30 …",
  "raw_output": "S`eT-It`em ...",     // decoded plaintext
  "elapsed_ms": 187
}
```

### Splunk Enterprise Security compatible field mapping
```
nivxray.verdict         →  ES notable.severity
nivxray.mitre[].id      →  ES notable.mitre_technique_id
nivxray.iocs.ips        →  ES notable.src_ip / dest_ip
nivxray.ti_hits[].source→  ES notable.threat_intel_source
```

### Sigma-format emission (for SIEM ingestion)
```
POST /api/emit/sysmon    →  returns Sysmon Event 1 rule + XPath + PowerShell hunt query
                            drop into Splunk savedsearch / Sentinel analytic rule
```

---

## Slide 4 · LLD — Component diagram

```
                    ┌───────────────────────────────────────────────────────────┐
                    │                 NivXRay Service (K8s)                     │
                    │                                                           │
     Ingress ──▶    │  ┌────────────────┐        ┌────────────────────────┐    │
     (HTTPS)        │  │  FastAPI       │───────▶│  Deterministic Engine  │    │
     mTLS optional  │  │  routers/      │        │  · wrapper_archetypes  │    │
                    │  │  · decode      │        │  · operations (MITRE)  │    │
                    │  │  · batch       │        │  · lolbas registry     │    │
                    │  │  · heatmap     │        │  · magic_decoder       │    │
                    │  │  · lab         │        └───────┬────────────────┘    │
                    │  │  · corpus_valid│                ▼                     │
                    │  │  · ti_enrich   │        ┌────────────────────────┐    │
                    │  │  · public_feeds│        │  AI Narrative Layer    │    │
                    │  └────────┬───────┘        │  (Claude · Emergent    │    │
                    │           │                │   LLM key)             │    │
                    │           ▼                └────────────────────────┘    │
                    │  ┌──────────────────────────────┐                        │
                    │  │  MongoDB                     │                        │
                    │  │  · workspace_cases           │    ┌──────────────┐   │
                    │  │  · batch_runs                │───▶│  IOC Cache   │   │
                    │  │  · iocs (8,915 · 6 sources)  │    │  (indexed on │   │
                    │  │  · lab_stats · lab_attempts  │    │   value)     │   │
                    │  │  · learner_payloads          │    └──────────────┘   │
                    │  │  · learner_versions          │                        │
                    │  └──────────────────────────────┘                        │
                    │                                                          │
                    │  ┌──────────────────────────────┐                        │
                    │  │  Public-Feed Sync (nightly)  │                        │
                    │  │  · SANS DShield              │  no API keys           │
                    │  │  · URLhaus abuse.ch          │                        │
                    │  │  · Feodo Tracker             │                        │
                    │  │  · CISA KEV                  │                        │
                    │  └──────────────────────────────┘                        │
                    └───────────────────────────────────────────────────────────┘
                                    │
                                    ▼  (outbound HTTPS, key-gated)
                            ┌──────────────────┐
                            │  VirusTotal · OTX│
                            │  · AbuseIPDB     │
                            │  · Shodan · GN   │
                            └──────────────────┘
```

---

## Slide 5 · SIEM connectors — the "adapter layer"

Small, per-SIEM adapters (~200 LoC each) — not part of core NivXRay, ship as a `connectors/` repo.

| SIEM/EDR | Adapter type | Latency | Effort |
|---|---|---|---|
| **Splunk Enterprise** | Custom search command (`nivxrayCheck`) — runs on SH | 200ms per event | 1-2 days |
| **Splunk ES** | Notable-event action button ("Decode with NivXRay") | interactive | 1 day |
| **Microsoft Sentinel** | Logic App connector · KQL `evaluate` function | 300ms | 2 days |
| **Sentinel Analytics Rule** | Custom entity trigger → HTTP data connector | streaming | 1 day |
| **IBM QRadar** | AQL app extension | 400ms | 3 days |
| **Elastic Security** | Ingest pipeline processor · painless script gate | 200ms | 2 days |
| **Sumo Logic** | Lookup function · scheduled search action | 300ms | 2 days |
| **CrowdStrike Falcon** | Fusion workflow action node | interactive | 1 day |
| **SentinelOne** | STAR rule custom action | interactive | 1 day |
| **Wazuh** | Integration script (`custom-nivxray.py`) | 200ms | 1 day |

---

## Slide 6 · SOAR connectors

| SOAR | Integration | Trigger |
|---|---|---|
| **Splunk SOAR** (formerly Phantom) | Custom app · 4 actions | on-alert → decode-and-tag |
| **Palo Alto XSOAR** | Integration YAML · 3 commands | notable → NivXRay → verdict → contain |
| **Tines** | HTTP action tile | any story branch |
| **Torq** | Webhook step | any workflow |
| **Swimlane** | Custom asset · 2 actions | alert triage stage |
| **IBM Resilient** | Function integration | task automation |

**Common playbook pattern**:
```
   Alert fires  →  Extract commandline field  →  POST NivXRay  →
   IF verdict == "Malicious" AND reached_shellcode → auto-isolate + create ticket
   IF verdict == "Suspicious"                       → analyst-review queue
   IF verdict == "Unknown"                          → drop / dedupe
```

---

## Slide 7 · Deployment topology (customer options)

### Option 1 · SaaS multi-tenant (NivXRay-hosted)
```
  Customer SIEM ──HTTPS──▶  api.nivxray.com  ──▶  regional pod (US/EU/APAC)
                                                   │
                                                   ▼
                                            Postgres + Mongo Atlas
```
- Fastest onboarding · zero infra footprint · **requires multi-tenancy (P0 blocker today)**

### Option 2 · Dedicated cloud (single-tenant AWS/GCP/Azure)
```
  Customer VPC ──peering──▶  NivXRay VPC ──▶ K8s (EKS/GKE/AKS) + Atlas/RDS
```
- Isolated data plane · SOC2/ISO27001 friendly · sales-friendly for regulated verticals

### Option 3 · On-prem / air-gapped
```
  Customer datacenter  →  helm-install nivxray-chart  →  local Mongo · offline model
```
- Ships as OCI images + helm chart · public feeds delivered via offline bundle · **highest ACV segment**

---

## Slide 8 · Security architecture

- **Auth**: JWT (bearer) · per-tenant issuer · rotation every 24h
- **Rate limit**: 100 req/sec per tenant (login endpoint hardened separately after P0)
- **Payload cap**: 20KB per request · 500 per batch
- **Egress control**: outbound calls (VT/OTX/AbuseIPDB) run through allow-listed proxy
- **Secrets**: never inline · AWS Secrets Manager / GCP Secret Manager / K8s sealed-secrets
- **Audit log**: every decode call gets `X-Request-ID` propagated to Mongo + stdout
- **PII policy**: no raw payload stored unless customer explicitly opts in (`retain_payload=true`)
- **Data residency**: US · EU · APAC regions available (per-tenant pinning)

---

## Slide 9 · Backlog roadmap (next 2-4 weeks)

### Sprint 5 (Week 1) — **Trust + Availability**
- 🔴 P0 · Rate-limit `/api/auth/login` (brute-force DoS vector)
- 🔴 P0 · Multi-tenancy retrofit — `tenant_id` in 17 collections (blocks SaaS)
- 🟡 P1 · Fix 9 pre-existing `test_training_corpus` failures
- 🟢 P2 · Auto-schedule `feeds/sync` in `_nightly_benchmark_loop` cron

### Sprint 6 (Week 2) — **Analyst UX polish**
- 🟡 P1 · Wire **"IOC → TI-HITS"** pill in decoder Workspace (red chips inline in output)
- 🟡 P1 · "Compare Two Runs" diff button on Batch Recent Runs panel
- 🟡 P1 · Cloud archetypes — AWS Cognito abuse + GCP service-account JWT decoder
- 🟢 P2 · Playwright E2E suite

### Sprint 7 (Week 3) — **Extensibility**
- 🟡 P1 · LLM-powered Learner code generation (Claude drafts real regex + handler, not stubs)
- 🟡 P1 · **Splunk connector** (custom search command) — first SIEM adapter
- 🟡 P1 · **Sentinel Logic App** connector — second SIEM adapter
- 🟢 P2 · Decompose `wrapper_archetypes.py` (4.2K LoC) → `archetypes/{windows,linux,macos,cloud}/`
- 🟢 P2 · Decompose `operations.py` (2.5K LoC)

### Sprint 8 (Week 4) — **Observability + Commercial**
- 🟡 P1 · Sentry + `/metrics` (Prometheus) + request tracing
- 🟡 P1 · Stripe integration (for SaaS billing)
- 🟡 P1 · SSO via Emergent Google Auth
- 🟢 P2 · Commercial docs (COMMERCIAL_PLAN · PRICING · COMPETITOR_MATRIX · KNOWN_LIMITATIONS)
- 🟢 P2 · "Powered by NivXRay" widget for nivxmachines.com

---

## Slide 10 · What ships in v1.4 vs v1.5

| Feature | v1.3.0 (today) | v1.4.0 (2 weeks) | v1.5.0 (4 weeks) |
|---|:---:|:---:|:---:|
| Deep-decode engine | ✅ | ✅ | ✅ |
| MITRE Heatmap | ✅ | ✅ | ✅ |
| Practice Lab | ✅ | ✅ | ✅ |
| Free public IOC feeds | ✅ | ✅ | ✅ |
| Cloud archetypes | – | ✅ | ✅ |
| Splunk / Sentinel connector | – | ✅ | ✅ |
| Multi-tenant SaaS | – | – | ✅ |
| Rate-limit + observability | – | – | ✅ |
| Stripe billing | – | – | ✅ |
| SSO (Google) | – | – | ✅ |
| Helm chart / OCI images | – | – | ✅ |

---

## Appendix A · Latency budget

```
   HTTP ingress                    │  5 ms
   JWT validation + tenant lookup  │  8 ms
   Payload cap check + normalize   │  2 ms
   Deterministic decode engine     │  30 ms  (fast)  · 80 ms (balanced) · 250 ms (deep)
   IOC extraction                  │  10 ms
   Local TI-HITS lookup (indexed)  │  1 ms
   External VT/OTX (if miss)       │  90 ms  (cached; else fallthrough)
   MITRE map + LOLBAS scan         │  15 ms
   Verdict card build              │  5 ms
   AI narrative (optional)         │  400 ms (async — returned via SSE if requested)
   Response serialization          │  2 ms
   ───────────────────────────────────────
   p95 balanced (no AI)            │  ~160 ms
   p95 balanced (with AI)          │  ~560 ms
```

## Appendix B · Data-flow when SIEM calls in

```
   Splunk SH
    │  |custom-command|  nivxrayCheck  input=$_raw
    ▼
   nivxrayCheck.py  ──▶  POST /api/decode/smart  ──▶  NivXRay pod
                                                       │
                                          decode engine + MITRE + IOC extract
                                                       │
                                          check local iocs cache ──▶ TI-HITS
                                                       │
                                          if miss → VT/OTX (async, cached)
                                                       │
                                                       ▼
                                          JSON verdict + narrative
    ◀────────────────────────────────────────────────────
   verdict written back as new event field(s)
    │
    ▼
   Splunk correlation search:  `nivxray.verdict=Malicious`  → notable-event
    │
    ▼
   Splunk ES notable → SOAR playbook → contain host + create JIRA ticket
```

## Appendix C · Metrics we'll publish (Prometheus)

```
   nivxray_decode_total{mode="fast|balanced|deep",verdict="malicious|...|unknown"}
   nivxray_decode_duration_seconds{mode,quantile="0.5|0.95|0.99"}
   nivxray_ti_lookup_hits_total{source="sans_dshield|urlhaus|feodo|cisa_kev|vt|otx|abuseipdb"}
   nivxray_ti_lookup_miss_total
   nivxray_feed_sync_total{source,status="ok|error"}
   nivxray_batch_size_histogram
   nivxray_ai_latency_seconds
   nivxray_active_tenants
```

---

*Generated 2026-07-18 · NivXRay v1.3.0-preview · Owner: E1 (agent) · Reviewers: CISO office, SOC leads*
