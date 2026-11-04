# NivXRay · Capabilities Document — Skeleton

**Version:** 1.0 (Skeleton) · Feb 2026
**Use:** Fill in ● sections during customer conversations. Skeleton = structure only, not prose.

---

## 0 · PRODUCT NAME (Decide first)

- [ ] **PayloadLens** ← recommended
- [ ] **Cognis**
- [ ] **NivXRay** (keep current)
- [ ] **CommandLens**
- [ ] **StackPeel**
- [ ] **DecoderOne**
- [ ] Other: __________

**Tagline:** _"________________________________"_

---

## 1 · ONE-LINER

> _<Product> is a __________ that plugs into __________ and delivers __________._

---

## 2 · PROBLEM WE SOLVE

| # | Pain | Cost to SOC |
|---|------|-------------|
| 1 | Obfuscated commandlines in EDR alerts | ● 20–40 min/analyst/alert |
| 2 | Manual CyberChef chains | ● Error-prone, unauditable |
| 3 | Missed IOCs stuck in obfuscation | ● 15–30% IOC loss |
| 4 | SIEM correlations on raw blobs | ● Rules never fire |
| 5 | Analyst burnout on grunt-decode work | ● Turnover |

---

## 3 · CAPABILITIES (What the tool does)

### 3.1 Decode
- [ ] Base encodings (Base64/32/58/91/Ascii85)
- [ ] Compression (gzip, zlib, brotli, lzma, zstd, snappy, bzip2, LZ4)
- [ ] Character encodings (UTF-16LE/BE, URL, hex)
- [ ] Classic ciphers (ROT13/47, Caesar, XOR 1–8 byte)
- [ ] PowerShell reconstruction
- [ ] CMD reconstruction (`%VAR%`, `!DELAYED!`, caret escape)
- [ ] JS reconstruction (`fromCharCode`, `atob`, `unescape`)
- [ ] VBS reconstruction (`Chr()`, `CreateObject`)

### 3.2 Extract
- [ ] IOCs (URLs, IPs, domains, hashes, UA, mutex)
- [ ] LOLBAS binaries (200+)
- [ ] MITRE ATT&CK techniques + sub-techniques
- [ ] Malware family attribution

### 3.3 Enrich (Optional)
- [ ] VirusTotal
- [ ] AbuseIPDB
- [ ] URLScan
- [ ] Shodan
- [ ] AlienVault OTX
- [ ] Hybrid Analysis
- [ ] abuse.ch
- [ ] IP-API geolocation

### 3.4 Deliver
- [ ] SOC verdict card
- [ ] Investigation summary (plain text)
- [ ] STIX 2.1 bundle
- [ ] CSV IOC export
- [ ] JSON payload for APIs
- [ ] Kill-chain graph (PNG/SVG)

---

## 4 · HLD (High-Level Design)

### 4.1 Layer Diagram
```
┌─ UI (React) ─────────────────────────────┐
├─ API Gateway (FastAPI · JWT · CORS) ─────┤
├─ Engine (Orchestrator + 34 plugins) ─────┤
├─ Enrichment (OSINT fan-out) ─────────────┤
├─ Integration adapters (EDR/SIEM/ITSM) ───┤
└─ Storage (MongoDB · Redis) ──────────────┘
```

### 4.2 Data Flow
```
EDR alert → Ingester → Orchestrator → Decoders → Extractors →
Enrichers → Verdict engine → { SIEM · ITSM · SOAR · UI }
```

### 4.3 Deployment Modes
- [ ] **SaaS** — Emergent-hosted
- [ ] **Self-hosted** — Kubernetes / Docker Compose
- [ ] **Airgap** — Zero outbound calls (feature flag `NVX_AIRGAP=true`)
- [ ] **Hybrid** — Self-hosted engine + SaaS TI feeds

---

## 5 · LLD (Low-Level Design)

### 5.1 API Contract (public)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v2/analyze` | POST | Full auto-investigate |
| `/api/decode/smart` | POST | Fast recursive decode |
| `/api/decode/chain` | POST | Manual recipe |
| `/api/v2/analyze/report?fmt=stix` | GET | STIX 2.1 bundle |
| `/api/cases` | GET/POST | Case CRUD |
| `/api/batch/run` | POST | Batch execution |

### 5.2 Request Schema
```json
{
  "input": "<obfuscated commandline>",
  "context": {
    "edr_source": "...",
    "host": "...",
    "user": "...",
    "detection_id": "...",
    "severity": "..."
  },
  "options": {
    "enable_osint": true,
    "enable_ai": false,
    "max_depth": 10,
    "wall_time_ms": 8000
  }
}
```

### 5.3 Response Schema
```json
{
  "verdict":            { "level": "...", "score": 0-100, "family": "...", "one_liner": "..." },
  "recovered_payload":  "<clean decoded command>",
  "trace":              [ { "decoder": "...", "confidence": 0-1, "preview": "..." } ],
  "iocs":               { "urls": [], "ips": [], "domains": [], "hashes": [], "user_agents": [] },
  "mitre":              [ { "id": "...", "tactic": "...", "evidence": "..." } ],
  "lolbas":             [ { "binary": "...", "context": "..." } ],
  "osint":              { "virustotal": {}, "abuseipdb": {}, "shodan": {} },
  "case_id":            "...",
  "processing_ms":      0
}
```

### 5.4 Decoder Plugin Interface
```python
class BaseDecoder:
    id: str
    name: str
    category: str
    cost: int

    def detect(payload, fp, ctx) -> DetectResult
    def decode(payload, args, ctx) -> PluginResult
```

### 5.5 Sizing (100k alerts/day)
- API pods: 5 × (1 CPU / 2 GB)
- Worker pods: 3 × (2 CPU / 4 GB)
- MongoDB: 3-node RS × (4 CPU / 16 GB / 500 GB SSD)
- Redis: 3-node cluster × (1 CPU / 4 GB)
- **Total:** ~30 vCPU · ~80 GB RAM · ~1.5 TB storage

### 5.6 SLA Targets
- p50 < 500 ms
- p95 < 2 s
- p99 < 8 s
- 99.9% availability

---

## 6 · EDR INTEGRATION MATRIX

| EDR | Ingestion Method | Endpoint | Effort |
|-----|------------------|----------|--------|
| CrowdStrike Falcon | Streaming API webhook | `/api/edr/crowdstrike/webhook` | Low · 1 day |
| SentinelOne | Deep Visibility API poll | `/api/edr/sentinelone/pull` | Low · 1 day |
| Microsoft Defender for Endpoint | Advanced Hunting → Logic App | `/api/edr/defender/webhook` | Medium · 2–3 days |
| Carbon Black Cloud | CBC notification webhook | `/api/edr/carbonblack/webhook` | Low · 1 day |
| Elastic Defend | Detection rule webhook connector | `/api/edr/elastic/webhook` | Low · 1 day |
| Trend Vision One | Workbench API poll | `/api/edr/trendmicro/pull` | Medium · 2–3 days |
| Cybereason | Malop API webhook | `/api/edr/cybereason/webhook` | Medium · 2–3 days |

---

## 7 · SIEM INTEGRATION MATRIX

| SIEM | Method | Format | Effort |
|------|--------|--------|--------|
| Splunk | HEC POST | JSON | Low · 1 day |
| Microsoft Sentinel | Log Analytics DCR | Custom log table | Medium · 2–3 days |
| IBM QRadar | Syslog TCP/UDP | LEEF | Medium · 2 days |
| Chronicle (Google SecOps) | UDM ingestion API | UDM JSON | Medium · 3 days |
| Elastic SIEM | Bulk index API | ECS JSON | Low · 1 day |
| Exabeam | Cloud Ingestion API | JSON | Medium · 2–3 days |
| Sumo Logic | HTTP source | JSON | Low · 1 day |

---

## 8 · ITSM INTEGRATION MATRIX

| Platform | Method | Ticket Type | Effort |
|----------|--------|-------------|--------|
| ServiceNow SIR | Table API POST | `sn_si_incident` | Medium · 2–3 days |
| ServiceNow ITSM | Table API POST | `incident` | Low · 1 day |
| Jira Service Management | REST API v3 | Issue | Low · 1 day |
| PagerDuty | Events API v2 | Alert | Low · 0.5 day |
| Opsgenie | Alert API | Alert | Low · 0.5 day |
| Zendesk | Tickets API | Ticket | Low · 1 day |
| Freshservice | REST API | Ticket | Low · 1 day |

---

## 9 · SOAR INTEGRATION MATRIX

| Platform | Method | Effort |
|----------|--------|--------|
| Splunk SOAR (Phantom) | Custom app w/ `analyze` action | High · 1–2 wks |
| Palo Alto Cortex XSOAR | Content pack + playbooks | High · 1–2 wks |
| Tines | HTTP action | Low · 0.5 day |
| Torq | HTTP step | Low · 0.5 day |
| Swimlane | Plugin | Medium · 3 days |

---

## 10 · SECURITY CONTROLS CHECKLIST

- [ ] JWT auth (short TTL + refresh)
- [ ] RBAC (admin · analyst · viewer)
- [ ] SAML / OIDC SSO
- [ ] Redis-backed rate limiting
- [ ] Input validation + payload size cap (1 MB default)
- [ ] Audit log on every decode + OSINT + emit
- [ ] TLS 1.2+ enforced ingress + inter-service
- [ ] MongoDB encryption at rest
- [ ] Secrets in K8s / Vault
- [ ] Airgap mode toggle
- [ ] IP allowlist / SSO enforcement per tenant

---

## 11 · COMPLIANCE TARGETS

| Standard | Status | Timeline |
|----------|--------|----------|
| SOC 2 Type II | Roadmap | Q3 2026 |
| ISO 27001 | Roadmap | Q4 2026 |
| FedRAMP Moderate | Airgap variant | Q2 2027 |
| CJIS | Airgap-compatible today | ✅ Now |
| HIPAA | Airgap-compatible today | ✅ Now |
| GDPR | Compliant (no PII processed) | ✅ Now |
| ITAR | Self-hosted only | ✅ Now |

---

## 12 · ROLLOUT PLAN (30 / 60 / 90)

### Days 0–30 · Pilot
- [ ] Deploy (SaaS or self-hosted)
- [ ] Connect 1 EDR (webhook)
- [ ] Manual STIX/CSV export to SIEM
- [ ] Baseline: measure current time-to-decode on 20 alerts
- [ ] **Success:** ≥90% chain-complete under 30 s

### Days 31–60 · SIEM
- [ ] Wire SIEM push (Splunk HEC / Sentinel / Chronicle)
- [ ] Enrich 3–5 existing correlation rules with decoded IOCs
- [ ] Build 3–5 new detections on MITRE mappings
- [ ] **Success:** SIEM rules firing on decoded IOCs

### Days 61–90 · ITSM + SOAR
- [ ] Wire ServiceNow SIR or Jira SM
- [ ] Wire SOAR playbook triggers
- [ ] Train SOC on UI for deep-dives
- [ ] **Success:** 80% of malware alerts auto-ticketed with pre-decoded evidence

---

## 13 · SUCCESS METRICS (KPIs)

| KPI | Before | Target After |
|-----|--------|---------------|
| Time-to-decode | 20–40 min | <30 s |
| Analyst hrs / 100 alerts | 50 hrs | <4 hrs |
| IOC recovery rate | 70–85% | >98% |
| MITRE mapping completeness | Partial/manual | Auto/full |
| Ticket enrichment | Manual summary | Pre-populated |
| Dwell-time reduction | Hours | Minutes |

---

## 14 · ROADMAP TIMELINE

| Phase | Scope | Target |
|-------|-------|--------|
| **RC2.9** | Workspace UX polish · RecoveredPayloadCard | Q1 2026 |
| **Phase D** | Family detectors (XWorm, RedLine, FormBook, NjRAT, Emotet) | Q1 2026 |
| **Phase E** | Sandbox detonation bridge (Triage, Hybrid Analysis, Cuckoo) | Q2 2026 |
| **Phase F** | Native EDR connectors | Q2 2026 |
| **Phase G** | Native SIEM/SOAR packs | Q3 2026 |
| **Phase H** | ServiceNow certified store app | Q3 2026 |
| **Cert** | SOC 2 Type II | Q3 2026 |

---

## 15 · COMPETITIVE POSITIONING

| Alternative | Their Focus | Our Edge |
|-------------|-------------|----------|
| CyberChef | Manual toolkit | Automated, verdict, MITRE |
| VirusTotal | Hash lookup | Decodes obfuscation first |
| Any.Run / Hybrid Analysis | Dynamic sandbox | Static complement — not overlap |
| PowerDecode | PS-only | + CMD + JS + VBS |
| AI-based decoders | LLM prompts | Deterministic, auditable, offline |

---

## 16 · COMMERCIAL TIERS

| Tier | Users | Alerts/mo | Deployment | Price |
|------|-------|-----------|------------|-------|
| Community | 1 | 100 | SaaS | Free |
| Team | 5 | 2,000 | SaaS | $499 |
| Business | 25 | 20,000 | SaaS + API | $2,499 |
| Enterprise | ∞ | ∞ | SaaS or Self | Contact |
| Airgap Enterprise | ∞ | ∞ | Self only + SLA | Contact |

---

## 17 · OPEN QUESTIONS TO RESOLVE WITH BUYER

- [ ] Which EDR(s) do they use today?
- [ ] Which SIEM?
- [ ] Which ITSM?
- [ ] SOAR platform?
- [ ] SaaS or self-hosted preference?
- [ ] Airgap requirement?
- [ ] Compliance drivers (SOC 2 / FedRAMP / HIPAA)?
- [ ] Volume: alerts/day with obfuscated commandlines?
- [ ] Data residency requirements?
- [ ] Pilot timeframe?
- [ ] Success metric they'll evaluate on?

---

## 18 · APPENDIX

- **Companion doc:** `VISION_ENTERPRISE_INTEGRATION.md` — narrative version
- **Living blueprint:** `ARCHITECTURE.md` — implementation details
- **Roadmap tracker:** `ROADMAP.md` — sprint priorities
- **PRD:** `PRD.md` — product requirements

---

*This skeleton is intentionally lean. Fill in ● bracketed sections and check boxes during buyer meetings.*
