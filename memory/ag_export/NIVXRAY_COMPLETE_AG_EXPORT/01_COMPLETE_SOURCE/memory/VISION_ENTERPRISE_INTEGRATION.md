# NivXRay · Enterprise Integration Vision & Scope

**Version:** 1.0 · Feb 2026
**Audience:** SOC leadership, IR managers, Detection Engineering, CISO office
**Positioning:** Deterministic-first malware command-line intelligence platform that plugs into the existing SOC stack.

---

## 1. Executive Summary

NivXRay is a **deterministic malware command-line decoder & threat-analysis platform** that recursively unwraps obfuscated PowerShell / CMD / VBScript / JavaScript / shellcode payloads to extract analyst-ready intelligence — **IOCs, MITRE ATT&CK mapping, LOLBAS binaries, malware family attribution, and SOC verdicts** — without depending on AI or cloud LLMs.

The platform is designed to sit at the **triage layer** between EDR alert → SOC analyst → SIEM/ITSM ticket, dramatically reducing the time an analyst spends decoding obfuscated commandlines from **20-40 minutes down to <30 seconds**.

## 2. The Problem

Modern malware campaigns bury their true intent under **5-8 layers** of obfuscation:
```
CMD caret escape → PowerShell -EncodedCommand → UTF16LE base64 →
inner base64 → String reconstruction (join / [char] / format) →
IEX-of-variable indirection → final payload (BITS download / shellcode / IEX(iwr))
```

**Current SOC pain:**
- EDR (CrowdStrike / SentinelOne / Defender) fires an alert with the **raw obfuscated commandline**
- Analyst copies it, opens CyberChef, manually chains decoders, guesses at reconstruction rules
- **20-40 minutes per commandline** — bottleneck during incident storms
- Analyst fatigue → missed IOCs → delayed containment
- SIEM correlations rely on IOCs that never made it out of the obfuscated blob

## 3. NivXRay's Answer

**One paste → full deterministic decode → analyst-ready verdict.**

The engine's 34+ decoder plugins auto-detect the encoding stack, peel layer by layer, and emit:
- **Recovered payload** (the true executable command)
- **IOCs** (URLs, IPs, domains, hashes, User-Agents)
- **LOLBAS** binaries (certutil, bitsadmin, mshta, rundll32…)
- **MITRE ATT&CK** techniques with evidence
- **Malware family** attribution (Cobalt Strike, Meterpreter, XWorm, RedLine…)
- **SOC verdict** with confidence score
- **OSINT enrichment** (VirusTotal, AbuseIPDB, URLScan, Shodan, AlienVault OTX)

**Chain-completeness: 96.8% on the RC2.8 benchmark. Zero false-positive IOCs.**

---

## 4. Enterprise Integration Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         ENTERPRISE SOC STACK                        │
└────────────────────────────────────────────────────────────────────┘

  ┌─────────────┐        ┌──────────────┐        ┌─────────────────┐
  │  EDR         │───────▶│   NivXRay     │───────▶│  SIEM /          │
  │  Alert       │  Raw   │   Decoder     │ Decoded │  ServiceNow      │
  │  (raw cmd)   │  cmd   │   + Verdict   │ IOCs   │  Ticket          │
  └─────────────┘        └──────────────┘        └─────────────────┘
    CrowdStrike             API-first                Splunk / Sentinel
    SentinelOne             Airgap-capable            QRadar / Chronicle
    Defender for            Deterministic             ServiceNow ITSM
    Endpoint                No LLM required           Jira · PagerDuty
    Carbon Black
```

---

## 5. Integration Patterns

### 5.1 EDR → NivXRay (Ingestion)

**Purpose:** Auto-triage every EDR alert that contains a suspicious commandline.

**Supported ingestion modes:**

| EDR | Method | Effort |
|-----|--------|--------|
| **CrowdStrike Falcon** | Falcon Streaming API webhook → NivXRay `/api/v2/analyze` | Low |
| **SentinelOne** | SentinelOne Deep Visibility API poll → batch submit | Low |
| **Microsoft Defender for Endpoint** | Advanced Hunting KQL → Logic App → NivXRay | Medium |
| **Carbon Black Cloud** | CBC API notification → webhook to NivXRay | Low |
| **Elastic Defend** | Elastic detection rule → webhook connector | Low |
| **Trend Vision One** | Workbench Insight API → scheduled poll | Medium |

**NivXRay endpoint:**
```
POST /api/v2/analyze
Content-Type: application/json
Authorization: Bearer <api-token>

{
  "input": "<raw obfuscated commandline from EDR alert>",
  "context": {
    "edr_source": "crowdstrike",
    "host": "WKSTN-042",
    "user": "j.doe",
    "detection_id": "ldt:abc123",
    "severity": "high"
  }
}
```

**Response:** analyst-ready JSON with decoded payload, IOCs, MITRE, verdict.

### 5.2 NivXRay → SIEM (Enrichment)

**Purpose:** Push decoded IOCs and MITRE mappings back to the SIEM so correlation rules can fire on the *real* IOCs, not the obfuscated blob.

**Supported SIEMs:**

| SIEM | Method | Payload |
|------|--------|---------|
| **Splunk** | HEC (HTTP Event Collector) POST | JSON event with decoded IOCs + verdict |
| **Microsoft Sentinel** | Log Analytics Data Collector API | Custom log table `NivXRay_CL` |
| **IBM QRadar** | LEEF-formatted syslog via TCP/UDP | Standard LEEF event |
| **Chronicle (Google SecOps)** | UDM ingestion API | Unified Data Model event |
| **Elastic SIEM** | Bulk index API to `nivxray-*` index | ECS-compliant JSON |
| **Exabeam** | Cloud Ingestion API | JSON |

**STIX 2.1 export** is already available via `GET /api/v2/analyze/report?fmt=stix` for platforms that consume threat intel bundles (MISP, OpenCTI, ThreatConnect).

### 5.3 NivXRay → ITSM / Ticketing (Case Management)

**Purpose:** When NivXRay verdict = MALICIOUS, auto-create a fully-enriched incident ticket with the recovered payload pre-populated as evidence.

**Supported ITSM platforms:**

| Platform | Method | Ticket Fields |
|----------|--------|----------------|
| **ServiceNow SIR** (Security Incident Response) | Table API POST to `sn_si_incident` | Short description = family + verdict · IOCs → observables table · MITRE → mapped ATT&CK field |
| **ServiceNow ITSM** (standard incident) | Table API POST to `incident` | Configurable field mapping |
| **Jira Service Management** | REST API v3 issue create | Custom fields for IOCs, MITRE, verdict |
| **PagerDuty** | Events API v2 trigger | Incident with custom payload |
| **Opsgenie** | Alert API | Priority mapped from verdict severity |
| **Zendesk** | Tickets API | Formatted markdown body |

**ServiceNow SIR example payload:**
```json
{
  "table": "sn_si_incident",
  "short_description": "[NivXRay] Cobalt Strike stager detected on WKSTN-042",
  "description": "<recovered payload + investigation summary>",
  "priority": "1",
  "category": "malware",
  "u_mitre_techniques": "T1059.001, T1027, T1105",
  "u_iocs": "[{...}, {...}]",
  "u_nivxray_verdict": "MALICIOUS · 98/100",
  "u_nivxray_case_id": "<link back to NivXRay case>"
}
```

### 5.4 NivXRay → SOAR (Automated Response)

**Purpose:** Trigger playbooks when NivXRay confirms malicious verdict.

**Supported SOAR platforms:**
- **Splunk SOAR (Phantom)** — custom app with `nivxray_analyze` action
- **Palo Alto Cortex XSOAR** — content pack + playbook triggers
- **Tines** — HTTP action + JSON parsing
- **Torq** — HTTP step + condition branches
- **Swimlane** — plugin

**Common automated actions after NivXRay verdict:**
1. Block extracted C2 IPs at the firewall (Palo Alto, Fortinet, Cisco)
2. Sinkhole extracted domains at the DNS layer (Cisco Umbrella, Infoblox)
3. Isolate the affected endpoint via EDR API
4. Hash-block the recovered dropper payload at EDR
5. Push YARA/Sigma rule stubs to detection-as-code repo
6. Notify SOC lead via Slack/Teams

---

## 6. Deployment Models

### 6.1 SaaS (nivxray.nivxforge.com)
- Fastest onboarding
- Emergent-hosted, auto-updated
- Suitable for small-to-mid SOCs and MSSPs

### 6.2 Self-Hosted (Kubernetes / Docker)
- Full airgap capability
- Deterministic engine works fully offline
- OSINT enrichment optional (can be turned off entirely)
- SOC 2 / ISO 27001 / FedRAMP compatibility path
- Suitable for regulated industries, government, defense

### 6.3 Hybrid
- Self-hosted engine for sensitive commandlines
- SaaS threat-intel enrichment layer
- Best of both worlds

---

## 7. Value Proposition (SOC Metrics)

| KPI | Before NivXRay | After NivXRay |
|-----|-----------------|-----------------|
| **Time-to-decode obfuscated commandline** | 20-40 minutes | <30 seconds |
| **Analyst hours per 100 EDR alerts (with obfuscation)** | ~50 hrs | ~4 hrs |
| **IOCs missed due to unsuccessful decode** | 15-30% | <2% |
| **MITRE ATT&CK coverage per alert** | Manual mapping, patchy | Auto-mapped, comprehensive |
| **Ticket enrichment completeness** | Analyst types summary | Pre-populated evidence |
| **Time-to-containment (dwell reduction)** | Hours | Minutes |
| **SOC analyst burnout / turnover** | High | Reduced (grunt work eliminated) |

---

## 8. Why Deterministic-First Matters for Enterprise

- **Audit-safe:** Every decode step is deterministic, reproducible, and explainable. No LLM "hallucinated IOC" risk — critical for evidence chains, SOC 2 audits, and court-admissible forensics.
- **Airgap-capable:** Zero AI dependency in the core decoder path. Works in classified / offline environments.
- **Data-sovereignty-friendly:** No customer commandlines are shipped to third-party LLMs for decoding. Optional OSINT enrichment can be scoped/toggled per deployment.
- **Predictable performance:** Deterministic decoders have bounded runtimes; LLM-based tools can stall or fail non-deterministically on adversarial input.
- **Regulatory alignment:** GDPR (no cross-border data flow), HIPAA (no PHI to LLMs), CJIS (no LEA data to public APIs), ITAR (no export-controlled tech to foreign clouds).

---

## 9. Rollout Plan (Enterprise Onboarding · 30/60/90)

### Days 0-30 · Pilot
- Deploy NivXRay (SaaS or self-hosted)
- Connect 1 EDR (typically CrowdStrike or Defender) via webhook
- Manual export of decoded IOCs → SIEM via CSV/STIX
- SOC baseline: measure current time-to-decode on 20 real alerts
- **Success metric:** NivXRay decodes 90%+ of pilot samples in <30s each

### Days 31-60 · SIEM Integration
- Wire NivXRay → SIEM (Splunk HEC / Sentinel DCR / Chronicle UDM)
- Enrich existing correlation rules with NivXRay IOCs
- Build 3-5 detection rules on top of NivXRay's MITRE mappings
- **Success metric:** SIEM correlations firing on decoded IOCs (not just raw blobs)

### Days 61-90 · ITSM + SOAR
- Wire NivXRay → ServiceNow SIR or Jira SM for auto-ticket creation
- Wire NivXRay → SOAR platform for automated response playbooks
- Train SOC on NivXRay UI for manual deep-dives
- **Success metric:** 80%+ of malware EDR alerts auto-ticketed with pre-decoded evidence; analyst spends time on decisions, not decoding

---

## 10. Roadmap Alignment (What's Coming)

- **RC2.9 / Q1 2026:** Analyst Workspace UX polish — dedicated recovered-payload panel
- **Phase D / Q1 2026:** Malware family detectors — XWorm, RedLine, FormBook, NjRAT, Emotet
- **Phase E / Q2 2026:** Sandbox detonation bridge — Triage / Hybrid Analysis / Cuckoo
- **Phase F / Q2 2026:** Native EDR connectors — CrowdStrike / SentinelOne / Defender webhook receivers
- **Phase G / Q3 2026:** Native SIEM/SOAR connectors — Splunk app, Sentinel workbook, XSOAR pack
- **Phase H / Q3 2026:** ServiceNow store certified app — SIR + ITSM native integration

---

## 11. Positioning vs. Alternatives

| Tool | Focus | vs. NivXRay |
|------|-------|-------------|
| **CyberChef** | Manual encoding toolkit | Manual, no verdict, no MITRE, no OSINT |
| **VirusTotal** | Hash lookup + sandbox | Doesn't decode obfuscated commandlines — needs the extracted IOC first |
| **Any.Run / Hybrid Analysis** | Dynamic sandbox | Detonation, not static decoding — complementary, not competitive |
| **Joe Sandbox** | Dynamic sandbox | Same as above |
| **PowerDecode** | PS-only, open-source | PowerShell only, no CMD/JS/VBS, no verdict |
| **Speakeasy / Unicorn** | Emulation-based | Requires binaries, not commandlines |
| **AI-based decoders (e.g. LLM prompts)** | Broad but hallucinates | Non-deterministic, unauditable, misses IOCs, data-privacy risk |

**NivXRay's moat:** Deterministic + commandline-first + analyst-ready output + enterprise-integratable.

---

## 12. Commercial Model (Suggested)

| Tier | Users | EDR Alerts/Month | Deployment | Pricing Idea |
|------|-------|-------------------|-------------|---------------|
| **Community** | 1 | 100 | SaaS only | Free (freemium) |
| **Team** | 5 | 2,000 | SaaS | $499/mo |
| **Business** | 25 | 20,000 | SaaS + API | $2,499/mo |
| **Enterprise** | Unlimited | Unlimited | SaaS or Self-hosted | Contact sales |
| **Airgap Enterprise** | Unlimited | Unlimited | Self-hosted only + on-prem support SLA | Contact sales |

---

## 13. Ask for the Buyer

- **1-week pilot** with real EDR alerts from the buyer's environment
- Metric: time-to-decode + IOC recovery rate improvement
- If NivXRay saves >10 analyst-hours/week in the pilot, the ROI is clear

---

*This is a living document — update after each customer conversation with new integration patterns and objections.*
