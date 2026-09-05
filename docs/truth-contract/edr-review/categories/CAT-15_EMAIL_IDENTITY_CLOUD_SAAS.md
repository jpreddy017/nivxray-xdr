# CAT-15 · Email / Identity / Cloud / SaaS XDR Coverage

> STRICT READ-ONLY deep-dive. **This category defines whether "XDR" in the product name is currently earned.**

## 1 · PRE-AG baseline

**NOT IMPLEMENTED at plane level.** What existed at `5d67934e`:

| Domain | PRE-AG artifact | Reality |
|---|---|---|
| Email | none | no mailbox entity, no message ingestion, no phishing analysis |
| Identity | `CROSS_USER` correlation operator; `routers/xdr_rbac.py` (NivXRay's *own* users) | **NivXRay's internal RBAC is not identity XDR** |
| Cloud | `aws_cloudtrail`, `azure_activity`, `gcp_audit_logs` declared as source **kinds** | declaration only |
| SaaS | `office365_activity` declared as a source **kind** | declaration only |
| Generic ingest | `/api/v2/ingest/{csv,evtx,json,ndjson,syslog,webhook}` | domain-agnostic transport |

## 2 · AG delta

| Added | Domain | Effect |
|---|---|---|
`detection_content/telemetry/aws_cloudtrail_dsm.py` | **cloud** | **the only genuine cloud-domain capability in the product** |
`detection_content/telemetry/linux_auditd_dsm.py` | host | (CAT-13) |
`detection_content/telemetry/windows_security_dsm.py` | host / partially identity-adjacent (4624/4625 class events) | (CAT-13) |
— | email | **AG added nothing for email** |
— | SaaS | **AG added nothing for SaaS** |

## 3 · Current state (live)

```
$ 733 live API paths:
  /email/i     → 0
  /identity/i  → 0
  /cloud/i     → 0
  /saas/i      → 0
  /mailbox/i   → 0
  /oauth|okta|entra|azure|gcp|o365|office/i → 0
```

| Domain | DSM | API plane | Configured source | Verdict |
|---|---|---|---|---|
| Endpoint / host | 3 (`windows_security`, `linux_auditd`, `sysmon`) | 4 `/api/edr/*` (projection) | **0** | PARTIAL |
| Network | 1 (`snort-eve`) | 0 | **0** | PARTIAL |
| Cloud | 1 (`aws_cloudtrail`, AG) | **0** | **0** | **NOT IMPLEMENTED** as a plane |
| Identity | 0 | 0 | 0 | **NOT IMPLEMENTED** |
| Email | 0 | 0 | 0 | **NOT IMPLEMENTED** |
| SaaS | 0 | 0 | 0 | **NOT IMPLEMENTED** |

**Honest conclusion:** NivXRay XDR currently covers **1.5 of the 6 XDR domains** in code (host + network, both unconnected), plus one cloud DSM with no plane. The "X" in XDR is **architecturally prepared** (16 declared source kinds, DSM/parser/normalizer pattern, 5 vendor adapters, generic ingest transports) and **operationally unrealised**.

## 4 · Industry benchmark

| Vendor | Email | Identity | Cloud | SaaS |
|---|---|---|---|---|
| **Microsoft Defender XDR** | ✅ Defender for Office 365 (native) | ✅ Defender for Identity | ✅ Defender for Cloud + Sentinel | ✅ Defender for Cloud Apps; disruption reaches **AWS and Okta** via Sentinel connection |
| **Cisco XDR** | ✅ email | ✅ identity | ✅ | ✅ via integrations |
| **Cortex XDR** | 🟡 via integrations | ✅ identity sources into the data lake | ✅ `cloud_audit_log` dataset is BIOC-filterable | 🟡 |
| **CrowdStrike** | 🟡 | ✅ Identity Protection | ✅ Cloud Security | 🟡 via NG-SIEM |
| **SentinelOne** | 🟡 | ✅ identity in Storyline + Purple AI | ✅ cloud in the data lake | 🟡 |
| **Splunk ES** | ✅ (ingests anything) | ✅ | ✅ | ✅ |
| **Trellix** | ✅ email is a core strength | ✅ | ✅ | ✅ Cloud Connect for SaaS via webhooks/APIs |
| **NivXRay XDR** | 🔴 | 🔴 | 🔴 (1 DSM, no plane) | 🔴 |

## 5 · Gap

| Gap | Severity | Justification (NivXRay-evidence-led) |
|---|---|---|
| **Identity domain absent** | **P1 — highest-value of the four** | `CROSS_USER` correlation is **already implemented** (live `/api/xdr/correlation/status`) and has no user data to correlate; `windows_security_dsm` already parses logon-class events. Identity is the **cheapest cross-domain unlock** and the one that makes CAT-10's user entity meaningful |
| **Cloud DSM has no plane** | **P1** | AG shipped `aws_cloudtrail_dsm.py`; `aws_cloudtrail` is a declared kind; **0 configured**. Registered capability, zero reachability — a DEV-2-class problem |
| **Email domain absent** | **P2** | Highest build cost of the four (mailbox entity, message model, URL/attachment detonation — and detonation is CAT-13's absent sandbox). Do not start here |
| **SaaS domain absent** | **P2** | `office365_activity` declared; needs the identity plane first |
| Cross-domain correlation impossible | **P0 (root)** | CAT-06 + CAT-12. Correlation operators exist; domains do not |

**Recommended sequencing (evidence-led, not vendor-led):** host → **identity** → network → cloud → SaaS → email. Rationale: `CROSS_USER` and `CROSS_HOST` operators are already implemented, `windows_security_dsm` already sees logon events, and identity is the entity type CAT-10 most needs. Email requires a sandbox that does not exist.

## 6 · Honest positive

The product does not claim domains it lacks. `/api/xdr/data-sources` returns the 16 declared kinds **alongside `count: 0`**, so an operator can see exactly what is *possible* versus what is *configured*. No fabricated domain coverage was found anywhere in the 733-path API surface.

## 7 · UNKNOWN

- U-15.1 — Whether `windows_security_dsm` normalises identity fields (user SID, logon type, source workstation) into canonical evidence. Would require reading and executing the DSM; **not claimed**.
- U-15.2 — Whether `aws_cloudtrail_dsm` has ever processed an event. `xdr_canonical_evidence` (222 docs) is not broken down by DSM in any surfaced API.
- U-15.3 — Whether the 22 rows in `xdr_data_sources` include cloud/identity kinds (master U-12.1).
