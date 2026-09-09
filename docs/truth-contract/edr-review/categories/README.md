# NivXRay XDR · Pre-AG Baseline + Industry Audit · CATEGORY DEEP-DIVE INDEX

> STRICT READ-ONLY. Master consolidated audit: `../NIVXRAY_XDR_PRE_AG_BASELINE_AND_INDUSTRY_AUDIT_FRAMEWORK.md`
> Boundary: PRE-AG = `5d67934e4cfb879c8cc69d42ab48878040cf793d` · AG import = `95b1c82a9aaeb0024814fd08cc509818d77367d1` · confidence **HIGH**.
> Framing: dashboard / incidents / workspace are **experiences**; detection, correlation, intelligence, telemetry, hunting, response and administration are **planes**. The 8-tab Investigation Workspace is not the XDR.

| # | File | Category | PRE-AG | AG delta | Current | Industry gap |
|---|---|---|---|---|---|---|
| 01 | `CAT-01_MSS_XDR_DASHBOARD.md` | MSS / XDR Dashboard | ✅ 100% PRE-AG | none | RUNTIME-PROVEN | MEDIUM |
| 02 | `CAT-02_ALERTS_AND_TRIAGE.md` | Alerts & triage | 🔴 absent | none | **NOT IMPLEMENTED** | **CRITICAL** |
| 03 | `CAT-03_INCIDENTS_CASE_MANAGEMENT.md` | Incidents / cases | ✅ broad | none | PARTIAL · 3 stores | HIGH |
| 04 | `CAT-04_INVESTIGATION_ANALYST_WORKSPACE.md` | Investigation / workspace / UI | ✅ shell + engine | 8-tab workspace + 3 pages | PARTIAL · 2 consoles | MEDIUM |
| 05 | `CAT-05_DETECTION_ENGINEERING.md` | Detection engineering | ✅ substantial | **largest AG contribution** | REGISTERED + PARTIAL | MEDIUM (above parity on lifecycle) |
| 06 | `CAT-06_CORRELATION_ATTACK_CHAINING.md` | Correlation / chaining | ✅ ICE, PRE-AG | modified | RUNTIME-PROVEN · 13/13 ops | HIGH (single domain) |
| 07 | `CAT-07_SECURITY_INTELLIGENCE_IUE.md` | Intelligence / IUE / UBAE | ✅ 31-file service | analyzers + new plane | EXECUTED | MEDIUM · UBAE absent |
| 08 | `CAT-08_VERDICT_RISK_PRIORITISATION.md` | Verdict / risk / Security State | ✅ VEEE untouched by AG | **Security State 81 files, 100% AG** | RUNTIME-PROVEN | HIGH (no entity risk) |
| 09 | `CAT-09_THREAT_HUNTING_QUERY.md` | Hunting / query | 🔴 suggestions only | none | **SCAFFOLD** | **CRITICAL** |
| 10 | `CAT-10_ENTITY_360.md` | Entity 360 | 🟡 primitives only | none | **NOT IMPLEMENTED** | **CRITICAL** |
| 11 | `CAT-11_THREAT_INTELLIGENCE.md` | TI / IOC / MITRE / YARA | ✅ deep, 100% PRE-AG | YARA runtime only | RUNTIME-PROVEN | **LOW — at/above parity** |
| 12 | `CAT-12_TELEMETRY_DATA_SOURCES.md` | Telemetry / data plane | 🟡 1 DSM | **+3 DSMs** | PARTIAL · **0 connected** | **CRITICAL — root cause** |
| 13 | `CAT-13_EDR_ENDPOINT.md` | EDR / endpoint / sandbox | 🟡 projection | +2 host DSMs | PARTIAL | **CRITICAL** |
| 14 | `CAT-14_NDR_NETWORK.md` | NDR / network | 🟡 Snort DSM | none | PARTIAL | **CRITICAL** |
| 15 | `CAT-15_EMAIL_IDENTITY_CLOUD_SAAS.md` | Email / identity / cloud / SaaS | 🔴 absent | +1 cloud DSM | **NOT IMPLEMENTED** | **CRITICAL** |
| 16 | `CAT-16_PLAYBOOKS_AUTOMATION_RESPONSE.md` | Playbooks / response / approvals | ✅ response fabric | **safety + verification** | PARTIAL · 5/13 actions | HIGH |
| 17 | `CAT-17_ADMINISTRATION_GOVERNANCE_TENANCY.md` | Admin / governance / tenancy / audit | ✅ strong | ledger + isolation tests | RUNTIME-PROVEN | **LOW — near parity** |

## Reading order recommendations

- **If you want the honest truth about whether this is an XDR:** CAT-12 → CAT-15 → CAT-14 → CAT-13 → CAT-06.
- **If you want to know what to build next:** CAT-12 → CAT-02 → CAT-10 → CAT-16.
- **If you want to know what NivXRay does better than the market:** CAT-11 → CAT-08 → CAT-17 → CAT-05 → CAT-16 §6.
- **If you want to avoid the biggest misreading of this codebase:** CAT-04 §framing — the 8-tab workspace is not the XDR.

## Standing exclusions honoured throughout

`mal-20` untouched · Truth Contract v1 unamended · no engine rebuilt · no IKG writer created · no UBAE · no Sandbox · no Stage-4 / Gap-B / Stage-11 implementation · no 615-content or decoder counts manufactured · zero application code, config, DB, UI or production behaviour modified.
