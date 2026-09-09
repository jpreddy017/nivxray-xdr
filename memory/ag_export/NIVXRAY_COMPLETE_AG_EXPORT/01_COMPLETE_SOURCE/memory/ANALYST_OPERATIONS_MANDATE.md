# NivXRay XDR · Analyst Operations Build Mandate

**Locked** · Owner directive · 2026-02-32
**Status** · Layer 1 shipped · Layers 2-7 pending

## Reference sources (UX only · never clone)

- Microsoft Defender XDR — Incident Queue: https://learn.microsoft.com/en-us/defender-xdr/incident-queue
- Microsoft Defender XDR — Manage Incidents: https://learn.microsoft.com/en-us/defender-xdr/manage-incidents
- Microsoft Defender XDR — Investigate Incidents: https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents
- ServiceNow SIR — Workspace Landing: https://www.servicenow.com/docs/r/security-management/security-incident-response/sir-workspace-landing-page.html
- ServiceNow SIR — New UI: https://www.servicenow.com/docs/r/xanadu/security-management/security-incident-response/sir-new-ui.html

## Absolute architectural lock

NivXRay is **Evidence-first + Investigation-centric + Deterministic-first XDR.**  The analyst workflow is:

```
COMMAND CENTER → INCIDENT QUEUE → INCIDENT RECORD → AUTO-INVESTIGATION
  → EVIDENCE → ENRICHMENT → VERDICT → ATTACK STORY → RESPONSE / CLOSURE
```

**The dashboard is not the replacement for the queue.**

## Engine fabric — NEVER rewrite

Never rewrite / rename / duplicate / replace / relocate:
IDA · IUE · UAIE · VEEE · DIE · ICE · IEDDE · UIL · Interpreter Identifier · Recipe Planner · Recursive Child Pipeline · Artifact Intelligence · PE Analyzer · Behavioral · Attack Fingerprint · Technique Detector · IOC Intelligence · CEM · Confidence & Provenance · SSOT · KB · MITRE · LOLBAS · Sigma · TI · OSINT · Evidence-Driven Mitigation · all 43 UAIE plugins.

The new UI is a **consumer/renderer** — the engine remains authoritative.

## Locked sidebar hierarchy (Layer 1 · SHIPPED)

```
WORKSPACE          Workspace (Analyst)
COMMAND CENTER     MSS Dashboard
OPERATIONS         ⭐ Incidents  ·  My Queue  ·  SLA / Aging  ·  Response
INVESTIGATIONS     Investigation Workspace  ·  Evidence Explorer  ·  Entity Search  ·  Attack Story
DETECT             Rule Studio  ·  Detection Registry  ·  Correlation Rules  ·  Detection Engineering
INTELLIGENCE       TI · IOC · Command · Malware · MITRE · KB · Docs · Exposure
RESPOND            Playbooks · Automation · Approvals
EXPOSURE           Assets · Vulnerabilities · Exposure · Attack Paths · Critical Assets
DATA               Security Data Lake
ADMINISTRATION     Integrations · Data Sources · Collectors · Agents · Telemetry Studio · …
```

Routing lock:
- `/xdr` → `/xdr/incidents`
- `/xdr/dashboard` → `/xdr/incidents`
- `/xdr/mss-dashboard` — MSS Dashboard (separate destination)

## Build layers

### Layer 1 · Information Architecture — **SHIPPED**
Sidebar reorganised · queue-first routing · Command Center section created.

### Layer 2 · Queue UX (Defender-grade)
Priority score chip bands (red > 85 · orange 15-85 · gray < 15) · time selector (1 day / 3 days / 1 week / 30 days / 6 months / custom) · default filter `state ∈ {new, in_progress}` and `severity ∈ {high, medium, low}` · side-pane preview (click row → drawer · up/down navigation · click name → full detail) · **coloured chip components** (`P1`/`P2`/… priority pills · `CRITICAL`/`HIGH`/… severity badges · `MALICIOUS`/`SUSPICIOUS`/… verdict pills · `NEW`/`INVESTIGATING`/… state pills · `EDR`/`NDR`/`ITDR`/… domain tags) · customize-columns dropdown + drag reorder · CSV export (10 000 cap) · priority strip (compact 8 tiles: Critical · High · Unassigned · My Queue · SLA Risk · On Hold · New · Updated).

### Layer 3 · Incident Record
Header: ID · Title · `[P1] [MALICIOUS] [HIGH CONFIDENCE]` chips · Customer · Detection Source · Owner · State · SLA · Created · Updated.  Tabs / sections: Executive Summary · Technical Summary · Supporting Evidence · Auto-Investigation · Engine Results · MITRE · Attack Story · Recommendations · Analyst Notes · Activity / Timeline · Related Records · Closure.

### Layer 4 · Investigation Surface
- **Executive Summary** · auto-assembled from evidence · analyst-editable · distinguish `AUTO-GENERATED` / `ANALYST-EDITED`.
- **Technical Summary** · host · user · process · parent · command line · hashes · file path · network activity · domains · IPs · timestamps · detection source · telemetry source — only fields with evidence.
- **Supporting Evidence** · structured cards (source · timestamp · entity · type · confidence · provenance · raw event · `[View Telemetry]`).
- **Attack Story** · deterministic timeline · every sentence links to evidence.
- **MITRE ATT&CK** · techniques from evidence only · each links to evidence.
- **Recommendations** · Immediate · Investigation · Detection Improvement — evidence-driven.

### Layer 5 · Engine Fabric Integration
Consume existing IUE / DIE / IDA / UAIE / VEEE / ICE / IEDDE / UIL / Artifact / PE / Behavioral / Fingerprint / Technique / IOC — through existing service interfaces.  No duplication.  Auto-Investigation status panel with `NOT_RUN` / `QUEUED` / `RUNNING` / `COMPLETE` / `PARTIAL` / `FAILED` per engine.

### Layer 6 · Enrichment
Internal (endpoint · network · identity telemetry · IKG · SSOT) + Intelligence (IOC · TI · Malware · MITRE · OSINT) + Artifact (hash reputation · PE intel · file metadata · cmdline decode · behavioural · fingerprint) — consume existing capabilities.

### Layer 7 · Provenance
`xdr_observations` collection + `engine_executions` ledger + immutable provenance.  `GET /api/incidents/{id}/engine-executions` and `GET /api/incidents/{id}/observations` — spec in `PHASE4_ORCHESTRATION_SPEC.md`.

## Lifecycle & SLA (Phase 3)

State model: `NEW → TRIAGED → INVESTIGATING → CONTAINMENT → ERADICATION → RECOVERY → RESOLVED → CLOSED`.
Side states: `WAITING_CUSTOMER · WAITING_EVIDENCE · WAITING_VENDOR`.
SLA policies keyed by priority (P1=4h, P2=8h, P3=24h, P4=72h · configurable).  Persist `sla_policy · sla_started_at · sla_due_at · sla_status ∈ {ON_TRACK, AT_RISK, BREACHED, PAUSED}`.

## Anti-fabrication contract (invariant)

| Data absent | Render |
|---|---|
| No evidence | `NO EVIDENCE` |
| No enrichment | `NOT RUN` |
| No engine execution | `NOT RUN` |
| Engine failed | `FAILED` |
| Telemetry unavailable | `UNAVAILABLE` |
| No MITRE mapping | `NO TECHNIQUE` |
| Verdict undetermined | `UNKNOWN` |

Never populate fake hashes · IPs · users · processes · verdicts · techniques · engine results · enrichment · recommendations · timelines.

## Acceptance flow (every layer must support)

```
LOGIN → INCIDENT QUEUE → FILTER P1 → OPEN INCIDENT → PREVIEW →
OPEN INVESTIGATION → AUTO-INVESTIGATION → ENGINE RESULTS →
EVIDENCE → ATT&CK → ATTACK STORY → RECOMMENDATIONS →
ANALYST NOTES → CONTAINMENT → RESOLUTION
```

## Design language

Dark NivXRay theme · high information density · subtle borders · compact typography · semantic colours · strong hierarchy · monospace for technical values · compact status pills · clear tables · expandable panels · drawers · evidence cards · timeline visualization.

Avoid: oversized empty KPI cards · excessive rounded cards · excessive whitespace · generic SaaS look · giant colourful widgets · fake graphs · meaningless animations.
