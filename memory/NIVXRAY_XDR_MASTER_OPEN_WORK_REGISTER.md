# NIVXRAY XDR — MASTER OPEN WORK REGISTER

Authority: OWNER MASTER DIRECTIVE — NIVXRAY XDR CONTROLLED-PARALLEL PROGRAM (2026-06).
This register is the master backlog. The previous 16-item list is **not** the
backlog — it is the ACTIVE EXECUTION-WAVE SUBSET and is carried below as
Program A items A-01…A-09 plus D/E/F/I entries.

Status vocabulary: `DONE | IN PROGRESS | PARTIAL | OPEN | PAUSED | HELD | BLOCKED`.
**`PAUSED` is never reported as `DONE`.** A row without evidence is not `DONE`.

Columns: Program | ID | Work Item | Priority | Status | Dependencies |
Security Boundary | Evidence/Proof | Next Action

---

## PROGRAM A — SPA / CORTEX-CLASS UI/UX  (continuously authorized, no UI gate)

| ID | Work Item | Pri | Status | Dependencies | Security Boundary | Evidence / Proof | Next Action |
|----|-----------|-----|--------|--------------|-------------------|------------------|-------------|
| A-01 | P0 `XdrScopeNavigator` async-effect crash blanking every incident page | P0 | DONE (2026-06) | — | none — lifecycle defect only | `XdrScopeNavigator.jsx:82-91` now builds the request then calls `resolve()`; effect returns `undefined`. Build PASS | Confirm in integrated regression |
| A-02 | Scope Navigator local error boundary in `XdrShell` | P0 | DONE (2026-06) | A-01 | FAULT CONTAINMENT ONLY — grants no tenant, unlocks no incident scope, hides no denial; fallback reads `SCOPE CONTROL ERROR · NO SCOPE GRANTED` | `NxErrorBoundary` gained a `fallback` render prop; `XdrShell.jsx` wraps the navigator | Regression |
| A-03 | REG5 intelligence overlays | P0 | DONE — verified end-to-end in-browser (iteration_117: 8 GET 200 + PUT 200 save + DELETE 200 revert, badge → ANALYST EDITED) | A-01 | analyst narrative only; evidence immutable | Live preview: `GET overlays` 200, `PUT …/finding/{id}/summary` 200 (v1), `DELETE` 200 (reverted). No `.append(` exists anywhere in the frontend | Re-test in-browser now that incident pages render; repair only on a reproduced failure |
| A-04 | REG4 tenant pill / incident lock rendering | P0 | DONE — verified (iteration_115: basis INHERITED_FROM_INCIDENT, data-scope-locked=true, lock suffix present; non-incident reads All Authorized Tenants) | A-01 | tenant authority is server-resolved; UI renders only what `/scope/select` returned | `xdr-tenant-pill`, `xdr-scope-label`, `xdr-scope-lock-suffix`, `data-scope-locked` present in code | Verify on an incident route in regression |
| A-05 | Entities / Activity Graph → Cortex-class workspace (§D) | P0 | DONE (2026-06) | A-06 | no synthesised ancestry; no edge without evidence | New `EntitiesGraphTab.jsx` + `attack_graph/NxGraphCanvas.jsx` + `nx/nx-workspace.css`: Graph\|Table switch, class filters with authoritative counts (`—`, never 0), left Graph Controls + Analysis Overlays + Export Graph, dominant node-card canvas, semantic edges with inferred edges visually distinct, right Entity Details (Details\|Relationships\|Evidence(n)\|Context), bottom related-event lanes + `View in Timeline →`. Legacy 1,643-line graph preserved under progressive disclosure | Regression |
| A-06 | Centralized capability label map (§B) | P0 | DONE (2026-06) | — | backend ids never renamed | `nx/capabilityLabels.js`, exported from `@/xdr/nx`; consumed by Findings, Activity, Graph details; unmapped ids marked `UNMAPPED LABEL` in Provenance | Extend to Report + Entity 360 |
| A-07 | Findings dense table + contextual details pane (§A) | P0 | DONE (2026-06) | A-06 | system assessment and analyst interpretation kept separate | New `FindingsTab.jsx`: Finding\|Category\|Capability\|State\|Confidence\|Evidence\|Entities\|MITRE\|Source\|Time + pane tabs Summary\|Evidence\|Entities\|MITRE\|Interpretation\|Provenance. Overlay editor appears ONCE, in the pane | Regression |
| A-08 | Activity table completion + Capability Runs secondary view (§C) | P1 | DONE (2026-06) | A-06 | honest result/state enums, no invented duration | `ActivityWorklogTab.jsx` now carries Time\|Type\|Activity\|Capability\|Result\|State\|Findings\|Duration\|Conf.\|Evidence\|Actor/source\|Actions and an `Event log \| Capability runs` switch | Regression |
| A-09 | Investigation cross-tab language (§E) | P1 | PARTIAL | A-05..A-08 | — | Timeline/Evidence/Technical/Activity/Findings/Entities on `xdr/nx`; Overview, Detections, MITRE, Response, Report not yet on the row→flyout pattern | Continue after the integrated regression |
| A-10 | Control Center | P1 | PARTIAL (B2-NAV) | — | — | Rail + Control Center landing live | Apply row→flyout pattern |
| A-11 | Incidents queue | P1 | PARTIAL | — | — | Split view exposes all 10 `cx-tab-<key>` incl. `cx-tab-report` | Contextual flyout on queue rows |
| A-12 | Hunting | P1 | DONE (2026-06) | A-06 | — | Rebuilt on NxInv: dense result table → contextual pane (Details/Context/Technical) → authoritative-record pivot; entity-type filter chips; honest NO MATCHING RECORD; unsupported/not-indexed moved under disclosures. Verified iteration_116 | Row→pane pattern for H-01 reuse |
| A-13 | Intelligence (TI · IOC · Command · Malware) | P1 | PARTIAL | C-* for Command UI | — | **TI + IOC modernized on NxInv (2026-06)**: TI reads 117,225 indicators · 9 of 11 sources · 3 honest source errors (HTTP 429/403/401) with an indicator table + contextual pane; IOC shows 7 of 7 providers with the governing credential, and enrichment now answers as a **per-provider table** (or states NO PER-PROVIDER ATTRIBUTION) instead of a JSON dump. Verified iteration_116. Command + Malware still legacy | Command UI waits on C-06 |
| A-14 | Automate / Response UX | P1 | OPEN | F-* | response authority unchanged | — | Wave B5 |
| A-15 | Assets | P1 | OPEN | — | — | — | Wave B6 |
| A-16 | Data Sources | P1 | PARTIAL | G-* | — | Page renders with rail (REG1 fixed) | Wave B7, then Program G |
| A-17 | Collectors | P1 | OPEN | G-* | — | — | Wave B7 |
| A-18 | Integrations | P2 | OPEN | — | — | — | Wave B8 |
| A-19 | Coverage | P2 | OPEN | I-* | — | — | Wave B9 |
| A-20 | Telemetry Health | P1 | OPEN | I-* | never render an unavailable metric as 0 | — | Wave B9 |
| A-21 | Reports | P2 | OPEN | — | — | — | Wave B10 |
| A-22 | Client Management | P1 | PARTIAL | D-* | tenant authority | "ALL CUSTOMERS" retired (REG3) | Wave B11 |
| A-23 | Administration | P1 | OPEN | D-* | RBAC enforcement is backend | — | Wave B12 |
| A-24 | Access Management surfaces | P1 | OPEN | D-* | no access without authority | — | Program D IA |
| A-25 | API / Webhooks | P2 | OPEN | — | key handling | — | Wave B13 |
| A-26 | Route consolidation + legacy-island removal | P1 | PARTIAL | — | — | `/xdr/investigations/:id` now always redirects to `/xdr/incidents/:id` incl. identity-mapped engine tabs; `UX0` prototype still present | Retire `Ux0*` and `_legacy` routes after regression |
| A-27 | **Rail / internal-link integrity** (owner report: "few of the tabs are not getting navigate or not landing on correct page") | P0 | DONE (2026-06) | — | — | Audited all 41 rail destinations + every internal `to=`/`navigate()`/`href` literal against the router and `adminMeta` keys → **41/41 rail PASS, 0 dead links**. Fixed: `Administration ▸ Detection Rules` → `/xdr/admin/detection-rules` was not an admin key and rendered "Unknown admin section" (row retired, deep link redirects to `detection-registry`); `Hunting ▸ Activities` bounced into Administration ▸ Telemetry Studio (row withdrawn — see A-29); Administration overview footers `/xdr/admin/data-sources-native` → `/xdr/data-sources`, `/xdr/admin/detection-content` → `/xdr/admin/detection-registry`, `/xdr/intelligence/ioc` → `/xdr/intelligence/iocs`; Entity 360 "Fleet file trajectory" navigated to `/xdr/intelligence/files` with no file key (catch-all bounce) → declared `no_evidence` | Keep the audit script in mind for every new row |
| A-28 | **Page-crash containment + one refusal reader** | P0 | DONE (2026-06) | A-27 | fault containment only — no authority granted, no refusal hidden | `/xdr/exposure` crashed the whole console: `Promise.all` rejected on a fail-closed `403 {code:TENANT_REQUIRED,…}` and the **object** was rendered as a React child. Fixed with `Promise.allSettled` + per-surface refusal reporting, new `xdr/nx/apiError.js` `apiErrorText()` applied across **34 files**, and `XdrShell` now wraps the page slot in `NxErrorBoundary` so a page throw can never unmount the rail again (same class as the earlier DataSources 403 crash) | Watch for remaining bespoke `detail` readers |
| A-29 | Hunting ▸ **Activities** — real analyst activity surface | P1 | OPEN (row withdrawn, not faked) | H-01, B-08 | — | There is NO estate-wide activity/event API in this build: `/api/activity/inventory` is **case-scoped** and Administration ▸ Telemetry Studio is *LLM decoding configuration*, not events. Rather than point the row at an unrelated page, the row was withdrawn and `/xdr/activities` now redirects to `/xdr/hunting`; the Hunting header control states `Environment activity — NOT AVAILABLE` with the reason | Restore the row when H-01 delivers the real event table |

---

## PROGRAM B — WINDOWS DEVICE ACQUISITION & TELEMETRY  (restored as a full program)

Architecture: Windows endpoint → native Windows Event Log adapter → NivXRay
collector → durable local outbox → authenticated ingestion → raw persistence →
DSM → normalization → canonical evidence → detection → correlation →
investigation.
Permanent invariant: **Read → Make Durable → Advance Acquisition → Deliver →
Account → Verify.**
W1 PowerShell/Sysmon forwarder remains **CLOSED / FROZEN** and must not be
expanded into the permanent architecture.

| ID | Work Item | Pri | Status | Dependencies | Security Boundary | Evidence / Proof | Next Action |
|----|-----------|-----|--------|--------------|-------------------|------------------|-------------|
| B-01 | Native Windows Event Log subscriptions | P1 | PAUSED (was W2-1) | — | collector credential server-side only | — | Resume only on owner go; verify existing worktree first |
| B-02 | Bookmark XML persistence + per-channel acquisition state | P1 | PAUSED | B-01 | — | — | — |
| B-03 | Strict stale detection · log-cleared handling | P1 | PAUSED | B-02 | — | — | — |
| B-04 | Durable outbox · retries · backpressure · queue accounting · measured drops | P1 | PAUSED | B-01 | no silent loss | — | — |
| B-05 | Channel-qualified identity + dedupe; origin computer vs collector identity | P1 | PAUSED | B-01 | tenant + collector identity proven | — | — |
| B-06 | Source/channel filtering + collection profiles | P2 | PAUSED | B-01 | — | — | — |
| B-07 | DSM coverage → canonical evidence → deterministic detection proof | P1 | PAUSED | B-01..B-06 | no fabricated telemetry | — | — |
| B-08 | Channel tracking: Sysmon · PowerShell · Security · Defender · Task Scheduler · WMI Activity · AppLocker · System · Application | P1 | PAUSED | B-01 | — | — | — |
| B-09 | ForwardedEvents / WEF-WEC | P2 | OPEN (later milestone) | B-08 | — | — | — |
| B-10 | Timezone safety — Sysmon `UtcTime` offset-naive parsing | P1 | OPEN | — | — | Carried from earlier fork | Backend fix + test |

---

## PROGRAM C — COMMAND INTELLIGENCE / UNIVERSAL DECODER  (restored as a full program)

Artifact classes preserved: `FRAGMENT · CONSTRUCTED_VALUE · ENCODED_ARTIFACT ·
DECODED_ARTIFACT · EXECUTABLE_ARTIFACT`.
Recovery states preserved: `NOT_REQUIRED · DETECTED · PARTIALLY_RECOVERED ·
RECOVERED · AMBIGUOUS · UNSUPPORTED · LIMIT_REACHED · FAILED`.
Partially reconstructed material must **never** be promoted to canonical
executable content to obtain a verdict.

| ID | Work Item | Pri | Status | Dependencies | Security Boundary | Evidence / Proof | Next Action |
|----|-----------|-----|--------|--------------|-------------------|------------------|-------------|
| C-01 | R-4 deterministic evaluator (safe constant evaluation) | P2 | PAUSED | — | sandboxed evaluation only | — | Resume on owner go |
| C-02 | R-5 variable / data-flow reconstruction (PowerShell AST) | P2 | PAUSED | C-01 | — | — | — |
| C-03 | Constructed strings · recursive codec recovery · fixed-point decoding with safety limits | P2 | PAUSED | C-02 | `LIMIT_REACHED` reported, never silently truncated | — | — |
| C-04 | Unresolved operands + artifact classification + canonical decoded artifact selection | P2 | PAUSED | C-03 | no promotion of partial material | — | — |
| C-05 | Canonical downstream propagation · IOC extraction · behavior analysis · ATT&CK enrichment · verified LOLBAS enrichment | P2 | PAUSED | C-04 | — | — | — |
| C-06 | Decoder provenance + exact fixture regression | P1 | PAUSED | C-01..C-05 | provenance mandatory | — | — |
| C-07 | Production Command Intelligence UI (Assessment · Decode Status · Execution Chain · Recovered Behavior · Decoded Payload · Indicators · MITRE · Decoder Chain · Evidence/Provenance · Technical Details) | P2 | OPEN | C-06, A-06 | — | Command analyser page exists incl. `needs_choice → force_decode_span` | Build after C-06 |

---

## PROGRAM D — IDENTITY / RBAC / TENANT / ACCESS MANAGEMENT

One SPA, role-aware experiences, authoritative backend enforcement. **No
separate Analyst and Admin products.** Admin may hold the functional superset of
authorized capabilities but never bypasses tenant isolation, audit or response
approval.
Model: Users · Groups · Roles · Permissions · Direct Grants · Direct
Restrictions · Resource Scope · Effective Access · Audit.
IA: `Users | Groups | Roles | Permissions | Assignments | Effective Access | Audit`.
User detail: `Overview | Groups | Roles | Additional Access | Restrictions |
Scope | Effective Access | Audit History`.

| ID | Work Item | Pri | Status | Dependencies | Security Boundary | Evidence / Proof | Next Action |
|----|-----------|-----|--------|--------------|-------------------|------------------|-------------|
| D-01 | Permission catalog (authoritative) | P1 | PARTIAL | — | — | 11 built-in permissions proven on `role_builtin_l1_analyst` | Publish the catalog surface |
| D-02 | Authoritative effective-access resolver + provenance | P1 | OPEN | D-01 | no privilege without provenance | `require_permission()` fails closed since P0-SEC | Design resolver output shape |
| D-03 | Groups · role inheritance · individual grants · restrictions | P1 | OPEN | D-02 | — | — | — |
| D-04 | Tenant / resource scope model | P0 | PARTIAL | D-02 | fail-closed; header spoofing rejected | Scope Navigator + `/scope/select`; cross-tenant IDOR closed | Extend to every admin surface |
| D-05 | Route + component authorization | P1 | PARTIAL | D-02 | UI never decides authority | `AccessProvider` + `useAccess` in the shell | Audit every route |
| D-06 | Response-specific permissions (`response.execute` / `response.approve`) | P0 | DONE | — | separation of duties | P0-1 gates 37 PASS | Keep under F-* |
| D-07 | Access Simulator | P2 | OPEN | D-02 | read-only | — | — |
| D-08 | Audit · revocation / session behaviour · privilege-escalation protection · cross-tenant regression | P1 | PARTIAL | D-02 | — | `xdr_audit_log`; P0-SEC suites 21/21 + 14/14 | Extend to grants/restrictions |

---

## PROGRAM E — DETECTION / INVESTIGATION / EVIDENCE

First-class entities: Device · User · Process · File · Hash · IP · Domain · URL ·
Detection · Incident · Evidence.
Required pivot model: Windows Event → Process → Parent/Child → User → Device →
Related activity → Detection → Incident → Evidence.
**No conclusion without evidence.** Every supported conclusion retains
provenance to authoritative evidence.

| ID | Work Item | Pri | Status | Dependencies | Security Boundary | Evidence / Proof | Next Action |
|----|-----------|-----|--------|--------------|-------------------|------------------|-------------|
| E-01 | Canonical evidence → detection → incident chain | P0 | PARTIAL | B-* | tenant-scoped | 64 detections from real events; 1 real domain only | Needs a second real domain |
| E-02 | Investigation · Timeline · Attack Story · Findings · MITRE | P1 | PARTIAL | A-05..A-09 | — | Tabs on `xdr/nx`; findings pane live | Cross-tab pass A-09 |
| E-03 | Entity 360 · Device Trajectory · process ancestry · relationships | P1 | PARTIAL | A-05 | alias resolution per query site (F-1 class) | Trajectory + process tree alias-resolved; equivalence proven on evidence ids | Audit remaining query sites |
| E-04 | IOC intelligence + judgements ownership | P2 | OPEN | A-13 | — | 7/7 providers live | Decide judgements authority (no third disposition engine) |
| E-05 | Analysis completeness + reports | P1 | PARTIAL | A-09 | never imply completeness that was not measured | Completeness metric on Overview | Report surface pass |
| E-06 | `parser_ok` / `normalized_ok` default to `True` unmeasured | P1 | OPEN | I-* | honest telemetry health | Carried from earlier fork | Measure or report `NOT MEASURED` |

---

## PROGRAM F — RESPONSE / SECURITY HARDENING / PRODUCTION READINESS

Chain: Requested → Approved → Dispatched → Executed → Verified. Never collapse
`ACCEPTED = EXECUTED` or `EXECUTED = VERIFIED`.

| ID | Work Item | Pri | Status | Dependencies | Security Boundary | Evidence / Proof | Next Action |
|----|-----------|-----|--------|--------------|-------------------|------------------|-------------|
| F-01 | Five-fact response lifecycle | P0 | DONE | — | approval authenticity | P0-1 37 PASS / 2 BLOCKED; `facts{}` derived, stub adapters terminate at `simulated` | — |
| F-02 | Endpoint execution + independent verification | P0 | BLOCKED (environment) | — | never simulated | `CAP_NET_ADMIN` absent in this pod | Real endpoint required |
| F-03 | T-RISK-3 response boundary tenant fallback | P0 | **HELD** | — | **SECURITY AUTHORITY — separately gated; no change without explicit owner authorization** | `memory/T-RISK-3_RESPONSE_BOUNDARY_TENANT_FALLBACK.md` (analysis complete) | Await owner authorization |
| F-04 | T-RISK-4 vendor wizards | P1 | OPEN (analysis not started) | — | security authority | — | Schedule separately from UI waves |
| F-05 | T-RISK-5 document labelling default tenant | P1 | OPEN (analysis not started) | — | tenant authority | — | Schedule separately |
| F-06 | Idempotency · replay protection · result accounting · audit | P1 | DONE | F-01 | — | Idempotent replay creates no second endpoint command (P0-1) | — |

---

## PROGRAM G — WINDOWS DATA SOURCE / COLLECTOR / ADMIN UI

Workflow: Data Sources → Windows → Add → choose collection profile →
deploy/connect collector → configure → verify ingestion → Ready.
**`CONNECTED` only after real telemetry evidence.** Configured/deployed must
never be converted into connected.

| ID | Work Item | Pri | Status | Dependencies | Security Boundary | Evidence / Proof | Next Action |
|----|-----------|-----|--------|--------------|-------------------|------------------|-------------|
| G-01 | Windows data-source add/configure wizard | P1 | OPEN | B-01, F-04 | vendor-wizard risk T-RISK-4 | — | Design after B-01 resumes |
| G-02 | Collector deploy / connect / verify flow | P1 | OPEN | B-01 | ingest key never printed to chat/repo/log | — | — |
| G-03 | Operational collector table (Device · Collector · Version · Channel · Profile · Last telemetry · Received · Durably queued · Delivered · Queue depth/bytes · Oldest event · Retries · Drops · Gaps · Parser health · Normalization health · Coverage · Config · Lifecycle · Errors) | P1 | OPEN | I-01 | unavailable metric ≠ 0 | Collector split-brain (two runtimes, two state stores) documented | Reconcile registries first (P0-4) |
| G-04 | Collector reconciliation (P0-4) | P1 | OPEN | — | tenant/source identity proven | `xdr_collector/*` 403 fail-closed under admin scope today | — |

---

## PROGRAM H — RAW WINDOWS EVENT / HUNTING EXPERIENCE

Primary table: `Time | Host | Channel | Provider | Event ID | Level | User |
Process | Activity | Source | Detection | Evidence`, with search, time range,
filters, sorting, field selection, entity/evidence pivots, related detection,
related incident, open in investigation.
Inspection exposes Raw XML · Parsed fields · Normalized event · Canonical
evidence · Provenance · Related entities · Related detections · Related
incidents. Timestamps kept distinct: activity time · sensor observation time ·
ingestion time. **No invented "Windows Explorer log" channel.**

| ID | Work Item | Pri | Status | Dependencies | Security Boundary | Evidence / Proof | Next Action |
|----|-----------|-----|--------|--------------|-------------------|------------------|-------------|
| H-01 | Event result table | P1 | OPEN | A-12, B-08 | tenant-scoped | — | Wave B3 (Hunting) |
| H-02 | Contextual event inspection (raw → parsed → normalized → canonical) | P1 | OPEN | H-01 | provenance mandatory | — | — |
| H-03 | Three-timestamp model | P1 | OPEN | B-10 | — | — | Depends on B-10 |
| H-04 | Pivots: entity · evidence · detection · incident · open in investigation | P1 | OPEN | H-01, E-03 | — | — | — |

---

## PROGRAM I — TELEMETRY HEALTH / EVIDENCE COMPLETENESS

States: `HEALTHY · HEALTHY · EVIDENCE INCOMPLETE · DEGRADED · BACKLOG · PAUSED ·
DROPPING · RECOVERING · NOT CONFIGURED · NOT OBSERVED · NOT AVAILABLE · ERROR`.
**An unavailable metric is never rendered as 0.**

| ID | Work Item | Pri | Status | Dependencies | Security Boundary | Evidence / Proof | Next Action |
|----|-----------|-----|--------|--------------|-------------------|------------------|-------------|
| I-01 | Per-stream counters · EPS · latency P50/P95/P99 · queue depth/bytes · oldest queued | P1 | OPEN | B-04 | — | — | Define the measurement contract |
| I-02 | received · durably queued · delivered · retries · drops · collection gaps | P1 | OPEN | B-04 | measured, never inferred | — | — |
| I-03 | `parser_ok` / `normalized_ok` real measurement | P1 | OPEN | E-06 | — | Currently default `True` unmeasured | Fix with E-06 |
| I-04 | dedupe + rule/channel coverage | P2 | OPEN | B-05 | — | — | — |
| I-05 | Health-state rendering vocabulary in the SPA | P1 | OPEN | A-20 | unavailable ≠ 0 | `ABSENCE` vocabulary exists in `xdr/nx` | Reuse `ABSENCE` for health |

---

## PLATFORM FENCES (cross-program, do not mix into UI change sets)

| ID | Item | Status | Rule |
|----|------|--------|------|
| X-01 | T-RISK-3 response boundary repair | HELD | Separate security decision required (F-03) |
| X-02 | Production zero-data | OPEN — owner decision | No preview→production copying, no migration, no synthetic telemetry, no `CONNECTED` claim without real acquisition |
| X-03 | W1 PowerShell/Sysmon forwarder | FROZEN / CLOSED | Never expanded into the permanent architecture |
| X-04 | Backend weakening to satisfy the UI | FORBIDDEN | The UI renders what the API proves |
| X-05 | Client-side debouncing of scope/overlay calls (429s seen) | OPEN | Only after the 429 root cause is confirmed server-side; debouncing must not hide incorrect server behaviour |

---

## MASTER PRINCIPLES
Advanced underneath. Simple on top. Powerful when needed.
No access without authority. No conclusion without evidence.
No success without verification. No edge without evidence.
`CONNECTED` only after real telemetry. Verdict, cited. Every time.
