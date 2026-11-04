# MASTER WORK RECONCILIATION — READ-ONLY

Date: 2026-06 · Mode: **strictly read-only** · Product changes: **zero**

Sources reconciled: all 27 documents under `/app/memory/production-gates/`
(including `MASTER_GATE_INDEX.md`), current source at `f7a25183`, the live
production OpenAPI, the deployed console artifacts, the backend capability
registry (`edr_plane/capability/inventory.py`), the sensor sources, and the
frozen pytest baseline.

---

## 1 · EXECUTIVE STATUS

**MASTER WORK RECONCILIATION: PASS** (the reconciliation itself is
complete and internally consistent).

The program state in one paragraph: the **platform plumbing is now real
and verified in production** — secrets, enrolment, backend plane,
route parity, both consoles — while the **security product itself is
mid-programme**. Fifteen release gates exist; 5 are PASS, 6 are
IN_PROGRESS, 3 NOT_STARTED, 1 BLOCKED on owner hardware. The single
largest honest gap is not a missing button: **NivXForge has no
endpoint-local detection, prevention, or inference engine.** Detection
today is server-side, on delivered telemetry. Nothing in production has
ever seen a real production endpoint, because production has zero
tenants and zero endpoints — by design, and correctly reported as such.

No contradiction was found between the closed-gate evidence and current
source. One earlier claim was corrected during this session (the
"28 failed / 18 errors" figure — see §23).

---

## 2 · VERIFIED CURRENT PRODUCTION BASELINE

| | Value | How established |
|---|---|---|
| Backend | `https://nivxray.nivxforge.com` · `/api/health` 200 | live probe |
| Route parity | **862 / 862 · 0 missing · 0 extra** | production `/api/openapi.json` vs source |
| XDR console | `xdr.nivxforge.com` · `/assets/index-DWES00xC.js` | live fetch; matches local build of the pushed commit |
| EDR console | `edr.nivxforge.com` · `/assets/index-Dyygw0sM.js` | same |
| Git commit | `f7a2518` (`feature/rc2-alignment`), local HEAD `f7a25183` | tip **and** parent hash match |
| Production tenants | **0** | console: `TENANT_REQUIRED`; XDR customer list empty |
| Production endpoints | **0** | consequence of the above |
| Response authority | **fail-closed** — unset, and a loopback value is refused in production | §15.5 of the sync report + 5 tests |
| Scope isolation | enforced — each host refuses the other product's path | browser check, both directions |
| Production DB mutations this phase | **0** | nothing was written |

`TENANT_REQUIRED` is **evidence of correctness**, not a defect: enrolment
cannot create tenancy and there is no default tenant (the B5 defect,
closed).

---

## 3 · PREVIOUSLY CLOSED GATES — RECONCILED

| Gate | Previous | Reconciled now | Evidence | Remaining limitation | Regressed? |
|---|---|---|---|---|---|
| P0-A · Response authority | CLOSED | **CLOSED** | `P0A_RESPONSE_AUTHORITY.md`; 8 live tests pass | dispatch target itself is P0-PROD-4 | no |
| P0-A.1 · Security harness integrity | CLOSED | **CLOSED** | `GATE_14_TEST_INTEGRITY_A1.md` | — | no |
| P0-A.2 · Secure enrolment foundation | CLOSED | **CLOSED** | 29 tests pass at HEAD | superseded in part by P0-PROD-2 | no |
| P0-B · Exclusion enforcement scope | CLOSED | **CLOSED** | `P0A1_P0B_EXCLUSION_SCOPE.md`, `GATE_07_EXCLUSIONS.md` | endpoint-side enforcement declared `EXCLUSION_NOT_SUPPORTED_BY_ENGINE` — never claimed | no |
| P0-C · Durable findings | CLOSED | **CLOSED (backend)** | `P0C_DURABLE_FINDINGS.md` | **no UI consumer in any console revision** → see NOT_WIRED | no |
| P0-PROD-1 · Secret closure | CLOSED | **CLOSED, amended** | 29 tests pass | amended twice this session: `MANDATORY_PRODUCTION_CONFIG` added; two unremovable platform keys reclassified INERT with a runtime-scan proof | no — strengthened |
| P0-PROD-2 · Secure endpoint enrolment | CLOSED | **CLOSED** | 25 tests pass; live mint→enrol→session→heartbeat→replay-refused | endpoint credential at rest is filesystem-permission only; no mTLS | no |
| P0-PROD-3 · Production backend plane | CLOSED | **CLOSED** | 29 tests pass; production now 862/862 | — | no |
| Production Backend Sync | PASS | **PASS** | §16 of the sync report; re-verified after console promotion | — | no |
| GitHub Source Sync | PASS | **PASS** | §19 — commit identity proof | agent cannot query origin (no credential, by design) | no |
| XDR / EDR Console Sync | PASS | **PASS** | §20 — bundle hashes + 162 chunks each + scope refusal | — | no |

**No closed gate is reopened.** Optional hardening remaining inside a
closed gate is recorded below, not used to reopen it.

---

## 4–16 · COMPLETE WORK INVENTORY BY STATUS

### CLOSED (11)
P0-A, P0-A.1, P0-A.2, P0-B, P0-C (backend), P0-PROD-1, P0-PROD-2,
P0-PROD-3, Production Backend Sync, GitHub Source Sync, Console Sync
(both). Plus programme gates **5 (policy authority)**, **7
(exclusions)**, **8 (policy precedence)**, **9 (exclusions affect
detection + UI)**, **11 (events explorer)** — all PASS with live proof on
a real *preview* endpoint.

### PARTIAL (7)
1. **Gate 2 · Telemetry acquisition** — delivery and canonicalisation
   proven; the **endpoint-local event journal does not exist**
   (`outbox.py` is a delivery outbox, not a journal). Retention, index,
   query and at-rest integrity absent.
2. **Gate 3 · Detection & prevention fabric** — contracts frozen, 15
   tests, 400 findings from real detections; **no ML model, no
   correlation engine, no UI consumer**.
3. **Gate 10 · Scale/performance** — trajectory first paint 1.06–1.82 s
   on 208,754 observations; **p95 under concurrency unmeasured**, legacy
   `/edr/device-trajectory` still 6.1 s, no failure injection.
4. **Gate 12 · UI/UX** — `PASS_DESKTOP / RESPONSIVE_VALIDATION_PENDING`;
   mobile breakpoints still fail (recurrence count 3).
5. **Gate 14 · Security/RBAC/tenant isolation** — 169 + 227 tests pass,
   66-case live authz matrix PASS; 13 stale live-contract test defects
   carried.
6. **Gate 16 · EDR independence** — own origin/product proven (5 tests);
   the owner's acceptance walk needs Files/Hunt/Live Query/Forensics/
   Outbreak to exist. Independence ≠ completeness.
7. **Events explorer** — PASS, but saved searches, deep links and CSV
   export are labelled not-implemented.

### SKIPPED (0 genuine)
No work was found to have been silently skipped. Two items were
explicitly recorded as "not now" by the owner and are DEFERRED, not
skipped: the weekly exclusion digest, and the harness debt sweep.

### DEFERRED (8)
Weekly exclusion digest · harness debt sweep (547/128 baseline) ·
TPM/DPAPI credential binding · mTLS · secure token-delivery UX ·
AMP-style UI parity matrix (`CISCO_AMP_360_PARITY_MATRIX.md`) ·
Gate 17 vendor-neutral detection source (design frozen) · Gate 6
retrospection (design complete, blocked on Gate 3 store).

### BLOCKED (9)
By **absence of a production tenant** (owner decision): telemetry
freshness truth · device/customer/user context · any production endpoint
count · production tenant-isolation mutation proof.
By **absence of a real endpoint**: authenticated production heartbeat ·
policy fetch/ACK in production · real production detection/finding ·
investigation on production data.
By **owner hardware**: Gate 1 · Windows real-host onboarding proof
(explicitly *postponed, not waived*).

### NOT_STARTED (4)
Gate 4 offline protection (depends on Gate 3 + Gate 2 journal) · Gate 13
production operations & reliability · Gate 15 backup/recovery/restore
equivalence · P0-D policy provenance on evidence (paused by owner).

### NOT_IMPLEMENTED (capability genuinely absent — 6)
Per the backend registry: **21 capability rows are graded
`NOT_IMPLEMENTED`**, including `network_ui`, `dns_ui`,
`outbreak_control_ui`. Also: **no endpoint-local detection engine, no
local behavioural engine, no local prevention/quarantine, no local ML, no
neural-network inference, no retrospection.** Verified by scanning both
sensors — no detection, prevention, quarantine, kill or isolate
implementation exists in `agents/nivxforge-*/nivxforge_sensor.py`; the
only local policy logic is exclusion evaluation. Detection is
**server-side on delivered telemetry**. Roadmap language must not be read
as capability.

### NOT_WIRED (backend live, no consumer — 8)
1. `/api/edr/findings`, `/findings/{id}`, `/findings/evaluation-state`,
   `/findings/taxonomy` — **P0-C, zero console references in either
   deployed artifact and no `Findings` page or nav entry in source.**
2. `POST /api/edr/enrollment/tokens/{token_id}/revoke` — P0-PROD-2, no
   caller.
3. `/api/edr/exclusions/{id}/approval`, `/{id}/revoke`,
   `/exclusions/enforcement-proof` — the exclusions **list** page exists;
   the P0-B approval authority has no UI.
4. `/api/edr/enrollment/rejections` — no feed.
5. `/api/edr/connector/releases`, `/connector/deployments` — productised
   (`CONNECTOR_PRODUCTIZATION.md`), no console caller.
6. `/api/edr/saved-views` — no caller.
7. `/api/edr/file-trajectory` in the EDR product — implemented, delivered
   only by the XDR-hosted fleet view (F-3). **Files is not native EDR.**
8. `/api/edr/findings/taxonomy` — as (1).

### IMPLEMENTED_NOT_RUNTIME_VERIFIED (34)
The registry's own count: **34 rows graded `BACKEND_IMPLEMENTED`** —
implemented, not runtime verified. This is what the console renders as
`IMPLEMENTED · NOT RUNTIME VERIFIED`, including `detections_ui`,
`process_tree_ui`, `file_trajectory_ui`, `device_trajectory_ui`. These
labels are backend-authored truth, **not stale UI text**.

### IMPLEMENTED_NOT_PRODUCTION_VERIFIED (12 + the whole EDR chain)
**12 rows graded `REAL_ENDPOINT_VALIDATED`** — proven on a real *preview*
endpoint, never in production. Gates 5, 7, 8, 9, 11 fall here for
production purposes: their live proof ran against preview. Also
P0-PROD-2's Windows path (token contract locked by test; no real Windows
host has enrolled) and the Linux sensor (proven in preview, not in fresh
production).

### SUPERSEDED (5)
1. "Blank `XDR_RESPONSE_SERVICE_URL` before republish" → superseded by
   the production loopback rule.
2. "Remove/blank `VERCEL_TOKEN`" → superseded by INERT classification
   with a runtime-scan proof.
3. "Remove/blank `TEST_ANALYST_NIVXLIVE_PASSWORD`" → same.
4. Pre-republish route-parity FAIL (795/862) → superseded by 862/862.
5. Console bundle mismatch / "9fcd53a is what's deployed" → superseded by
   the `f7a2518` promotion.

### UNKNOWN (4)
1. Production replica count at this instant (Scale tier, platform
   autoscaled; deployment pod not readable by the agent).
2. Whether the production `EDR_AUTH_PEPPER` is genuinely independent of
   preview — only the owner can confirm; production booted, which proves
   it is *set and not a placeholder*, not that it is *fresh*.
3. Production tenant-isolation behaviour under mutation — unprovable
   without creating tenants.
4. Whether the disclosed analyst credential has been rotated yet.

---

## 17 · FRONTEND ↔ BACKEND CONTRACT MATRIX

Legend: BE = backend route in production · BND = console API binding ·
PG = page component · NAV = navigation entry · RT = runtime verified
(preview) · PROD = production verified with real data.

| Surface | BE | BND | PG | NAV | RT | PROD |
|---|---|---|---|---|---|---|
| Computers / onboarding | ✔ | ✔ | `EdrComputersPage` | ✔ | ✔ | ✖ (no tenant) |
| Events | ✔ | ✔ | `EdrEventsPage` | ✔ | ✔ | ✖ |
| Detections | ✔ | ✔ | `EdrDetectionsPage` | ✔ | ✔ | ✖ |
| Device Trajectory | ✔ | ✔ | (trajectory view) | ✔ | ✔ | ✖ |
| Process Tree | ✔ | ✔ | `EdrProcessTreePage` | ✔ | ✔ | ✖ |
| Campaign Story | ✔ | ✔ | `EdrCampaignStoryPage` | ✔ | ✔ | ✖ |
| **Findings (P0-C)** | ✔ | **✖** | **✖** | **✖** | ✖ | ✖ |
| **Findings evaluation-state** | ✔ | **✖** | **✖** | **✖** | ✖ | ✖ |
| Policies | ✔ | ✔ | `EdrPoliciesPage` | ✔ | ✔ | ✖ |
| Exclusions (list) | ✔ | ✔ | `EdrExclusionsPage` | ✔ | ✔ | ✖ |
| **Exclusion approve / revoke / proof** | ✔ | **✖** | ✖ | n/a | ✖ | ✖ |
| Downloads | ✔ | ✔ | `EdrDownloadsPage` | ✔ | ✔ | ✖ |
| Audit | ✔ | ✔ | `EdrAuditPage` | ✔ | ✔ | ✖ |
| Response (read) | ✔ | ✔ | `EdrResponsePage` | ✔ | ✔ | fail-closed by design |
| Enrolment (add device) | ✔ | ✔ | `EdrAddDevicePage` | ✔ | ✔ | ✖ |
| **Token revoke** | ✔ | **✖** | ✖ | n/a | ✖ | ✖ |
| **Endpoint commands** | ✔ | ✔ | (within response) | — | partial | ✖ |
| **Enrolment rejections** | ✔ | **✖** | ✖ | ✖ | ✖ | ✖ |
| **Connectors** | ✔ | **✖** | ✖ | ✖ | ✖ | ✖ |
| **Saved views** | ✔ | **✖** | ✖ | ✖ | ✖ | ✖ |
| Files (in EDR) | ✔ (XDR-hosted) | ✖ | reserved | ✔ (N/I) | ✖ | ✖ |
| Hunt · Forensics · Live Query | ✖ | ✖ | reserved | ✔ (N/I) | ✖ | ✖ |
| Network · DNS · Outbreak | ✖ | ✖ | reserved | ✔ (N/I) | ✖ | ✖ |

Nothing above is called complete on the strength of one layer.

---

## 18 · PRODUCTION TRUTH-CHAIN MATRIX

| # | Transition | Impl | Runtime (preview) | Production | Prerequisite | Exact blocker | Mutation? | Owner approval? | Security consequence if faked |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Explicit production tenant | ✔ | ✔ | **✖** | authorised principal | **no tenant exists** | **YES — first production DB write** | **YES** | a "default" tenant would destroy the tenant boundary |
| 2 | Authorised user / tenant membership | ✔ | ✔ | partial (admin exists) | tenant | (1) | yes | yes | cross-tenant access |
| 3 | Enrolment token | ✔ | ✔ | ✖ | tenant | (1) | yes (token doc) | yes | bootstrap authority leak |
| 4 | Endpoint enrolment | ✔ | ✔ | ✖ | token + real host | (3) | yes | yes | rogue endpoint in tenant |
| 5 | Endpoint-scoped credential | ✔ | ✔ | ✖ | (4) | (4) | yes | no | privilege escalation |
| 6 | Authenticated heartbeat | ✔ | ✔ | ✖ | (5) | (5) | yes | no | liveness ≠ delivery confusion |
| 7 | Policy fetch | ✔ | ✔ | ✖ | (5) | (5) | no | no | unenforced policy claimed |
| 8 | Policy ACK | ✔ | ✔ | ✖ | (7) | (7) | yes | no | APPLIED ≠ VERIFIED |
| 9 | Authenticated telemetry | ✔ | ✔ | ✖ | (5) | (5) | yes | no | NO TELEMETRY ≠ BENIGN |
| 10 | Normalisation | ✔ | ✔ | ✖ | (9) | (9) | no | no | silent loss |
| 11 | Detection / finding | ✔ server-side | ✔ | ✖ | (10) | (10) + **no endpoint-local engine** | no | no | NOT_EVALUATED ≠ CLEAN |
| 12 | Evidence + provenance | ✔ | ✔ | ✖ | (11) | (11) | no | no | unfalsifiable evidence |
| 13 | Investigation | ✔ | ✔ | ✖ | (12) | (12) | no | no | fabricated narrative |
| 14 | Approved response | ✔ | ✔ | ✖ | (13) | **P0-PROD-4** | yes | **YES** | destructive action without authority |
| 15 | Dispatch | ✔ | ✔ (preview localhost) | **✖ refused** | authority URL | **P0-PROD-4** | no | yes | action on wrong host |
| 16 | Endpoint execution | ✔ | ✔ | ✖ | (15) | (15) | yes | yes | ACCEPTED ≠ EXECUTED |
| 17 | Result reported | ✔ | ✔ | ✖ | (16) | (16) | yes | no | false success |
| 18 | Independent verification | ✔ | ✔ | ✖ | (17) | (17) | no | no | EXECUTED ≠ VERIFIED |

Steps 1–13 are blocked **only** by the tenant/endpoint decision. Steps
14–18 are blocked by **P0-PROD-4**, correctly and deliberately.

---

## 19 · SECURITY-CRITICAL OUTSTANDING WORK

1. **Rotate the disclosed analyst credential** (`analyst@nivx-live`) —
   exposed in a chat screenshot. No production effect (the key is inert),
   so hygiene, not incident.
2. **Confirm the production `EDR_AUTH_PEPPER` is genuinely fresh** —
   UNKNOWN to the agent; a copied preview pepper would make
   preview-issued endpoint credentials verifiable in production.
3. **P0-PROD-4** — destructive response has no production authority.
   Currently fail-closed, which is correct.
4. **P0-PROD-6** — four in-process loops (nightly benchmark, LOLBAS
   refresh, confusion-matrix prewarm, FileStore retention sweeper) run in
   **every replica**; production is autoscaled from 2. None is required
   for any synchronous route.
5. **Endpoint credential at rest** — filesystem permissions only
   (`0600` / SYSTEM+Administrators ACL). No TPM/DPAPI. Root/SYSTEM on the
   host can impersonate that endpoint until revocation.
6. **No mTLS** — transport is TLS + bearer secrets.
7. **13 stale live-contract test defects** in the Gate 14 security suite
   — test defects, not product defects, but they blunt the signal.

---

## 20 · PRODUCTION-BLOCKING WORK

**Blocking the first production tenant: nothing technical.** It is an
owner decision plus two values (tenant id, display name).

**Blocking the first real endpoint:** a real host, a production-minted
token, and the sensor package from `/api/edr/onboarding/packages`
(Windows still awaits owner hardware — Gate 1).

**Blocking an honest end-to-end production claim:** P0-PROD-4 (steps
14–18) and at least one real detection produced from real production
telemetry.

---

## 21 · NON-BLOCKING HARDENING
TPM/DPAPI · mTLS · secure token-delivery UX · P0-PROD-6 · Gate 10 p95
and failure injection · Gate 12 mobile · Gate 13 production operations ·
Gate 15 backup/restore · harness debt sweep.

## 22 · UI / PRODUCT-COMPLETENESS BACKLOG
Findings page + evaluation-state badge + taxonomy · token revoke ·
exclusion approve/revoke/enforcement-proof · enrolment rejections feed ·
connector surfaces · saved views · events saved searches / deep links /
CSV · `[object Object]` freshness render fix · Files native to EDR (F-3)
· Network/DNS/Outbreak (need backends first) · Hunt/Forensics/Live Query
· AMP parity matrix.

## 23 · TEST / HARNESS DEBT
Frozen baseline `BASELINE_PYTEST_PRE_P0PROD2.json`: **12,767 run ·
11,807 passed · 547 failed · 128 errored**, plus 3 collection-aborting
modules. Classification:
- **TEST/FIXTURE DEFECT** — closed event loops, a `_Cached` stub missing
  `raise_for_status`, unauthenticated fixture bootstrap, duplicate-key
  seeds, a missing `/tmp/SEP.csv`, xdist worker-id parametrisation,
  duplicate module basename, a missing `ImpactScoringEngine` import.
- **STALE TEST EXPECTATION** — the 13 Gate 14 live-contract defects.
- **LIVE EXTERNAL DEPENDENCY** — suites that dial the preview host.
- **PRODUCT DEFECT** — none identified.
Correction recorded: the earlier "28 failed / 18 errors" was a *scoped*
run, superseded by the full-suite freeze. No full suite was run for this
reconciliation.

---

## 24 · OWNER DECISIONS REQUIRED (only genuine ones)

1. **Production tenant id + display name** — the agent must not derive or
   invent one.
2. **Authorisation for the first production DB write** (tenant creation).
3. **Authorisation to enrol the first real endpoint**, and which host
   (Linux now, or wait for a Windows host — Gate 1).
4. **Authorisation to open P0-PROD-4**, including where the production
   response authority will live (private address, not loopback).
5. **Authorisation for P0-PROD-6** worker/topology changes.
6. **Rotate the disclosed analyst credential** — yes/no, when.
7. **Confirm the production pepper is fresh** — owner-only knowledge.
8. **Sequencing choice**: build the Findings UI *before* the first tenant
   (so the first real finding is visible when it arrives) or *after*.

---

## 25 · PRIORITISED QUEUE

**P0 — security / correctness**
1. Confirm production `EDR_AUTH_PEPPER` freshness (UNKNOWN).
2. Rotate the disclosed analyst credential.
3. Keep destructive response fail-closed until P0-PROD-4 (no action —
   guard against regression).

**P1 — required for real production end-to-end**
1. Create the explicit production tenant (owner decision + first write).
2. Mint a production enrolment token and enrol one real endpoint.
3. Prove authenticated heartbeat → policy fetch/ACK → telemetry in
   production.
4. P0-PROD-4 response authority (before any destructive action).

**P2 — product / operator completeness**
1. **Findings UI** — the P0-C surface, including `NOT_EVALUATED` ≠
   `CLEAN`. Highest-value UI gap in the programme.
2. Token revoke button.
3. Exclusion approve / revoke / enforcement-proof UI.
4. Enrolment rejections feed.
5. `[object Object]` freshness render fix.
6. Connector + saved views surfaces.

**P3 — hardening / future**
1. P0-PROD-6 replica safety.
2. Gate 12 mobile; Gate 10 p95 + failure injection.
3. TPM/DPAPI, mTLS, token-delivery UX.
4. Gate 2 endpoint event journal; Gate 3 ML/correlation; Gate 4 offline
   protection; Gate 6 retrospection; Gate 13; Gate 15; P0-D; Network/DNS;
   AMP parity.

---

## 26 · DEPENDENCY GRAPH (condensed)

```
OWNER: tenant id/name
   └─> production tenant ────┬─> enrolment token ─> real endpoint enrolment
                             │        └─> endpoint credential ─> heartbeat
                             │                 ├─> policy fetch ─> policy ACK
                             │                 └─> telemetry ─> normalisation
                             │                          └─> detection/finding
                             │                                   ├─> evidence
                             │                                   └─> investigation
                             │                                          └─> P0-PROD-4
                             │                                               └─> dispatch
                             │                                                    └─> execution
                             │                                                         └─> result
                             │                                                              └─> independent verification
                             └─> (parallel, no dependency) Findings UI · token revoke ·
                                 exclusion approval UI · rejections feed · freshness fix

INDEPENDENT OF THE CHAIN: P0-PROD-6 · Gate 12 mobile · Gate 10 · TPM/DPAPI ·
                          mTLS · Gate 2 journal · Gate 3 ML · Gate 4 · Gate 6
```

Note the useful fact: **every P2 UI item is off the critical path.** None
of them blocks the tenant or the first endpoint.

---

## 27 · RECOMMENDED NEXT ONE ACTION

**Create the explicit production tenant** — owner supplies the id and
display name, the agent prepares the exact authenticated API call, the
owner approves, and it runs through the authoritative registry (not a DB
insert). It is the single unblocker for 13 of the 18 truth-chain steps,
it is small, and it is auditable.

**Exact blocker to that action:** owner decision only — the tenant
identity and authorisation for the first production DB write.

**Strong second, if the owner prefers to read before writing:** build the
**Findings UI** first, so that when the first real finding arrives it is
visible rather than invisible. It touches no production data.

---

## 28 · EXACT STOP POINT

Stopping here. Nothing was created, modified, deployed, enrolled,
rotated, enabled or executed.

```
CHANGES MADE
  Code: 0 · Production DB: 0 · Tenant: 0 · Endpoint: 0 · Secrets: 0
  Environment configuration: 0 · Commits: 0 · Pushes: 0
  Deployments: 0 · Response actions: 0
```
