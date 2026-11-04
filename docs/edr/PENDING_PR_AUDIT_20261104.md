# Pending PR audit — 2026-11-04

Repository: jpreddy017/nivxray-xdr
Production branch inspected: phase2/edr-production @ a159b86a4b836965cd1e304dd08ff48962da6cb8

41 open PRs. Open status is not a deployment queue. Ancestry was checked individually against the production SHA. GitHub compare file lists are capped at 300; a 300-file result is not a complete change inventory.

| PR | Title | Ancestry versus production | Current disposition |
|---|---|---|---|
| #56 | Add EDR file investigation workspace and multi-computer trajectory | ahead; 3 ahead / 0 behind | File evidence candidate plus Device Trajectory picker/theme corrections; targeted tests pass. Full backend/live validation and remaining capability gaps outstanding. |
| #54 | Protect incident consolidation against concurrent updates and tenant collisions | diverged; 3 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #53 | Resume detection citation writes without duplicating protected endpoint evidence | diverged; 9 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #52 | Preserve canonical evidence across stable authenticated endpoint retries | diverged; 5 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #51 | Prevent duplicate single-event correlation writes for stable tenant-scoped replay | diverged; 3 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #50 | Resume bounded reconciliation across restarts and historical owned evidence | diverged; 9 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #49 | Cache successful empty authored-rule snapshots to avoid per-event database reads | diverged; 2 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #48 | fix(edr): prevent incomplete detection from becoming a no-match result | diverged; 3 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #47 | fix(edr): refresh device overview and report telemetry counts accurately | diverged; 6 ahead / 4 behind | Pending bounded integration/retest; not included in this candidate. |
| #46 | fix(edr): renew active worker leases and cancel on ownership loss | diverged; 4 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #45 | fix(edr): accept concurrent raw-event redelivery safely | diverged; 2 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #44 | fix(edr): distinguish freshness threshold from declared cadence | diverged; 1 ahead / 4 behind | Pending bounded integration/retest; not included in this candidate. |
| #43 | Make EDR processing concurrency configurable with unchanged default | diverged; 2 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #42 | fix(sensor): selectively port journal recovery and bounded drain waits to M1 | diverged; 73 ahead / 65 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #41 | feat(edr): record attempt-scoped backend processing timings | diverged; 4 ahead / 4 behind | Backend/worker chain: individual PR reports tests, but combined retry/completion semantics, integration regression and canary remain outstanding. No worker-count change. |
| #40 | fix(edr): make partial trajectory history and next-page control visible | diverged; 2 ahead / 4 behind | Exact patch integrated into File Trajectory candidate; source baseline SHA verified equal. Targeted React regression passes. Preview/build verification pending. |
| #31 | feat(edr): add read-only endpoint File Trajectory slice | diverged; 6 ahead / 21 behind | Reconciled source is represented in PR56; do not independently merge without comparison. |
| #29 | Align EDR Device Trajectory navigation, filters and header with AMP | behind; 0 ahead / 28 behind | Already in production ancestry; no code merge needed. PR closure not performed. |
| #27 | [G4][REVIEW ONLY] Signed Windows ACE mask correction — native installer candidate | diverged; 70 ahead / 65 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #25 | G4-A2 fix: TrustedInstaller ancestor ACE on stock Program Files — REVIEW HOLD | diverged; 72 ahead / 65 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #24 | [G4-A1][HOLD] Windows ancestor ACL false-refusal repair + protected bootstrap root | diverged; 68 ahead / 65 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #22 | Integrate exact G3-approved M1 into one Windows installer and build real EXE | diverged; 63 ahead / 65 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #21 | P0-3: retire broken PowerShell installer for new Windows deployments | diverged; 61 ahead / 65 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #20 | Windows installer: refuse bad enrollment before mutations + safe EXE build workflow | diverged; 59 ahead / 65 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #19 | [SECURITY] Windows installer CI: manual-only; quarantine SCM native gates | diverged; 53 ahead / 65 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #18 | NivXForge Windows re-enrolment recovery — installer safety and CI (HOLD) | diverged; 27 ahead / 378 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #17 | [DRAFT] EDR: keep customer selector available for TENANT_REQUIRED | diverged; 26 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #16 | [DRAFT] N-3A: scoped BSON serialization repair for recent telemetry | diverged; 25 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #15 | [HOLD] Prepare isolated Stage1 staging deployment package | diverged; 22 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #14 | [HOLD] diagnose staging contract drift and repair legacy inline analysis | diverged; 17 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #13 | [HOLD] close independent command review findings and RC22 gate | diverged; 16 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #12 | [HOLD] bounded static Command Intelligence maturity improvements | diverged; 14 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #11 | [HOLD] XDR automatic command intelligence in Universal Decoder | diverged; 10 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #10 | chore: organize four product owners in the existing monorepo | diverged; 10 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #9 | [NO-GO] XDR RC2: integrate scope repair and Mongo validation | diverged; 7 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #8 | [NO-GO] XDR RC1: dashboard and authorization integration candidate | diverged; 5 ahead / 378 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #7 | E3: validate engines and preserve trajectory evidence identity | diverged; 5 ahead / 145 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #6 | Validate E3 trajectory cursors and add deterministic engine/UI CI | diverged; 2 ahead / 145 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #5 | fix(edr): make failed clean install atomic | diverged; 1 ahead / 61 behind | Windows installer/sensor lineage: reconcile supersession and native Windows gates before release; not a web deployment. |
| #2 | Fix authority-derived tenant selector | diverged; 3 ahead / 240 behind | Separate/older release lineage: reconcile current source and existing HOLD/NO-GO findings before any merge. |
| #1 | Feature/rc2 alignment | behind; 0 ahead / 208 behind | Already in production ancestry; no code merge needed. PR closure not performed. |

## Immediate Device Trajectory repair

The /edr/device-trajectory route previously requested an endpoint list before the surrounding console completed customer authorization and swallowed directory failures. The surface also forced dark theme. The candidate now mounts standalone trajectory content inside the console authorization gate, uses the existing computer directory, explicitly displays loading/empty/error/retry states, rejects stale customer responses in the picker, preserves query parameters on device choice, and follows the console theme. Existing evidence/trajectory query semantics are preserved.

PR29 is already an ancestor of production. Earlier advice that its open state meant its changes were absent was incorrect.

## Deployment decision

Not ready for combined production promotion. The backend repair PRs explicitly leave stage replay and truthful queue completion unresolved; frontend build success cannot satisfy these gates. No production services, sensor settings, queues, databases or evidence were changed. No PR was closed or marked merged by this audit.

## Validation performed for this increment

- Actual endpoint-picker React component: loading, 403, retry, empty response, malformed response, stale customer response, selection and listener cleanup.
- Actual legacy Device Trajectory JSX transforms successfully; full application build is checked by the candidate preview.
- PR40 actual React component: initial partial count, pagination placement, failure preserves events, retry cursor, 200-to-400 accumulation and exhausted cursor.
- Existing File Trajectory React/model suites remain part of candidate validation.

Native Windows and authenticated backend acceptance are not claimed.
