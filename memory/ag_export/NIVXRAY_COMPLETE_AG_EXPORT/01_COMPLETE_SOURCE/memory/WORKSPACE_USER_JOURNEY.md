# NivXRay · Workspace User Journey

**Status**: DRAFT v1.0 — companion to `ANALYST_WORKSPACE_BLUEPRINT.md`
**Implementation authorization**: NOT GRANTED (requires ARB approval alongside blueprint)
**Purpose**: Validate that the Workspace design produces coherent, efficient analyst experiences for every persona and mode BEFORE any code is written.
**Date**: 2026-08-04

> Blueprint describes the architecture. **This document validates the experience.** Every journey must be walkable step-by-step on paper before a single React component is built.

---

## 1 · Journey Overview

| # | Journey | Persona | Mode | Target Duration |
|---|---|---|---|---|
| J1 | Tier-1 Triage | Tier-1 | Quick Triage | 30-90 seconds |
| J2 | Standard Investigation | Tier-1 → Tier-2 | Investigation | 5-15 minutes |
| J3 | Deep Investigation | Tier-2/3 | Deep Analysis | 30 min - 4 hours |
| J4 | Executive Report | Tier-2/3 or Manager | Investigation → Reported | 1-3 minutes after Completed |
| J5 | Reopen & Iterate | Tier-2/3 | Investigation | Variable |

Every journey happens **inside the single `/investigate` Workspace**. Zero cross-page navigation.

---

## J1 · Tier-1 Triage Journey (target: 30-90s)

**Trigger**: SOC L1 receives an alert from SIEM/EDR containing an obfuscated command line.

| Step | Action | Workspace State | Persistence Written |
|---|---|---|---|
| 1 | Analyst clicks alert link → `/investigate?case_id=CS-2026-08-04-0001&mode=quick_triage` | Case: New · Mode: Quick Triage · Lens: Summary (default) | Case row created |
| 2 | Workspace auto-populates input from alert; auto-clicks Investigate | Case: New → **Collecting** | State transition logged |
| 3 | Convergence completes; Certificate emitted | Case: Collecting → **Correlating** | State transition logged |
| 4 | Summary lens renders: Verdict · Risk · Top 3 IOCs · Top 3 Recommended Actions | Case: Correlating → **Reviewing** | Workspace state saved |
| 5 | Analyst reads Summary. If sufficient, marks **Completed**. Case is triaged. | Case: Reviewing → **Completed** | Audit-log entry |

**Success criteria**:
- ≤ 2 clicks from alert URL to actionable Summary
- Analyst can complete triage without opening any other lens
- All 3 IOCs and 3 recommended actions clickable → drill into Evidence (§8.4) if analyst wants proof

**Failure modes to guard against**:
- Summary hides a critical IOC → mitigated by "top 3" always being the 3 highest-severity IOCs by score
- Verdict feels black-box → mitigated by verdict badge being clickable, opening Story lens

---

## J2 · Standard Investigation Journey (target: 5-15 min)

**Trigger**: Alert requires more than a triage look — L1 escalates within the same Workspace by switching mode.

| Step | Action | Workspace State | Persistence Written |
|---|---|---|---|
| 1 | Analyst arrives in Quick Triage (J1 step 4), sees a Cobalt Strike download cradle | Case: Reviewing · Mode: Quick Triage | — |
| 2 | Clicks **Investigation** mode toggle | Case: Reviewing · Mode: **Investigation** | Mode change persisted · no page reload · no data refetch |
| 3 | Summary + Story + Timeline lenses now visible; Story shows ordered attack narrative | Same case, expanded disclosure | — |
| 4 | Analyst clicks an IOC in Summary → drills to Evidence lens with that IOC highlighted (Amendment A6) | Lens: **Evidence** · selected element: IOC · scroll: pinned to IOC panel | Persistence: selected evidence saved |
| 5 | Reviews Convergence Certificate provenance for that IOC · confirms deterministic decode chain | Same lens · Certificate panel expanded | Persistence: scroll saved |
| 6 | Returns to Story via top nav; state restored (scroll position, selected IOC still highlighted) | Lens: Story · IOC selection preserved | — |
| 7 | Applies MITRE filter to Timeline (e.g. show only T1059.001 events) | Lens: Timeline · filter active | Persistence: filter saved |
| 8 | Marks case Completed | Case: Reviewing → **Completed** | Audit-log entry |

**Success criteria**:
- Mode switch (Quick Triage → Investigation) is instant and preserves all state
- Every claim in Summary/Story drills to Evidence in 1 click
- Filters persist so an interrupted analyst returns to the exact same view

---

## J3 · Deep Investigation Journey (target: 30 min - 4 hr)

**Trigger**: Sample requires forensic-grade investigation — Tier-2/3 opens directly in Deep Analysis mode.

| Step | Action | Workspace State | Persistence Written |
|---|---|---|---|
| 1 | Analyst opens `/investigate?case_id=CS-…&mode=deep_analysis` | Mode: **Deep Analysis** · Lens: **Evidence** (default for this mode) | Case row created |
| 2 | Evidence lens opens with Certificate + human_trace expanded, all iterations visible | — | — |
| 3 | Analyst scrubs Timeline to iteration N-3, sees which transformations fired there | Timeline pos saved · Lens active | Persistence: timeline position |
| 4 | Clicks a transformation name → drills to Certificate row for that transformation | Certificate lens · row highlighted | — |
| 5 | Opens Related Samples panel → sees other CS samples using the same transformation | Related-samples panel open | — |
| 6 | Analyst is interrupted, closes browser | State persisted server-side | Full state snapshot saved |
| 7 | 3 hours later returns to same case URL | Restored: mode, lens, scroll, timeline position, filters, selected evidence, related-samples panel | Read on load |
| 8 | Continues from exact previous state | — | — |
| 9 | Marks Completed → generates Executive Report (J4) | Case: Completed | Audit-log entry |

**Success criteria**:
- Full persistence on interrupt/return (Amendment A5)
- Deep evidence navigation never breaks the "one Workspace" principle (P5)
- Every element in Evidence lens is traceable to a Convergence Certificate row

---

## J4 · Executive Report Journey (target: 1-3 min post-Completed)

**Trigger**: Case marked Completed; analyst needs to generate stakeholder report.

| Step | Action | Workspace State | Persistence Written |
|---|---|---|---|
| 1 | Analyst opens **Exports** lens | Lens: Exports · Case: Completed | — |
| 2 | Sees deterministic-format buttons: PDF · DOCX · STIX · Sigma · KQL · IOCs | — | — |
| 3 | Clicks PDF · Executive Report generates from L2 executive_summary + attack_story + IOCs + MITRE + Recommendations (each an evidence-anchored section) | Case: Completed → **Reported** | Audit-log entry |
| 4 | PDF downloads; case state now Reported and locked | — | Audit-log finalized |
| 5 | (Optional) Clicks Sigma / KQL / Splunk to grab deployable detections | — | Downloads only, no state change |

**Success criteria**:
- ≤ 1 click per export
- Every PDF section anchored to specific evidence (courtroom-defensible)
- Two exports of the same case produce **byte-identical** PDFs (P10)

---

## J5 · Reopen & Iterate Journey

**Trigger**: New intel arrives about a case previously marked Reported.

| Step | Action | Workspace State |
|---|---|---|
| 1 | Analyst opens the case, clicks **Reopen** | Case: Reported → **Reopened** → **Correlating** |
| 2 | New evidence added (e.g. new IOC surfaced by threat feed enrichment) | Correlation re-runs |
| 3 | Analyst continues investigation | Case: Correlating → Reviewing |
| 4 | Full audit trail preserved: original Report timestamp, reopen event, re-report | Full audit chain |
| 5 | Marks Completed again → new Report version generated | Case: Reviewing → Completed → **Reported (v2)** |

**Success criteria**:
- Original report artifact never overwritten (audit integrity)
- Every reopen is a first-class transition in the state machine (§8.1)

---

## 2 · Cross-Cutting Journey Guarantees

For **every** journey above:

| Guarantee | How Enforced |
|---|---|
| Same Workspace throughout | Single `/investigate` route (P5) |
| Zero page reloads on mode / lens / filter changes | Client-side state · server-side persistence |
| Every UI element traceable to evidence | Evidence Navigation Contract (§8.4) |
| Interrupt-and-return preserves full state | Persistence Contract (§8.3) |
| State transitions audit-logged | State Machine endpoint (§10 · A7) |
| Two identical investigations yield byte-identical Reports | Deterministic L0-L2 chain (P10) |

---

## 3 · Journey Failure Modes to Test Against Before Implementation

Before PR-1 begins, the following experience defects must be explicitly ruled out on paper:

- **F1**: Analyst opens a case, mode = Quick Triage. Summary shows verdict but no reason. Analyst asks "why?" and finds no drill-through. → **Fail** (violates P9). Guard: verdict badge is clickable → Story lens.
- **F2**: Analyst switches from Investigation to Deep Analysis mid-case. The Deep Analysis view refetches all evidence and analyst loses selected IOC. → **Fail** (violates A4, A5). Guard: mode switch is client-side, evidence cache preserved.
- **F3**: Analyst filters Timeline to T1059.001, then clicks an IOC. Clicking the IOC clears the filter. → **Fail** (violates A5). Guard: filters are lens-scoped; IOC drill preserves filter state.
- **F4**: Analyst reopens a case after a week; sees the original mode/lens/filters but the evidence is a different iteration. → **Fail** (violates P10). Guard: persistence stores case + workspace state; case is immutable once Completed (only Reopen creates a new transition).
- **F5**: Exec Report PDF differs between two exports of same case. → **Fail** (violates P10). Guard: PDF generator is deterministic from evidence + registry only.

---

## 4 · Journey Approval Gate

Before PR-0 sign-off, the ARB must confirm:

- [ ] J1 Tier-1 Triage is walkable in ≤ 90 seconds using only Workspace primitives
- [ ] J2 Standard Investigation preserves full state across lens/mode changes
- [ ] J3 Deep Investigation supports full interrupt-and-return
- [ ] J4 Executive Report is 1-click per export, evidence-anchored, byte-identical
- [ ] J5 Reopen produces a proper audit trail with immutable original report
- [ ] F1-F5 failure modes are all guarded

Only after this journey document AND the blueprint are both approved does PR-0 sign-off happen. Only after PR-0 sign-off does PR-1 begin.

---

**End of Journey Document · Awaiting ARB Review**
