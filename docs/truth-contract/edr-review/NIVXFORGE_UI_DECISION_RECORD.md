# NivXForge · UI Decision Record (UDR-2026-09-05)

> **Mode:** READ-ONLY documentation. No code / tests / configs / UI changed. UI freeze in force. **Step 3 remains NOT authorized.**
> **Basis:** owner review of `NIVXFORGE_UI_SIDE_BY_SIDE_REVIEW.md` + `NIVXFORGE_UI_GAP_MATRIX.md`.
> **Verdict:** **UI direction APPROVED with three explicit conditions.**

---

## 0 · Authoritative architectural wording (owner correction, incorporated)

> **NivXRay XDR is the authoritative SOC operator experience.** Existing NivXRay research / analysis capabilities remain available as specialized research surfaces and are **not duplicated inside the XDR operator console unless operationally required.**

This supersedes any earlier wording that could have been read as the main NivXRay SPA "retreating". Nothing is thrown away. Decoder Cockpit, Command Analyzer, Sample Library, Model Studio, Lab, Batch Test, IEDDE Trace, Benchmark, Multi-Layer Battery, Knowledge Base, Docs, Threat Model, Compare, Corrections Admin, Analyst-workspace/RC5 remain first-class research surfaces on the existing main SPA and are reachable from the XDR operator shell only when operationally required for an investigation.

## 1 · Reserved placeholders — DECISION: REMOVE / REPLACE

- **Affected files:** `apps/nivxray-xdr/src/xdr/pages/XdrReservedPage.jsx`, `apps/nivxray-xdr/src/nivxforge/pages/EdrReservedPages.jsx`.
- **Rule:** no operational surface may present a "coming soon" placeholder that implies enterprise capability is available when it is not. This violates the Honest-State invariant (`NO AUTHORITATIVE EVIDENCE RECORDED`).
- **Action (queued for post-Step-3 UI slot):** either
  - **(a)** connect each reserved slot to its real implementation (once the corresponding backend surface exists and the UI freeze is lifted for it), OR
  - **(b)** remove the file and the operator-navigation entry entirely.
- **Interim state (Gate 0.5):** file remains untouched (UI freeze). No misleading link is added; existing navigation is unchanged. Analysts continue to see the same surface they see today.
- **Ban:** no new placeholder / stub / "coming soon" component may be added in any Phase.

## 2 · Investigation Workspace — DECISION: ONE canonical NivXRay XDR workspace

- **Canonical location (target):** the AG 8-tab `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` (58,988 B, 1,104 LOC) becomes THE Investigation Workspace after it lands via Step 3.
- **Canonical 8-tab ordering (locked):**
  1. **Attack Story** (causal narrative)
  2. **Device Trajectory** (5-lane microsecond window)
  3. **Process Ancestry** (parent → child tree)
  4. **Evidence Graph** (IKG projection + provenance)
  5. **Security State & Causal FSM** (rc5 / `backend/security_state/` FSM read-side)
  6. **Artifacts / Hashes** (Canonical Evidence surface)
  7. **Deterministic Verdict** (verdict_stage2 output + rationale)
  8. **MITRE ATT&CK** (technique heatmap + evidence backlinks)
- **Retired at consolidation time:**
  - `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx` (functionality migrated into the 8-tab)
  - `frontend/src/v2/pages/InvestigationWorkspace.jsx` (functionality migrated; then the main-SPA page redirects to the XDR workspace)
- **Migration rule:** any capability present on either retired page that is NOT already in the 8-tab MUST be migrated into the correct tab **before** the retired page is removed. No feature regression.
- **Interim state:** all three files remain untouched until Step 3 + UI-freeze lift are authorized.

## 3 · Evidence Explorer — DECISION: keep the richer implementation, absorb useful AG capabilities

- **Canonical owner (locked):** main-SPA `frontend/src/pages/EvidenceExplorerPage.jsx` — the richer existing implementation — is the authoritative Evidence Explorer.
- **AG-side contribution:** `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` (imported at Step 3) contributes any capability the main-SPA page does not have. Contributions are **absorbed into the canonical page**, not the other way around.
- **XDR-shell integration:** `XdrEvidenceRefPage.jsx` (the current thin stub) is retired at consolidation; the XDR shell embeds/routes to the canonical Evidence Explorer under the Investigate plane so operators never leave the XDR console.
- **Migration protocol:** produce a per-feature diff between the two implementations at Step-3 time; each AG-side feature that does not exist on the canonical page is added deliberately (no wholesale replacement). No functionality regressions permitted.
- **Interim state:** both files remain untouched.

## 4 · Locked architectural shape (result of decisions 1-3)

```
                    NivXRay XDR (authoritative SOC operator experience)
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
           DETECT               INVESTIGATE               RESPOND
              │                      │                      │
        Dashboard              Incident Detail          Approvals
        Incidents              8-Tab Workspace          Playbooks
        Detections             Evidence Explorer        Automation
        Rule Studio            Attack Story             Live Query (add)
        MITRE ATT&CK           Attack Graph             Forensics (add)
        Threat Intel           Device Trajectory        Response Drawer
        Threat Hunting (add)   Process Tree             Verification (add)
                               Endpoint Entity 360      Sandbox (Phase 4)
                               User Entity 360 / UBAE
                               Files/Net/DNS/Reg (add)
                                     │
                                     │ (operationally when required)
                                     ▼
                    Research surfaces (main NivXRay SPA)
                    Decoder Cockpit · Sample Library · Model Studio ·
                    Lab · Batch Test · IEDDE Trace · Benchmark ·
                    Compare · Corrections Admin · Knowledge Base ·
                    Threat Model · Analyst RC5 · Multi-Layer Battery
```

One investigation cockpit. Three planes. Sandbox is an evidence tab and Phase-4 subsystem, not a second app. UBAE is a badge overlay on Entity 360, not a second console. Research surfaces preserved on the main SPA — reachable from the XDR shell only when operationally required.

## 5 · Honest-state invariants (locked · never negotiated)

- No placeholder / "coming soon" surface may ship in an operator-facing plane.
- Empty states display `NO AUTHORITATIVE EVIDENCE RECORDED`, not fabricated data.
- No prototype data leaks into production unless labelled with the persistent `REPRESENTATIVE / PROTOTYPE DATA` badge per AG IA spec §1.1.
- Any surface whose backend data source does not yet exist stays hidden (route guarded by feature flag) until the source is live and verified.

## 6 · What this decision record does NOT do

- Does NOT modify any pod file.
- Does NOT authorize Step 3.
- Does NOT lift the UI freeze.
- Does NOT authorize any AG-file import, conflict resolution, or Phase 1 work.
- Does NOT modify the AG master export.
- Does NOT amend Truth Contract v1, v2, or v3.

## 7 · Standing state

- ✅ Preservation tag `preserve-pre-alignment-2026-09-05` intact at SHA `06b56144…`
- ✅ Immutable Truth v1 SHAs unchanged (`061fd851…` MD, `295d1e70…` JSON)
- ✅ AG master export unchanged (SHA `ba06f99d…aa1f`)
- ✅ Preservation manifest, alignment index, Truth v3, Gate 0.5 closure, Master reconciliation, UI Side-by-Side, UI Gap Matrix — all pinned to GitHub
- ✅ Zero pod frontend / decoder / content-fabric / reasoning-engine drift
- ⛔ Step 3 · Conflict resolution · UI freeze · Phase 1 — ALL blocked pending owner review of this UDR
- ⛔ Truth Contract v3 not yet committed to GitHub (pending Save-to-Github with this UDR)

## 8 · Next authorized event (only after owner Save-to-Github of this UDR)

Owner reviews & confirms this record → clicks Save-to-Github → verified commit-pinned → then and only then may Step-3 authorization be considered.

## END · UDR-2026-09-05 delivered · read-only · awaiting Save-to-Github + Step-3 authorization
