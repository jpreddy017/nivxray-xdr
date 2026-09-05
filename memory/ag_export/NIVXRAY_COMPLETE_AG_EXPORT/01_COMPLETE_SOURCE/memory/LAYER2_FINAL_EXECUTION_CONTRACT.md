# Layer 2 · FINAL Execution Contract

**Locked** · Owner directive · 2026-02-32
**Status** · This is the last word.  No more preference questions.

---

## Reference hierarchy (owner-locked · 2026-02-32)

- **Primary** — Microsoft Defender XDR (NivXRay is an XDR platform,
  so Defender is the strongest end-to-end reference).
- **Secondary** — ServiceNow SIR (case-management / workspace /
  lifecycle patterns).

Reference URLs:
- Defender · Incident Queue: https://learn.microsoft.com/en-us/defender-xdr/incident-queue
- Defender · Manage Incidents: https://learn.microsoft.com/en-us/defender-xdr/manage-incidents
- Defender · Investigate Incidents: https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents
- SIR · Workspace Landing: https://www.servicenow.com/docs/r/security-management/security-incident-response/sir-workspace-landing-page.html
- SIR · New UI: https://www.servicenow.com/docs/r/xanadu/security-management/security-incident-response/sir-new-ui.html

### Reference-to-area mapping (use as the design decision matrix)

| NivXRay area | Primary reference |
|---|---|
| XDR overall experience | **Defender XDR** |
| Incident Queue | **Defender XDR** |
| Detection → Incident workflow | **Defender XDR** |
| Investigation workspace | **Defender XDR** |
| Evidence / context presentation | **Defender XDR** + NivXRay evidence-first model |
| MITRE / attack investigation | **Defender XDR** |
| Incident record | Defender XDR + ServiceNow SIR |
| Case lifecycle | **ServiceNow SIR** |
| Assignment / ownership | **ServiceNow SIR** |
| SLA / workflow | **ServiceNow SIR** |
| Tabs / workspaces / operational actions | Both |
| Visual design / theme | Both — pick what works best |

The goal is **Defender-level XDR usability + SIR-level incident
workflow + NivXRay's evidence-first architecture + NivXRay's own
visual identity.**  Never a clone of either.

---

## Verbatim owner instruction

> Read the locked Layer 2 mandate and execute it end-to-end.
>
> Use Microsoft Defender XDR + ServiceNow SIR as the primary UX
> benchmarks.  Do not inherit NivXRay's current black theme.  Make
> the complete visual-system decision yourself and build the
> strongest enterprise SOC experience.
>
> **Do not ask me to choose theme, colours, layout, columns, chip
> styles, spacing, buttons, or other cosmetic/UX decisions.**
>
> Build the queue as a first-class analyst workspace, not a
> cosmetic enhancement:
>
> `Queue → priority/attention strip → toolbar/filtering → dense
> incident table → preview/peek experience → investigation context`
>
> Implement all Layer 2 requirements, verify them on the deployed
> application, capture the required acceptance screenshots, and ship.
>
> **ABSOLUTE ENGINE LOCK**: do not modify, rename, replace, rewrite,
> duplicate, or reimplement any existing investigation/detection/
> correlation engine.  The rebuild is allowed to change the
> presentation and analyst workflow around existing APIs/data only.
>
> Missing data remains honest: `UNKNOWN` · `NOT_RUN` · `—` · `NO
> EVIDENCE` · `NOT AVAILABLE`.
>
> Preserve:
> - `/xdr/incidents` → primary analyst landing
> - `/xdr/mss-dashboard` → separate Command Center
>
> **Study → Design → Implement → Verify → Ship.**
>
> Do not stop at `yarn build`.  The deployed UI and the acceptance
> screenshots are the completion gate.

---

## Execution flow the next session must follow (no deviation)

1. **Study** — Open and read (in order):
   - `/app/memory/LAYER2_QUEUE_REBUILD_MANDATE.md`
   - Defender Queue · Manage · Investigate references
   - SIR Workspace · New UI references

2. **Design** — Make the entire visual-system decision (theme ·
   colours · surfaces · typography · spacing · cards · borders ·
   buttons · dropdowns · filters · chips · tables · tabs · toolbars ·
   drawers · states · empty states · hierarchy · responsive
   behaviour) **without asking the owner**.

3. **Implement** — Build in `/app/apps/nivxray-xdr/src/`:
   - 6 chip families in `xdr/components/chips/`
   - Priority strip · toolbar · time selector · Customize Columns ·
     preview drawer · CSV export · responsive dense table
   - Rebuild `xdr/pages/XdrIncidentsPage.jsx` from scratch around
     existing `/api/incidents` + `/api/xdr/dashboard/tiles` +
     `/api/xdr/mss/*` APIs.
   - **Do not touch** the backend.  Do not touch any engine.

4. **Verify** — On the deployed URL `https://nivxray-xdr.vercel.app/xdr/incidents`
   after `git push origin main` completes Vercel build:
   - Full queue screenshot
   - KPI strip + toolbar screenshot
   - Customize Columns dropdown open
   - Filtered queue with chip visible
   - Right-side preview drawer open on a real incident
   - Bulk-selection state with action bar visible

5. **Ship** — Only after all six screenshots capture the intended
   Defender / SIR-level experience.  `yarn build` passing alone is
   **not** acceptance.

---

## Rules that must not be re-asked

| Question the agent must NEVER ask the owner | Answer already given |
|---|---|
| Light or dark theme? | Agent decides based on references |
| Which columns to show by default? | 10 default · 5 in Customize · agent may adjust |
| What chip styles? | Agent decides — filled pill / outlined badge / etc. |
| Where should the preview drawer live? | Right-side, matches Defender |
| Spacing / typography / button style? | Agent decides |
| Should I merge dashboard into queue? | No — MSS Dashboard is separate |
| Should I preserve existing dark theme? | No — theme is a design decision |
| Should I build all 6 chip families or just some? | All six, reusable in Layer 3 |
| Is `yarn build` enough for acceptance? | No — 6 screenshots required |

---

## The one thing the agent may still ask about

If a **truly blocking ambiguity** appears — for example, an existing
API returns data in a shape that cannot be projected without a
schema change, or an engine's provenance format is undocumented —
then and only then may the agent surface the specific blocker.
Never for a design / cosmetic / preference decision.
