# OWNER DIRECTIVE (2026-06) — CORTEX-CLASS INVESTIGATION UX · NEXT WAVE

Continuously authorized. No owner gate. No screenshots. Preview = owner review.

## A · Findings surface (Activity ▸ Findings) — NOT ACCEPTED as-is
Replace `Capability | giant interpretation card | State | Confidence` with a
dense table: **Finding | Category | Capability | State | Confidence | Evidence |
Entities | MITRE | Source | Time | Actions**. Search/filter/sort/column pick/
time+state+capability filters; entity/evidence/MITRE pivots. Row select opens a
contextual details pane: Summary · Evidence · Entities · Relationships · MITRE ·
Provenance · Analyst interpretation · History · Technical details. System
assessment stays separate from analyst interpretation. ANALYST INTERPRETATION /
NIVXRAY GENERATED / EDIT / HISTORY must NOT repeat inline in every row.

## B · Capability label map (analyst label ▸ keep backend id in Technical details)
detection_intel → Detection Intelligence · process_ancestry → Process Ancestry ·
commandline_decode → Command Intelligence · lolbas_lookup → LOLBAS Analysis ·
mitre_expansion → ATT&CK Analysis · ioc_pivot → Indicator Intelligence ·
historical_correlation / correlation → Correlation · network_pivot → Network
Intelligence · identity_pivot → Identity Intelligence · dns_pivot → DNS
Intelligence · file_reputation → File Reputation. Never change backend ids.

## C · Activity table (DONE this session, keep extending)
Add columns where authoritative: State, Findings, Duration, Actions. Secondary
view "Capability Runs": Capability | Engine | Status | Duration | Findings |
Evidence | Started | Completed.

## D · Entities ▸ Graph — REBUILD TO THE OWNER REFERENCE IMAGE (top priority)
Reference supplied by owner (INC000001378 mock). Information architecture, not
restyling:
- incident header (unchanged, compact) → the 10 analyst tabs, Entities selected
- **Graph | Table** switch (same data, two representations; Table = NxDataTable)
- entity filter bar with authoritative counts: Entities · Processes · Events ·
  Files · Network · Registry · Users · Hosts · More + Time Range + Filters +
  "Search entities, hashes, IPs…". A missing count is `—`, never 0.
- LEFT collapsible **Graph Controls** (Center · Fit to view · Expand selection ·
  Show neighbors · Show all paths · Group similar · Show legend) and **Analysis
  Overlays** (ATT&CK · Confidence · Risk indicators · Data flow) + Export Graph.
  Only controls that really work.
- CENTRE canvas is DOMINANT: node cards (not dots) typed INCIDENT/HOST/PROCESS/
  EVENT/FILE/REGISTRY/NETWORK/USER/DETECTION/IOC/TECHNIQUE with 2–3 lines of
  identifying context.
- EDGES carry semantics (executed · spawned · created · accessed · connected_to ·
  resolved · modified · authenticated_as · evidence_of · related_to · dropped).
  **No edge without evidence**; inferred edges visually distinct from observed.
- RIGHT persistent **Entity Details** pane: Details | Relationships | Evidence(n)
  | Context. Inspect without navigating away; Entity 360 stays for depth.
- BOTTOM related-event timeline (Process/File/Registry/Network/Other) synchronised
  with node selection + "View in Timeline →".
- Retire the current `6/35 nodes · 6/21 edges · 0 obs · 0 sup · 3 gaps`, exposed
  checkbox wall, PATH REPLAY, inline legends, Attack Chain/Evidence Graph/Full
  switcher as PRIMARY chrome — move under Graph Controls / Overlays / More /
  Technical details. Delete no capability.
- ONE primary graph; Attack Path / Evidence / Process lineage become overlays.
- Render REAL data only. No process tree evidence → `NO PROCESS RELATIONSHIP
  EVIDENCE`, never synthesised ancestry.

## E · Same language everywhere
Overview · Attack Story · Timeline · Evidence · Entities · Detections · MITRE ·
Response · Activity · Report = table → row → contextual flyout → evidence pivot
→ technical details on demand. Exceptions: Attack Story + graphs may visualise.

## F · Truth invariant (unchanged)
NO DATA · NOT AVAILABLE · NOT AUTHORIZED · NOT OBSERVED · NOT EVALUATED ·
UNSUPPORTED · EVIDENCE INCOMPLETE · ERROR. Never synthesise to fill the UI.
Preserve canonical evidence, provenance, deterministic verdict reasoning,
analysis completeness, decoder provenance, negative explainability, response
verification, tenant isolation.

## Where to continue
- New primitives to compose with: `src/xdr/nx/NxInv.jsx` + `nx-inv.css`
  (NxInvSection/Table/Filters/Metrics/Tech/Value/ABSENCE).
- Findings currently live inside `tabs/AutoInvestigationTab.jsx` (legacy feed,
  now demoted into the `incident-activity-auto-tech` disclosure) — extract the
  findings table from there into a new `FindingsTab`-style component.
- Graph lives in `tabs/AttackGraphTab.jsx` (1643 lines) mounted under
  `incident-entities-relationships` in `XdrIncidentDetailPage.jsx`.
- Engine panels are provided by `XdrInvestigationWorkspacePage.jsx`
  (`embedded` + `capabilities` props).
