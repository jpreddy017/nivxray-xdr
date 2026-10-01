# S3-A · INCIDENT STORY DEPTH — 2026-06-21

**Status: DONE · PROVEN PROGRAMMATICALLY** (no screenshots).
**Frontend only.** Zero backend change, zero data-model change. Verdict
Explainability deliberately NOT implemented.

Proof: `scripts/p1_s3a_story_depth_dom_proof.py` → **23 PASS · 0 FAIL**
(`test_reports/p1_s3a_story_depth_dom_proof.txt`) · production build **PASS**.

## VISIBLE UI CHANGES

On `/xdr/incidents/:id?tab=story`, immediately under the incident's own
attack story, three new dense sections (the engine's collapsed `EngineDepth`
panels are untouched and remain underneath — the engine workspace was **not**
re-embedded):

1. **Attack milestones** — metric strip (Milestones · Entities ·
   Relationships · Evidence-cited relationships) + an ordered table:
   `# · What happened · Stage · Entity · Why it is a milestone ·
   First observed`. Expanding a row reveals L3 provenance (supporting event
   frames, plus the exact field every fact was read from, under Technical
   details).
2. **Observed attack stages** — all 14 stages as chips: a stage placed by
   evidence carries its technique ids; a stage with none is drawn **dashed**
   with the line *"A stage drawn dashed is NOT OBSERVED — it is not a
   statement that the activity did not happen."* Live: **2 placed · 12 not
   observed**.
3. **Causal anchors** — `Anchor · Class · Relationships · First observed ·
   Investigate`, rendered through `NxEntity`, with pivots taken from the
   existing `investigationPivots` contract only (no URL is invented; an
   anchor with no honest pivot reads NOT AVAILABLE).
4. **Relationship intelligence** — readable
   `entity —relationship→ entity` lines (e.g. `powershell.exe —spawned→ …`),
   each carrying **Evidence cited** or **Derived · no event cited**.
   Behavioural relationships are primary; structural ones are kept under a
   disclosure. Engine internals (`by_node_type`, `by_edge_type`, engine
   versions, association authority) live under Technical details.

Two new design-system state tokens (`ASSOCIATED`, `NOT_ASSOCIATED`) plus
`EVIDENCE_CITED` / `ENGINE_DERIVED` added to `NxOpsState` — the vocabulary
lives in the design system, not in the page.

## DATA SOURCES USED

One authoritative read, already authorized for a tenant analyst by S2-mini:
`GET /api/v2/cases/{incident.id}/investigation?limit=500&profile=soc_balanced`
(`getIncidentCausalAnalysis` in `lib/incidentsApi.js`).
- milestones ← `story[]` (`idx · text · tactic · severity · signals ·
  frame_iids · process_iids · evidence_ref`)
- stages ← `attack_mapping.kill_chain[]` (`tactic · covered · techniques`)
- anchors + relationships ← `ikg.nodes[] / ikg.edges[] / ikg.stats`
- association ← `engine_association` (S2-mini)
- "First observed" ← the cited entity's `attrs.first_seen`; absent ⇒
  **NOT RECORDED** (never a fabricated timestamp)

Nothing is derived beyond ordering, joining a cited id to its node, and
counting relationships per node. All counts shown as "Entities" and
"Relationships" are the engine's own `stats`.

## ASSOCIATED EXPERIENCE

Verified live on `inc_c1edae99d4e541c58552` as `analyst@default.com`:
surface mounts with `data-nx-state="ASSOCIATED"` · **1** milestone row ·
metric strip · **14** stages (2 placed / 12 NOT OBSERVED) · **2** causal
anchors rendered as entities · **14** relationships each classified
(6 evidence-cited) · milestone provenance reachable on row expansion.

## NOT_ASSOCIATED EXPERIENCE

Verified live on `inc_r381_promote`: exactly ONE compact state —
`NOT_ASSOCIATED` chip + *"Causal analysis not available for this incident"* +
**the server's own reason** + two explicit statements that this is an absence
of engine analysis, **not** a benign finding and **not** a claim that nothing
happened. Asserted absent: the metric strip, the milestone table and the
stage strip — **no zeros, no empty chart, no empty kill chain.**

## PROVENANCE BEHAVIOR

- Every milestone row exposes its supporting event-frame count, its
  `evidence_ref`, and the field each value came from.
- Every relationship states whether an event was cited; an uncited edge is
  `Derived · no event cited` and is never presented as established fact
  (the "no relationship without evidence" invariant is expressed as a visible
  classification, not by hiding data).
- An anchor node whose only label is the incident id carries **no identity of
  its own**: it is not rendered as a named entity, and the count of such nodes
  is stated ("an anchor is never given a borrowed name").
- A refusal or error renders `NOT_AUTHORIZED` + *"This is a refusal or an
  error — not a finding about the incident."*
- Analyst-facing copy carries no implementation vocabulary; asserted live:
  `v2_cases`, `shadow_observation`, `case_authz`, "IKG engine" → **0
  occurrences**.

## FILES CHANGED

New: `apps/nivxray-xdr/src/xdr/incidents/IncidentStoryDepth.jsx` ·
`scripts/p1_s3a_story_depth_dom_proof.py`.
Changed: `src/lib/incidentsApi.js` (+1 read) ·
`src/xdr/nx/NxOpsState.jsx` (+4 tokens) ·
`src/xdr/pages/XdrIncidentDetailPage.jsx` (+1 import, +1 mount in the Story
tab).

## FOCUSED TEST / BUILD RESULTS

- `scripts/p1_s3a_story_depth_dom_proof.py` — **23 PASS · 0 FAIL** (real
  browser, real login, real preview edge).
- `yarn build` — **PASS** (`XdrIncidentDetailPage` chunk 307.36 kB).
- Tenant isolation re-verified through the UI: the same analyst on the
  `nivx-live` incident `inc_7742fe7120174204be36` gets **no** ASSOCIATED
  surface and no engine content in the DOM.
- All seven incident tabs still render (overview · story · timeline ·
  evidence · detections · response · activity).
- No backend regression run (frontend presentation task).
- Environment note for the next agent: the preview edge throttles rapid
  sequential navigation, which showed up as 0-character bodies. The sweep now
  waits on a real anchor element and retries once — a slow edge is not a
  product defect.

## SCREEN / PREVIEW ROUTE VERIFIED

`/xdr/incidents/inc_c1edae99d4e541c58552?tab=story` (ASSOCIATED) ·
`/xdr/incidents/inc_r381_promote?tab=story` (NOT_ASSOCIATED) ·
`/xdr/incidents/inc_7742fe7120174204be36?tab=story` (cross-tenant) — all as
`analyst@default.com`.

## NOT DONE (by instruction)

Verdict Explainability (S3-B) · standalone Investigate retirement · Hunting ·
Event Explorer · Control Center · Response · the response-executions residual ·
engine algorithms · golden-case ownership.
