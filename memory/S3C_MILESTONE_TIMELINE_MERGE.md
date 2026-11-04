# S3-C · MILESTONE TIMELINE MERGE — 2026-06-21

**Status: DONE · PROVEN PROGRAMMATICALLY** (no screenshots).
**Frontend only.** Zero backend change, zero new engine, zero new data store.
Proof: `scripts/p1_s3c_milestone_timeline_proof.py` → **31 PASS · 0 FAIL**
(`test_reports/p1_s3c_milestone_timeline_proof.txt`) · `yarn build` **PASS**.

## RECORDED AUTHORITY DECISION (owner, no code in this task)

> The Incident deterministic verdict is the authoritative analyst-facing
> Incident verdict. The causal-engine assessment is analytical input and
> context, **not** a second competing Incident verdict. Never average, merge
> or synthesize them into a third verdict. Where they differ, preserve both
> truthfully and disclose the difference without implying either observation
> did not occur.

Current state already complies: S3-B shows the incident verdict as the
headline and discloses the causal band/score/confidence under Technical
details. The explanatory disagreement narrative remains a **separate, later**
task and must be derived from the actual scopes/evidence, never hard-coded.

## TIME AUTHORITIES (inventoried before any UI change)

| fact | authority | field |
|---|---|---|
| incident timeline rows (existing) | `GET /api/incidents/:id/attack-story` + `incident.state_history` | `steps[].time` · `state_history[].at` |
| causal milestone | causal analysis `story[]` | `idx · text · tactic · signals · **frame_iids**` — **carries NO timestamp of its own** |
| milestone's evidence event | `GET /api/v2/cases/:id/trajectory/device` | `frames[] {frame_iid · **ts** · lane · action · label · process · device · user · mitre · evidence_ids[] · provenance}` |
| ACTIVITY_TIME | the frame | `frames[].ts` (e.g. `2026-06-01T10:00:00Z`) |
| SENSOR_OBSERVED_AT | the frame's provenance | `provenance.sensor_observed_at` / `observed_at` — **absent in this dataset ⇒ NOT RECORDED** |
| INGEST_TIME | the frame's provenance | `provenance.ingested_at` (e.g. `2026-09-16T16:11:01Z`) |
| canonical evidence | the frame | `evidence_ids[]` → `provenance.normalizer · source · origin · ingest_job_id` |

No timestamp is invented anywhere. Ordering uses activity time only.

## VISIBLE TIMELINE CHANGE

`?tab=timeline` keeps **ONE** table (asserted: exactly one
`inv-timeline-table`). It now also carries:
- **Observed event** rows — one per trajectory frame, each positioned by its
  own `ts`, with its lane as category, its provenance source, its MITRE
  techniques and its `evidence_ids`.
- **Causal milestone** rows — marked with a filled
  `ATTACK MILESTONE · <stage>` chip so a milestone can never be mistaken for
  raw telemetry, plus a `Show in story` action.
- **"Milestones with no authoritative activity time"** — a separate section
  *below* the chronology for milestones citing no time-bearing evidence. They
  are listed, never placed.

Live: the milestone row and its cited event row both read
`2026-06-01 10:00:00`, and the full row order is descending by authoritative
time.

## STORY ↔ TIMELINE BEHAVIOR

Existing query-param routing only — no new route, no second router.
`Show on timeline` (Story) → `?tab=timeline&focus=m-0`;
`Show in story` (Timeline) → `?tab=story&focus=m-0`.
`NxInvTable` gained one optional `openKey` prop: the focused row is expanded
and marked `data-focus="true"`, and the timeline scrolls it into view. Proven
in both directions.

## THREE-CLOCK BEHAVIOR

The expanded milestone row states: *"A milestone has no clock of its own — it
is positioned by the activity time of the cited evidence event
`tf_487f2c73b75943aa`."* `Activity time`, `Sensor observed` and `Ingested`
remain three separate labelled facts (asserted individually). The frame's
`ingested_at` (`2026-09-16`) is never shown as its activity time
(`2026-06-01`). A milestone with no cited time reads **TIME NOT RECORDED** and
is excluded from the chronology rather than snapped to a neighbouring event.

## EVIDENCE PROVENANCE

Each milestone's expanded row prints the chain
`event <frame_iid> → canonical <evidence_ids> → normalizer → source → origin
→ ingest job`, and embeds the **existing** shared `EvidenceInspector`
(`/api/incidents/:id/inspector/event/{frame_iid}`, authorized by S1) so the
cited evidence is inspectable in place. No evidence was copied into a new
store and no synthetic evidence row was created.

## NOT_ASSOCIATED BEHAVIOR

On `inc_r381_promote`: **no** milestone row, **no** unpositioned-milestone
section, no zero-count milestone chart, no placeholder progression — and the
timeline itself still renders its own authoritative records. S3-A honesty
intact.

## FILES CHANGED

- `src/xdr/pages/incidents/record/tabs/TimelineTab.jsx` — causal + trajectory
  reads, merged rows, milestone marker, three-clock detail, evidence chain,
  embedded inspector, unpositioned section, focus handling.
- `src/xdr/incidents/IncidentStoryDepth.jsx` — `Show on timeline` per
  milestone, honours `?focus=`.
- `src/xdr/nx/NxInv.jsx` — `NxInvTable` gained the optional `openKey` prop
  (+`data-focus`).
- `src/lib/incidentsApi.js` — `getIncidentDeviceTrajectory`.
- New: `scripts/p1_s3c_milestone_timeline_proof.py`.

## FOCUSED PROOF

**31 PASS · 0 FAIL**: one timeline · milestone inside it · evidence events
alongside · milestone visually distinct · milestone time == cited event's
activity time · order agrees with time · "no clock of its own" stated · three
clocks separate · ingest ≠ activity · evidence chain present · inspector
mounted · Story→Timeline and Timeline→Story hand-off with focus+expansion ·
NOT_ASSOCIATED fabricates nothing · cross-tenant exposes no rows · all seven
tabs render. `yarn build` PASS.
Two proof-script defects were found and fixed during verification (a selector
that also matched row ids; a row click that landed on the hand-off button) —
both were assertion bugs, not product defects.

## RESIDUALS

1. `SENSOR_OBSERVED_AT` is **not present** in this dataset's frame provenance,
   so it reads NOT RECORDED everywhere. If the collector contract does carry a
   sensor clock under another key, the mapping is a one-line addition — worth
   confirming against the collector schema.
2. This incident has exactly **1** frame and **1** milestone, so the merge is
   proven correct but not proven at scale; an incident with a dense frame set
   should be spot-checked for ordering/perf.
3. Verdict-disagreement narrative: recorded as an authority rule above, UI
   deliberately not built.
4. Carried P0 security residual, untouched: `response-executions` trusts a
   client-supplied `tenant_id`.
