# PRODUCTION ZERO-DATA · ROOT CAUSE · NOT A CODE DEFECT
Date: 2026-06 · P0 raised after the production login check

## Root cause
**Preview and production are backed by two different databases.**

Proof:
- The preview backend reads `MONGO_URL="mongodb://localhost:27017"` and
  `DB_NAME="test_database"` from `/app/backend/.env` — a MongoDB running
  **inside this container**. It has no public listener and is unreachable from
  any external deployment.
- That local database holds **636 `workspace_cases`** documents. Those are the
  348 unassigned / 34 critical / 48 high / 27 new / 27 updated figures.
- `https://nivxray.nivxforge.com` is a separate deployment with its own
  database. Its `/api/incidents` correctly returns an **empty authorized set**
  because that database contains no incidents.

What is therefore NOT wrong:
- Authentication — the owner signed in to production as `admin@nivxray.com`.
- Tenant attribution — the production header shows the same principal and
  `ALL CUSTOMERS` plane as preview.
- `/api/incidents` — it answers correctly for the data it has.
- The promoted frontend — identical artifact, verified by md5 on the live host.

The UI is already honest about it: *"No incidents returned by /api/incidents
for this tenant."* That is a true statement about the production dataset.

## Why there is no "smallest possible change"
Making production show 348 requires either seeding/copying the preview dataset
into production, or fabricating counts. The owner forbade both, and correctly:
the preview dataset is development data generated in this container
(hostnames like `agent-env-630704a1-621f-478b-9b86-a321772d01bf`), not the
owner's real estate. Shipping it to production would put demo data into a
production security console.

No code change was made for this defect, and none should be.

## Legitimate paths forward (owner decision)
1. **Enrol a real production collector** — the previously frozen P0
   "Controlled Production Collector Enrollment". Production then generates its
   own real detections and incidents, and every count populates by itself.
2. **Explicitly authorise a one-time migration** of the preview dataset into
   production. This reverses the current instruction and puts development data
   in production; only worth it for a demo environment.
3. **Accept production as empty** until telemetry flows. The console already
   states the true condition rather than showing a fake number.

## Expected same-cause effects on production
Intelligence and KB data (105,052 indicators, 334 KB entries) also live in the
container's local database, so those surfaces will read low or zero on
production for exactly the same reason. That is the same single root cause, not
four separate defects. The pages will render real production values the moment
that database has them, and will show `—` / a named empty state until then.

## Tenant isolation
Unchanged — no authorization, scoping or query code was touched in this round.
The preview isolation gates remain green (nav integrity 1916, branding 51).

## `/xdr/activities` — FIXED and verified in Preview
`App.jsx`: added `/xdr/activities` → `Navigate` to `/xdr/admin/telemetry-studio`
(Cisco places Activities under Investigate; the surface is the telemetry
studio, so the canonical route redirects rather than duplicating a page).
`XdrShell.jsx`: the Activities rail item now points at `/xdr/activities`.
Verified live in Preview: `/xdr/activities` → `/xdr/admin/telemetry-studio`,
shell mounted, 1 tab. Build PASS, nav gate PASS.

**Not deployed.** Production is deliberately untouched while this P0 decision
is open. Rollback reference remains `dpl_BF14GQG3bb4VCt7M3JP56NizCjFQ`.

## Also not done, per instruction
Cisco visual matching and the Incident Priority Score are not started.
