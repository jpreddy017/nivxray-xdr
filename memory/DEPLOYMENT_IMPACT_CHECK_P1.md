# DEPLOYMENT IMPACT CHECK — read-only · 2026-06

Nothing was deployed, minted, installed, seeded or written to production while
producing this. All production requests were unauthenticated probes that were
refused, plus `GET /api/openapi.json`.

## VERDICT: **NOT SAFE TO DEPLOY** (one blocker, one approval away)

## 1 · Revisions

| | Commit | Date (UTC) |
|---|---|---|
| **Currently deployed production backend** | **`be651bce`** — "P0-SEC GATE — LAST TEST FAILURE CLOSED" | 2026-09-09 05:02:49 |
| **Candidate (accepted P1 hardening)** | **`e9978291`** — "P1 Machine-Credential Hardening Complete" | HEAD |

`a6d13209` and `32dbd478` sit between them but are **documentation-only**, so
`be651bce` is the exact deployed *code* state.

### How the deployed revision was established (measured, not assumed)
- `GET /api/openapi.json`: production and preview both report **785 paths /
  275 schemas**, and **exactly 3 schemas differ**: `CreateKeyBody`,
  `ReasoningOutcome`, `TelemetryReceipt`.
- `POST /api/xdr/ingest/telemetry` with an API key only →
  production `403 {"detail":"Not authenticated"}` vs preview
  `401 unknown-api-key`. **The machine API-key auth path (`85bcc86a`) is NOT
  in production** — no collector can authenticate there today.
- `GET /api/xdr/collectors` with legacy `X-Tenant-Id`/`X-Principal-Id` headers
  only → **403 on both**, so the P0-SEC fail-closed fix (`be651bce`) **IS**
  in production.
- Therefore: production ≥ `be651bce`, production < `85bcc86a`.

## 2 · Changed files, `be651bce` → `e9978291`

Runtime backend (7):
```
backend/routers/incidents.py          deep_link → /xdr/intelligence/iocs
backend/routers/xdr_api_keys.py       confirm_tenant_id + unknown-tenant guard
backend/routers/xdr_ingest.py         idempotency partition + `message` passthrough
backend/routers/xdr_rbac.py           API-key machine auth + rate-limit wiring
backend/server.py                     additive /openapi.json alias (in-process only)
backend/services/ingest_idempotency.py   NEW — exactly-once delivery claims
backend/services/machine_rate_limit.py   NEW — per-IP/key/tenant throttle
```
Tests (11), `memory/` (17), `test_reports/` (5), `scripts/` (3),
`apps/nivxray-xdr/` (38 — Vercel-only, not part of this host),
root `vercel.json` (1 — the deployment-refusal script; both Vercel projects
use rootDirectory `apps/nivxray-xdr`, verified via the Vercel API, so the root
file is never read by them).

**Not changed anywhere in the range:** no `.env`, no `requirements.txt`, no
`package.json`, no `Dockerfile`, no supervisor config. No new startup hook and
no migration. The only production-DB writes the new code can make are
*lazy, on first use*: `xdr_ingest_dedupe` and `xdr_machine_rate_buckets` — two
**new** collections with their own indexes. No existing collection is read
destructively, altered, dropped or seeded.

## 3 · Workspace (NivXMachines) impact

- Emergent builds the **entire project from the current workspace state** and
  there is **no backend-only deploy**, so the Workspace CRA at
  `nivxray.nivxforge.com` **will** be republished. (Confirmed against
  platform documentation, not inferred.)
- **`frontend/` source: 0 files changed** between `be651bce` and `HEAD`.
  `frontend/package.json` unchanged. So the Workspace source is identical to
  what the live bundle (`static/js/main.46cdaa0a.js`) was built from.

### THE BLOCKER — uncommitted lockfile drift
```
frontend/yarn.lock              +1329 / -37   (UNCOMMITTED, working tree only)
apps/nivxray-xdr/yarn.lock      +287  / -0    (UNCOMMITTED, working tree only)
```
The committed lockfiles are byte-identical to `be651bce`; the **working-tree**
copies are not. New resolutions appear (`@adobe/css-tools 4.5.0`,
`@apidevtools/json-schema-ref-parser 11.9.3`, …) with **no `package.json`
change** — i.e. drift from an incidental `yarn install`, not an intended
dependency change. Because the deploy uses the working tree, the Workspace
would be rebuilt against a dependency graph the live bundle was **never**
built with. That is an unreviewed change to a working product, which the
owner-locked rule forbids.

`memory/AUTHORITATIVE_XDR_yarn.lock` (untracked) is byte-identical to the
drifted `apps/nivxray-xdr/yarn.lock`, so a previous session already treated
this drift as a known hazard.

## 4 · Confirmed NOT touched by the deploy
- **Production MongoDB / tenant data** — redeploy keeps the same
  `MONGO_URL` and database; the migrate step only runs on first deploy or an
  explicit replace. No wipe, no seed, no schema migration.
- **DNS / custom domains** — unchanged by redeploy.
- **NivXRay XDR frontend (`xdr.nivxforge.com`)** and **NivXForge/NivXRay EDR
  (`edr.nivxforge.com`)** — served by separate **Vercel** projects; an
  Emergent deploy does not build or publish them.
- **No other product** shares this host.

## 5 · Rollback target (before deploying)
- **Platform**: Manage Publishes → **Overview** → rollback icon (↺) on the
  previous deployment of `nivxray.nivxforge.com`. Up to 3 recent successful
  deployments are eligible; rollback reuses the previous Docker image, so
  **backend and Workspace frontend revert atomically** (1–3 min).
- **Code-level**: commit **`be651bce`**.

## 6 · EXACT NEXT OWNER ACTION
Approve restoring `frontend/yarn.lock` and `apps/nivxray-xdr/yarn.lock` to
their **committed** state (a working-tree revert — no source change, no
install, no deploy). Once that is done the Workspace build inputs are
byte-identical to the live deployment and the verdict becomes
**SAFE TO DEPLOY**.

Not done, per instruction: no credential minted, no collector created, no
auditd installed, no telemetry sent, no data seeded, nothing deployed.
