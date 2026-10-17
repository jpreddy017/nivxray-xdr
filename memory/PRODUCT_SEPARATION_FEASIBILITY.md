# Product separation feasibility — XDR / EDR / NivXMachines

Date: 2026-06
Status: **assessment only.** No code changed, nothing deployed, production
untouched. The Stage 2B pin (`cd2b8b92` / app `593b3e9f`) is undisturbed and
all E3 HOLDs remain in force.

---

## Answer

**Yes — but the three separations are not equally hard, and "separate" is not
the same as "independent".**

| Separation | Verdict | Real cost |
|---|---|---|
| Cut **NivXMachines Workspace** loose | **YES — already structurally separate** | hours |
| Ship **XDR and EDR as separate products/origins** | **YES — already ~70% built** | days |
| Make **XDR genuinely independent of the EDR plane** | **YES, but this is the real work** | weeks |

The asymmetry is the whole story: **EDR barely depends on XDR, but XDR depends
heavily on EDR.** EDR is where XDR's endpoint telemetry comes from.

---

## Evidence

### Frontend — the split is largely done already

- `apps/nivxray-xdr/src/productScope.js` — `REACT_APP_PRODUCT_SCOPE=xdr|edr`
  already enforces a client-side product boundary, with `isForeignPath()`
  blocking cross-product navigation and separate brand identities
  (**NivXRay XDR** vs **NivXForge EDR**, an explicit owner lock).
- `apps/nivxray-xdr/src/productOrigins.js` — per-product origins
  (`REACT_APP_XDR_URL`, `_EDR_URL`, `_WORKSPACE_URL`) with an honest
  `CONFIGURED` / `SAME_ORIGIN` distinction.
- `apps/nivxray-xdr/vercel.json` — host rules already route
  `xdr.nivxforge.com → /xdr` and `edr.nivxforge.com → /edr`.
- Target topology is documented: `xdr.nivxforge.com`, `edr.nivxforge.com`,
  `workspace.nivxmachines.com`.

**What is missing:** it is still **one bundle**. An EDR visitor downloads the
XDR console code and vice versa. Scope gating is a routing and branding
boundary, not a code boundary.

### NivXMachines Workspace — already a separate frontend

`/app/frontend` is a *separate* React codebase (owner decision 2026-09-08,
deliberately not merged) that calls the same backend. Its API namespace is
**disjoint** from the products:

```
/analyze  /decode  /die  /ai  /cases  /batch  /behavioral
/documents  /benchmark  /corrections  /correlations  /activity
```

versus `/api/xdr/*` and `/edr/*`. Nothing in the XDR or EDR consoles imports
it. Its only couplings are the **shared backend process**, the **shared Mongo
database** and the **shared auth/user store**. `WorkspaceLaunch.jsx` already
degrades to `NOT CONFIGURED` when no Workspace origin is set, so with it unset
the XDR console does not reference NivXMachines at all.

### Backend — one process, 157 routers, 173 registrations, one database

| Area | Lines |
|---|---|
| `routers/edr_*.py` (16 files) | 6,848 |
| `routers/xdr_*.py` | 15,133 |
| other routers (Workspace/decoder/shared) | 28,264 |
| `edr_plane/` | 22,840 |
| `edr_trajectory/` | 4,007 |
| `edr_behavior/` | 2,154 |
| `services/edr/` | 2,019 |

**EDR → XDR coupling is thin.** Across all 16 EDR routers the only XDR import
is `routers.edr_session → routers.xdr_audit_log.emit_audit`. Everything else
is `deps`, `edr_tenancy`, `edr_plane`, `services.edr`.

**XDR → EDR coupling is thick, and it is load-bearing:**

- `routers/xdr_search.py` queries `edr_raw_events` and
  `edr_endpoints/v2_shadow_observations` **directly** and imports
  `services.edr.device_identity` / `endpoint_query`. XDR hunting *is* built on
  the EDR telemetry plane.
- Four core investigation services reference the EDR plane:
  `services/entity_resolution.py`, `services/evidence_bridge.py`,
  `services/incident_provenance.py`, `services/session_context.py`.
- Evidence provenance is explicitly joined across both planes:
  `edr_raw_events.raw_id ↔ xdr_canonical_events._id`.
- `detection_content/xdr_edr_adapter.py` bridges detection content.

**Shared by all three, today:** one FastAPI process, one Mongo database and
`DB_NAME`, one JWT/user store, one tenancy model
(`/api/xdr/tenants`, `/api/xdr/rbac`, `edr_tenancy`) and one audit log
(`xdr_audit_log`). There is no service-profile switch — only
`NIVX_EDR_WORKERS_DISABLED`, added for synthetic isolation.

---

## Three ways to do it

### Option A — Deployment profiles (one codebase, three services)

Add `NIVXRAY_SERVICE_PROFILE=xdr|edr|workspace|combined`; `server.py` registers
only that profile's routers, each deployment gets its own `DB_NAME`, and each
frontend builds with its own `REACT_APP_PRODUCT_SCOPE`.

- Smallest change (one registration block plus a profile test), fully
  reversible, keeps shared contracts honest in one place.
- Proven pattern here — the staging package already runs the response engine as
  a separate, credential-gated service.
- **Honest limit:** this separates *surface and data*, not *supply chain*.
  Every image still contains all the code, so it is not an isolation boundary
  against a code-level compromise. The cross-plane reads in `xdr_search` would
  return empty on a split database — you would be shipping an XDR with no
  endpoint telemetry unless Option B follows.

### Option B — EDR as a telemetry provider behind an API contract

Replace XDR's direct `edr_raw_events` / `edr_endpoints` reads with a
service-credential-gated EDR API, exactly like the existing backend →
response-engine boundary (distinct service identity, fail-closed, audited).

- This is the only option that makes "separate" also mean "independent".
- Touches `xdr_search.py` plus the four services above, the evidence
  provenance join, and the ingestion path. Needs its own regression suite
  because evidence-chain and fail-closed claims depend on those joins.

### Option C — Full repo and database split

Separate repositories, images, databases and release trains.

- Strongest isolation; highest cost.
- Forces identity/tenancy federation first: tenancy, RBAC and audit are shared
  today, so two products would otherwise mean two disconnected account
  universes — which would break cross-product pivots and the tenant isolation
  contracts A0.5 locks down.

---

## Recommended sequence

1. **Workspace first** (hours, near-zero risk): leave `REACT_APP_WORKSPACE_URL`
   unset, stop registering the Workspace router group, give it its own
   database. Independently verifiable and trivially reversible.
2. **Option A** for XDR/EDR, to get two products, two origins, two databases
   with honest branding.
3. **Option B** only if XDR must survive without the EDR plane. Decide this
   explicitly — it is the difference between two deployments and two products.
4. **Option C** only if a regulatory or commercial boundary demands it, and
   only after identity federation exists.

## Constraints that apply to any of these

- Do this on a **branch after** Stage 2B host acceptance. The staging package
  pins `593b3e9f` and `prepare.py` fails if HEAD drifts outside
  `deploy/stage1-staging/`, so splitting work now would block the Hetzner run.
- Splitting the database without Option B silently empties XDR hunting results
  — a wrong-but-quiet outcome, the exact failure class the owner has
  prohibited. Any split must fail loudly instead.
- Tenant isolation, RBAC, fail-closed response admission and the audit trail
  are shared code. They must be preserved per-product, not duplicated and
  allowed to drift.
- Production `nivxray.nivxforge.com` stays untouched; all E3 HOLDs stand.
