> Note: this file names NO passwords, tokens or credential values — by
> owner security decision, secrets belong only in the environment/secret
> facility, never in git, code, docs or reports.

# Pre-deployment actions · 2026-09-08

Step 1 remains **STOPPED** awaiting the owner's control-plane result. No
deploy, no detach, no DNS, no CORS change, no production change.

---

## 1 · Preview sensor credential ROTATED (owner security action)

The credential had entered git history, so it was treated as
compromised. Rotated through the existing P0-3-safe lifecycle — the
sensor was **not** redesigned.

```
stop sensor  →  POST /api/edr/enrollment/endpoints/{ep}/revoke
             →  delete the exposed identity.json
             →  start sensor (supervised bootstrap re-enrols)
```

Proven:

| check | result |
|---|---|
| old credential now refused | `403 AGENT_CREDENTIAL_REVOKED` on `POST /api/edr/agent/session` |
| same endpoint identity | `ep_2d57cbe6f80152062109`, **1** enrolment row |
| credential rotated | `cred_81f9a04c…` → `cred_00b4f731…` (1 ACTIVE, 30 REVOKED) |
| delivery history preserved | `event_count 20364 → 20408` (not reset) |
| `revoked_at` cleared, state healed | `sensor_state: REPORTING` |
| delivering | `DELIVERING · DELIVERY_WITHIN_DECLARED_CADENCE` |
| queue drained, nothing lost | `collected=44 sent=118` — the outbox replayed the rotation-window events |
| new-credential chain | 200 raw events, **200 AUTHENTICATED**, 199 canonical evidence, **1 DETECTION_MATCHED**, 0 untrusted |
| Process Tree | `reason=ok`, 43 nodes, window honesty intact |
| Device Trajectory | `RESOLVED`, 2,509 events / 5 lanes in 1 h |
| P0-3 proof | **40 PASS · 0 FAIL · 1 BLOCKED** (the BLOCKED is the honest "no rule matched this benign binary") |
| regression | `tests/edr` **368 passed / 3 pre-existing** |

**Defect fixed to make rotation safe.** `sensor_state` is a delivery fact
and therefore `$setOnInsert`, which is right for `REPORTING` but wrong
for `REVOKED`: a re-enrolled endpoint would have kept the `REVOKED`
token until its first event landed, so the console would have called a
delivering endpoint revoked. `enroll()` now heals a stale `REVOKED`
from the delivery record itself.

---

## 2 · How the production backend is exposed → safest `api.nivxforge.com` mapping

**Determined, not changed.** Measured: the production frontend and its
API are the **same origin** — the live Workspace bundle at
`nivxray.nivxforge.com` was built with its own host as
`REACT_APP_BACKEND_URL`, and `https://nivxray.nivxforge.com/api/*`
serves the FastAPI app directly. There is exactly **one** production
backend + database.

**Safest mapping (no new backend, no new DB, no rebuild):** attach
`api.nivxforge.com` as an **additional custom domain on the existing
deployment that already serves that backend.** Emergent support confirms
a deployment can hold unlimited custom domains at no extra cost. Then
`https://api.nivxforge.com/api/…` reaches the same FastAPI process and
the same MongoDB, and the API address becomes **independent of
`nivxray.nivxforge.com`'s retirement** — which is the whole point.

Consequences to accept deliberately:
- that host will also serve the deployment's frontend bundle at `/`.
  Harmless, but if a bare API origin is wanted it needs a platform-side
  route restriction, which does not exist today.
- **DNS:** `api` is a subdomain → a single `CNAME`. No apex/`www` pair,
  so the marketing site's records are untouched.
- **CORS, later not now:** `CORS_ORIGINS="*"` still works because auth
  is a Bearer token in `localStorage` and no request is credentialed.
  When the domains are final the explicit list is:
  `https://workspace.nivxmachines.com`, `https://xdr.nivxforge.com`,
  `https://edr.nivxforge.com` (+ `https://nivxray.nivxforge.com` only
  while the legacy redirect window is open). **Not changed in this pass.**
- ⚠️ **Attaching a domain does not make it authoritative.** Until
  Step 1 says which deployment owns which hostname, do not attach
  `api.nivxforge.com` to a deployment that might be rebuilt into
  something else.

---

## 3 · Cross-origin product pivots — implemented and proven both ways

`apps/nivxray-xdr/src/productOrigins.js` is the single resolver:
`REACT_APP_XDR_URL` / `REACT_APP_EDR_URL` /
`REACT_APP_WORKSPACE_URL` (the `VITE_*` spelling is accepted too — see
`vite.config.js`). Two modes:

- **`CONFIGURED`** — the product has its own origin → an **absolute
  cross-origin URL**.
- **`SAME_ORIGIN`** — nothing set → the products genuinely **are** one
  deployment at one origin (preview, and any combined deployment), so
  in-app navigation is correct.

On the owner's rule *"never silently navigate inside the wrong
product"*: in `SAME_ORIGIN` mode there is no wrong product — it is the
same deployment. The prohibited failure is pretending to leave for a
product that lives elsewhere, and that is what `CONFIGURED` mode
prevents. Every control exposes its mode via `data-pivot-mode`.
**Workspace is different** — it is never in this bundle, so with no URL
it renders **disabled · `◇ NOT CONFIGURED`** rather than navigating.

Pivot sites converted: `nivxforge/NivXForgeConsole.jsx` (EDR→XDR,
carries `incident_id`), `xdr/pages/XdrIncidentDomainPage.jsx`
(XDR→EDR trajectory, carries `incident_id` + `device`),
`components/incidents/tabs/ActivityTab.jsx` (XDR→EDR trajectory).
Context stays in the **query contract**, which is precisely why it
survives becoming cross-origin.

**Proven in the browser, both modes:**

```
SAME_ORIGIN (shipped default)
  data-pivot-mode=SAME_ORIGIN  data-pivot-href=/xdr/incidents/inc_57fee…
  clicking it still navigates in-app to /xdr/incidents/…   ← preview unharmed

CONFIGURED (env set temporarily, then REVERTED)
  data-pivot-mode=CONFIGURED
  data-pivot-href=https://xdr.nivxforge.com/xdr/incidents/inc_57fee8bc67a047da9685
  workspace launcher → CONFIGURED, https://workspace.nivxmachines.com
```

The env was **reverted to empty** immediately: those hostnames are
`NXDOMAIN` today, and leaving them set would ship dead controls.

---

## 4 · Credentials — policy applied, and a finding

**No password, token or secret value appears in this report, in any file
I created, or in the chat.** Per the owner's decision I did not request,
reuse, copy, migrate or document any existing credential.

**Production credentials cannot be created by me, and should not be.**
The production admin is seeded from `ADMIN_EMAIL` / `ADMIN_PASSWORD` in
the *production* environment's secret facility — values the owner sets,
which the agent never sees. The production **sensor** credential is
minted by the legitimate enrolment flow against the production backend
(one-time enrolment token → durable credential shown once), which
requires a production operator login that does not exist yet.
→ **`OWNER_CREDENTIAL_ACTION_REQUIRED`** for anything needing production
authentication. Nothing was guessed, extracted from git history, reset,
or bypassed. **No existing production credential was rotated or
deleted** — new-then-verify-then-retire, as instructed.

Frontend build variables hold **public configuration only**
(`REACT_APP_XDR_URL`, `REACT_APP_EDR_URL`,
`REACT_APP_WORKSPACE_URL`, `REACT_APP_BACKEND_URL`). Never a credential
— a build variable is readable in the shipped bundle.

### 🔴 FINDING · 275 tracked files contain the preview admin password

`memory/test_credentials.md` is correctly gitignored. But:

```
git ls-files | xargs grep -lF <preview admin password>  →  275 files
  backend/tests/edr/*_live*.py, *_live_api.py, *_adversarial_live.py …
  backend/docs/assets/NIVXRAY_XDR_SOURCE_EXPORT.html
  memory/…/COMPLETE_AG_EXPORT/…/test_reports/iteration_59.json
```

A long-standing pattern of inlining the live-API credential in tracked
test files. It is **preview-only**, but it is a secret in git and it
violates the owner's rule directly.

**Fixed my own contributions only:**
`scripts/p0_3_sensor_recovery_proof.py` now reads `ADMIN_EMAIL` /
`ADMIN_PASSWORD` from the environment and reports
`TEST_ANALYST_NIVXLIVE_PASSWORD` as **BLOCKED** rather than inlining it
— it refuses to guess and refuses to embed. Re-verified: **40 PASS · 0
FAIL · 1 BLOCKED.**

**Not fixed — needs an owner decision:** the remaining ~274 files. This
is a bulk edit across the live-API test suite plus a generated source
export, and git history would still hold the value, so the honest
remedy is *rotate the preview admin password* and move every test to an
env var. Rotating it would invalidate the credential the owner has been
using and appears in ~274 files, so it is not something to do
unannounced.
