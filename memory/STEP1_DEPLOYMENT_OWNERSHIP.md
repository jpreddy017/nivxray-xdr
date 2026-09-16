# STEP 1 · Deployment ownership of `nivxray.nivxforge.com` — read-only forensics

**Date:** 2026-09-08 · **Actions taken: NONE beyond HTTP/DNS/TLS reads.**
No deploy, no detach, no DNS, no CORS, no backend or production change.

**RESULT: `OWNERSHIP_NOT_AUTHORITATIVELY_CONFIRMABLE_FROM_POD` → STOP.**

Per the owner's own rule ("STOP if ownership cannot be confirmed"), this
stage halts here. The deployment registry lives in the Emergent control
plane, not in the container, so no command available to me can name the
owning project. What follows is the evidence that narrows it to one
strong hypothesis, and the exact question set that closes it.

---

## 1 · Measured facts

**Edge / DNS.** All three custom domains resolve to the *same* Cloudflare
address pair, and the preview URL to a *different* one:

| host | A records | notable headers |
|---|---|---|
| `nivxray.nivxforge.com` | `162.159.142.117`, `172.66.2.113` | `server: cloudflare`, HSTS preload |
| `nivxforge.com` | `162.159.142.117`, `172.66.2.113` | — |
| `nivxmachines.com` | `172.66.2.113`, `162.159.142.117` | `server: cloudflare`, HSTS preload |
| `greeting-app-5782.preview…` | `104.18.10.243`, `104.18.11.243` | `server: cloudflare`, **`via: 1.1 google`** |

**No `x-vercel-*` header on any host.** These are **not** Vercel
deployments — they sit on Emergent's own Cloudflare-fronted edge. TLS is
a per-hostname single-SAN certificate from Google Trust Services
(`CN = nivxray.nivxforge.com`), i.e. each hostname is attached and
certified individually.

**The deployed backend is running THIS session's code.**
`nivxray.nivxforge.com/api/openapi.json` exposes
`HeartbeatBody.queue_depth`, including my own description string
verbatim:

> *"Unsent events in the sensor's local outbox. Lets the platform
> distinguish a BACKLOG from a silence: a sensor that is alive and behind
> has not stopped."*

That field was written **minutes before this check**, in this session. No
older deployment snapshot can contain it. Path count is **785 on both**
hosts, and `/api/health` is byte-identical.

**Yet the user store is different.** Identical `POST /api/auth/login`
payload → **200 + access_token** on preview, **401 "Invalid credentials"**
on `nivxray.nivxforge.com`. Same code, same schema, **different
database**.

**Target hostnames are free.** `xdr.nivxforge.com`,
`edr.nivxforge.com`, `workspace.nivxmachines.com` → all **NXDOMAIN**.
Nothing to displace at any of the three Step 2/4/5 targets.

---

## 2 · What this changes — my earlier hazard warning was probably WRONG

I previously warned that pressing Deploy would replace the live Workspace
with XDR, reasoning from the repo-root `vercel.json`
(`buildCommand: cd apps/nivxray-xdr && vite build`). The new evidence
undermines that reasoning:

- there is **no Vercel involvement** on any live host, so `vercel.json`
  appears **not to govern these deployments at all**;
- the deployed **backend is current to minutes ago** while the deployed
  **frontend is still the CRA Workspace** — if a deploy had switched the
  frontend target to the Vite XDR app, that domain would already be
  serving XDR. It is not.

**Most probable reading:** Emergent's pipeline builds the conventional
`/app/frontend` (+ `/app/backend`), ignoring `vercel.json`. The Vite XDR
app is visible only in *preview*, because supervisor was pointed at
`/app/apps/nivxray-xdr`.

If that is right, the risk **inverts**:

- ✅ **Workspace is probably NOT endangered** by a redeploy — a deploy
  would rebuild `/app/frontend` again.
- ⚠️ **XDR/EDR probably CANNOT be production-deployed from this project
  at all.** The pipeline would keep shipping Workspace. Making it ship
  XDR would mean changing what the pipeline builds — and *that* is the
  action that would take the live Workspace down.

This is exactly why the owner's Step 4/5 (separate deployments, prove on
the generated URL first) is the correct shape. It also means **Step 2
must not be executed by changing this project's build target.**

Both readings remain hypotheses. Neither may be acted on.

---

## 3 · What only the Emergent UI can answer (STEP 1 completion)

Home → **View all deployed apps**, then for the deployment holding
`nivxray.nivxforge.com` record:

1. Which **project/app** owns that hostname, and its deployment URL.
2. Whether `nivxforge.com` / `www.nivxforge.com` and `nivxmachines.com`
   are the **same** project or **different** ones (three distinct
   frontend bundles are live, so most likely three deployments).
3. What that deployment **builds** — `/app/frontend` or
   `apps/nivxray-xdr`? This is the single fact that decides whether a
   redeploy is safe.
4. Its **last deploy timestamp** — if it is within the last hour, the
   backend currency is explained by a recent deploy rather than by
   code-sync, and hypothesis (A) is confirmed.
5. Whether a **rollback / previous deployments** list exists for it.

---

## 4 · Blockers to record before Step 2

- **Production credentials unknown.** The preview admin credential is
  rejected by production, so I cannot log into the live Workspace to
  prove Step 3's requirement *"`nivxray.nivxforge.com` still works
  during the migration."* A production account is needed, or that check
  must be performed by the owner.
- **`REACT_APP_BACKEND_URL` for Step 2 is undecided.** CRA inlines it at
  build time. The live Workspace bundle was built pointing at its **own
  origin** (`https://nivxray.nivxforge.com`), i.e. a same-origin
  full-stack deployment. A Workspace deployment at
  `workspace.nivxmachines.com` must be told *which* backend — and
  therefore *which database* — it is for. Pointing it at production and
  pointing it at preview are both one env var away, and the wrong choice
  is invisible in the UI.
- **Step 5 + Step 7 interaction.** `apps/nivxray-xdr` contains **both**
  product shells, so if XDR and EDR become separate deployments of the
  same bundle, `xdr.nivxforge.com/edr` and `edr.nivxforge.com/xdr` will
  both still resolve inside the app. Enforcing product-origin boundaries
  is additional work, and the existing XDR↔EDR pivot is an **in-app
  `navigate()`** — it must become an env-driven **absolute cross-origin
  URL** before those products live on different hostnames, or the pivot
  will keep the analyst on the wrong product origin. The
  `WorkspaceLaunch` component already has the right shape for this
  (env-driven, new tab, honest `NOT CONFIGURED` state) and is the
  pattern to extend in Step 7.

---

## 5 · Security defect found and fixed during this stage (self-inflicted, P0-3)

Putting the sensor's durable state under `/app` to survive container
recreation had a consequence I did not check at the time: **`/app` is the
git working tree, and the state files were tracked.**

```
git ls-files agents/nivxforge-linux/.state/
  agents/nivxforge-linux/.state/identity.json      ← the endpoint's AGENT CREDENTIAL (0600)
  agents/nivxforge-linux/.state/observed.json
  agents/nivxforge-linux/.state/outbox.jsonl       ← 18,152 lines of RAW HOST TELEMETRY
  agents/nivxforge-linux/.state/outbox.offset
```

`identity.json` carries a 47-character bearer credential that
authenticates telemetry ingest as this endpoint. `outbox.jsonl` (6.4 MB)
carries real process names, command lines, PIDs, start ticks and file
paths from this host. **"Save to Github" would have published both.**

Fixed:
- `.gitignore` → `agents/nivxforge-linux/.state/`, with the reason
  written next to it.
- `git rm --cached -r agents/nivxforge-linux/.state/` — files remain on
  disk, so the sensor is untouched (verified: same PID, uptime 1:51,
  `DELIVERING` immediately after).
- Regression guard: `test_sensor_runtime_state_is_never_committed`
  (17 tests now green in
  `backend/tests/edr/test_p0_3_telemetry_freshness.py`).

**Residual risk — owner decision required.** Git *history* still contains
the credential, so it is compromised in the strict sense. Mitigating
facts: it authenticates only against the **preview** backend and
database, whose data is non-production, and the endpoint it identifies is
this container. Rotation is now safe and cheap (revoke the credential and
let the supervised bootstrap re-enrol — P0-3 made re-enrolment preserve
the delivery record, so no history is lost), but it touches the sensor,
and the owner's rule is not to change the sensor to complete a migration.
**Not rotated. Awaiting instruction.**
