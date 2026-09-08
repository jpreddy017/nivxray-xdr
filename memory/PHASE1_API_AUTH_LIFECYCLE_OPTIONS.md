# Phase 1 · §5 · API / auth lifecycle — proven options and consequences

**Report only. Nothing executed. No API migration performed.**
Question asked: *can the existing authoritative backend be made
independently deployable/restartable without replacing its frontend, and can
it eventually be exposed at `api.nivxforge.com` without creating a second
backend or a second production database?*

---

## 1 · What the platform confirms — the hard constraints

| question | platform answer |
|---|---|
| Restart or re-configure the backend **without** rebuilding the frontend | **Not supported.** Deployments are atomic full-stack units |
| Any "restart only" / "reload env" action that does not pull new code | **Not supported** |
| Console, shell, task runner or migration hook against a deployed app | **Not supported** |
| Direct production MongoDB connection string | **Not supported** |
| Env-var change on a deployed app | **Triggers a rebuild from current repo state** |
| Rollback | **Restores the previous build artefact** (does not re-run the build) |
| One backend serving several separate frontends | **Not a documented pattern** — see §2, it is not *blocked*, only unmanaged |
| Adding an **additional custom domain** to an already-deployed app: rebuild or routing-only? | **UNKNOWN — the platform team could not confirm** |
| Is the production MongoDB preserved across a rebuild? | **UNKNOWN — the platform team could not confirm** |

## 2 · One correction to the platform's answer, on our own evidence

"One backend serving multiple frontends is not a documented pattern" is a
statement about what the platform *manages*, not about what *works*. We have
already proven the mechanism at the HTTP layer:

```
OPTIONS https://nivxray.nivxforge.com/api/auth/login
  Origin: https://workspace.nivxmachines.com
→ 200 · access-control-allow-origin: * · allow-headers: content-type,authorization
```

Auth is a Bearer token in `localStorage`, not a cookie, so no credentialed
cross-site request is involved. The target architecture — three frontends,
one authoritative API, one production database — is therefore **already
functioning today** for the Workspace. No second backend is required for it,
and none is proposed.

## 3 · THE BLOCKING UNKNOWN — must be answered before ANY rebuild

**Nobody has confirmed whether a rebuild preserves the production MongoDB.**
Every option below that involves a rebuild is gated on this. It must be
answered by `support@emergent.sh` with the job id, in writing, before a
rebuild of the legacy project is contemplated under any circumstances.

If the answer were "data is re-provisioned", a rebuild would destroy the
authoritative production database — categorically worse than any frontend
concern, and it would invalidate the "rebuild is safe once the new Workspace
is live" reasoning I offered earlier. **I withdraw that reasoning until this
is confirmed.**

## 4 · The options, ranked, with honest consequences

### Option A · Make a legacy rebuild *non-destructive in kind* — repo-side only

Point **repo-root `vercel.json`** at `frontend` instead of
`apps/nivxray-xdr`. A rebuild of the legacy project would then produce a
**Workspace** frontend — the cleaned one — instead of the XDR app.

- Disarms the standing hazard at its root: the reason a rebuild is dangerous
  today is purely that the repo-root config builds a *different product*.
- **Unblocks the credential** without any product cutover: once a rebuild is
  merely "same product, cleaned version", env vars can be set and
  `seed_admin` runs.
- No second backend. No second database. No new hostname. No code duplication.
- **Consequence to accept:** `nivxray.nivxforge.com` would begin serving the
  **cleaned** Workspace — so XDR / Investigations nav items, `/nivxforge/*`
  and `/edr/trajectory` would disappear from the legacy host too, and
  `/benchmark` would require auth there. That is the same product with the
  approved cleanup applied, **not** a replacement by a different product.
- **Consequence to weigh:** Phase 2/3 would then deploy XDR and EDR as their
  own Vercel projects (Root Directory `apps/nivxray-xdr`), which is the
  approach already recommended for the Workspace — so nothing is lost.
- **Conflicts with a standing instruction.** You said *"do not change
  repo-root `vercel.json`"* — in the context of making the Workspace
  deployment fit. This is a different purpose (disarming the hazard), so it
  is reported for an explicit decision rather than acted on.
- **Still gated on §3.**

### Option B · Attach `api.nivxforge.com` to the existing deployment

If adding a custom domain is routing-only, this delivers the permanent API
origin **with no rebuild at all**, keeping one authoritative backend and one
production database — exactly the target architecture.

- Cheapest and cleanest path to the end state.
- Does **not** by itself unblock the credential: `seed_admin` still needs an
  env var, which still needs a rebuild.
- **Depends entirely on one unanswered factual question** (§1, row 8). Ask
  support: *"does adding a custom domain to an already-deployed app trigger a
  rebuild, or is it purely routing/DNS?"*

### Option C · Do nothing; keep the credential blocked

Fully consistent with your decision. Workspace reaches
`WORKSPACE_MIGRATION_UNAUTHENTICATED_VERIFIED` and stops there.

- Zero risk, zero cost, nothing irreversible.
- **Consequence:** authenticated production acceptance stays blocked
  indefinitely, so `WORKSPACE_MIGRATION_RUNTIME_VERIFIED` is unreachable, and
  Phase 5 retirement of the legacy hostname cannot begin.
- Acceptable as a holding position, not as an end state.

### Option D · Ask Emergent support to provision the admin row

The platform team themselves raised this as a non-standard possibility.

- No rebuild, no code change, no unsupported mechanism added to the product.
- **Consequence:** depends on vendor goodwill, is not a repeatable process,
  and a third party would handle a credential. Last resort.

### Rejected outright

A second backend or second production database (creates a second
authoritative source — the failure this whole programme exists to prevent) ·
an app-side admin-creation endpoint built only for this migration (you
forbade it, and it would be a permanent attack surface for a one-off need) ·
direct production DB manipulation (not supported and not attempted) ·
brute-forcing the existing credential (the login route rate-limits to `429`;
it would be attacking our own production).

## 5 · Recommendation

1. **Now:** deploy the Workspace to Vercel and run the sweep → Option C
   holds; nothing else is needed for Phase 1's unauthenticated gate.
2. **In parallel, ask support two factual questions** — they cost nothing and
   they unlock everything:
   - does adding a custom domain to a deployed app trigger a rebuild?
   - **is the production MongoDB preserved across a rebuild?**
3. **Then decide between A and B** with those answers in hand. If domains are
   routing-only, B gives the permanent API hostname immediately; A remains
   the only path that unblocks the credential without a product cutover.

No further work on this is warranted until those two answers exist — any plan
built before them would be speculation dressed as architecture.
