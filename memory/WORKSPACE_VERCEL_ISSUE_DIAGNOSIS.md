# Workspace Vercel issue · diagnosis

**Diagnose only. Nothing deployed, no setting changed, XDR/EDR untouched.**

## Symptom

A new Vercel project was created with **Root Directory = `frontend`**, but
Build / Install / Output stayed **locked** and showed the XDR
`apps/nivxray-xdr` configuration.

## Cause — measured on GitHub raw, not inferred

| ref | `vercel.json` (repo root) | `frontend/vercel.json` | `frontend/.nvmrc` |
|---|---|---|---|
| `conflict_310826_2116` | 200 · 440 B | **200 · 3566 B** | **200** |
| `main` | 200 · 440 B (**the XDR config**) | **404** | **404** |

A new Vercel project defaults its **Production Branch to `main`**. On `main`
the **only** `vercel.json` in the repository is the **repo-root** one, whose
commands are:

```
cd apps/nivxray-xdr && yarn install …
cd apps/nivxray-xdr && node ./node_modules/vite/bin/vite.js build
apps/nivxray-xdr/dist
```

Vercel locks the Build/Install/Output fields whenever a `vercel.json`
supplies them, and it displayed those values. Setting Root Directory to
`frontend` could not help, because **on `main` there is no
`frontend/vercel.json` to read** — it exists only on
`conflict_310826_2116`.

**The import flow was not wrong.** The project was pointed at a branch that
does not contain the Workspace configuration. Re-importing would reproduce
the identical result, which is why it must not be repeated.

## The one safe next action

**Do this in the WORKSPACE project — NOT in `nivxray-xdr`.** Use the project
switcher at the top of the Vercel dashboard to leave `nivxray-xdr` first;
that project's branch tracking must not be touched, because changing it
would alter which branch fires its production deployments.

> **Settings → Environments → Production → Branch Tracking**
> set the branch to **`conflict_310826_2116`**, then **Save**.

**Correction to an earlier instruction in this file's history:** I first said
*Settings → Git → Production Branch*. That path is **out of date** —
current Vercel keeps only Connected Git Repository, Git Commits, Git LFS and
Deploy Hooks on the Git page. The production branch lives under
**Environments → Production → Branch Tracking**
(`vercel.com/docs/git`, `vercel.com/kb/guide/can-i-use-a-non-default-branch-for-production`).
The `Branch` field next to **Create Hook** on the Git page is a **deploy
hook** — it triggers a deployment and is not the branch setting. Do not
create one.

Then re-open **Settings → Build and Deployment**. The locked values should
now read from `frontend/vercel.json`:

```
Install  yarn install --production=false --frozen-lockfile
Build    CI=false GENERATE_SOURCEMAP=false REACT_APP_BACKEND_URL=https://nivxray.nivxforge.com \
         REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE=disabled \
         REACT_APP_NIVX_FLAG_CASE_ENGINE=disabled \
         REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3=disabled \
         yarn build && node scripts/verify-production-build.js
Output   build
Node     20.x   (frontend/.nvmrc)
```

**If they still show `apps/nivxray-xdr` after saving**, stop and tell me:
that would mean Vercel is consulting the repo-root config regardless of Root
Directory, which is a different cause and needs a different fix. Do not
deploy to find out.

### Worth knowing for later, not an action now

The same **Branch Tracking** panel has an **Auto-assign Custom Production
Domains** toggle. Turning it **off** lets a push build without going live,
so a deployment can be verified first and then promoted manually via
Deployments → ⋯ → **Promote to Production**. That is a good fit for this
migration's "verify before cutover" rule — but it is a later decision, not
part of this next action.

## Why the obvious alternatives are NOT safe

- **Push `frontend/vercel.json` to `main`** — `main` is the **production
  branch of the existing `nivxray-xdr` Vercel project**, so any push to it
  fires that project's **production** deployment. Unapproved Phase 2 action.
- **Merge the working branch into `main`** — same problem, larger.
- **Edit repo-root `vercel.json`** — it governs the frozen Emergent project's
  build and you instructed it not be changed.

Changing one branch setting on the new project touches nothing else and is
reversible.

## Unchanged by this diagnosis

Legacy watchdog healthy · Workspace build guard PASSED · repo-root
`vercel.json` untouched · `apps/nivxray-xdr` untouched · nothing deployed.

---

## FINAL CAUSE · the Workspace project never existed

Confirmed by the owner: the Vercel project switcher shows only
**`nivxray-xdr`** and **Create Project**. There is no Workspace project.

So the earlier instruction — "set Branch Tracking in the Workspace
project" — was **not performable**, and every attempt to fix settings was
chasing a project that does not exist. The `frontend`-rooted import was
either never completed or was abandoned at the screen showing the locked
XDR values.

**Do not save the `conflict_310826_2116` value typed into `nivxray-xdr`.**
That field is that project's own production branch; saving it would
repoint its production deployments. Refresh the page to discard it.

### The ordering constraint nobody had spotted

Branch Tracking only exists **after** a project exists, and a Vercel
project is only created by completing an import — which performs a first
build immediately. So the sequence *must* be:

```
create project (first build happens, and may be WRONG) 
      ↓
set Branch Tracking → conflict_310826_2116
      ↓
redeploy → settings now read frontend/vercel.json
      ↓
only THEN attach workspace.nivxmachines.com
```

**The first build is expendable, and that is what makes this safe.** No
custom domain is attached at that point, so a wrong or failed first build
serves nobody and damages nothing. The mistake before was treating that
first screen as something that had to be perfect.

### The single safe method

1. Vercel → **Create Project** → import `jpreddy017/nivxray-xdr`.
2. Name it **`nivxmachines-workspace`**.
3. **Root Directory → `frontend`.**
4. If the import screen offers a **branch** selector, pick
   `conflict_310826_2116`. If it does not, continue anyway.
5. Press **Deploy** and let it finish **however it turns out**. Ignore the
   locked `apps/nivxray-xdr` values on this screen — they come from `main`,
   which has no `frontend/vercel.json`. Expect this build to be wrong or to
   fail. That is fine and expected.
6. In the **new** project: **Settings → Environments → Production →
   Branch Tracking** → `conflict_310826_2116` → **Save**.
7. Recommended in the same panel: turn **Auto-assign Custom Production
   Domains OFF**, so future builds do not go live until promoted.
8. **Deployments → Redeploy** (or push).
9. Re-open **Settings → Build and Deployment** and confirm it now reads
   from `frontend/vercel.json` (install with `--frozen-lockfile`, the
   guarded build command, output `build`, Node 20).
10. **STOP.** Do not add `workspace.nivxmachines.com` until step 9 is
    confirmed and reported.

### What must NOT be done

- Do not touch `nivxray-xdr` — no Save, no branch change, no deploy hook.
- Do not push `frontend/vercel.json` to `main`, and do not merge into
  `main`: `main` is `nivxray-xdr`'s production branch, so that fires its
  production deployment from 218-commit-stale code.
- Do not attach the custom domain before the build settings are correct.
