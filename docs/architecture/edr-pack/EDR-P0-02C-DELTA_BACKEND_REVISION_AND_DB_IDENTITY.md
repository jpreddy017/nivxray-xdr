# EDR-P0-02C — DELTA REPORT
## Deployed Backend Revision · Production MongoDB Identity · Database-Specific Backup Evidence

- **Date:** 2026-10-30
- **Scope:** strictly read-only metadata verification. Supersedes the corresponding UNKNOWN rows in `EDR-P0-02C_PRODUCTION_ARCH_RECOVERY_VERIFICATION.md`.
- **Result:** **PARTIAL** — backend runtime identity and production database identity are now VERIFIED; database-specific backup/restore evidence remains BLOCKED.
- **Actions taken:** platform metadata read only. No deploy, no redeploy, no record export, no record read, no connection string read, no secret value read, no source change, no GitHub push, no Vercel operation, no production mutation.

---

## 0 · Carried-forward VERIFIED facts (Vercel — closed, not re-audited)

Supplied by the user from an independent read-only Vercel audit and accepted as **VERIFIED**; this audit was **not** repeated and no `VERCEL_TOKEN` was requested for it.

| Fact | Value |
|---|---|
| Vercel project | `nivxray-edr-production` (project ID supplied; masked in transit) |
| Production deployment | domain-assigned, state `READY` (deployment ID supplied; masked in transit) |
| Source repository | `jpreddy017/nivxray-xdr` |
| Source branch | `phase2/edr-production` |
| Source commit | `35d47cc96352f492bd4c603a2f2f1b65afb4119f` |

**Vercel deployment identity and source provenance → VERIFIED.** Frontend recovery provenance is therefore closed: the production frontend is rebuildable from a named repo/branch/commit.

Local corroboration (read-only, non-blocking): this workspace has **no git remote configured** and does **not** contain object `35d47cc9…` — i.e. the Vercel source lineage lives in a repository that is **not** this pod's checkout. This is consistent with, and does not contradict, the Vercel finding; it does mean frontend and backend provenance come from two different places.

---

## 1 · Deployed Emergent backend revision — **PARTIAL (runtime identity VERIFIED, commit UNRECORDED)**

### 1.1 Verified

| Attribute | Value | Evidence source |
|---|---|---|
| Backend deployment | `greeting-app-5782` (serving API origin `nivxray.nivxforge.com`) | platform deployment record |
| Active run ID | `81342093-10f6-4291-9643-46c538a41d57` | platform deployment record |
| **Deployed image digest** | **`sha256:be6d97d5a1a44cdad0812ffbd528a7a63cf6c6bee4447c5f8e5f54223d080ac5`** | container image reference of the running revision |
| Image tag | the run ID `81342093-…` (**not** a commit) | image tag |
| Build record | Cloud Build `4159f71a-…` | build pipeline record |
| Built → promoted | **2026-10-30 09:22 → 09:36 UTC** | build/promotion timestamps |
| Deployment ID | `96834a37-643a-4d79-aa15-44810db52b06` | platform deployment record |
| Job ID | `486146a0-9a5d-462a-8072-904d27d6c533` | `/app/.emergent/emergent.yml` (matches platform) |
| Base image | `fastapi_react_mongo_shadcn_base_image_cloud_arm:release-09072026-3` | `/app/.emergent/emergent.yml` |

**The production backend revision is now pinned and immutable.** An image digest is a content-addressed identifier: it is a *stronger* recovery anchor than a commit SHA for the question "what is running", because it identifies the exact bytes deployed.

### 1.2 Confirmed absent — no commit SHA exists to find

| Attribute | Status |
|---|---|
| Git commit SHA of deployed backend | **UNRECORDED — confirmed absent, not merely unlocated** |
| Git branch of deployed backend | **UNRECORDED** |
| Git repository of deployed backend | **UNRECORDED** |

**Root cause (structural, not an access limitation):** the Emergent backend build is a **zip-based build taken from the preview `/app` working tree**. No VCS metadata is captured into the build or the image. There is therefore **no commit SHA to retrieve from any platform surface** — this is not a permissions problem and will not be solved by a different token or a support escalation. The previously open blocker "deployed backend revision unknown" is hereby **closed as structurally unobtainable**, and replaced by the digest/run-ID anchor above.

### 1.3 Inference — strong, explicitly labelled **INFERRED**

The byte-identical `platform-health` payload reported earlier (`md5 2d42361e204fba252b2b3f6c88637ade`, production vs. this checkout) is now **explained**: that endpoint reads repository files at runtime, and the production image was built from a zip of this very `/app` tree at **09:22 UTC today**. The deployed backend content therefore corresponds to **the `/app` working tree as it stood at ~09:22 UTC on 2026-10-30**, not to any tagged commit.

Boundary of that inference:
- This pod's HEAD is `a6f0ebb54021d3a07644272754fa3538df205bf7` on `fix/dt-v3-auth-contract-backend`, committed **13:58 UTC — after the 09:22 build**. HEAD is therefore **not** the deployed content; at minimum the post-build documentation commits are not in the image.
- A zip build captures **uncommitted working-tree state** as well. Any file dirty at 09:22 is in production but in no commit anywhere. This is a **recovery-integrity hazard**: production backend bytes are not guaranteed to be reproducible from Git.
- `"build_id": "1ecec01"` in the health payload remains **static repository text, identical locally, and must never be cited as the deployed revision.** Reconfirmed; not used above.

### 1.4 Consequence for the EDR candidate

The manifest-to-deployment question from the main report is unchanged in verdict but sharper in form: the frozen EDR candidate `d2f8b7429e9018cde7e049e69e7c316277de147f` **cannot be shown equal to production by commit comparison, because production has no commit.** Equivalence could only ever be argued by rebuilding the candidate and comparing image digests — which is a build action and is **not authorized**. Status stays **CONSISTENT, NOT PROVEN**.

---

## 2 · Production MongoDB identity — **VERIFIED (name/ownership) / BLOCKED (cluster topology)**

### 2.1 Verified

| Attribute | Value | Evidence source |
|---|---|---|
| **Production `DB_NAME`** | **`greeting-app-5782-test_database`** | resolved from the live production `MONGO_URL` binding |
| Collections present | **103** | live database metadata (count only; **no records read, no records exported**) |
| Hosting | Emergent-managed **MongoDB Atlas**; `MONGO_URL` is a platform **system secret** | production environment binding |
| Exclusivity | database is **app-namespaced / dedicated to this app** | platform ownership model + name scoping |
| Preview separation | preview `DB_NAME="test_database"` on **local** Mongo; `matches_expected:false` vs production | `/app/backend/.env` + production binding |

The earlier **INFERRED** production database name from the main report is now **CONFIRMED CORRECT** — the `{app_name}-{preview_db_name}` convention held. That row is upgraded **INFERRED → VERIFIED**.

Cross-check on scale (read-only, corroborating): the production database holds **103** collections against the **117** authoritative collection names catalogued in A0-03. Consistent with a live subset of the documented schema; it also means the production database is **not** reconstructible from the 39 EDR-exclusive collections alone. No connection string, credential, username or record value was read or printed at any point.

### 2.2 Blocked

| Attribute | Status | Reason |
|---|---|---|
| Atlas **cluster** name | **BLOCKED** | connection string is a system secret and is never returned by any available tool surface |
| Atlas **project/organisation** name | **BLOCKED** | same |
| Cluster topology / shared-vs-dedicated **cluster** | **BLOCKED** | same — note: the *database* is dedicated (verified); whether the *cluster* hosting it is shared is unknown |

---

## 3 · Database-specific backup / restore evidence — **BLOCKED**

The generic platform retention policy (hourly 7d / daily 7d / weekly 4w / monthly 12m / yearly 1y, 7-day PITR, restore via support, DB preserved on undeploy) is **already recorded and is not restated as new evidence**. The question asked here was whether that policy is **materialised** for `greeting-app-5782-test_database`. It could not be answered.

| Evidence sought for THIS database | Status |
|---|---|
| Most recent snapshot timestamp | **BLOCKED** |
| Count of retained snapshots | **BLOCKED** |
| PITR actually enabled on the hosting cluster | **BLOCKED** |
| Restore-execution owner for this database | **BLOCKED** (policy says platform/support; unconfirmed for this DB) |
| Any prior restore ever performed for this app | **BLOCKED** |
| Materialised RTO / RPO | **BLOCKED** — no documented value |

**Reason:** no available tool surface exposes Atlas snapshot metadata. This is a genuine access boundary, not an absence of data.

**Who can unblock:** Emergent Support / platform infrastructure, quoting `deployment_id 96834a37-643a-4d79-aa15-44810db52b06` and `job_id 486146a0-9a5d-462a-8072-904d27d6c533`.

**Governance position:** backup for the production EDR database remains **POLICY-ASSERTED, NOT EVIDENCED, NEVER EXERCISED**. The T1/T2 Git-history archives remain the **only** RESTORE-VERIFIED assets in the system, and they are source history — **not** production data.

---

## 4 · Delta against the main P0-02C report

| Row | Was | Now |
|---|---|---|
| Vercel deployment identity + source provenance | BLOCKED (empty `VERCEL_TOKEN`) | **VERIFIED** (project / READY deployment / repo / branch / commit `35d47cc9…`) |
| Deployed backend runtime identity | UNKNOWN | **VERIFIED** — digest `sha256:be6d97d5…d080ac5`, run `81342093-…`, built 2026-10-30 09:22 UTC |
| Deployed backend **commit SHA** | UNKNOWN | **UNRECORDED — structurally unobtainable** (zip build, no VCS metadata) |
| Production `DB_NAME` | INFERRED | **VERIFIED** — `greeting-app-5782-test_database`, 103 collections, dedicated, Atlas-managed |
| Atlas cluster / project identity | UNKNOWN | **BLOCKED** (system secret) |
| Database-specific snapshot inventory / PITR / restore history / RTO / RPO | UNKNOWN | **BLOCKED** (no tool surface; Support-only) |
| Manifest ↔ deployment equality for `d2f8b742` | CONSISTENT, NOT PROVEN | **unchanged** — now provably undecidable by commit; digest rebuild would be required (not authorized) |

### New risk raised by this delta

**R-1 · Production backend bytes may not be reproducible from Git.** The zip-based build can capture uncommitted working-tree state, and the deployed content (09:22 UTC) predates this pod's HEAD (13:58 UTC). Until the exact deployed tree is reconciled, "restore the backend from Git" is an **unproven** recovery path regardless of how complete the 191-module manifest is.

---

## 5 · Remaining blockers after this delta

1. **Database-specific backup evidence** — Support-only (§3). The single largest unmitigated production recovery gap.
2. **Atlas cluster/project identity** — system secret (§2.2).
3. **Deployed-tree reconciliation** — whether the 09:22 UTC build tree is byte-equal to a commit, or contains uncommitted state (§1.3). Resolvable in-workspace, read-only, if authorized.
4. **Off-pod custody of the T1/T2 archives** and **rotation of the `.tok` credential** whose 22 historical versions sit inside them — neither requires production access.
5. **Temporary documentation/preservation routes** (`/api/_arch`, `/api/_pv/*`, flag `ARCH_DOCS_SHARE`) remain present in `backend/server.py` and are flagged for removal under a **separate authorization**; no change was made under this read-only task.

EDR separation remains **HOLD**.

---

*Report ends. No further action taken.*
