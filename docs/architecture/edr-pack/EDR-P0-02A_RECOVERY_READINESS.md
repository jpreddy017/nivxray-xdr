# EDR-P0-02A — Recovery Readiness Audit

**Reference:** P0-02A · **Date:** 2026-10-30 · **Mode:** STRICTLY READ ONLY · **Implementation:** HOLD
**Governance:** `EDR_ISOLATION_DIRECTIVE.md` + G0–G6 · **Baseline:** `EDR-P0-01_DEPENDENCY_PRESERVATION_MANIFEST.md`
**Change performed:** NONE — no backup created, no restore run, no database access, no repository change, no build, no deployment, no VM or agent operation, no production modification. No secret value was read, printed or logged.

**Classification used for every item:**
**[SP] Source preserved** · **[BU] Backup exists but untested** · **[RV] Restore verified** · **[MU] Missing or unknown**

---

## 1 · Manifest validation against its Git revision (task 1) — **PASS**

Each of the 191 modules was checked three ways and all three agree:

| Check | Method | Result |
|---|---|---|
| Present in the referenced revision | `git ls-tree -r 5040c08c -- backend` | **191 / 191 present**, zero missing |
| Manifest hash equals committed object | Appendix-A blob vs tree blob | **0 mismatches** |
| Committed object equals bytes on disk | `git hash-object <path>` vs tree blob | **0 mismatches** |

```text
modules checked: 191
missing from 5040c08c tree: []
worktree / HEAD / manifest mismatches: 0
```

**Conclusion:** the P0-01 manifest is a faithful, re-verifiable description of revision `5040c08cfd27e835c1ea9013c5d959ae9ea79c5c`. Classification **[SP]**. This is the only item in the audit that is fully closed.

---

## 2 · Production backup arrangements (task 2) — **[MU]**

| Question | Finding |
|---|---|
| Does a production database backup exist? | **UNKNOWN.** No backup configuration, policy, schedule, snapshot record or restore log exists anywhere in the repository or this environment |
| Who owns it? | **No owner identified.** The production database is platform-managed; its backup arrangement is not expressed in code or config that this environment can read |
| Is any production dump present locally? | **No.** `mongodump` exists as a binary (`/usr/bin/mongodump`) but no dump artefact of production exists; the only `.bson` files on disk belong to the local preview/lab stores |
| Recoverability | **Unproven in both directions** — neither confirmed present nor confirmed absent |

**This is the single most important gap in the audit.** Every downstream step of the directive (step 3 — *preserve the original and verify required recovery backups*) depends on it, and it cannot be closed from inside this environment.

**Required to close (read-only, needs your authorization):** the platform's backup/retention policy for the production application — provider, schedule, retention window, restore mechanism and who may invoke it. Names and schedule only; no credentials.

---

## 3 · Deployed backend release provenance (task 3) — **[MU]**

| Evidence attempted | Result |
|---|---|
| Build stamp endpoints | `/api/version`, `/api/build-info` → **404** (confirmed live in A0-01) |
| API-surface comparison | production / preview / local OpenAPI byte-identical (`md5 a8c5abe0…`) — proves schema parity only, **cannot** identify a revision |
| Frontend ledger re-verification | `VERCEL_TOKEN` **is registered** in the secret store (live slot, no test slot) but its **value is empty in this environment** (length 0) — the Vercel API refuses the call with `missingToken`. Re-verification of project/deployment/source SHA therefore remains blocked, exactly as in A0-01 |
| Branch-tip provenance | **verified** via GitHub: `phase2/edr-production` = `35d47cc96352…`, `release/xdr-b8-selector-candidate` = `e2f15a2526…`, `main` = `752a00ff…` **[SP]** |
| Deployed **backend** revision | **UNKNOWN [MU]** |

**Required to close:** an authorized platform read returning the production deployment ID, image/revision and build log. Alternatively, populating the registered `VERCEL_TOKEN` slot would close the *frontend* ledger only — it says nothing about the backend, which is not on Vercel.

---

## 4 · Database backup mechanisms, consistency and restore prerequisites (task 4)

### 4.1 Mechanisms found

| Scope | Mechanism | Class |
|---|---|---|
| Production | none readable | **[MU]** |
| Preview / local (`/data/db`, 1.6 GB) | no scheduled mechanism; live instance only | **[MU]** |
| G4 lab (`nivx_g4_lab`, 9.8 MB) | none | **[MU]** |
| `rocket-e2e/db` (328 MB) | a committed test-fixture store, not a backup | **[SP]** (as a fixture) |
| In-repo tooling | `edr_plane/canonical_index_contract.py` + `routers/edr_migration_control.py` provide **report-mode** index verification — useful for post-restore validation, **not** a backup mechanism | **[SP]** |

### 4.2 Consistency requirements any restore must satisfy

Derived from A0-03; these are the properties a restored database must hold, and they are why a naive collection-level restore is unsafe:

1. **Chain integrity** — `edr_raw_events` → `edr_processing_queue` (references only) → canonical delivery → observation → activity → `edr_findings` → trajectory rows must be mutually consistent. A queue referencing a raw ID that was not restored is a silent corruption.
2. **One authoritative writer** — restoring while a worker runs creates a second writer. Any restore must happen with the processing workers stopped.
3. **Identity preservation** — `observation_id` / `observation_identity_state` / `observation_identity_key` must survive byte-identically, or association silently changes behaviour.
4. **No fabricated promotion** — `case_id` must remain `None` for observations that were never promoted.
5. **Credential epoch coherence** — `edr_agent_credentials.auth_epoch` and `edr_agent_sessions` must be restored consistently or every sensor is either locked out or wrongly accepted.
6. **Tenant boundary** — `edr_tenant_boundary` and per-document `tenant_id` must match; a cross-tenant mix is unrecoverable by replay.
7. **Cross-product references** — `xdr_canonical_evidence` and `v2_shadow_observations` are written through the shared bridge; restoring EDR alone can leave XDR evidence pointing at observations that no longer exist.

### 4.3 Restore prerequisites

Indexes per the canonical index contract (noting the known preview drift: target `sd_canonical_endpointid_eventtime` absent, legacy `pvw_sd_hostname_eventtime` present with a byte-identical key), workers stopped, a target database that is **not** production, and a post-restore cardinality reconciliation acquired → accepted → unique-raw → canonical → rendered.

---

## 5 · Environment configuration and secret custody (task 5) — **[BU]**, improved

A read-only query of the platform secret register (names, slots and update timestamps only — **no values requested, returned or stored**) shows custody **does** exist:

| Property | Finding |
|---|---|
| Application secrets registered | **60** (backend 57, frontend 3) |
| Platform/system keys | 13 (incl. `MONGO_URL`, `DB_NAME`, `REACT_APP_BACKEND_URL`, `CORS_ORIGINS`) |
| Slot model | most keys carry **separate `live` and `test` slots**; `EMERGENT_LLM_KEY` is platform-managed (universal key); `GITHUB_TOKEN` and `INTEGRATION_PROXY_URL` are shared-mode |
| Rotation evidence | update timestamps recorded for 9 sensitive keys, incl. `ADMIN_PASSWORD` (2026-09-26T15:02Z), `JWT_SECRET` (15:01Z), `EDR_AUTH_PEPPER` (14:59Z), `NIVXRAY_SIGNING_SECRET` (14:53Z), `XDR_ROOT_KEY` (14:54Z), `XDR_SECRETS_MASTER` (14:51Z), `XDR_AUDIT_MASTER_SECRET` (14:49Z), `NIVX_DEPLOYMENT_ENV` (15:05Z), `GITHUB_TOKEN` (2026-10-29T11:57Z) |
| EDR-relevant keys present | `EDR_AUTH_PEPPER`, `EDR_AGENT_SESSION_TTL_SECONDS`, `EDR_ENROLLMENT_TOKEN_TTL_SECONDS`, `EDR_MAINTENANCE_TOKEN` |
| Registered but **empty in this environment** | `VERCEL_TOKEN` (value length 0) — a live slot exists in the register; the preview environment has no usable value |
| Recovery procedure | **re-issue, not export.** Values are write-only through the secure card; there is no supported value read-back |

**Upgrade of gap G4:** *existence and custody of configuration secrets* moves from **[MU]** to **[BU]** — a register with slots and rotation timestamps exists, but **no restore drill has ever been performed**, and three keys are unrecoverable-by-design if lost rather than re-issued: `EDR_AUTH_PEPPER` (invalidates every agent credential), `XDR_SECRETS_MASTER` / `XDR_ROOT_KEY` (vault root), `XDR_AUDIT_MASTER_SECRET` (audit chain). Those three deserve an explicit out-of-band custody record.

---

## 6 · Installer EXEs vs G4 evidence (task 6) — **[MU]**, confirmed missing

| Search | Result |
|---|---|
| Any `NivXForgeEDRSetup.exe` / `NivXForgeSensor.exe` on this filesystem | **none** — the only `.exe` files are unrelated Python/npm vendor stubs |
| `payload-manifest.json` anywhere | **not present** |
| `m1-ownership.json` anywhere | **not present** (it exists only on the endpoint) |
| Recorded SHA-256 of a built service image | **none found.** The only 64-hex digest in the installer decision record, `099a6338bb9e1efd96fe9b3f11fc0f1130cf1a2fb6e9b1db8f4c9ff4e2c4d503`, is the hash of the *input document* `NIVXFORGE_EDR_P0_1_WINDOWS_EXECUTION_PATHS.md`, **not** of any executable |
| The VM-reported service image `9AF2F96B2A872B444310D2236922C35831171475481E8503730055AE00146490` | **no corroborating record exists** in the repository, memory or evidence corpora — it appears only where it was reported to me |

**Consequences:** the exact deployed sensor binary cannot be reproduced (unsigned PyInstaller one-file builds are not byte-reproducible), and its hash cannot currently be bound to any source revision from preserved evidence.

**Required to close (no VM change):** read `C:\ProgramData\NivXForgeM1Bootstrap\m1-ownership.json` on the endpoint and record `resources.service.evidence.service_image.sha256` alongside the artefact itself and its `payload-manifest.json` in a durable store. The installer hashed that image before registering the service, so this record — not the running file — is the authoritative provenance.

---

## 7 · G4 VM durable-state preservation requirements (task 7) — **[MU]**

No VM was contacted. The required preservation set, derived from the sensor/M1 source:

| Artefact | Location pattern | Why it is irreplaceable |
|---|---|---|
| `identity.json` | `<state_dir>` | the endpoint credential identity; losing it forces re-enrolment and a new `endpoint_id` |
| `outbox.jsonl` | `<state_dir>` | telemetry queued during any backend outage — unrecoverable if lost |
| journal + bookmarks | `<state_dir>` | channel read positions; loss causes either gaps or duplicate re-reads |
| `channels.json`, `policy.json` | `<state_dir>` | applied policy state and acknowledgement |
| `m1-ownership.json` | bootstrap root | installation provenance, service SD evidence, image digest |
| `m1-config.json` | bootstrap root | the approved configuration contract (origin, tenant, paths, cert policy) |
| Service registration | SCM | `--m1-service-run --m1-config … --state-dir …` with the exact binary path |

**Preservation method with zero VM risk:** a Hyper-V checkpoint of `NIVX-G4-WIN11` / `NIVX-G4-WIN02` while powered off, plus a read-only copy of the two JSON records. **Not performed, not authorized here.**

---

## 8 · `rocket-p0/` classification (task 8) — **unique assets confirmed [MU]**

| Measurement | Value |
|---|---|
| Size on disk | **1.2 GB**, 64,337 files (22,653 `.py`, 11,400 `.js`, 7,054 `.json`, 4,777 `.md`) |
| Tracked by Git | **8 files only** — 99.99 % is untracked |
| Composition | `src/` 366 MB · `f1/` 208 MB · six gate working copies ≈ 94 MB each (`a1`, `a3`, `edr-loop`, `n3a`, `n5gate`, `win-reenrol`) each containing `backend/`, `frontend/`, `apps/`, `docs/`, `SECURE_EXPORT/` |
| **`rocket-p0/src/.git`** | **a separate, complete Git clone** — 158 MB, pack 140.45 MiB, **27 refs** |

### 8.1 The finding that matters

`rocket-p0/src/.git` carries **15 named engineering branches** whose commits exist **nowhere else**:

```
engineering/a1-security-harness          3db07b18…    engineering/n1-ci-gate                09a8c2e8
engineering/a3-security-gate             62a2c658     engineering/n3-http500-investigation  1158afcc
engineering/e3-stabilization             1dc4e358     engineering/n3a-telemetry-bson        38e294c6
engineering/e3-stage2b-package           cd2b8b92  ←HEAD  engineering/n5-ci-gate             1158afcc
engineering/edr-access-loop              eac0192b     engineering/n5-tenant-authority-tests 113ebfb8
engineering/edr-access-permanent         e4031475     engineering/reenrol-placement-preserved 24139032
engineering/f1-v2-dependency             d5bceb80     engineering/win-reenrol-recovery      05b152ac
engineering/n1-audit-provenance          e2c96f2e
```

Verification performed:

```text
/app git      : git cat-file -t cd2b8b92  → "Not a valid object name"      (absent locally)
GitHub API    : commits/cd2b8b92d785bee2f88432d3202367bbd51508c0 → 422     (absent upstream)
control probe : commits/35d47cc96352f492bd4c603a2f2f1b65afb4119f → 200      (API works, SHA resolvable)
/app branches : no branch named e3-stage2b / win-reenrol / a1-security / n3a-telemetry / edr-access
```

**Classification: `rocket-p0/` is NOT redundant.** Most of it is duplicated working copies, but it contains **unique, unpreserved Git history** — up to 140 MiB of objects, including branches whose names map directly onto security-harness, tenant-authority, audit-provenance, telemetry-BSON and Windows re-enrolment recovery work. It is untracked, unbacked-up, and sitting on a volume that is **90 % full with 1.1 GB free**.

**Required (read-only) next step:** `git bundle create` from that clone into a location outside `/app`, then verify with `git bundle verify` + `fsck` — a copy operation on evidence, not on product source. **Not performed; it creates a file, and file creation is outside this task's remit.**

---

## 9 · Recovery inventory — consolidated

| # | Asset | Class | Evidence |
|---|---|---|---|
| 1 | Backend source at `5040c08c` (191-module closure) | **[SP]** | §1, triple-checked blob hashes |
| 2 | M1 installer source, 4 generations | **[SP]** | 13 bundles, `VERIFY.sh` (fsck + 18/18 blobs + 373 tests), subtree `db21f422…` |
| 3 | Frozen G3 candidate `d2f8b742` | **[SP]** | reviewer repo branch tip, full monorepo tree |
| 4 | Deployed frontend branch tips | **[SP]** | GitHub API, control-verified |
| 5 | Evidence corpora (`evidence/` 63 MB, `rocket-evidence/` 118 MB, `memory/evidence/` 2.4 MB, `test_reports/` 5.6 MB) | **[SP]** | on disk, tracked |
| 6 | Test suites (159 backend + 13 frontend EDR modules) | **[SP]** | in repo |
| 7 | `rocket-e2e/db` fixtures (328 MB) | **[SP]** | tracked |
| 8 | Secret register — 60 app + 13 system keys, slots, rotation timestamps | **[BU]** | §5, never restore-tested |
| 9 | M1 bundles as a *restorable* source | **[BU]** | read-only clone + ref resolution succeeded; full restore-to-build never run |
| 10 | **Production database** | **[MU]** | §2 — no backup, no owner, no policy readable |
| 11 | **Deployed backend revision** | **[MU]** | §3 |
| 12 | **Installer EXEs + payload manifest + image digest record** | **[MU]** | §6 |
| 13 | **G4 VM durable state** | **[MU]** | §7 — no snapshot exists |
| 14 | **`rocket-p0/src` unique Git history (≈140 MiB)** | **[MU]** | §8 — untracked, absent locally and upstream |
| 15 | `VERCEL_TOKEN` usable value | **[MU]** | §3 — registered, empty here |
| — | **Anything at all** | **[RV]** | **NONE. Zero assets in this system have a verified restore.** |

---

## 10 · Production access blockers

| # | Blocker | Needs |
|---|---|---|
| B1 | Production backup policy and owner unreadable | authorized platform read (policy/schedule names only) |
| B2 | Production backend deployment ID / revision unreadable | authorized platform read |
| B3 | Production `DB_NAME`, database identity and ownership unreadable | authorized platform read (name-level only) |
| B4 | Production collection counts / index sizes unreadable | follows B3; **explicitly requires separate database authorization**, which this task does not have |
| B5 | `VERCEL_TOKEN` slot empty in this environment | a value provisioned through the secure card — frontend ledger only |
| B6 | Endpoint-held records (`m1-ownership.json`, `m1-config.json`) | a read-only read on the VM, no modification |

---

## 11 · Storage estimates and a minimal, cost-conscious plan

### 11.1 Current storage position

| Volume | Size | Used | Free |
|---|---|---|---|
| `/app` (and `/root`) | 9.8 GB | 8.8 GB | **1.1 GB — 90 % full** |
| `/` overlay | 282 GB | 44 GB | 238 GB |
| `/data/db` (local Mongo: preview + labs) | 1.6 GB | — | — |

**Operational constraint: nothing of size may be written to `/app`.** Any staging must target the overlay or an external destination.

### 11.2 Estimated sizes to preserve

| Item | Estimate | Note |
|---|---|---|
| `rocket-p0/src` history bundle | **≈ 140–160 MB** | one `git bundle`, compressed pack |
| Backend source at `5040c08c` | ≈ 60 MB | already preserved in Git |
| Evidence corpora | ≈ 189 MB | already tracked |
| M1 bundles | ≈ 100 MB | already present |
| Local Mongo (preview + labs) logical dump | ≈ 0.6–1.0 GB | compressed; **not** production |
| G4 VM checkpoint | 10–40 GB per VM | lives on your Hyper-V host; zero cloud cost |
| **Production database dump** | **UNKNOWN** | cannot be sized without B3/B4 |

**Cost posture:** every recommended action is free — Git bundles, existing disk, your own Hyper-V host. No paid MongoDB service, no new workstation, no additional storage product is required or proposed.

### 11.3 Proposed isolated restore tests (ordered, each small and reversible)

| # | Test | Method | Pass criterion | Authorization needed |
|---|---|---|---|---|
| T1 | **Unique-history preservation** | `git bundle create` from `rocket-p0/src` to the overlay, then `git bundle verify` + `git fsck`, then clone the bundle read-only and confirm all 27 refs resolve | all refs resolve, fsck clean, bundle re-clonable | creates one file — needs your go-ahead |
| T2 | **M1 source restore-to-build readiness** | clone each bundle into the overlay, confirm the subtree hash equals `db21f422…`, run the 373 portable tests | hash matches, 373 pass | read-only + temp files |
| T3 | **Candidate restore** | shallow read-only clone of `reviewer/g3-clean-pass`, confirm HEAD = `d2f8b742`, confirm the tree contains a bootable app layout | all three true | read-only |
| T4 | **Database restore drill — synthetic only** | create a small synthetic dataset in an isolated local database, dump it, drop it, restore it, then run the index contract in report mode and a cardinality reconciliation | counts and identities reconcile exactly; report mode names the expected indexes | **database authorization required — prohibited today** |
| T5 | **Secret recovery drill** | re-issue one non-critical key into its **test** slot via the secure card and confirm the application picks it up | key updates, app healthy, no value ever displayed | your action in the UI |
| T6 | **Installer provenance capture** | read `m1-ownership.json` on the VM and compare `service_image.sha256` with `9AF2F96B…` | digests match | read-only VM read |
| T7 | **Production backup confirmation** | authorized platform read of backup policy/schedule/owner | a named policy with a restore mechanism | **your authorization** |

T1 is the highest value per minute: it is the only test that protects an asset which currently exists in exactly one place.

---

## 12 · Explicit stop conditions

Separation work must **stop and remain on HOLD** while any of the following is true:

1. No verified production database backup exists (**currently true — B1**).
2. The deployed backend revision is unknown (**currently true — B2**).
3. Production database identity and ownership are unknown (**currently true — B3**).
4. Unique, unpreserved Git history exists outside version control (**currently true — §8**).
5. The deployed installer artefact and its digest record cannot be produced (**currently true — §6**).
6. G4 VM durable state has no snapshot while any sensor-side action is contemplated (**currently true — §7**).
7. Any critical secret lacks an out-of-band custody record (`EDR_AUTH_PEPPER`, `XDR_SECRETS_MASTER`, `XDR_ROOT_KEY`, `XDR_AUDIT_MASTER_SECRET`) (**currently true — §5**).
8. Zero assets have a verified restore (**currently true — §9**).

---

## 13 · Assessment

### **BLOCKED**

The bounded audit tasks were completed and are evidence-backed: the 191-module manifest **validates cleanly** against its revision and file hashes (task 1 — PASS); secret custody is better than previously recorded (task 5 — upgraded to [BU]); installer artefacts are **confirmed absent** rather than merely unlocated (task 6); VM preservation requirements are specified without touching the VM (task 7); and `rocket-p0/` is now **classified, not guessed** (task 8).

But the **mission question — can existing EDR, XDR, Workspace and NivX Machines functionality be recovered — is answered NO, not today.** Five independent reasons, any one of which is sufficient:

1. No production database backup can be shown to exist, and no owner for one can be identified.
2. The deployed backend revision is unknown, so there is nothing definite to restore *to*.
3. Production database identity and ownership are unknown.
4. Unique Git history exists in exactly one untracked copy on a 90 %-full volume.
5. The deployed sensor binary cannot be reproduced and its digest has no corroborating record.

**No asset in this system has a verified restore.** Preservation evidence is strong for source and absent for data; the two must not be conflated.

**Directive position:** step 3 (*preserve the original and verify required recovery backups*) **cannot be certified**. No source copying, engine adaptation or separation is authorized. Production separation remains **HOLD**.

**Smallest set of actions that would change this verdict:** T1 (protect the unique history — free, minutes), T7 + B2/B3 (one authorized production read), and T6 (one read-only VM read). T4 would then raise the data answer from *unknown* to *drilled*.
