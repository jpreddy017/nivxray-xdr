# A3_SECURITY_RELEASE_GATE_REPORT

Date: 2026-06
Branch: `engineering/a3-security-gate` (isolated worktree — **not merged, not pushed**)
Prerequisite verified: A1 candidate `3db07b18625d01205592009cdbe17ac293d96220`
Candidate: `62a2c658f638f118920aad4853c3747eeda801ec` / tree `71a64740ffa955f1a229cba57f99812f04831bc0`

## FINAL RESULT: **PARTIAL**

The gate is built, wired, mandatory and reproducible — that part is PASS. It is
**RED on this candidate**, for one reason: `test_v2_isolation` fails on 27
unwrapped legacy `v2` imports (F1). Per instruction it was not skipped,
xfailed, deselected or weakened. A mandatory gate that is red because the
product has a real defect is the gate working.

---

## 1 · Source identity

```
A0 baseline      cd2b8b92d785bee2f88432d3202367bbd51508c0 / 15a13aa6…
A1 candidate     3db07b18625d01205592009cdbe17ac293d96220 / 2284f5e2…
A3 candidate     62a2c658f638f118920aad4853c3747eeda801ec / 71a64740…
worktree status  clean (0 modified)
ancestry         git merge-base --is-ancestor cd2b8b92 HEAD → true
```

Worked in a third worktree derived from the verified A1 commit.
`engineering/e3-stage2b-package` and `engineering/a1-security-harness` were
never checked out or modified.

## 2 · Changed files — two, both tooling

| File | Change |
|---|---|
| `tools/rocket-validation/run.py` | new `security` gate; per-gate timeout table; database-safe `RLIMIT_FSIZE` for that gate only |
| `tools/security-harness/run.py` | import-origin guard that aborts the run unless imports resolve inside the candidate |

No application file. No test assertion. No deployment or secret configuration.
`ruff` clean on both (the six errors elsewhere in `tools/` are pre-existing).

Two implementation notes a reviewer should check:

- **The gate inventory lives in the gate file, not the harness.** `GATES`
  lists all six suites explicitly, so `run.py --list` shows exactly what is
  mandatory rather than hiding it behind a `--tier` flag.
- **`RLIMIT_FSIZE` of 8 MiB kills mongod during startup.** The first gate run
  failed with "mongod exited during startup". That cap is a runaway-output
  guard for test processes; the security gate gets 4 GiB instead, keeping its
  own process group and `RLIMIT_CORE=0`. The cap was raised for a database,
  not relaxed for a test.

## 3 · Test commands and inventory

```bash
python3 tools/rocket-validation/run.py --gate security --output <outside-worktree>
python3 tools/rocket-validation/run.py --gate decoder --gate command --gate tenant \
    --gate boundaries --gate response --gate frontend --gate build --gate security \
    --output <outside-worktree>
```

Mandatory security inventory (6 suites, 108 tests):

| Suite | Covers |
|---|---|
| `test_xdr_webhooks.py` | webhook HMAC auth, secret-once disclosure, DLQ replay, tenant isolation, audit chain |
| `test_collector_api_key_auth.py` | scoped API-key admission, malformed/unknown key refusal, cross-tenant key denial |
| `test_d11_ingest_provenance.py` | ingest provenance stamping and idempotency |
| `test_p0prod1_secret_policy.py` | production secret closure, no fallback to known material |
| `test_v2_isolation.py` | legacy-tree deletion-safety contract |
| `test_phase2_1_tenant_isolation.py` | tenant isolation at the security-state boundary |

## 4 · Results

### Security gate

```
108 tests · 1 failed · 0 errors · 1 skipped · exit 1 · 293s
```

| Non-passing | Kind |
|---|---|
| `test_v2_isolation::test_rc5_source_never_imports_v2_unwrapped` | **failure — F1, genuine defect** |
| `test_p0prod1_secret_policy::test_the_application_env_holds_no_deploy_or_test_credential` | **explicit skip** — no `.env` exists in a checkout; the skip states why rather than passing vacuously |

### Full required set

| Gate | Tests | Failures | Errors | Skipped | Exit |
|---|---|---|---|---|---|
| decoder | 147 | 0 | 0 | 6 | 0 |
| command | 372 | 0 | 0 | 0 | 0 |
| tenant | 104 | 0 | 0 | 0 | 0 |
| boundaries | 136 | 0 | 0 | 0 | 0 |
| response | 39 | 0 | 0 | 0 | 0 |
| **security (new)** | **108** | **1** | 0 | 1 | **1** |
| frontend (vitest) | 420 | 0 | 0 | 0 | 0 |
| build (vite) | — | — | — | — | 0 |
| **Backend + security** | **906** | **1** | **0** | **7** | — |

**Overall mandatory validation: RED**, solely from F1.

Evidence: `/app/rocket-evidence/a3/gates/security.{xml,log}`,
`/app/rocket-evidence/a3/full/*.{xml,log}`,
`/app/rocket-evidence/a3/frontend/*`.

The `frontend` and `build` gates were executed from
`/app/rocket-p0/src` because the A3 worktree has no `node_modules`. This is
legitimate only because the frontend is **provably identical**:
`git diff --name-only cd2b8b92 HEAD -- apps/nivxray-xdr frontend` → **0 files**.
Running `yarn install` in the worktree would change nothing about the result.

## 5 · Candidate-source import proof

The harness now refuses to report anything until it has checked where the code
came from. From the gate log:

```
[origin] deps                     -> /app/rocket-p0/a3/backend/deps.py
[origin] server                   -> /app/rocket-p0/a3/backend/server.py
[origin] tests._verified_session  -> /app/rocket-p0/a3/backend/tests/_verified_session.py
```

All three resolve inside the candidate worktree — **not** `/app/backend`. If any
resolved outside, the harness exits 3 with
`RESOLVED OUTSIDE THE CANDIDATE: {...}` and the gate fails rather than
reporting green results for the deployed tree. The guard deliberately imports
`server` first, because that is what triggers `routers/benchmark.py` to mutate
`sys.path` (F3). **The guard is not a fix for F3**, and F3 remains open.

## 6 · Baseline regression

The five pre-existing backend gates return exactly their A0/A1 numbers —
**798 tests, 0 failures** — and the frontend gate returns its 420. Nothing
regressed; the new gate only adds coverage.

## 7 · Security checks preserved

- No assertion changed, deleted, skipped, xfailed or deselected in A3.
- Expected rejections still fire: `SecretPolicyError` on unkeyed material,
  `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` on an unauthorized selector,
  `read_only` refused the collector plane.
- Every secret is generated per run; no production or committed credential is
  used anywhere in the gate.
- The one skip is explicit and states its missing prerequisite.
- Database and process containment were tightened in scope, not loosened:
  own process group, no core dumps, bounded file size.

## 8 · Remaining blockers

| ID | Blocker | Effect on the gate |
|---|---|---|
| **F1** | 27 unwrapped `v2` imports | **keeps the mandatory gate red**; the single unblocker |
| F2 | tenant refusal-code contract | not in this gate (tier-2 only) |
| F3 | `benchmark.py` mutates `sys.path`, defaulting to `/app` | guarded, not fixed |
| F4 | no supported first-principal RBAC bootstrap | harness writes the rows; operators still have no path |
| — | tier-2 live-HTTP suites | deliberately **excluded** from the mandatory gate; they need a provisioned environment and would otherwise be 16 failures of an unresolved contract |
| — | ~4 min of index initialisation per run | the gate's cost; already budgeted at 1500s |

## 9 · Staging package impact — **none; package stays frozen**

Checked file by file with `prepare.included()` against pin `593b3e9f`:
**13 changed files, 0 included in the build context** — tests, tooling and the
staging directory itself are all excluded. The image contents would be
byte-identical; only the commit SHA differs.

```
=== verify-only on a3 ===
ValueError: Candidate includes changes outside staging packaging
=== frozen package still verifies ===
cd2b8b92d785bee2f88432d3202367bbd51508c0 · 0 modified · Pinned source verified
```

The refusal is the admission control working as designed. Consequences:

- Hetzner package **untouched**: pin `593b3e9f`, bundle SHA-256
  `98e4adba…fdfa`, branch `engineering/e3-stage2b-package` — unchanged and
  still verifying.
- A3 cannot be merged into the staging branch without a re-pin, a new bundle
  and a new checksum. **No re-pin was performed.**

## 10 · Rollback

The gate is additive and lives on its own branch; nothing needs undoing unless
it is merged.

```bash
# discard A3 entirely
git worktree remove /app/rocket-p0/a3 --force
git branch -D engineering/a3-security-gate

# keep the branch, disable the gate only
git revert 62a2c658f638f118920aad4853c3747eeda801ec   # drops the gate, keeps A1

# verify the frozen package is unaffected, from the staging worktree
cd /app/rocket-p0/src && git rev-parse HEAD && \
  NIVXRAY_REPO_ROOT=$PWD python3 deploy/stage1-staging/prepare.py --verify-only
```

Removing the gate restores the previous 798-test required set exactly; no
application state, database or artefact is involved.

---

**No merge, push, deployment, migration, source deletion, database change,
staging re-pin or package regeneration.** All security HOLDs preserved.
Release status **NO-GO**.
