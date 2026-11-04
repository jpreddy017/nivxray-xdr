# P0-PROD-1 · PRODUCTION SECRET CLOSURE — EVIDENCE

Owner directive *P0-PROD-1 APPROVED WITH SECURITY CHANGES*, 2026-09-26.
**No secret value appears anywhere in this document.**

## 1 · EXECUTIVE RESULT — **PASS**

Production can no longer run on a key this repository knows. A misspelled
environment cannot downgrade security. Preview keys are instance-rooted
and purpose-separated. Key rotation is no longer mistakable for
tampering, and genuine modification still fails.

## 2 · SCOPE ACTUALLY CHANGED

Backend cryptographic key resolution, startup validation, audit-chain
verification semantics, connector-secret read semantics, `.env` hygiene
and the live-credential test mechanism. **No deployment, no production
secret, no database migration, no UI, no P0-PROD-2, no P0-D.**

## 3 · FILES CHANGED (file · what)

| File | Change |
|---|---|
| `backend/security/secret_policy.py` **(new, 248 lines)** | the single authority: `deployment_env()` (L88-110 · rejects unknown values), `resolve()` (L152-175 · production refuses, preview derives), `resolve_fernet()` (L178-193), `assert_production_ready()` (L196-224 · fail-closed), `report()` (L227-248 · non-secret provenance), `MANDATORY_PRODUCTION_SECRETS` (L47-56), `FORBIDDEN_IN_PRODUCTION` (L59-64), purposes (L67-73), `_PLACEHOLDER_TOKENS` (L79-85), `key_id()` (L127-134) |
| `backend/deps.py` | `validate_config()` now calls `assert_production_ready()` (L92-98) — production refuses to serve on a missing/invalid secret or a forbidden runtime credential |
| `backend/routers/xdr_audit_log.py` | dev constant **deleted**; lazy `_master()` + `active_key_id()` (L51-79); `sig_key_id` inside the **signed** payload (L143); `verify_chain` four-state semantics (L262-325) |
| `backend/routers/xdr_secrets.py` | `_master_key()` via policy (L57-73); self-describing ciphertext `nivxk1.<key_id>.<token>` (L66, L101-104); `_decrypt()` honest refusal (L106-133) |
| `backend/v2/report/bundle.py` | fixed-salt fallback **deleted**; policy-resolved signing key (L34-47) |
| `backend/detection_content/xdr_credential_vault.py` | `EnvRootKeyProvider.root_key()` via policy (L90-98) |
| `backend/.env` | `VERCEL_TOKEN` and `TEST_ANALYST_NIVXLIVE_PASSWORD` **removed**; `NIVX_DEPLOYMENT_ENV=preview` added explicitly |
| `backend/tests/test_p0prod1_secret_policy.py` **(new, 28 tests)** | the security suite |
| `backend/tests/test_xdr_secrets.py` | tamper test **strengthened**: now proves BOTH the corrupted-payload path (422) and the absent-key-identity path (409) |
| `tests/test_edr_route_tenant_authority.py`, `tests/test_e2e_xdr_rbac_effective.py`, `tests/edr/test_iter107_p0_3_freshness_review.py`, `tests/edr/test_p0c_durable_findings_live.py` | committed credential literal removed; credential injected from the environment, explicit prerequisite skip otherwise |

## 4 · SECURITY DEFECTS CLOSED

1. **Forgeable audit chain** — `xdr_audit_log.py:55` used the literal
   `"xdr-audit-master-do-not-use-in-prod"`. Anyone with the source could
   mint a valid per-tenant HMAC chain. **Removed; no fallback exists.**
2. **Source-decryptable connector secrets** — `xdr_secrets.py:54-72`
   derived its Fernet key from a repository literal. **Removed.**
3. **Reproducible evidence-bundle signatures** — `bundle.py:43-47` used a
   fixed salt + case id. **Removed.**
4. **Silent security downgrade by typo** — nothing previously distinguished
   environments. `NIVX_DEPLOYMENT_ENV=prod` / `Production` / `productionn`
   now **fails configuration validation**.
5. **Rotation mislabelled as tampering** — audit rows carried no key
   identity, so rotating the master would have reported all 16 876
   historical rows as signature mismatches. **Fixed with `sig_key_id` +
   four-state verification.**
6. **Deploy-plane authority inside the app runtime** — `VERCEL_TOKEN`
   removed from `backend/.env` and forbidden in production.
7. **Committed test credential** — the live analyst password existed as a
   literal in 4 test files and in `backend/.env`. **Removed from both.**

## 5 · SECRET-SOURCE MATRIX (names only)

| Secret | Purpose | Preview before | Preview after | Test/CI after | Production required | Fallback exists | Derivation exists | Production may derive | key_id | Fail-closed |
|---|---|---|---|---|---|---|---|---|---|---|
| `JWT_SECRET` | operator sessions · instance derivation root | `.env` | `.env` (unchanged) | env | operator-set | no | no | no | n/a | yes (pre-existing `_REQUIRED_ENV`) |
| `XDR_AUDIT_MASTER_SECRET` | `audit-signing` | **repo literal** | derived instance-local | derived | operator-set | **removed** | preview/test only | **no** | on every new row | yes |
| `XDR_SECRETS_MASTER` | `connector-secret-encryption` | **repo-derived** | derived instance-local | derived | operator-set | **removed** | preview/test only | **no** | in ciphertext prefix | yes |
| `NIVXRAY_SIGNING_SECRET` | `evidence-bundle-signing` | **fixed salt + case id** | derived instance-local | derived | operator-set | **removed** | preview/test only | **no** | in bundle manifest | yes |
| `XDR_ROOT_KEY` | `credential-vault-root` | absent → `KeyError` | derived instance-local | derived | operator-set | no | preview/test only | **no** | vault `dek_id` (pre-existing) | yes |
| `EDR_AUTH_PEPPER` | endpoint credential digests | `.env` | `.env` (unchanged) | env | operator-set | no (already refused) | no | no | n/a | yes |
| `VERCEL_TOKEN` | deployment plane | **in `backend/.env`** | **absent** | must not exist | **forbidden** | n/a | n/a | n/a | n/a | production startup refuses if present |
| `TEST_ANALYST_NIVXLIVE_PASSWORD` | live test authority | **in `backend/.env`** + 4 committed literals | **absent** | shell/CI only, else SKIP | **forbidden** | n/a | n/a | n/a | n/a | production startup refuses if present |

## 6 · `NIVX_DEPLOYMENT_ENV`

Accepted values exactly `preview` · `test` · `production`. Unset/blank is
`preview`; **any other value raises** `SecretPolicyError` with the reason
that "a misspelled environment must not silently fall back to preview,
because that would let a production process run on preview-grade,
instance-derived key material". Proven for `prod`, `prd`, `Production`,
`productionn`, `unknown`, `PREVIEW`. Preview declares itself explicitly
in `backend/.env`.

## 7 · PRODUCTION FAIL-CLOSED PROOF (local/test only)

* each mandatory secret missing / blank / whitespace / `changeme` /
  `placeholder-secret` / the old repo literal → `resolve()` raises, and
  **the refusal never echoes the offending value**;
* `assert_production_ready()` names **all six** mandatory secrets and
  states "No value is printed";
* `deps.validate_config()` raises under `production`, so uvicorn refuses
  to serve — no partial initialisation;
* `VERCEL_TOKEN` present under `production` → refusal naming the variable
  only (asserted that its value is absent from the message);
* production **never** derives: all four purposes raise for both
  `resolve()` and `resolve_fernet()`.

The real production environment was **not** touched to prove this.

## 8 · PREVIEW `DERIVED_INSTANCE_LOCAL` PROOF

HKDF-SHA256, salt `nivx-instance-local-key-v1`, info `<purpose>\x1f<name>`,
rooted in this instance's own `JWT_SECRET`. Changing the root changes both
the key and its `key_id` (asserted), so a derived key belongs to one
instance only. `basis` is reported as `DERIVED_INSTANCE_LOCAL` — never
presented as an operator key. `report()` asserted to contain no key
material. Preview and production secret policy are deliberately **not**
equivalent.

## 9 · PURPOSE-SEPARATION PROOF

`audit-signing`, `connector-secret-encryption`, `evidence-bundle-signing`
and `credential-vault-root` derive **four distinct keys** from one root
(asserted as a 4-element set), the same variable under a different purpose
derives a different key, and an **unlabelled** purpose is refused
(`"unlabelled key use is not permitted"`).

## 10 · key_id

`sha256(key)[:12]` — publishable, non-invertible, carries no key
material. New audit rows carry `sig_key_id` **inside the signed payload**,
so the key identity is itself tamper-evident. New ciphertext is
self-describing (`nivxk1.<key_id>.<token>`). Bundles already emitted
`key_id` in their manifest.

## 11 · AUDIT ROTATION SEMANTICS

`VERIFIED` (recomputed and matched) · `SIGNED_UNDER_DIFFERENT_KEY_ID`
(another generation; "rotation is not modification") ·
`UNVERIFIABLE_NO_KEY_ID_RECORDED` ("NOT evidence of tampering and must
never be presented as such") · `chain_broken` (verifiable material that
actually failed, or a `prev_sig` linkage break). **Linkage is checked for
every row including unverifiable ones**, so insertion or deletion is still
detected, and altered verifiable material still returns `chain_broken`.
Tamper detection was not weakened to solve rotation.

## 12 · THE 12 CONNECTOR + 6 WEBHOOK SECRETS

Untouched. Not read, not decrypted, not re-encrypted, not migrated, not
deleted. Classified in code as
`PREVIEW_LEGACY_SECRET — REPLACEMENT_REQUIRED_BEFORE_PRODUCTION_USE`
(`secret_policy.LEGACY_CLASSIFICATION`). They must never be promoted to
production by migrating ciphertext; each credential must be re-entered or
reissued at its authoritative provider under the real production key,
outside this slice.

## 13 · `SECRET_UNDECRYPTABLE_UNDER_CURRENT_KEY`

HTTP **409** (never 500) with `code`, `recorded_key_id` (null for
pre-P0-PROD-1 rows), `active_key_id`, the legacy `classification`, the
reason "nothing will be substituted for it", and `also_possible` stating
that a value with no key identity **may equally have been MODIFIED** —
the read path does not guess between the two. No plaintext is fabricated;
asserted that the original value never appears in the response.

## 14 · `.env` HYGIENE PROOF

Asserted by test against the live file: `VERCEL_TOKEN` **absent**,
`TEST_ANALYST_NIVXLIVE_PASSWORD` **absent**, `NIVX_DEPLOYMENT_ENV=preview`
present. 46 keys remain, file newline-terminated,
`MONGO_URL`/`DB_NAME`/`JWT_SECRET` untouched. A second test scans
`backend/tests/**` and fails if the credential literal is committed
anywhere, so no workaround copy can be reintroduced. Former values are
not printed here.

## 15 · TEST CREDENTIAL MECHANISM

Four live suites read `TEST_ANALYST_NIVXLIVE_PASSWORD` from the
environment only and `pytest.skip(..., allow_module_level=True)` with an
explicit prerequisite when it is absent. **Proven both ways**: with the
credential exported → 328 passed; with it unset → the modules **skip**
(no default substituted, no fall back to `ADMIN_PASSWORD`). A test asserts
no file resolves this credential from `/app/memory/test_credentials.md`.
*Reported, not changed (§11 of the directive):*
`tests/test_adr0014_endpoints.py:45-57` reads the **admin** password from
that memo — a different, pre-existing pattern, outside this slice.

## 16 · FORBIDDEN PRODUCTION RUNTIME CREDENTIALS

`VERCEL_TOKEN`, `TEST_ANALYST_NIVXLIVE_PASSWORD` → production startup
refuses when either is present, naming the variable only. No other
equivalent deploy/test credential was found in `backend/.env`; the
remaining third-party keys (`VT_API_KEY`, `OTX_API_KEY`, …) are
feature-scoped API keys, not deployment authority.

## 17-18 · LOCAL CONSOLE PRODUCTION BUILDS (no deployment)

| Scope | Result | Guard output |
|---|---|---|
| `NIVX_PRODUCT_SCOPE=xdr` | **PASS** (exit 0, 6.87 s) | no preview origin (174 artifacts scanned) · no `edr.nivxforge.com` dependency · API origin `https://nivxray.nivxforge.com` · scope declared `xdr` (`/edr/*` cannot render) · landed collector base resolves |
| `NIVX_PRODUCT_SCOPE=edr` | **PASS** (exit 0, 6.60 s) | no preview origin · no `xdr.nivxforge.com` dependency · same API origin · scope declared `edr` (`/xdr/*` cannot render) |

No build guard was bypassed. Nothing was deployed.

## 19 · CONSOLE DRIFT (read-only)

Live artefacts: `edr.nivxforge.com` `built_at` **2026-09-09T11:48:50Z** ·
`xdr.nivxforge.com` **2026-09-18T09:25:23Z**, both on API origin
`https://nivxray.nivxforge.com`.

* **51 commits** touched `apps/nivxray-xdr/src` after the live **EDR**
  build; **36 commits** after the live **XDR** build.
* Pages/modules changed since the live EDR build include
  `EdrExclusionsPage`, `EdrPoliciesPage`, `EdrAuditPage`,
  `EdrDetectionsPage`, `EdrComputersPage`, `EdrEventsPage`,
  `EdrCampaignStoryPage`, `EdrResponsePage`, `EdrAddDevicePage`,
  `EdrDownloadsPage`, `EdrProcessTreePage`, the whole
  `trajectory/` set (`AmpCanvas`, `AmpComputerHeader`, `AmpNavigator`,
  `EdrDeviceTrajectoryPage`), `device/` (`EdrDevicePage`,
  `DeviceOverview`, `CommandIntelligence`), `NivXForgeConsole.jsx`,
  `nivxforge.css`, `nvf-ops.css`, and the API layers
  (`managementApi.js`, `onboardingApi.js`, `scopeApi.js`, `tenant.js`,
  `refusal.js`).
* **Honest limitation**: the live bundle lazy-loads its routes, so
  grepping the live main chunk cannot prove a route is absent. Drift is
  therefore reported from commit history, not from bundle contents.
* **Measured in both builds**: neither the live nor the current local
  build contains any `findings` / `evaluation-state` surface — **no
  console consumes the P0-C findings API yet**, by design.
* Reminder from the deployment audit: even after a Vercel rebuild, these
  pages would call a production backend where `/api/edr/policies`,
  `/exclusions` and `/findings` are still **404** until the backend is
  redeployed (P0-PROD-3).

## 20 · REGRESSION

| Suite | Result |
|---|---|
| `tests/test_p0prod1_secret_policy.py` (new) | **28 passed** |
| `tests/edr` (P0-A/A.1/B/C + gates) | **494 passed · 1 skipped · 0 failed** |
| `test_edr_route_tenant_authority.py` + `test_e2e_xdr_rbac_effective.py` | **328 passed** |
| `tests/test_xdr_audit_log.py` + `tests/test_xdr_secrets.py` | **16 passed** |
| Broad selection `-k "audit or secret or vault or webhook or bundle or report or config"` | **1938 passed · 28 failed · 15 skipped · 18 errors** |
| Live-credential prerequisite (credential unset) | **2 modules skipped** with the stated prerequisite |
| Guarded console builds | XDR **PASS** · EDR **PASS** |

No assertion was deleted, weakened or bypassed. The only test semantics
changed is `test_tamper_ciphertext_detected`, which was **strengthened**
from one case to two (corrupted payload under the active key → 422
tampered; absent key identity → 409 with both possibilities disclosed).

### Pre-existing failure proof

The identical broad selection was run on the **pre-P0-PROD-1 tree**
(`git stash push -- backend/`, new untracked modules excluded):
**baseline 1911 passed · 28 failed · 15 skipped · 18 errors** →
**after 1938 passed · 28 failed · 15 skipped · 18 errors**. Same 28
failures and same 18 errors; the delta is exactly the +27 P0-PROD-1 tests
collected in that selection. **Zero failures are in P0-PROD-1 code or
tests** (`grep -c p0prod1` over the failure list = 0). The 46
failures/errors sit in 28 unrelated modules (largest:
`test_a05_tenant_scope_contract` 4, `test_xdr_round44_cockpit_audit_lock`
3, `test_xdr_round25b_vault` 3, `test_uaie_baseline_gates` 3) and include
collection-level `ImportError`/`import file mismatch` cases. An earlier
run of the same selection reported 29 failures; re-running produced 28,
so at least one of those modules is **flaky**, which is itself carried as
a pre-existing risk rather than hidden.

## 21 · DATABASE / MIGRATION STATEMENT

**No database migration. No historical rewrite.** No audit row, finding,
ciphertext or secret document was modified. No production database was
contacted. The only persistent writes in this slice came from tests
creating and cleaning their **own** disposable records (the
`xdr_secrets` suite's own secrets, the audit suite's own events, the
throwaway `p0c-*`/`p0b-*` tenants). Existing preview application records
remain exactly as they were, as evidence of the configuration that
produced them.

## 22 · REMAINING RISKS

1. **Preview keys are derived, not operator-held.** Every preview audit
   signature and connector ciphertext is keyed to this pod's
   `JWT_SECRET`. If that value changes, preview loses the ability to
   verify or decrypt its own historical records — reported truthfully
   (`UNVERIFIABLE…` / `SECRET_UNDECRYPTABLE…`), never as tampering.
2. **16 876 historical audit rows have no key identity** and can never be
   recomputed. They are reported as unverifiable, and their `prev_sig`
   linkage is still checked. Not remediable without rewriting history,
   which is forbidden.
3. **The 12+6 legacy secrets remain unusable for production** until
   re-entered or reissued. Until then any connector depending on them
   cannot be enabled in production.
4. **Production secrets do not exist yet.** The fail-closed path means a
   Republish with `NIVX_DEPLOYMENT_ENV=production` set *before* the six
   secrets exist will correctly refuse to serve. Order matters: secrets
   first, then the environment declaration.
5. **28 pre-existing failures + 18 errors** in unrelated suites remain,
   with at least one flaky module. Carried, not hidden.
6. `tests/test_adr0014_endpoints.py` still resolves the **admin**
   password from `/app/memory/test_credentials.md` — reported, out of
   scope.
7. The consoles remain weeks behind and the production backend still
   lacks the EDR control, agent and findings planes (P0-PROD-3).

## 23 · BOUNDARY RESTATED

```
CODE READY            != PRODUCTION DEPLOYED
PRODUCTION DEPLOYED   != ENDPOINT ENROLLED
ENDPOINT ENROLLED     != TELEMETRY VERIFIED
TELEMETRY VERIFIED    != DETECTION VERIFIED
DETECTION VERIFIED    != RESPONSE VERIFIED
```

## 24 · NEXT GATE (proposed only — NOT started)

**P0-PROD-2 · TOKEN-BASED ENDPOINT ENROLLMENT.** Objective: eliminate
administrator/operator credentials from protected Windows/Linux endpoints
and replace bootstrap authentication with one-time, short-lived,
tenant-bound enrolment authority carrying expiry, single-use replay
prevention, audit and revocation. The concrete defect it closes is
`scripts/nivxforge_sensor_supervise.py:73-83`, which logs in with
`ADMIN_EMAIL`/`ADMIN_PASSWORD` to mint its own token. **Not implemented.**

---

## 25 · PRE-NEXT-GATE CLEANUP (owner-directed addendum, 2026-06)

Scope authorised by the owner: **only** the credential-file dependency in
the ADR-0014 endpoint tests plus a frozen regression baseline. No
P0-PROD-2 work, no deployment, no database migration, no Vercel action.

### 25.1 · Credential-file dependency removed

`backend/tests/test_adr0014_endpoints.py`

- Deleted `_read_seeded_password()`, which parsed the admin password out
  of `/app/memory/test_credentials.md`, and dropped the now-unused
  `pathlib.Path` import.
- The `auth_headers` fixture now resolves the admin password **only**
  from `os.environ["ADMIN_PASSWORD"]` (shell/CI injection) and calls
  `pytest.skip("Missing test credential: inject ADMIN_PASSWORD via the
  shell/CI environment. Credential files are never read by tests
  (P0-PROD-1 hygiene).")` when absent.
- The file no longer references `TEST_ANALYST_NIVXLIVE_PASSWORD` at all,
  so no admin-password fallback for the live analyst credential can
  exist here — `test_no_test_file_substitutes_a_default_live_credential`
  now holds for this module.
- Closes finding **§22.6** of this document ("still resolves the admin
  password from `/app/memory/test_credentials.md` — reported, out of
  scope").

Where the value comes from in this pod: `backend/conftest.py:70-71`
seeds a CI-only `ADMIN_EMAIL`/`ADMIN_PASSWORD` via `os.environ.setdefault`,
and `backend/.env` supplies the local value. Both are environment
injection paths; neither is a credential-memo read.

### 25.2 · Proofs

1. **Skip path proven** (credential absent → explicit skip, never a
   file read, never a substituted default):

```
$ python - <<'PY'
import os, sys, importlib.util
sys.path.insert(0, "/app/backend")
import pymongo, deps                 # let any dotenv loading happen first
os.environ.pop("ADMIN_PASSWORD", None)
spec = importlib.util.spec_from_file_location("t", "/app/backend/tests/test_adr0014_endpoints.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.auth_headers.__wrapped__(client=None)
PY
Skipped: Missing test credential: inject ADMIN_PASSWORD via the
shell/CI environment. Credential files are never read by tests
(P0-PROD-1 hygiene).
```

   Note: running the whole module with `ADMIN_PASSWORD=""` fails earlier,
   at app startup — `RuntimeError: NivXRay config error — missing
   required env var(s): ['ADMIN_PASSWORD']`. That is the pre-existing
   fail-closed config validator, i.e. the stricter of the two outcomes.

2. **Secret-policy suite green:**

```
$ python -m pytest tests/test_p0prod1_secret_policy.py -q
28 passed in 1.37s
```

3. **ADR-0014 module with the credential injected:**

```
$ python -m pytest tests/test_adr0014_endpoints.py -q
3 failed, 6 passed in 149.67s
FAILED TestAutoInvestigateCIO::test_cio_parses_and_validates
FAILED TestCIOAcrossEndpointsPrinciple::test_both_endpoints_produce_valid_cio_for_same_input
FAILED TestDecodeSmartCIO::test_cio_parses_as_pydantic_model
```

   All three are CIO-validation failures present in the frozen baseline
   (§25.3) and unrelated to credential handling. Stated, not hidden.

### 25.3 · Regression baseline frozen

- Human-readable: `memory/production-gates/BASELINE_PYTEST_PRE_P0PROD2.md`
- Machine-comparable: `memory/production-gates/BASELINE_PYTEST_PRE_P0PROD2.json`
  (every failing/erroring node id, generated by
  `backend/tools/freeze_pytest_baseline.py`)

Full-suite capture: **12,767 run · 11,807 passed · 547 failed · 128
errored · 270 skipped (+15 xfail)** in 2,872 s. Three modules are
excluded because they abort collection under `-n 2 --dist loadscope`
(duplicate module basename, a missing `ImpactScoringEngine` import, and
a module that parametrises node ids with the xdist worker id).

**Correction to §22.5 of this document:** the "28 failed + 18 errors"
figure was a *scoped* run, not a whole-suite run. The full-suite numbers
above supersede it. The delta is scope, not new breakage: every error
cluster is a setup-phase harness fault (closed event loops, a `_Cached`
stub lacking `raise_for_status`, unauthenticated fixture bootstrap,
duplicate-key seeds, a missing `/tmp/SEP.csv`) and none originate in
`security/secret_policy.py`.

Later gates are regression-free only if no failing/erroring node id
appears that is absent from the frozen JSON, and
`tests/test_p0prod1_secret_policy.py` stays 28/28.

### 25.4 · Boundary

**P0-PROD-2 (token-based endpoint enrollment) has NOT been started.** No
production deployment, no Vercel publish, no database migration and no
preview→production data movement was performed. Stopping for Owner
Review.
