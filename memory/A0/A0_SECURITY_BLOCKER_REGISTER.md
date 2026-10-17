# A0_SECURITY_BLOCKER_REGISTER

Mode: READ-ONLY. **No previously reported HOLD is closed by this task.**
Classification is deliberately conservative: a control that exists in source
but was not exercised here is *not* "verified closed".

## Test-coverage reality — read this first

`backend/tests/` contains **601 test files**. The release gates in
`tools/rocket-validation/run.py` run roughly **30 of them**
(`decoder`, `command`, `tenant`, `boundaries`, `response`, `frontend`, `build`).
The 798 passing tests reported for Stage 2B.3 come from that curated set.

Several security suites outside the gates **cannot run in this environment**
because they require preconditions that do not exist here:

```
tests/test_collector_plane_auth.py      ERROR KeyError: 'NIVXRAY_EXPORT_REQUIRED_CREDENTIAL_…'
tests/test_edr_route_tenant_authority.py ERROR same
tests/test_xdr_webhooks.py              13 ERRORs (Mongo-backed fixtures)
tests/test_p0prod1_secret_policy.py     SecretPolicyError: XDR_AUDIT_MASTER_SECRET not configured
tests/test_d11_ingest_provenance.py     2 failures (Mongo-backed)
```

The `SecretPolicyError` is the control **working as designed** — it refuses to
derive an audit key from an unkeyed or repository-known value. That is evidence
of fail-closed behaviour, not a defect. But it also means those suites prove
nothing here, so the items they cover stay **UNVERIFIED**.

## Register

| # | Blocker | Classification | Evidence |
|---|---|---|---|
| 1 | **EDR collector tenant isolation** | **FIX PRESENT BUT UNVERIFIED** | `routers/collector_authz.py` `collector_guard` with MACHINE / HUMAN_CONTROL / TEST_PLANE route classes; `routers/edr_tenancy.py` `sensor_tenant()`, `_opaque_refusal()`. Tests `test_collector_plane_auth.py`, `test_collector_api_key_adversarial_regression.py` exist but **error on a missing credential env contract**; not in any gate |
| 2 | **Cross-tenant endpoint access** | **FIX PRESENT, PARTIALLY VERIFIED** | `edr_tenancy.edr_scope()` + `services/edr/endpoint_query.endpoint_predicate` enforce tenant-scoped predicates. `tenant` gate = 104 tests green, A0.5 contract suite = 74 green. But `test_edr_route_tenant_authority.py` and `test_d14_tenant_authority.py` are **outside the gates and error here** |
| 3 | **Enrollment token hygiene** | **FIX PRESENT BUT UNVERIFIED** | `routers/edr_enrollment.py:101` plaintext returned once and nowhere else; `:116` "no route returns a token's plaintext"; `:301` stores `token_hash` only. No gate exercises it |
| 4 | **Webhook authentication and replay protection** | **FIX PRESENT BUT UNVERIFIED** | `routers/xdr_webhooks.py` HMAC-SHA256 signing, secret held as Fernet `secret_ciphertext` under a tenant DEK, only a `secret_preview` (last chars) exposed, DLQ + replay path. **All 13 tests error here** (Mongo fixtures); not in any gate |
| 5 | **Legacy decoder resource-limit bypass** | **VERIFIED CLOSED — on the specific ordering claim only** | `services/decoder/isolated.py:62-75`: in the forked child, `setrlimit(RLIMIT_AS)` and `RLIMIT_CPU` are applied in phase `resource_setup`, **before** phase `target_import` calls `importlib.import_module`. The rejected "import first, limit later" workaround is **not** present. P1 traced the real failure to checkout-coupled import shadowing, not the limit. `decoder` gate = 147 tests, 0 failures, 6 skipped |
| 6 | **XDR authorization and data isolation** | **FIX PRESENT, PARTIALLY VERIFIED** | `routers/xdr_rbac.py` `require_permission`, `verified_actor`, `_audit_scope_denial`; owner-approved strict contract requires an active provisioned principal **plus** explicit tenant grants, and rejects+audits foreign selectors. A0.5 = 74 green, `tenant` = 104 green, `boundaries` = 136 green. Broader suites (`test_s1_incident_subresource_authz.py`, `test_v2_isolation.py`, `test_phase2_1_tenant_isolation.py`) are **outside the gates** |
| 7 | **Response approval and dispatch boundary** | **VERIFIED CLOSED for the admission contract; execution remains simulation-only** | `routers/xdr_respond_boundary.py` holds no approval logic; `_service_credential()` keeps analyst bearer distinct from engine authority; missing config → 503, wrong credential → 401; `_audit_response_selector_denial()` rejects foreign selectors. `response` gate = 39 green, admission 6, authority resolution 9. **Real containment has never executed** — simulation only |
| 8 | **Evidence integrity and provenance** | **FIX PRESENT BUT UNVERIFIED** | `services/incident_provenance.py`, `services/evidence_bridge.py` join `edr_raw_events.raw_id ↔ xdr_canonical_events._id`; `services/ingest_provenance.py`, `services/ingest_idempotency.py` used by `routers/xdr_ingest.py`. `test_d11_ingest_provenance.py` **fails here on Mongo fixtures**; not in a gate |
| 9 | **Staging versus production isolation** | **FIX PRESENT; KERNEL ENFORCEMENT UNVERIFIED** | `deploy/stage1-staging/preflight.py` refuses production hostnames and shared secrets (`test_package.py` 16 green, 38 with acceptance scripts); compose network is `internal: true`; response engine has no host ports. **The egress-denial test has never been executed** — phase 8 of host acceptance is BLOCKED |
| 10 | **Secrets and credential exposure** | **NO EXPOSURE FOUND; POLICY UNVERIFIED** | Scanned **5,666 blobs across all 12 commits**: no `.env`, key, certificate or token file in any tree; all pattern hits benign (AWS's published `AKIAIOSFODNN7EXAMPLE` fixture, `xoxb-…` UI placeholders, `<pwd>` docs template, negative-test strings). `security/secret_policy.py` refuses repository-known values at runtime. But `test_p0prod1_secret_policy.py` **cannot pass here**, and it audits `/app/backend` — the preview pod — rather than its own repository root (`:30`, `:50`, `:224`, `:265`, `:302`) |

### Additional findings surfaced by this audit

| # | Finding | Classification | Evidence |
|---|---|---|---|
| 11 | **Unsigned private dependency** | **CONFIRMED OPEN** | `emergentintegrations-0.2.0`, SHA-256 `1822c409…a4bdd`, from a single-vendor CDN. Hash-pinned (integrity) but unsigned, no attestation, no reproducible build, anonymous metadata, and declares unused `stripe` payments code |
| 12 | **Routes read paths absent from the image** | **CONFIRMED OPEN** | `deck_download.py:16,32,50`, `audit_downloads.py`, `services/platform_metrics.py:42` read `/app/memory`, `/app/deck_assets`, `/app/backend/...`; `backend.Dockerfile` does `COPY backend/ /app/`, so these do not exist in staging. 59 non-test + 316 test literals remain |
| 13 | **Security tests audit the wrong tree outside a container** | **CONFIRMED OPEN** | `test_p0prod1_secret_policy.py:30` `pathlib.Path("/app/backend")`. An auditability defect: the suite can pass while the repository under test is unexamined |
| 14 | **Most security suites are outside the release gates** | **CONFIRMED OPEN** | 601 test files, ~30 gated. Tenant, webhook, collector-auth and provenance suites are not part of the pass/fail evidence quoted for a release |

## Summary

- **VERIFIED CLOSED:** 2 — decoder resource-limit ordering (#5), response
  admission contract (#7, simulation-only).
- **FIX PRESENT BUT UNVERIFIED:** 6 — #1, #2, #3, #4, #6, #8.
- **PARTIALLY VERIFIED:** #9 (policy yes, kernel enforcement no), #10 (no
  exposure found, policy untested).
- **CONFIRMED OPEN:** 4 new — #11, #12, #13, #14.
- **NOT ASSESSED:** production configuration of any kind; this is source only.

Release status: **NO-GO**. No HOLD waived.
