# E3 final acceptance gates — A to G

Date: 2026-10-16
Branch: `engineering/e3-stabilization` (isolated; never pushed)
Evidence: `/app/rocket-evidence/e3/`
Disposition: **NO-GO for release or production**

Owner security contracts approved 2026-10-16 and implemented as written:
1. Administrative access requires an **active, provisioned principal with
   explicit tenant authorization**. Role-only admin shortcuts are prohibited.
2. Foreign or unauthorized tenant/scope selectors are **rejected explicitly
   and audited** — never ignored, never substituted.
3. Existing fail-closed behaviour preserved. Legacy assertions changed only
   where they contradicted these contracts; each change is documented in the
   test body itself.

## A · Original A0.5 suite closed

**74 tests, 0 failures, 0 errors, 0 skipped** (was 72 / 5 failures / 1 error).
Complete accounting of every previously failing outcome:

| Original test | Was | Now | Disposition |
|---|---|---|---|
| `test_trisk1_principal_with_no_tenant_scope_fails_closed` | demanded literal `ACCESS_DENIED` | accepts `ACCESS_DENIED` **or** `TENANT_NOT_RESOLVED`, and additionally proves no tenant resolved and no records read | Label-only. Both are explicit denials; the contract requires fail-closed, not one string. |
| `test_cross_tenant_admin_with_explicit_tenant_still_works` | expected **200** for a role-only platform admin | renamed `test_role_only_admin_is_denied_without_explicit_tenant_provisioning`, expects **403** `user-not-provisioned` | Expectation inverted under contract 1. Confirmed as live runtime behaviour before changing the test. |
| *(new)* `test_provisioned_admin_with_explicit_tenant_grant_still_works` | — | **200** | Added so contract 1 is proven not to remove legitimate capability. |
| `...manipulate_authority_via_query_or_header[tenant_id]` | expected **200** (selector ignored) | **403** `SCOPE_SELECTOR_CONFLICT`, `fail_closed: true` | Expectation inverted under contract 2. |
| `...manipulate_authority_via_query_or_header[customer_id]` | expected **200** | **403** same | Expectation inverted under contract 2. |
| `...[scope, scope_type, tenant_group, incident_id, resource_id, console, role, permission]` | 200 | **200, unchanged** | Not tenant selectors; they carry no authority. Still proven by asserting the resolved scope. |
| *(new)* `test_rejected_selector_conflict_is_audited` | — | PASS | Added so the "and audited" half of contract 2 is proven, not assumed. |
| `test_client_cached_effective_access_object_is_not_authority` | expected **403**, got **422** | asserts **both**: the verbatim cached object is refused (422/403 with no tenant granted) **and** a schema-valid replay of the same claim is denied at **403** with `tenant_ids: []` | The 422 was schema refusal preceding authorization, so the test's own intent was never exercised. Now it is. |
| `test_the_guard_is_not_vacuous` | timeout error at 90 s / 120 s | **PASS** | Never a defect — the test needs ~200 s. Suite now runs with `--timeout=300`. Total A0.5 runtime 190.8 s. |

No security control was weakened and no assertion was deleted to obtain a pass.

## B · Frontend validation on this exact tree

`yarn install --frozen-lockfile` (Yarn 1.22.22) against the committed lockfile.

| Gate | Result |
|---|---|
| Vitest | **420 passed / 420**, 25 files, exit 0 |
| Vite production build | **PASS**, exit 0, built in 7.85 s |

No genuine failures were found, so nothing was fixed. Matches Work's figures
on a different host and interpreter.

## C · Egress isolation — **BLOCKED, not bypassed**

Kernel-enforced network isolation **cannot** be established here. Evidence in
`egress_isolation_probe.txt`:

```
CAP_NET_ADMIN  ABSENT      CAP_NET_RAW  ABSENT      CAP_SYS_ADMIN  ABSENT
unshare -n           -> Operation not permitted
ip netns add         -> Operation not permitted
ip link add dummy0   -> Operation not permitted
nft add table        -> Operation not permitted
https://api.anthropic.com -> HTTP 405   (reachable, therefore NOT denied)
DNS example.com           -> resolves
```

Per the owner's instruction this is reported rather than worked around.
Python-level socket guards were **not** substituted for it. Therefore
**FULL_E2E = BLOCKED** regardless of the trace result below.

## D · Complete authenticated XDR trace — 25/25

`tools/rocket_e2e/acceptance_trace.py` against a disposable stack: isolated
MongoDB 7.0.43 on `127.0.0.1:37017` (fresh storage, separate from the platform
instance), backend on `127.0.0.1:18001` with `NIVX_EDR_WORKERS_DISABLED=1`,
standalone response engine on `127.0.0.1:39099`.

| Stage | Checks | Result |
|---|---|---|
| auth | synthetic analysts + machine ingest principal authenticate | PASS |
| ingestion | rendered Sysmon Event 1 accepted via authorized collector, `REASONED`, no blocker, `selected_dsm_id=microsoft-sysmon` | PASS |
| normalization | canonical event queryable with `time_basis=ACTIVITY_TIME`, `time_source=sysmon:EventData.UtcTime`, `time_substituted=false` | PASS |
| detection | ingested event **promoted a real incident**; detection plane reports `COMPLETE` MITRE ATT&CK version | PASS ×2 |
| correlation | tenant-scoped rules and matches readable | PASS ×2 |
| incident | queue projects own tenant only | PASS |
| investigation | investigation view resolves (`WAITING_FOR_EVIDENCE`) | PASS |
| evidence timeline | canonical evidence resolves, `tenant_scope=INCIDENT_RESOLVED` | PASS |
| reporting | incident report resolves with correct `tenant_id` | PASS |
| tenant isolation | analyst B denied tenant A incident; cross-tenant ingest `TENANT_ISOLATION_VIOLATION`; foreign tenant header refused | PASS ×3 |
| audit | tenant audit log readable with principal attribution | PASS |
| response | see E | PASS ×9 |

## E · Response: credentials, permissions, approval, cross-tenant

Real response execution stayed disabled throughout.

| Check | Result |
|---|---|
| engine reachable only through the service credential (`REAL_RUNTIME_VERIFIED`) | PASS |
| action catalogue requires an admitted backend (18 actions) | PASS |
| authorized execute admitted and held at `WAITING_APPROVAL` | PASS |
| foreign `tenant_id` selector **refused, not substituted** (`response_selector_conflict`) | PASS |
| forged `invoker.id` refused (`conflicting_field: invoker.id`) | PASS |
| pending-approval queue readable | PASS |
| approved **simulated** response roundtrip `WAITING_APPROVAL` → approve → `SUCCEEDED` on `network.block_ip` (`STUB_NO_SIDE_EFFECT`) | PASS |
| `endpoint.isolate` (`REAL_PRODUCT_API`, destructive) submitted and **never executed** — stays `WAITING_APPROVAL` | PASS |
| only the simulation-only action completed; per-execution states verified individually | PASS |
| no evidence forwarded to any gateway (`not_wired`, `forwarded: 0`) | PASS |

**Two product defects were found and fixed while doing this.**

1. **Granular RBAC was never consulted by the response boundary.**
   `_permissions_of()` passed the session **email** into
   `_resolve_user_permissions()`, which looks principals up by **id**. Every
   email-identified principal therefore fell back to the coarse session role
   and the `xdr_user_roles` store — documented as authoritative — was silently
   ignored. The immediate effect was fail-closed, but the dangerous direction
   is the other one: a built-in coarse role could grant response permissions
   where a granular restriction was meant to subtract them. The boundary now
   resolves email → id first, with fail-closed fallback. Regression:
   `backend/tests/test_rocket_response_authority_resolution.py` (3 tests).

2. **The execute route silently substituted the session tenant/invoker.**
   It overwrote a client-supplied `tenant_id` and `invoker.id`. Fail-safe, but
   exactly the silent substitution contract 2 prohibits. It now refuses with
   `response_selector_conflict`, audits the denial through the existing audit
   path, and does so **before** any catalogue lookup or engine call. Regression
   added to `test_rocket_response_admission.py` (2 tests), including proof that
   an audit-store failure cannot turn a denial into a 500.

## F · Regression accounting

| Scope | Passed | Failed | Skipped | Blocked |
|---|---:|---:|---:|---:|
| decoder gate | 147 | 0 | 6 | 0 |
| command gate | 372 | 0 | 0 | 0 |
| tenant gate | 104 | 0 | 0 | 0 |
| boundaries gate | 112 | 0 | 0 | 0 |
| response gate | 39 | 0 | 0 | 0 |
| **backend gate total** | **774** | **0** | **6** | **0** |
| frontend Vitest | 420 | 0 | 0 | 0 |
| Vite build | PASS | 0 | — | 0 |
| original A0.5 | 74 | 0 | 0 | 0 |
| acceptance trace | 25 | 0 | 0 | 0 |
| E2E safety guards | 9 | 0 | 0 | 0 |
| RC3.0 benchmark | PASS | 0 | — | 0 |

RC3.0 benchmark: chain 30/31 (96.8%), verdict 30/31, false-positive IOCs 0,
avg latency **473 ms** against the unchanged 500 ms ceiling. This run was
concurrent with the backend gates; the quiet-host measurement earlier in the
sprint was 391 ms. No threshold was altered.

Counts overlap across scopes and must not be summed as unique tests.
**Not executed:** authenticated browser/DOM acceptance, real Mongo concurrency
and reconciliation, target-host resource/concurrency gates, exact candidate
packaging. Host remains **ARM64 / CPython 3.11.17**, which is not target-host
proof.

## G · Handoff

| Item | Value |
|---|---|
| Final commit | `1dc4e35809c4b30bda15d0ed25db06c6feb50e24` |
| Final tree | `1995523652e25ff86de3cec19741199e55bec55f` |
| Bundle | `/app/rocket-evidence/e3/nivxray-e3-final-acceptance.bundle` — 23,502,285 bytes, SHA-256 `36515e1d9624f3ee5bf5182b0e57e8e3bee75f56ea4a4acf72de4b4d7580e757`, verified in a fresh clone: 6 commits, no alternates, `fsck` clean |
| Evidence | `/app/rocket-evidence/e3/` |
| Credentials | `/app/memory/test_credentials.md` (all synthetic; stack stopped) |

All isolated services were stopped after the run. The platform preview
services in `/app` were never touched.

### Remaining release HOLDs — none waived

- **FULL_E2E** — blocked on kernel-enforced egress denial (section C).
- Authenticated browser/DOM acceptance not performed.
- Real Mongo concurrency, reconciliation and target-host worker/resource gates.
- Collector missing-signature acceptance and replay durability.
- Credential/runtime hygiene and owner rotation; the response engine's
  `data/executions.db` is still a tracked file that runtime mutates.
- NCI permission/service delegation and automatic admission.
- Legacy cache exposure and migration.
- CI-09 and related security gates; SDK provenance.
- Exact candidate packaging for release; EDR feature development.
- Production/release approval.

No push, merge, PR, deployment, production or customer access, real
containment, purchase or infrastructure change occurred.
