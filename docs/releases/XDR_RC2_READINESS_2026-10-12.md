# XDR RC2 — Integration and Production Readiness

Branch: `release/xdr-rc2-validation`. **Production status: NO-GO.** RC1-P1 is included by direct ancestry, not duplicated or cherry-picked onto itself. No application code is changed beyond the approved repair.

## Verified source chain

| Source | Published SHA | RC2 treatment |
|---|---|---|
| Production reference | e2f15a252630e478c5667f9e1d883a02acad1a1c | Preserved production base and B8 selector behavior |
| RC1 | 688941cc9473263dba9864681ff80373299dd077 | Combined dashboard/IA1/RBAC2/loader candidate |
| RC1-P1 | 374b7e3e78fdb5b7f94557159ad8b75f08b94c3a | Direct RC2 parent, containing all four repair files |
| RC2 | Final publication SHA reported with delivery | Adds Mongo-backed validation and this report only |

Both source branch heads and P1→RC1 ancestry independently verified through GitHub in this task. Local application source tree matches published P1 tree `1a96b25f80d4091f0a3ab96875061b640950d383`. Dashboard, guards, selected-customer permissions, investigation loader, B8 selectors and ordered route paths remain intact. MITRE remains blocked; S1, EDR, PR #7 and experimental additions remain excluded. RC1/PR #8 are not rewritten or merged.

## Fresh local results

| Check | Result / limits |
|---|---|
| Existing deterministic backend suite | **166 passed** |
| New real Mongo acceptance suite | **17 passed** |
| Combined backend run | **183 passed**, one Starlette/httpx deprecation warning |
| Complete RC frontend suite | **117 passed**, 9 suites |
| Frontend production build | **PASS** |
| Python syntax / diff / route preservation | **PASS** |
| Approved shared staging environment | **NOT ESTABLISHED** |
| Authenticated application browser acceptance | **BLOCKED / NOT VERIFIED** |
| Independent security approval | **OUTSTANDING** |

The production-based RC test inventory excludes unrelated E3/EDR modules. These counts are fresh, not historical reports.

### Mongo-backed gate advanced

Downloaded MongoDB 7.0.16 from its official distribution endpoint and verified the official SHA-256: `376c258ae9b104b88814214bc3214a2e0d1300d8192d24d8c46259f364866422`. Download: https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2204-7.0.16.tgz. Checksum: same URL plus `.sha256`. This frozen version is a test dependency, not a production Mongo version recommendation.

A disposable standalone server ran only on 127.0.0.1, with temporary data under `/dev/shm`. No preexisting Mongo credentials, shared database, customer records or environment files were consulted. The successful final run kept server and tests in the same managed command/network environment. Its completion verified that all `xdr_rc2_test_*` databases were removed and requested server shutdown.

The new fixture rejects non-loopback URIs and defaults to no database. It generates separate unique databases, ephemeral JWT/signing keys and synthetic Administrator-A, Analyst-A and MSSP-A/B records; C is unauthorized. No skipped tests. It blocks external socket connections while allowing only its named local Mongo port.

Real FastAPI scope and RBAC handlers, real JWT validation, permission resolution and Mongo queries were exercised. Authentication's async user lookup is adapted to a real synchronous Mongo collection; it is not a login browser session or a full Motor/server startup test. No authorization dependency or signature computation is replaced. Audit emission uses the supported ephemeral signing configuration and real Mongo inserts.

Coverage:

- A/B/C selection and effective projections for all three profiles; Administrator-A cannot access B/C by role alone.
- Different MSSP permissions in A and B; no administrative grants inferred from multi-customer entitlement.
- Real user list and user-effective ownership checks. Foreign and nonexistent IDs receive equivalent 404 bodies.
- A foreign-resource DELETE is denied and leaves the original Mongo membership/assignments unchanged. Analyst mutation of a same-customer record is denied, with a persisted audit event.
- Suspension excluded from selected, group, all-authorized and incident scopes.
- Missing/disabled RBAC memberships produce empty effective permissions; revoked identity grants are not cached.
- Foreign incident scope and conflicting query/header tenant claims deny.

Initial attempts were diagnostic, not accepted results: cross-command localhost connectivity caused 17 setup errors; using one command fixed environmental isolation. A subsequent audit assertion failed because the test had not configured a signing key; adding an ephemeral key through the supported configuration fixed the fixture, without mocking or weakening audit assertions. Final combined run passed all 183 tests.

Command (after starting the disposable local Mongo server in the same environment):

```text
MONGO_URL='' XDR_RC2_TEST_MONGO_URI='mongodb://127.0.0.1:27185' PYTHONPATH=backend python -m pytest --noconftest -o addopts='' backend/tests/test_xdr_rc1_p1_scope_authority.py backend/tests/test_xdr_rc1_integration.py backend/tests/test_rbac_selected_customer.py backend/tests/test_d14_tenant_authority.py backend/tests/test_xdr_rc2_mongo_acceptance.py --tb=short -q
```

This closes the local test execution blocker for the tested scope/RBAC paths. It does not certify every resource service, replica-set behavior, concurrent audit chains, distributed replay, all incident/collector endpoints or the deployed frontend/backend pair.

## Fresh authorization review and remaining concerns

Reviewed P1 selection against mandatory registry authority, body/header semantics, incident locking and B8 picker projection. Current header A/request body B is intentionally permitted only when both independently belong to the active authorized universe; it represents a switch, not a grant. Group intersection retains excluded-member diagnostics. Permission breadth is still per customer, not a union of A/B permissions.

The same engineering agent performed this source review; it is **not independent owner/security approval**. Required independent review remains a release gate.

Existing material gaps remain:

- Legacy console projection/global administrator and global role-definition policies are not fully migrated by RBAC2.
- MSS aggregate endpoints still use their separate authenticated scope resolver and do not automatically acquire per-customer resource permission checks. Scope breadth and permissions are distinct; a valid selection is not proof of authority to read every API.
- MITRE observations still have the separate S1 backend repair candidate. A frontend guard is not API protection. Do not enable observations or claim backend isolation closure until independently reviewed and integrated.
- IOC authentication, EDR collector/webhook and credential hygiene HOLDs are unchanged.
- The Mongo suite validates specific RBAC resource ownership, not full Secrets/API keys/collectors/incident/evidence CRUD coverage. Broader deployed-backend integration is still needed.

## Protected preview and domain verification

The current source-equivalent P1 preview is READY: `https://nivxray-dz7watgqv-jpreddy017.vercel.app`, deployment `dpl_FRQZru2sjWpWQcDrZjfiaWohtnRG`, source 374b7e3e, target null. Protected fetch in this task failed at `read_protection_bypass` with HTTP 403: the Vercel connection lacks project/team deployment access. No bypass or application authentication workaround was attempted. No permitted CLI/browser fallback session was available. RC2 automatic preview creation is not assumed from P1 metadata.

Required access: authorize the appropriate Vercel project/team in the existing connection and confirm that account can access the protected deployment; establish an approved staging backend/database; provision both supported login and RBAC membership records using the authorized provisioning mechanism; then provide approved synthetic app sessions. Keep deployment protection enabled and never share passwords/tokens in chat.

The requested new target **`www.xdr.nivxray.com`** returned deployment-not-found (404) in the connected Vercel account. This does not prove the domain does not exist elsewhere. Local DNS lookup failed for both it and the known old hostname, so that DNS failure is environmental and is not evidence of misconfiguration. A project/team/domain mapping for the new target remains required; no DNS, aliases or domains were changed.

Fresh Vercel inspection confirms the known existing `xdr.nivxforge.com` still aliases READY production deployment `dpl_7f2hrNr5pwTpEqJiJCyavPBJQVrP`, project `nivxray-xdr-production`, source e2f15a25. It was not promoted or updated.

## Screenshot review and feature acceptance

Both attached files were successfully opened from the supplied workspace paths. They are user-provided desktop images, not screenshots captured by this task:

- 8.56.39 AM: IA1 preview `nivxray-8cjzuowbr-jpreddy017.vercel.app`; purple identity, Priority Incident Queue and a stale snapshot warning, zero returned records.
- 8.56.41 AM: existing `xdr.nivxforge.com`; older orange-accented Control Center, a Needs attention panel and larger inter-panel blank area.

These support the reported production/preview presentation difference. They do not establish RC2 rendering, backend pairing, persona permissions, correct zero values, queue interactions, investigation Preview, tenant races or mobile behavior. No new authenticated screenshots were fabricated, and no pixel-fidelity acceptance is claimed.

| Feature | Source/local verification | Required browser acceptance |
|---|---|---|
| Compact dashboard and KPI cards | Existing RC rendering/state tests pass | Real permitted data; genuine zero vs denied/unavailable, reporting scope and responsive density |
| Priority Incident Queue | Sorting/filter/empty/stale regressions pass | Four real authorized rows at desktop target when records exist; action destinations and focus |
| Incident Preview | Record matching, denied evidence and focus tests pass | Correct Story/Timeline/Evidence, Escape/return focus, rapid incident switching |
| Engine loader | Denial/no fallback, unavailable/zero and delayed responses pass | Real backend failures, tab/profile/history, customer/logout invalidation |
| Direct guards / customer selection | Local direct-route tests and real Mongo scope/RBAC tests pass | Administrator/Analyst/MSSP navigation, refresh/deep links, C denial and session transitions |
| Premium graph / observable redesign | Not part of RC2 | Separate approved implementation; do not claim this release creates those interfaces |

Future UI completion requires actual React implementation to match an approved visual reference and interactions to work with real authorized data, with genuine desktop/mobile screenshots. Tests alone establish no visual acceptance. NivXRay XDR and NivXForge EDR keep separate identities and release/security gates despite any shared design language.

## Deployment compatibility and rollback

RC frontend requires its matching backend selected-customer RBAC, mandatory active registry authority and `authorized_tenants` projection. Deploying only the frontend against the old backend can cause unavailable/denied pages or misleading scope behavior. Do not change production origins to an unvalidated backend.

Review/bootstrap explicit customer grants, ACTIVE tenant/organization records, separate login/RBAC membership, console permissions and audit signing in staging before promoting any build. Do not restore an admin bypass to resolve migration lockouts. Shared session-context consumers require regression review.

No migrations or configuration changes are performed here. Before any approved future promotion, record the exact frontend and backend release revisions/configuration and verify their pairing. Keep e2f15a25 / `dpl_7f2hrNr5pwTpEqJiJCyavPBJQVrP` as the observed frontend rollback reference; backend rollback must be compatible with any later changes and preserve security boundaries. Require explicit owner approval of the exact reviewed production build.

**NO-GO remains:** local scope/RBAC Mongo validation has advanced, but protected browser/staging access, independent security approval, broader backend boundaries and the requested domain mapping are not resolved. No production identities, customer-data modifications, merges, deployments or HOLD changes. STOP after candidate publication and reporting.
