# RC1-P1 — Suspended Customer Authorization Repair

Branch: `security/xdr-rc1-p1-scope-authority`. Published parent: `688941cc9473263dba9864681ff80373299dd077` (`release/xdr-rc1-integration`). Local baseline source tree verified equal to published RC1: `bee8625e6a3eb7f36edc010e49c941d52f03800d`.

## Original reproduction

Before editing, ran the unchanged RC1 negative test:

```text
MONGO_URL='' PYTHONPATH=backend python -m pytest --noconftest -o addopts='' backend/tests/test_xdr_rc1_integration.py::test_inactive_customer_selection_and_rbac_must_agree --tb=short -q
```

**FAILED:** synthetic B was SUSPENDED; selected-customer effective RBAC returned 403, but scope selection returned 200 rather than the expected 403. No customer data or production requests were used. The original assertion and test remain unchanged.

## Repair

`session_context.effective_scope` now uses the registry-validated active authorized universe for every selected, group, all-authorized and incident-bound decision. Raw grant lists and PLATFORM designation cannot bypass registry validation. Incident scope still rejects a conflicting destination and remains locked to its authorized active owner.

Platform registry enumeration is revalidated through the same mandatory registry entry used by RBAC; stale enumeration cannot authorize unknown/deactivated records. Duplicate grants/members are removed. Empty or unavailable authority denies rather than returning an authorized empty scope. Unsupported scope kinds and contradictory body selectors deny.

Group behavior retains the existing intersection contract: a mixed request can return 200 for the active authorized subset, listing excluded customers in `denied_tenant_ids`; a group containing only invalid customers returns 403. All-authorized scope omits invalid customers; it does not fabricate a permission union. Partial registry failure excludes the affected customer; total registry failure refuses all scopes. RBAC may report registry failure as 503 while selection reports fail-closed 403; both deny access.

`xdr_scope.ScopeSelection` rejects unknown body fields instead of silently ignoring forged aliases. The selection handler rejects contradictory query selectors, blank or conflicting context headers, and a foreign/inactive current context. **Compatibility distinction:** the request body names the requested destination, while the normal browser `X-Tenant-Id` header describes its current context. Switching A→B legitimately carries header A/body B; both must independently be active and authorized. Requiring those two different-purpose values to match would break existing MSSP switching. Neither value grants authority.

Scope selection establishes customer breadth, not a resource permission. Tenant A can retain `secrets.read` while Tenant B does not; selection does not promote B's permissions. Existing RBAC and resource ownership checks remain authoritative. This task does not define aggregate effective permissions or migrate unmapped global/console endpoints.

## Changed files

- `backend/services/session_context.py`
- `backend/routers/xdr_scope.py`
- `backend/tests/test_xdr_rc1_p1_scope_authority.py`
- This validation record.

No changes to xdr_rbac, tenant_registry, frontend, MITRE/S1, IOC, EDR, CI, deployment configuration, original RC1 negative tests or PR #7.

## Fresh results

| Validation | Result |
|---|---|
| Original RC1 negative test after repair | PASS, included in combined run |
| New focused negative suite | 48 passed |
| RC1 integration + RBAC2 + D14 regressions | 118 passed |
| Combined deterministic backend | **166 passed**, one Starlette/httpx deprecation warning |
| Full RC frontend suite | **117 passed**, 9 suites |
| Frontend build | **PASS** |
| Changed Python AST/syntax and diff checks | **PASS** |
| Mongo-backed/live backend | NOT RUN |
| Authenticated browser acceptance | BLOCKED / NOT VERIFIED |

New tests cover A/B/C, suspended/disabled/unknown customers, inactive organization, stale grants, partial and total registry failure, all four scope forms, platform enumeration, empty registry, conflicting selectors, invalid headers, authorized A→B switching and B8 selector visibility with no incidents. Existing incident-lock and different-per-customer permission tests pass. Synthetic stores reuse fixtures blocking socket connections; no real credentials or customer data. Tests exercise the real FastAPI scope/RBAC handlers with synthetic backing stores, not a live Mongo integration.

Backend command:

```text
MONGO_URL='' PYTHONPATH=backend python -m pytest --noconftest -o addopts='' backend/tests/test_xdr_rc1_p1_scope_authority.py backend/tests/test_xdr_rc1_integration.py backend/tests/test_rbac_selected_customer.py backend/tests/test_d14_tenant_authority.py --tb=short -q
```

Frontend commands: `npm test --prefix apps/nivxray-xdr`; `npm run build --prefix apps/nivxray-xdr`. Reused the existing cache corresponding to the unchanged RC lockfile; no dependency files modified.

## Remaining gates and compatibility risks

**Overall release recommendation: NO-GO.** The demonstrated suspended-customer blocker is repaired only on this isolated branch. RC1/PR #8 remain unchanged until separate integration review; the original RC1 commit still contains the failure.

Independent authorization review, Mongo-backed membership/resource isolation and audit persistence, approved synthetic staging identities, authenticated Administrator/Analyst/MSSP desktop/mobile acceptance and exact-build owner approval remain open. MITRE/S1 observations remain blocked, IOC authentication and EDR gates remain separate. Legacy/global RBAC and selected-customer console/aggregate migration issues are not closed by fixing scope breadth.

Revoked/stale current context headers are refused even when a new destination is valid. Browser recovery must clear that stale selection through the approved context reset/session flow; no fallback grants are introduced. Registry enumeration limits and changes during separate requests remain integration considerations; resource endpoints must independently reauthorize each request. No new cache of grants was introduced.

No production changes, identity provisioning, merge, deployment or HOLD removal. STOP after repair publication.
