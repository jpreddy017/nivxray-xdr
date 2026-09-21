# S1 · INCIDENT SUB-RESOURCE AUTHORIZATION CLOSURE — 2026-06-21

**Status: CLOSED · PROVEN.** Backend only. No frontend change. No S2/S3/S4 work.

Proofs kept in `/app/test_reports/`:
`s1_live_authz_matrix.txt` (66 PASS · 0 FAIL, real JWTs over the preview edge) ·
`s1_focused_regression.txt` · `s1_fixture_isolation_proof.txt` ·
`s1_incident_family_authz_audit.txt`.

## AUTHORIZATION MODEL APPLIED (one model, one authority)

    authenticated principal
      → server-resolved tenant scope        (`resolve_tenant_scope`, never a
                                             client-presented tenant)
      → the incident belongs to that scope  (out of scope ⇒ 404, existence
                                             never disclosed)
      → required permission for a MUTATION  (`incidents.update`)
      → resource / action, actor = the verified principal

Exported from `routers/incidents.py` as `authorized_incident()` +
`require_incident_action()`. It **delegates to the existing** `_authorized_incident`
(P0-W) — no second authorization model was introduced.

## ROUTES FIXED (14)

Originally reported by the consolidation inventory (6 + the write API):
- `GET  /api/incidents/{id}/investigation`
- `GET  /api/incidents/{id}/investigation/executions`
- `GET  /api/incidents/{id}/investigation/findings`
- `GET  /api/incidents/{id}/attack-story`
- `GET  /api/incidents/{id}/attack-graph`
- `GET  /api/incidents/{id}/report`
- `GET  /api/incidents/{id}/report/pdf`
- `POST /api/incidents/{id}/report/blocks`
- `PATCH /api/incidents/{id}/report/blocks/{block_id}`
- `DELETE /api/incidents/{id}/report/blocks/{block_id}`
- `POST /api/incidents/{id}/report/blocks/{block_id}/suppress`

ADDITIONAL SAME-CLASS, found while verifying the boundary (owner-approved, same pass):
- `GET  /api/incidents/{id}/attack-evidence` — **no authentication dependency at all**
- `GET  /api/incidents/{id}/inspector/{kind}/{ref_id}` — **no authentication dependency at all**
- `GET  /api/incidents/{id}/summary` — authenticated, **no tenant predicate**
- `GET  /api/incidents/{id}/threat-model` — optional principal, **no tenant predicate**
- `GET  /api/incidents/{id}/intelligence/overlays`
- `GET  /api/incidents/{id}/intelligence/overlays/{kind}/{target}/{field}`
- `GET  …/overlays/{kind}/{target}/{field}/history`
- `PUT  …/overlays/{kind}/{target}/{field}` — cross-tenant **write**
- `DELETE …/overlays/{kind}/{target}/{field}` — cross-tenant **write**

## ORIGINAL VULNERABILITIES

1. **Anonymous read of another customer's incident content.** Seven projections
   answered `200` with no authenticated principal.
2. **Unauthenticated write.** The whole report-block API had *no* auth
   dependency and took `author_email` **from the request body** — attribution
   was a client claim.
3. **Cross-tenant direct object reference.** Every sub-resource resolved
   `{"id": incident_id}` with no tenant predicate.
4. **Block hijack.** Block mutations were keyed on `block_id` alone, so a
   principal authorized for their own incident could edit/delete a block of
   another customer's incident by putting their own incident id in the path.

## ADDITIONAL SAME-CLASS VULNERABILITIES FOUND

- Two routers (`attack_evidence`, `evidence_inspector`) carried **no auth at all**.
- `incident_summary` / `incident_threat_model` were authenticated (or optional)
  but unscoped.
- The **entire analyst intelligence-overlay family** was authenticated and
  unscoped on both planes — one customer's analyst could read *and overwrite*
  another customer's analyst interpretation. Its two mutations now also require
  `incidents.update`.

**Different root cause → recorded, NOT changed (owner decision):**
`GET /api/xdr/incidents/{id}/response-executions` (`routers/xdr_response_evidence.py`)
is a different resource family, gated on `evidence.read`, but queries by
`invoker.context.incident_id` with an **optional, client-supplied `tenant_id`**.
The defect class is "client-presented tenant", not "missing authority". Left for
an owner decision.

`content_supply_chain.py`'s eight per-incident routes are `require_admin` — not a
leak; that is the **S2** over-restriction question.

## FILES CHANGED / CREATED

Changed: `routers/incidents.py` (exported authority + action gate) ·
`routers/report.py` · `routers/autonomous_investigator.py` ·
`routers/attack_story.py` · `routers/attack_graph.py` ·
`routers/attack_evidence.py` · `routers/evidence_inspector.py` ·
`routers/incident_summary.py` · `routers/incident_threat_model.py` ·
`routers/intelligence_overlay.py`.
Created: `backend/tests/test_s1_incident_subresource_authz.py` ·
`backend/scripts/s1_incident_family_authz_audit.py` ·
`backend/scripts/s1_fixture_isolation_proof.py` ·
`scripts/s1_live_authz_matrix.py`.

## TEST RESULTS

- **S1 suite — 61 passed / 0 failed** (`tests/test_s1_incident_subresource_authz.py`).
- **Live edge matrix — 66 PASS · 0 FAIL**, real logins, no overrides: anonymous
  denied on all 14 reads · own-tenant analyst **200 on all 14** · cross-tenant
  404 with the incident name absent from the body · anonymous + cross-tenant
  mutations denied · same-tenant mutation without the grant →
  `403 {permission: incidents.update, reason: user-not-provisioned}` ·
  `?tenant=`, `?customer=`, `X-Tenant-Id`, `X-Principal-Id` all **not authority** ·
  unknown incident → 404 on every route.
- **Focused regression (10 suites, one serial process) — 316 passed · 3 skipped ·
  2 failed**, both proven **pre-existing** by re-running on the pre-S1 tree
  (`git stash`):
  - `test_iteration_81_review::test_admin_sees_all_198` → `expected 198, got 500`:
    a hard-coded **live-dataset count** (the preview DB has grown). Fails
    identically without S1.
  - `test_a05_tenant_scope_contract::test_incident_resource_authorization_is_independent_of_scope_request`:
    `test_xdr_incident_queue` installs a **module-level**
    `dependency_overrides[get_current_user_optional] = admin` at *import* time,
    so merely collecting it makes a05's acme principal answer as admin. Fails
    byte-identically on the pre-S1 tree (`1 failed, 88 passed`).
- **Real defect in my own first S1 test file, fixed:** `_anon()` called
  `app.dependency_overrides.clear()`, which deleted the queue module's override
  and broke **9** `test_xdr_incident_queue` tests. The suite now owns exactly one
  key (`pop(get_current_user)`) and touches nothing else. Those 9 now pass.

## FIXTURE ISOLATION STATUS — PASS

`backend/scripts/s1_fixture_isolation_proof.py`: snapshot → S1 suite (pass) →
a **deliberately failing** module using the same fixture → snapshot.
- Cleanup runs on success **and** on failure (the failing module is asserted to
  fail; `rc=1`).
- S1-owned collections count-identical: `workspace_cases 1272 → 1272` ·
  `users 17 → 17` · `xdr_report_blocks 15 → 15` · overlays `10 → 10` ·
  overlay audit `16 → 16`; **0** fixture documents remaining by id/email.
- **Incident queue count 942 → 942.**
- Every other collection that moved is attributed by measurement, not assumption:
  two control windows with no tests running, plus a control module that only
  enters the app lifespan — the app's **own startup job** (detection-content sync
  + TI sync) writes `xdr_detection_versions`/`xdr_audit_log`/`edr_raw_events`/
  `xdr_canonical_evidence`/`xdr_cortex_scheduler_audit`/`xdr_vault_audit`/
  `v2_shadow_observations`.

## KNOWN RESIDUALS

1. **TEST INFRASTRUCTURE RESIDUAL — DOES NOT INVALIDATE S1.** `ti_sync_runs +1`
   during the test window and in neither control window. Probed: **0** documents
   carry an S1 fixture marker; its newest document is a TI feed roll-up
   (`threatfox/urlhaus/feodo/blocklist_de/otx`) written by the background sync
   loop on its own period.
2. **Two pre-existing test defects** (above) remain failing and are NOT absorbed,
   NOT baseline-reset: a stale hard-coded live count, and the queue module's
   import-time global dependency override. Both reproduce without S1.
3. **Three incident routes keep the P0-W optional-principal dependency** —
   `GET /api/incidents/{id}`, `GET …/understanding`, `PATCH …/operations`. They
   all resolve through the authority, so an anonymous caller is **fail-closed**
   (proven live: `…/understanding` anonymous → **404**). The residual is
   *vocabulary*, not exposure: they deny with 404 where the S1 routes deny with
   401/403. Not changed — no further expansion.
4. `GET /api/xdr/incidents/{id}/response-executions` — different root cause,
   recorded above, awaiting an owner decision.

## GIT DIFF SUMMARY

10 backend routers modified (authorization only — no projection, contract,
collection, state machine or frontend change), 4 new test/proof files, 4 proof
reports. No `.env`, dependency, schema or index change.
